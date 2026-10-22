from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from app import database
from app.plans import (
    PlanConfigurationError,
    QuotaExceeded,
    current_period_start,
    get_usage,
    reserve_quota,
    settle_quota,
)


def set_limits(monkeypatch, *, audits: int = 1) -> None:
    metrics = {
        "audits": audits,
        "ai_reviews": 2,
        "agent_runs": 2,
        "conversation_messages": 4,
        "conversation_creations": 2,
    }
    monkeypatch.setenv(
        "AEGIS_PLAN_LIMITS",
        json.dumps({
            "free": metrics,
            "pro": metrics,
            "enterprise": metrics,
        }),
    )


@pytest.fixture
def quota_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "quota.db")
    database.init_db()
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO organizations (id, name, created_at) VALUES ('org', 'Org', 'now')"
        )
        connection.execute(
            """INSERT INTO users (id, organization_id, email, password_hash, role, created_at)
               VALUES ('user', 'org', 'user@example.test', 'synthetic', 'admin', 'now')"""
        )


def test_plan_limits_validate_exact_plans_and_metrics(monkeypatch):
    monkeypatch.setenv("AEGIS_PLAN_LIMITS", '{"free":{},"pro":{},"enterprise":{}}')
    with pytest.raises(PlanConfigurationError):
        from app.plans import load_plan_limits

        load_plan_limits()


def test_quota_reservation_confirmation_and_release(quota_db, monkeypatch):
    set_limits(monkeypatch)
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        reservation = reserve_quota(
            connection,
            organization_id="org",
            user_id="user",
            metric="audits",
            idempotency_key="audit-1",
        )
        assert settle_quota(connection, reservation, confirm=False)
        assert not settle_quota(connection, reservation, confirm=True)

        replacement = reserve_quota(
            connection,
            organization_id="org",
            user_id="user",
            metric="audits",
            idempotency_key="audit-2",
        )
        assert settle_quota(connection, replacement, confirm=True)
        assert not settle_quota(connection, replacement, confirm=True)
        usage = get_usage(connection, organization_id="org", user_id="user")

    assert usage["usage"]["audits"] == {
        "user": {"consumed": 1, "reserved": 0},
        "organization": {"consumed": 1, "reserved": 0},
    }


def test_organization_limit_is_shared_across_users(quota_db, monkeypatch):
    set_limits(monkeypatch)
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """INSERT INTO users (id, organization_id, email, password_hash, role, created_at)
               VALUES ('user-2', 'org', 'second@example.test', 'synthetic', 'admin', 'now')"""
        )
        first = reserve_quota(
            connection,
            organization_id="org",
            user_id="user",
            metric="audits",
            idempotency_key="audit-1",
        )
        settle_quota(connection, first, confirm=True)
        with pytest.raises(QuotaExceeded):
            reserve_quota(
                connection,
                organization_id="org",
                user_id="user-2",
                metric="audits",
                idempotency_key="audit-2",
            )


def test_quota_limits_are_atomic_across_concurrent_requests(quota_db, monkeypatch):
    set_limits(monkeypatch)

    def consume(index: int) -> bool:
        with database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                reservation = reserve_quota(
                    connection,
                    organization_id="org",
                    user_id="user",
                    metric="audits",
                    idempotency_key=f"audit-{index}",
                )
            except QuotaExceeded:
                return False
            settle_quota(connection, reservation, confirm=True)
            return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(consume, (1, 2)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 1


def test_concurrent_settlement_changes_reservation_and_counters_once(
    quota_db, monkeypatch
):
    set_limits(monkeypatch)
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        reservation = reserve_quota(
            connection,
            organization_id="org",
            user_id="user",
            metric="audits",
            idempotency_key="concurrent-settlement",
        )

    start = threading.Barrier(2)

    def settle(confirm: bool) -> bool:
        with database.connect() as connection:
            start.wait(timeout=5)
            return settle_quota(connection, reservation, confirm=confirm)

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(settle, (True, False)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 1
    with database.connect() as connection:
        status = connection.execute(
            "SELECT status FROM quota_reservations WHERE id=?",
            (reservation,),
        ).fetchone()["status"]
        usage = get_usage(connection, organization_id="org", user_id="user")

    assert status in {"confirmed", "released"}
    assert usage["usage"]["audits"]["user"] == {
        "consumed": int(status == "confirmed"),
        "reserved": 0,
    }
    assert usage["usage"]["audits"]["organization"] == {
        "consumed": int(status == "confirmed"),
        "reserved": 0,
    }


def test_many_concurrent_settlements_apply_exactly_once(quota_db, monkeypatch):
    set_limits(monkeypatch)
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        reservation = reserve_quota(
            connection,
            organization_id="org",
            user_id="user",
            metric="audits",
            idempotency_key="many-settlements",
        )

    workers = 8
    start = threading.Barrier(workers)

    def settle(_: int) -> bool:
        with database.connect() as connection:
            start.wait(timeout=5)
            return settle_quota(connection, reservation, confirm=True)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        outcomes = list(executor.map(settle, range(workers)))

    assert outcomes.count(True) == 1
    with database.connect() as connection:
        usage = get_usage(connection, organization_id="org", user_id="user")
    expected = {"consumed": 1, "reserved": 0}
    assert usage["usage"]["audits"]["user"] == expected
    assert usage["usage"]["audits"]["organization"] == expected


def test_quota_period_uses_utc_calendar_date():
    assert current_period_start(datetime(2026, 10, 20, 23, 59, tzinfo=UTC)) == "2026-10-20"
