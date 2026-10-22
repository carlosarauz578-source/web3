from __future__ import annotations

import json
import math
import os
import sqlite3
import uuid
from datetime import UTC, date, datetime, timedelta
from datetime import time as datetime_time
from typing import Any

PLAN_IDS = ("free", "pro", "enterprise")
METRICS = (
    "audits",
    "ai_reviews",
    "agent_runs",
    "conversation_messages",
    "conversation_creations",
)
DEVELOPMENT_PLAN_LIMITS: dict[str, dict[str, int]] = {
    "free": {
        "audits": 5,
        "ai_reviews": 5,
        "agent_runs": 10,
        "conversation_messages": 100,
        "conversation_creations": 20,
    },
    "pro": {
        "audits": 50,
        "ai_reviews": 50,
        "agent_runs": 100,
        "conversation_messages": 500,
        "conversation_creations": 100,
    },
    "enterprise": {
        "audits": 200,
        "ai_reviews": 200,
        "agent_runs": 500,
        "conversation_messages": 2_000,
        "conversation_creations": 500,
    },
}


class PlanConfigurationError(ValueError):
    pass


class QuotaExceeded(Exception):
    def __init__(self, metric: str, limit: int, period_start: str) -> None:
        self.metric = metric
        self.limit = limit
        self.period_start = period_start
        now = datetime.now(UTC)
        reset_at = datetime.combine(
            now.date() + timedelta(days=1),
            datetime_time.min,
            UTC,
        )
        self.retry_after = max(1, math.ceil((reset_at - now).total_seconds()))
        super().__init__(f"Quota exceeded for {metric}.")


def load_plan_limits() -> dict[str, dict[str, int]]:
    raw = os.getenv("AEGIS_PLAN_LIMITS")
    if raw is None:
        return {plan: dict(limits) for plan, limits in DEVELOPMENT_PLAN_LIMITS.items()}
    try:
        parsed: Any = json.loads(raw)
    except json.JSONDecodeError as error:
        raise PlanConfigurationError from error
    if not isinstance(parsed, dict) or set(parsed) != set(PLAN_IDS):
        raise PlanConfigurationError
    validated: dict[str, dict[str, int]] = {}
    for plan_id in PLAN_IDS:
        limits = parsed[plan_id]
        if not isinstance(limits, dict) or set(limits) != set(METRICS):
            raise PlanConfigurationError
        if any(type(limits[metric]) is not int or limits[metric] < 1 for metric in METRICS):
            raise PlanConfigurationError
        validated[plan_id] = dict(limits)
    return validated


def current_period_start(now: datetime | None = None) -> str:
    current = now or datetime.now(UTC)
    current = current.astimezone(UTC) if current.tzinfo else current.replace(tzinfo=UTC)
    return date(current.year, current.month, current.day).isoformat()


def reserve_quota(
    connection: sqlite3.Connection,
    *,
    organization_id: str,
    user_id: str,
    metric: str,
    idempotency_key: str,
    now: datetime | None = None,
) -> str:
    if metric not in METRICS or not idempotency_key or len(idempotency_key) > 128:
        raise ValueError("Invalid quota reservation.")
    limits_by_plan = load_plan_limits()
    organization = connection.execute(
        "SELECT plan_id FROM organizations WHERE id=?",
        (organization_id,),
    ).fetchone()
    if organization is None:
        raise ValueError("Organization does not exist.")
    limit = limits_by_plan.get(organization["plan_id"])
    if limit is None:
        raise PlanConfigurationError
    period_start = current_period_start(now)
    existing = connection.execute(
        """SELECT id, status FROM quota_reservations
           WHERE organization_id=? AND user_id=? AND metric=? AND idempotency_key=?""",
        (organization_id, user_id, metric, idempotency_key),
    ).fetchone()
    if existing is not None:
        if existing["status"] in {"reserved", "confirmed"}:
            return existing["id"]
        raise ValueError("Quota idempotency key was already released.")
    counter = connection.execute(
        """SELECT consumed, reserved FROM quota_counters
           WHERE organization_id=? AND user_id=? AND metric=? AND period_start=?""",
        (organization_id, user_id, metric, period_start),
    ).fetchone()
    organization_counter = connection.execute(
        """SELECT consumed, reserved FROM organization_quota_counters
           WHERE organization_id=? AND metric=? AND period_start=?""",
        (organization_id, metric, period_start),
    ).fetchone()
    consumed = counter["consumed"] if counter else 0
    reserved = counter["reserved"] if counter else 0
    organization_consumed = organization_counter["consumed"] if organization_counter else 0
    organization_reserved = organization_counter["reserved"] if organization_counter else 0
    if consumed + reserved >= limit[metric] or (
        organization_consumed + organization_reserved >= limit[metric]
    ):
        raise QuotaExceeded(metric, limit[metric], period_start)
    reservation_id = str(uuid.uuid4())
    connection.execute(
        """INSERT INTO quota_reservations
           (id, organization_id, user_id, metric, period_start, idempotency_key,
            status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?)""",
        (
            reservation_id,
            organization_id,
            user_id,
            metric,
            period_start,
            idempotency_key,
            (now or datetime.now(UTC)).isoformat(),
        ),
    )
    connection.execute(
        """INSERT INTO quota_counters
           (organization_id, user_id, metric, period_start, consumed, reserved)
           VALUES (?, ?, ?, ?, 0, 1)
           ON CONFLICT(organization_id, user_id, metric, period_start)
           DO UPDATE SET reserved=reserved+1""",
        (organization_id, user_id, metric, period_start),
    )
    connection.execute(
        """INSERT INTO organization_quota_counters
           (organization_id, metric, period_start, consumed, reserved)
           VALUES (?, ?, ?, 0, 1)
           ON CONFLICT(organization_id, metric, period_start)
           DO UPDATE SET reserved=reserved+1""",
        (organization_id, metric, period_start),
    )
    return reservation_id


def settle_quota(
    connection: sqlite3.Connection,
    reservation_id: str,
    *,
    confirm: bool,
    now: datetime | None = None,
) -> bool:
    next_status = "confirmed" if confirm else "released"
    cursor = connection.execute(
        """UPDATE quota_reservations SET status=?, finalized_at=?
           WHERE id=? AND status='reserved'""",
        (next_status, (now or datetime.now(UTC)).isoformat(), reservation_id),
    )
    if cursor.rowcount != 1:
        return False
    reservation = connection.execute(
        """SELECT organization_id, user_id, metric, period_start
           FROM quota_reservations WHERE id=?""",
        (reservation_id,),
    ).fetchone()
    connection.execute(
        """UPDATE quota_counters
           SET reserved=reserved-1, consumed=consumed+?
           WHERE organization_id=? AND user_id=? AND metric=? AND period_start=?
             AND reserved > 0""",
        (
            int(confirm),
            reservation["organization_id"],
            reservation["user_id"],
            reservation["metric"],
            reservation["period_start"],
        ),
    )
    connection.execute(
        """UPDATE organization_quota_counters
           SET reserved=reserved-1, consumed=consumed+?
           WHERE organization_id=? AND metric=? AND period_start=? AND reserved > 0""",
        (
            int(confirm),
            reservation["organization_id"],
            reservation["metric"],
            reservation["period_start"],
        ),
    )
    return True


def get_usage(
    connection: sqlite3.Connection,
    *,
    organization_id: str,
    user_id: str,
    now: datetime | None = None,
) -> dict[str, object]:
    limits_by_plan = load_plan_limits()
    organization = connection.execute(
        "SELECT plan_id FROM organizations WHERE id=?",
        (organization_id,),
    ).fetchone()
    if organization is None or organization["plan_id"] not in limits_by_plan:
        raise PlanConfigurationError
    period_start = current_period_start(now)
    rows = connection.execute(
        """SELECT metric, consumed, reserved FROM quota_counters
           WHERE organization_id=? AND user_id=? AND period_start=?""",
        (organization_id, user_id, period_start),
    ).fetchall()
    usage = {row["metric"]: row for row in rows}
    organization_rows = connection.execute(
        """SELECT metric, consumed, reserved FROM organization_quota_counters
           WHERE organization_id=? AND period_start=?""",
        (organization_id, period_start),
    ).fetchall()
    organization_usage = {row["metric"]: row for row in organization_rows}
    return {
        "plan": organization["plan_id"],
        "period": "UTC calendar day",
        "period_start": period_start,
        "limits": {
            "per_user": limits_by_plan[organization["plan_id"]],
            "per_organization": limits_by_plan[organization["plan_id"]],
        },
        "usage": {
            metric: {
                "user": {
                    "consumed": usage[metric]["consumed"] if metric in usage else 0,
                    "reserved": usage[metric]["reserved"] if metric in usage else 0,
                },
                "organization": {
                    "consumed": organization_usage[metric]["consumed"]
                    if metric in organization_usage
                    else 0,
                    "reserved": organization_usage[metric]["reserved"]
                    if metric in organization_usage
                    else 0,
                },
            }
            for metric in METRICS
        },
    }
