from __future__ import annotations

import sqlite3
import stat
from pathlib import Path

import pytest

from app import database


def test_platform_migrations_preserve_legacy_audit_rows(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE audit_runs (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            record_json TEXT NOT NULL,
            evidence_hash TEXT NOT NULL
        );
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            event_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );
        INSERT INTO audit_runs VALUES ('legacy-run', '2026-01-01T00:00:00Z', '{}', 'legacy-hash');
        INSERT INTO audit_events
        (run_id, event_type, created_at, event_json, previous_hash, event_hash)
        VALUES ('legacy-run', 'legacy', '2026-01-01T00:00:00Z', '{}', 'zero', 'event');
        """
    )
    connection.commit()
    connection.close()

    monkeypatch.setattr(database, "DB_PATH", path)
    database.init_db()
    database.init_db()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with database.connect() as migrated:
        run = migrated.execute(
            "SELECT id, evidence_hash, organization_id FROM audit_runs WHERE id='legacy-run'"
        ).fetchone()
        events = migrated.execute(
            "SELECT COUNT(*) FROM audit_events WHERE run_id='legacy-run'"
        ).fetchone()[0]
        versions = migrated.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
        conversation_tables = migrated.execute(
            """SELECT COUNT(*) FROM sqlite_master
               WHERE type='table' AND name IN ('conversations', 'conversation_messages')"""
        ).fetchone()[0]

    assert run["id"] == "legacy-run"
    assert run["evidence_hash"] == "legacy-hash"
    assert run["organization_id"] is None
    assert events == 1
    assert versions == 13
    assert conversation_tables == 2


def test_ai_review_migration_preserves_existing_messages(tmp_path):
    path = tmp_path / "conversation-upgrade.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        PRAGMA foreign_keys=ON;
        CREATE TABLE conversations (
            id TEXT PRIMARY KEY,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE conversation_messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK(role = 'user'),
            content TEXT NOT NULL CHECK(
                length(trim(content)) > 0 AND length(CAST(content AS BLOB)) <= 20000
            ),
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_conversation_messages_history
        ON conversation_messages(conversation_id, created_at DESC, id DESC);
        CREATE TRIGGER conversation_message_updates_conversation
        AFTER INSERT ON conversation_messages
        BEGIN
            UPDATE conversations SET updated_at=NEW.created_at WHERE id=NEW.conversation_id;
        END;
        INSERT INTO conversations VALUES ('conversation-1', '2026-01-01T00:00:00Z');
        INSERT INTO conversation_messages
        VALUES ('message-1', 'conversation-1', 'user', 'existing content', '2026-01-01T00:00:00Z');
        """
    )
    migration = (
        Path(__file__).parents[1] / "app/migrations/0007_ai_code_reviews.sql"
    ).read_text(encoding="utf-8")
    connection.executescript(migration)
    connection.executescript(
        """
        INSERT INTO conversation_messages
            (id, conversation_id, role, content, created_at)
        VALUES ('assistant-valid', 'conversation-1', 'assistant', '{}', '2026-01-02T00:00:00Z');
        INSERT INTO conversation_messages
            (id, conversation_id, role, content, created_at)
        VALUES ('message-2', 'conversation-1', 'user', 'second request', '2026-01-02T00:00:00Z');
        INSERT INTO conversation_messages
            (id, conversation_id, role, content, created_at)
        VALUES ('running-user', 'conversation-1', 'user', 'running request', '2026-01-03T00:00:00Z');
        """
    )
    connection.execute(
        """INSERT INTO ai_code_reviews
           (user_message_id, status, provider, model, created_at, updated_at)
           VALUES ('running-user', 'running', 'openai-compatible', 'test-model',
                   '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"""
    )
    connection.execute(
        """INSERT INTO ai_code_reviews
           (user_message_id, assistant_message_id, status, provider, model, created_at, updated_at)
           VALUES ('message-2', 'assistant-valid', 'completed', 'openai-compatible',
                   'test-model', '2026-01-02T00:00:00Z', '2026-01-02T00:00:00Z')"""
    )
    connection.execute(
        """INSERT INTO ai_code_reviews
           (user_message_id, assistant_message_id, status, provider, model, created_at, updated_at)
           VALUES ('message-1', 'message-1', 'completed', 'openai-compatible', 'test-model',
                   '2026-01-03T00:00:00Z', '2026-01-03T00:00:00Z')"""
    )
    recovery_migration = (
        Path(__file__).parents[1] / "app/migrations/0008_inconclusive_ai_reviews.sql"
    ).read_text(encoding="utf-8")
    connection.executescript(recovery_migration)
    consistent_result_migration = (
        Path(__file__).parents[1] / "app/migrations/0009_consistent_ai_review_results.sql"
    ).read_text(encoding="utf-8")
    connection.executescript(consistent_result_migration)

    old_message = connection.execute(
        """SELECT id, conversation_id, role, content, created_at, client_message_id
           FROM conversation_messages WHERE id='message-1'"""
    ).fetchone()
    assert old_message == (
        "message-1",
        "conversation-1",
        "user",
        "existing content",
        "2026-01-01T00:00:00Z",
        None,
    )
    review = connection.execute(
        "SELECT status, failure_kind FROM ai_code_reviews WHERE user_message_id='running-user'"
    ).fetchone()
    assert tuple(review) == ("running", None)
    connection.execute(
        """UPDATE ai_code_reviews
           SET status='inconclusive', failure_kind='abandoned_after_provider_request'
           WHERE user_message_id='running-user'"""
    )
    missing_result = connection.execute(
        """SELECT status, assistant_message_id, failure_kind
           FROM ai_code_reviews WHERE user_message_id='message-1'"""
    ).fetchone()
    assert tuple(missing_result) == (
        "inconclusive",
        None,
        "migration_found_missing_or_inconsistent_result",
    )
    valid_result = connection.execute(
        """SELECT status, assistant_message_id
           FROM ai_code_reviews WHERE user_message_id='message-2'"""
    ).fetchone()
    assert tuple(valid_result) == ("completed", "assistant-valid")

    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            """UPDATE ai_code_reviews SET assistant_message_id=NULL
               WHERE user_message_id='message-2'"""
        )
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            """UPDATE ai_code_reviews SET status='running'
               WHERE user_message_id='message-2'"""
        )
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "DELETE FROM conversation_messages WHERE id='assistant-valid'"
        )
    connection.execute(
        """INSERT INTO conversation_messages
           (id, conversation_id, role, content, created_at)
           VALUES ('fresh-user', 'conversation-1', 'user', 'fresh', '2026-01-04T00:00:00Z')"""
    )
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            """INSERT INTO ai_code_reviews
               (user_message_id, assistant_message_id, status, provider, model,
                created_at, updated_at)
               VALUES ('fresh-user', 'fresh-user', 'completed', 'openai-compatible',
                       'test-model', '2026-01-04T00:00:00Z', '2026-01-04T00:00:00Z')"""
        )
    connection.execute(
        """INSERT INTO conversation_messages
           (id, conversation_id, role, content, created_at)
           VALUES ('assistant-1', 'conversation-1', 'assistant', ?, '2026-01-02T00:00:00Z')""",
        ("a" * 30_000,),
    )
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            """INSERT INTO conversation_messages
               (id, conversation_id, role, content, created_at)
               VALUES ('oversized-user', 'conversation-1', 'user', ?, '2026-01-02T00:00:00Z')""",
            ("u" * 20_001,),
        )
    connection.close()


def test_init_db_upgrades_version_seven_database_once_and_preserves_history(
    tmp_path, monkeypatch
):
    path = tmp_path / "version-seven.db"
    prior_migrations = tmp_path / "prior-migrations"
    prior_migrations.mkdir()
    source_migrations = Path(__file__).parents[1] / "app/migrations"
    for version in range(1, 8):
        source = next(source_migrations.glob(f"{version:04d}_*.sql"))
        (prior_migrations / source.name).write_text(
            source.read_text(encoding="utf-8"), encoding="utf-8"
        )

    monkeypatch.setattr(database, "DB_PATH", path)
    monkeypatch.setattr(database, "MIGRATIONS_DIR", prior_migrations)
    database.init_db()
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)",
            ("org-old", "Legacy organization", "2026-01-01T00:00:00Z"),
        )
        connection.execute(
            """INSERT INTO users
               (id, organization_id, email, password_hash, role, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                "user-old",
                "org-old",
                "legacy@example.test",
                "not-a-real-password-hash",
                "admin",
                "2026-01-01T00:00:00Z",
            ),
        )
        connection.execute(
            """INSERT INTO projects
               (id, organization_id, name, created_at, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (
                "project-old",
                "org-old",
                "Legacy project",
                "2026-01-01T00:00:00Z",
                "user-old",
            ),
        )
        connection.execute(
            """INSERT INTO conversations
               (id, organization_id, project_id, owner_user_id, specialty, status,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, 'code_auditor', 'open', ?, ?)""",
            (
                "conversation-old",
                "org-old",
                "project-old",
                "user-old",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            ),
        )
        connection.executemany(
            """INSERT INTO conversation_messages
               (id, conversation_id, role, content, created_at)
               VALUES (?, 'conversation-old', ?, ?, ?)""",
            [
                (
                    "user-valid",
                    "user",
                    "legacy source",
                    "2026-01-01T00:00:00Z",
                ),
                (
                    "assistant-valid",
                    "assistant",
                    '{"summary":"legacy result"}',
                    "2026-01-01T00:01:00Z",
                ),
                (
                    "user-inconsistent",
                    "user",
                    "legacy inconsistent source",
                    "2026-01-01T00:02:00Z",
                ),
            ],
        )
        connection.executemany(
            """INSERT INTO ai_code_reviews
               (user_message_id, assistant_message_id, status, provider, model,
                created_at, updated_at)
               VALUES (?, ?, 'completed', 'legacy-provider', 'legacy-model', ?, ?)""",
            [
                (
                    "user-valid",
                    "assistant-valid",
                    "2026-01-01T00:01:00Z",
                    "2026-01-01T00:01:00Z",
                ),
                (
                    "user-inconsistent",
                    "user-inconsistent",
                    "2026-01-01T00:02:00Z",
                    "2026-01-01T00:02:00Z",
                ),
            ],
        )

    monkeypatch.setattr(database, "MIGRATIONS_DIR", source_migrations)
    database.init_db()
    database.init_db()

    with database.connect() as connection:
        versions = [
            row["version"]
            for row in connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ]
        history = connection.execute(
            """SELECT id, role, content FROM conversation_messages
               WHERE conversation_id='conversation-old' ORDER BY created_at, id"""
        ).fetchall()
        reviews = {
            row["user_message_id"]: (
                row["status"],
                row["assistant_message_id"],
                row["failure_kind"],
            )
            for row in connection.execute(
                """SELECT user_message_id, status, assistant_message_id, failure_kind
                   FROM ai_code_reviews"""
            )
        }
        integrity = connection.execute("PRAGMA foreign_key_check").fetchall()
        trigger_count = connection.execute(
            """SELECT COUNT(*) FROM sqlite_master
               WHERE type='trigger' AND name LIKE 'ai_code_review_%_guard'"""
        ).fetchone()[0]
        event_count = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

    assert versions == sorted(path.name for path in source_migrations.glob("*.sql"))
    assert [tuple(row) for row in history] == [
        ("user-valid", "user", "legacy source"),
        ("assistant-valid", "assistant", '{"summary":"legacy result"}'),
        ("user-inconsistent", "user", "legacy inconsistent source"),
    ]
    assert reviews["user-valid"] == ("completed", "assistant-valid", None)
    assert reviews["user-inconsistent"] == (
        "inconclusive",
        None,
        "migration_found_missing_or_inconsistent_result",
    )
    assert integrity == []
    assert trigger_count == 4
    assert event_count == 0


def test_connect_tolerates_sqlite_sidecar_removed_before_chmod(tmp_path, monkeypatch):
    path = tmp_path / "concurrent.db"
    path.touch()
    monkeypatch.setattr(database, "DB_PATH", path)
    original_exists = Path.exists
    original_chmod = database.os.chmod

    def exists(candidate):
        if str(candidate) == f"{path}-shm":
            return True
        return original_exists(candidate)

    def chmod(candidate, mode):
        if str(candidate) == f"{path}-shm":
            raise FileNotFoundError(candidate)
        return original_chmod(candidate, mode)

    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(database.os, "chmod", chmod)
    with database.connect():
        pass
