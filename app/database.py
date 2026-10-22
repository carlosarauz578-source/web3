from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from app.config import DB_PATH

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(DB_PATH, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    except FileExistsError:
        os.chmod(DB_PATH, 0o600)
    else:
        os.close(descriptor)
    for suffix in ("-wal", "-shm"):
        auxiliary_file = Path(f"{DB_PATH}{suffix}")
        if auxiliary_file.exists():
            try:
                os.chmod(auxiliary_file, 0o600)
            except FileNotFoundError:
                pass
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    return connection


def migrate() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        applied = {
            row["version"]
            for row in connection.execute("SELECT version FROM schema_migrations")
        }
        for migration in sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.sql")):
            if migration.name in applied:
                continue
            sql = migration.read_text(encoding="utf-8")
            connection.executescript(
                "BEGIN IMMEDIATE;\n"
                + sql
                + "\nINSERT INTO schema_migrations(version, applied_at) "
                + "VALUES("
                + "'" + migration.name.replace("'", "''") + "', "
                + "strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));\nCOMMIT;"
            )


def init_db() -> None:
    migrate()
