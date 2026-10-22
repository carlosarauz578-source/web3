from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
import time
import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

from fastapi import Cookie, Header, HTTPException

from app.database import connect

PASSWORD_ITERATIONS = 600_000
ROLES = {"admin", "auditor", "client", "collaborator"}


def hash_password(password: str) -> str:
    if len(password) < 12 or len(password) > 1024:
        raise HTTPException(400, "La contraseña debe tener entre 12 y 1024 caracteres.")
    try:
        password_bytes = password.encode("utf-8")
    except UnicodeEncodeError as error:
        raise HTTPException(400, "La contraseña contiene caracteres Unicode no válidos.") from error
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, PASSWORD_ITERATIONS)
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${encode(salt)}${encode(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, digest_text = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iteration_text)
        if not 100_000 <= iterations <= 2_000_000:
            return False
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        expected = decode(digest_text)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), decode(salt_text), iterations
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


@lru_cache(maxsize=1)
def dummy_password_hash() -> str:
    return hash_password("invalid-user-placeholder-password")


def issue_session(user_id: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(seconds=12 * 60 * 60)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with connect() as connection:
        connection.execute(
            "INSERT INTO sessions(token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, user_id, datetime.now(UTC).isoformat(), expires_at.isoformat()),
        )
    return token, expires_at.isoformat()


def get_current_user(
    authorization: str | None = Header(default=None),
    session: str | None = Cookie(default=None, alias="aegis_session"),
) -> dict[str, Any]:
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
    elif session:
        token = session
    else:
        raise HTTPException(401, "Autenticación requerida.")
    if not token or len(token) > 256:
        raise HTTPException(401, "Token inválido.")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(UTC).isoformat()
    with connect() as connection:
        row = connection.execute(
            """SELECT u.id, u.email, u.role, u.organization_id, u.is_platform_admin,
                      o.name AS organization_name, s.token_hash
               FROM sessions s JOIN users u ON u.id = s.user_id
               JOIN organizations o ON o.id = u.organization_id
               WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1""",
            (token_hash, now),
        ).fetchone()
    if row is None:
        raise HTTPException(401, "Sesión inválida o expirada.")
    return dict(row)


def revoke_session(user: dict[str, Any]) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (user["token_hash"],))


def require_roles(user: dict[str, Any], *roles: str) -> None:
    if user["role"] not in roles:
        raise HTTPException(403, "No tienes permisos para esta operación.")


def new_id() -> str:
    return str(uuid.uuid4())


def allow_login_attempt(client_key: str) -> bool:
    now = int(time.time())
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT window_started_at, attempts FROM login_attempts WHERE client_key = ?",
            (client_key,),
        ).fetchone()
        if row is None or now - row["window_started_at"] >= 900:
            connection.execute(
                """INSERT INTO login_attempts(client_key, window_started_at, attempts)
                   VALUES (?, ?, 1)
                   ON CONFLICT(client_key) DO UPDATE SET
                   window_started_at=excluded.window_started_at, attempts=1""",
                (client_key, now),
            )
            return True
        if row["attempts"] >= 10:
            return False
        connection.execute(
            "UPDATE login_attempts SET attempts = attempts + 1 WHERE client_key = ?",
            (client_key,),
        )
        return True


def allow_request(client_key: str, limit: int, window_seconds: int) -> bool:
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        return allow_request_in(connection, client_key, limit, window_seconds)


def allow_request_in(
    connection: sqlite3.Connection,
    client_key: str,
    limit: int,
    window_seconds: int,
) -> bool:
    now = int(time.time())
    row = connection.execute(
        """SELECT window_started_at, requests FROM api_rate_limits
           WHERE client_key=?""",
        (client_key,),
    ).fetchone()
    if row is None or now - row["window_started_at"] >= window_seconds:
        connection.execute(
            """INSERT INTO api_rate_limits(client_key, window_started_at, requests)
               VALUES (?, ?, 1)
               ON CONFLICT(client_key) DO UPDATE SET
               window_started_at=excluded.window_started_at, requests=1""",
            (client_key, now),
        )
        return True
    if row["requests"] >= limit:
        return False
    connection.execute(
        "UPDATE api_rate_limits SET requests=requests+1 WHERE client_key=?",
        (client_key,),
    )
    return True


def clear_login_attempts(client_key: str) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM login_attempts WHERE client_key = ?", (client_key,))
