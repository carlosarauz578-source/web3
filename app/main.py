from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from app.agents.blockchain_analyst import SUPPORTED_NETWORKS
from app.agents.code_auditor import MAX_REVIEW_SOURCE_BYTES, review_code
from app.agents.orchestrator import execute_task
from app.config import MAX_SOURCE_BYTES, ROOT
from app.connectors.evm import evm_status
from app.connectors.stellar import stellar_status
from app.database import connect, init_db
from app.engines import audit_source
from app.plans import (
    PlanConfigurationError,
    QuotaExceeded,
    get_usage,
    reserve_quota,
    settle_quota,
)
from app.providers import (
    ProviderError,
    provider_status,
)
from app.security import (
    allow_login_attempt,
    allow_request,
    allow_request_in,
    clear_login_attempts,
    dummy_password_hash,
    get_current_user,
    hash_password,
    issue_session,
    new_id,
    require_roles,
    revoke_session,
    verify_password,
)
from app.sensitive_data import (
    contains_duplicate_json_keys,
    contains_sensitive_content,
    contains_sensitive_content_in_value,
    redact_sensitive_content_in_value,
)

app = FastAPI(
    title="Aegis-Web3 Core",
    version="0.4.0",
    description="Plataforma de análisis de laboratorio; no certifica seguridad.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("AEGIS_ALLOWED_ORIGINS", "http://localhost:8000").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
init_db()
SESSION_MAX_AGE = 12 * 60 * 60
AI_REVIEW_LEASE_SECONDS = 120
CurrentUser = Annotated[dict[str, Any], Depends(get_current_user)]


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError):
    errors = [
        {
            "loc": [str(part) for part in error.get("loc", ())],
            "msg": error.get("msg", "Invalid input."),
            "type": error.get("type", "value_error"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        "aegis_session",
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=os.getenv("AEGIS_COOKIE_SECURE", "true").lower() == "true",
        samesite="strict",
        path="/",
    )


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def reserve_quota_or_http(
    connection: sqlite3.Connection,
    *,
    organization_id: str,
    user_id: str,
    metric: str,
    idempotency_key: str,
) -> str:
    try:
        return reserve_quota(
            connection,
            organization_id=organization_id,
            user_id=user_id,
            metric=metric,
            idempotency_key=idempotency_key,
        )
    except QuotaExceeded as error:
        raise HTTPException(
            429,
            f"Se agotó la cuota diaria de {error.metric}.",
            headers={"Retry-After": str(error.retry_after)},
        ) from None
    except PlanConfigurationError:
        raise HTTPException(503, "La configuración de planes no es válida.") from None


def recover_abandoned_ai_reviews(
    connection: sqlite3.Connection,
    conversation_id: str,
    user: dict[str, Any],
) -> None:
    cutoff = datetime.now(UTC) - timedelta(seconds=AI_REVIEW_LEASE_SECONDS)
    rows = connection.execute(
        """SELECT r.user_message_id, r.updated_at
           FROM ai_code_reviews r
           JOIN conversation_messages m ON m.id=r.user_message_id
           WHERE m.conversation_id=? AND r.status='running'""",
        (conversation_id,),
    ).fetchall()
    for row in rows:
        try:
            updated = datetime.fromisoformat(row["updated_at"])
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=UTC)
        except ValueError:
            updated = datetime.min.replace(tzinfo=UTC)
        if updated > cutoff:
            continue
        recovered_at = utc_now()
        changed = connection.execute(
            """UPDATE ai_code_reviews
               SET status='inconclusive',
                   failure_kind='abandoned_after_provider_request',
                   updated_at=?
               WHERE user_message_id=? AND status='running' AND updated_at=?""",
            (recovered_at, row["user_message_id"], row["updated_at"]),
        )
        if changed.rowcount:
            message = connection.execute(
                """SELECT m.client_message_id, m.conversation_id,
                          c.organization_id, c.owner_user_id
                   FROM conversation_messages m
                   JOIN conversations c ON c.id=m.conversation_id
                   WHERE m.id=?""",
                (row["user_message_id"],),
            ).fetchone()
            if message and message["client_message_id"]:
                reservation = connection.execute(
                    """SELECT id FROM quota_reservations
                       WHERE organization_id=? AND user_id=? AND metric='ai_reviews'
                         AND idempotency_key=?""",
                    (
                        message["organization_id"],
                        message["owner_user_id"],
                        f'{message["conversation_id"]}:{message["client_message_id"]}',
                    ),
                ).fetchone()
                if reservation:
                    settle_quota(connection, reservation["id"], confirm=True)
            connection.execute(
                """INSERT INTO security_events
                   (id, organization_id, actor_user_id, action, target_type, target_id,
                    created_at, metadata_json)
                   VALUES (?, ?, ?, 'ai_review_marked_inconclusive', 'conversation', ?, ?, ?)""",
                (
                    new_id(),
                    user["organization_id"],
                    user["id"],
                    conversation_id,
                    recovered_at,
                    json.dumps(
                        {
                            "user_message_id": row["user_message_id"],
                            "failure_kind": "abandoned_after_provider_request",
                        },
                        sort_keys=True,
                    ),
                ),
            )
def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def record_security_event(
    user: dict[str, Any] | None,
    action: str,
    target_type: str,
    target_id: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    with connect() as connection:
        connection.execute(
            """INSERT INTO security_events
               (id, organization_id, actor_user_id, action, target_type, target_id,
                created_at, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                new_id(),
                user["organization_id"] if user else None,
                user["id"] if user else None,
                action,
                target_type,
                target_id,
                utc_now(),
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )


def add_event(
    connection: sqlite3.Connection,
    run_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> None:
    previous = connection.execute(
        "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else "0" * 64
    created = utc_now()
    event = {
        "run_id": run_id,
        "event_type": event_type,
        "created_at": created,
        "payload": payload,
    }
    body = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    event_hash = sha256_text(previous_hash + body)
    connection.execute(
        """INSERT INTO audit_events
           (run_id, event_type, created_at, event_json, previous_hash, event_hash)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (run_id, event_type, created, body, previous_hash, event_hash),
    )


def get_record(run_id: str, organization_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT record_json FROM audit_runs WHERE id=? AND organization_id=?",
            (run_id, organization_id),
        ).fetchone()
    return json.loads(row["record_json"]) if row else None


def get_accessible_record(run_id: str, user: dict[str, Any]) -> dict[str, Any] | None:
    record = get_record(run_id, user["organization_id"])
    if record is None:
        return None
    if user["role"] in {"admin", "auditor"}:
        return record
    with connect() as connection:
        membership = connection.execute(
            "SELECT 1 FROM project_memberships WHERE project_id=? AND user_id=?",
            (record["project_id"], user["id"]),
        ).fetchone()
    return record if membership else None


def require_project(project_id: str, user: dict[str, Any]) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT id, organization_id, name FROM projects WHERE id=? AND organization_id=?",
            (project_id, user["organization_id"]),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "Proyecto no encontrado.")
    if user["role"] in {"client", "collaborator"}:
        with connect() as connection:
            membership = connection.execute(
                "SELECT 1 FROM project_memberships WHERE project_id=? AND user_id=?",
                (project_id, user["id"]),
            ).fetchone()
        if membership is None:
            raise HTTPException(404, "Proyecto no encontrado.")
    return dict(row)


def get_accessible_conversation(
    connection: sqlite3.Connection,
    conversation_id: str,
    user: dict[str, Any],
) -> sqlite3.Row:
    row = connection.execute(
        """SELECT c.id, c.organization_id, c.project_id, c.owner_user_id,
                  c.specialty, c.status, c.created_at, c.updated_at
           FROM conversations c
           WHERE c.id=? AND c.organization_id=? AND c.owner_user_id=?
             AND (
                 ? IN ('admin', 'auditor')
                 OR EXISTS (
                     SELECT 1 FROM project_memberships m
                     WHERE m.project_id=c.project_id AND m.user_id=?
                 )
             )""",
        (
            conversation_id,
            user["organization_id"],
            user["id"],
            user["role"],
            user["id"],
        ),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Conversación no encontrada.")
    return row


def _conversation_message_response(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    response = dict(row)
    content = response.get("content", "")
    sensitive_content_detected = contains_sensitive_content_in_value(content)
    redacted_content = redact_sensitive_content_in_value(content)
    response["sensitive_content_detected"] = sensitive_content_detected
    response["content"] = redacted_content
    response["content_redacted"] = redacted_content != content
    return response


def _audit_record_http_response(record: dict[str, Any]) -> dict[str, Any]:
    redacted = contains_sensitive_content_in_value(record)
    response = redact_sensitive_content_in_value(record)
    if isinstance(response, dict):
        response["sensitive_content_redacted"] = redacted
    return response


def run_audit_job(run_id: str, source: str, filename: str) -> None:
    with connect() as connection:
        row = connection.execute(
            "SELECT record_json FROM audit_runs WHERE id=?", (run_id,)
        ).fetchone()
        if row is None:
            return
        record = json.loads(row["record_json"])
        record["status"] = "running"
        record["started_at"] = utc_now()
        record_body = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        connection.execute(
            "UPDATE audit_runs SET record_json=?, evidence_hash=? WHERE id=?",
            (record_body, sha256_text(record_body), run_id),
        )

    result = audit_source(source, filename)
    status = result.get("status", "engine_error")
    raw_stdout = result.get("raw_stdout", "")
    raw_stderr = result.get("raw_stderr", result.get("error", ""))
    record.update(
        {
            "status": status,
            "findings": result.get("findings", []),
            "engine": result.get("engine", "slither"),
            "engine_version": result.get("engine_version"),
            "worker_image_digest": result.get("worker_image_digest"),
            "worker_cleanup_error": result.get("cleanup_error"),
            "execution_output": {
                "stdout_sha256": result.get("raw_stdout_sha256") or sha256_text(raw_stdout),
                "stderr_sha256": result.get("raw_stderr_sha256") or sha256_text(raw_stderr),
                "stdout_truncated": result.get("raw_stdout_truncated", False),
                "stderr_truncated": result.get("raw_stderr_truncated", False),
            },
            "message": result.get("message", "Resultado inconcluso."),
            "duration_ms": result.get("duration_ms", 0),
            "finished_at": utc_now(),
            "exit_code": result.get("exit_code"),
        }
    )
    record["sensitive_content_detected"] = (
        contains_sensitive_content(raw_stdout)
        or contains_sensitive_content(raw_stderr)
        or contains_sensitive_content_in_value(
            {"findings": record["findings"], "message": record["message"]}
        )
    )
    artifact_hash = sha256_text(
        json.dumps(
            {"stdout": raw_stdout, "stderr": raw_stderr},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    with connect() as connection:
        connection.execute(
            "UPDATE audit_runs SET record_json=?, evidence_hash=? WHERE id=?",
            (
                json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
                sha256_text(json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))),
                run_id,
            ),
        )
        connection.execute(
            """INSERT OR REPLACE INTO audit_execution_evidence
               (run_id, raw_stdout, raw_stderr, evidence_sha256) VALUES (?, ?, ?, ?)""",
            (run_id, raw_stdout, raw_stderr, artifact_hash),
        )
        add_event(
            connection,
            run_id,
            "analysis_finished",
            {"status": status, "evidence_sha256": artifact_hash},
        )
    record_security_event(
        {
            "id": record["created_by"],
            "organization_id": record["organization_id"],
        },
        "analysis_finished",
        "audit",
        run_id,
        {"status": status},
    )


class BootstrapRequest(BaseModel):
    bootstrap_token: str = Field(min_length=1, max_length=256)
    organization_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=12, max_length=1024)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class UserCreateRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=12, max_length=1024)
    role: str = Field(pattern="^(admin|auditor|client|collaborator)$")


class OrganizationCreateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(min_length=2, max_length=120)
    admin_email: str = Field(min_length=5, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    admin_password: str = Field(min_length=12, max_length=1024)


class PlanAssignmentRequest(BaseModel):
    model_config = {"extra": "forbid"}

    plan_id: Literal["free", "pro", "enterprise"]


class ProjectCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class ProjectMemberRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=64)


class ConversationCreateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    project_id: str = Field(min_length=1, max_length=64)
    specialty: Literal["code_auditor", "blockchain_analyst", "independent_validator"]


class ConversationMessageRequest(BaseModel):
    model_config = {"extra": "forbid"}

    content: str = Field(min_length=1, max_length=20_000)
    client_message_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    request_ai_review: bool = False

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("El mensaje no puede estar vacío.")
        try:
            byte_length = len(value.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise ValueError("El mensaje contiene caracteres Unicode no válidos.") from error
        if byte_length > 20_000:
            raise ValueError("El mensaje excede el límite de 20000 bytes UTF-8.")
        if contains_sensitive_content(value):
            raise ValueError(
                "No incluyas credenciales, claves privadas ni frases semilla en mensajes."
            )
        return value


class AuditRequest(BaseModel):
    project_id: str = Field(min_length=1, max_length=64)
    filename: str = Field(min_length=5, max_length=120, pattern=r"^[A-Za-z0-9_.-]+\.sol$")
    source: str = Field(min_length=1, max_length=MAX_SOURCE_BYTES)
    acknowledge_lab_only: bool = False

    @field_validator("source")
    @classmethod
    def require_valid_utf8(cls, value: str) -> str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("El código contiene caracteres Unicode no válidos.") from error
        return value


class ApprovalRequest(BaseModel):
    reviewer: str = Field(min_length=2, max_length=120)
    decision: str = Field(pattern="^(approve|reject)$")
    reason: str = Field(min_length=5, max_length=1000)

    @field_validator("reason")
    @classmethod
    def reject_sensitive_reason(cls, value: str) -> str:
        if contains_sensitive_content(value):
            raise ValueError("El motivo contiene un patrón sensible reconocido.")
        return value


class AgentRunRequest(BaseModel):
    model_config = {"extra": "forbid"}

    task_type: Literal["blockchain_health", "validate_review", "code_review"]
    project_id: str = Field(min_length=1, max_length=64)
    idempotency_key: uuid.UUID = Field(default_factory=uuid.uuid4)
    network: str | None = Field(default=None, max_length=40)
    conversation_id: str | None = Field(default=None, max_length=64)
    user_message_id: str | None = Field(default=None, max_length=64)
    source: str | None = Field(default=None, max_length=MAX_REVIEW_SOURCE_BYTES)
    acknowledge_external_ai: bool = False


@app.middleware("http")
async def security_headers(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_SOURCE_BYTES + 16_384:
        return JSONResponse(status_code=413, content={"detail": "Solicitud demasiado grande."})
    path = request.url.path
    sensitive_json_post = request.method == "POST" and (
        path in {"/api/audits", "/api/agent-runs"}
        or re.fullmatch(r"/api/conversations/[^/]+/messages", path) is not None
        or re.fullmatch(r"/api/audits/[^/]+/approval", path) is not None
    )
    if sensitive_json_post:
        body = await request.body()
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        is_json = (
            content_type.startswith("application/json")
            or content_type.endswith("+json")
            or (
                not content_type
                and body.lstrip().startswith((b"{", b"["))
            )
        )
        try:
            body_text = body.decode("utf-8-sig")
        except UnicodeDecodeError:
            body_text = ""
        if is_json and contains_duplicate_json_keys(body_text):
            return JSONResponse(
                status_code=422,
                content={"detail": "La solicitud contiene claves JSON duplicadas."},
            )
        body_consumed = False

        async def replay_body():
            nonlocal body_consumed
            if body_consumed:
                return {"type": "http.request", "body": b"", "more_body": False}
            body_consumed = True
            return {"type": "http.request", "body": body, "more_body": False}

        request = Request(request.scope, receive=replay_body)
    response = await call_next(request)
    response.headers.update(
        {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "Content-Security-Policy": (
                "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; connect-src 'self'"
            ),
        }
    )
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (ROOT / "app" / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    docker_available = shutil.which("docker") is not None
    image_configured = bool(os.getenv("AEGIS_WORKER_IMAGE"))
    return {
        "status": "ok",
        "service": "aegis-web3-core",
        "mode": "development",
        "audit_engine": (
            "configured" if docker_available and image_configured
            else "tool_unavailable" if not docker_available
            else "not_configured"
        ),
        "ai_provider": provider_status()["status"],
        "production_ready": False,
    }


@app.get("/api/usage")
def usage(user: CurrentUser):
    try:
        with connect() as connection:
            return get_usage(
                connection,
                organization_id=user["organization_id"],
                user_id=user["id"],
            )
    except PlanConfigurationError:
        raise HTTPException(503, "La configuración de planes no es válida.") from None


@app.get("/api/agent-runs")
def list_agent_runs(
    user: CurrentUser,
    project_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=50, ge=1, le=100),
):
    with connect() as connection:
        if project_id is not None:
            require_project(project_id, user)
            ownership_filter = ""
            parameters: tuple[object, ...] = (user["organization_id"], project_id, limit)
            if user["role"] not in {"admin", "auditor"}:
                ownership_filter = " AND requested_by=?"
                parameters = (user["organization_id"], project_id, user["id"], limit)
            rows = connection.execute(
                f"""SELECT id, task_type, status, result_json, created_at, updated_at, project_id
                   FROM agent_runs
                   WHERE organization_id=? AND project_id=?{ownership_filter}
                   ORDER BY updated_at DESC, id DESC LIMIT ?""",
                parameters,
            ).fetchall()
        elif user["role"] in {"admin", "auditor"}:
            rows = connection.execute(
                """SELECT id, task_type, status, result_json, created_at, updated_at, project_id
                   FROM agent_runs
                   WHERE organization_id=?
                   ORDER BY updated_at DESC, id DESC LIMIT ?""",
                (user["organization_id"], limit),
            ).fetchall()
        else:
            rows = connection.execute(
                """SELECT a.id, a.task_type, a.status, a.result_json, a.created_at, a.updated_at, a.project_id
                   FROM agent_runs a
                   WHERE a.organization_id=? AND a.requested_by=?
                     AND EXISTS (
                         SELECT 1 FROM project_memberships m
                         WHERE m.project_id=a.project_id AND m.user_id=?
                     )
                   ORDER BY a.updated_at DESC, a.id DESC LIMIT ?""",
                (user["organization_id"], user["id"], user["id"], limit),
            ).fetchall()
    return {"items": [_agent_run_response(row) for row in rows]}


@app.post("/api/auth/bootstrap", status_code=201)
def bootstrap(payload: BootstrapRequest, response: Response):
    configured_token = os.getenv("AEGIS_BOOTSTRAP_TOKEN", "")
    if len(configured_token) < 32:
        raise HTTPException(503, "Bootstrap no configurado con un secreto de 32 caracteres o más.")
    if not hmac.compare_digest(payload.bootstrap_token, configured_token):
        raise HTTPException(401, "Token de bootstrap inválido.")
    password_hash = hash_password(payload.password)
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise HTTPException(409, "El bootstrap inicial ya se completó.")
        organization_id = new_id()
        user_id = new_id()
        created = utc_now()
        connection.execute(
            "INSERT INTO organizations(id, name, created_at) VALUES (?, ?, ?)",
            (organization_id, payload.organization_name, created),
        )
        connection.execute(
            """INSERT INTO users
               (id, organization_id, email, password_hash, role, created_at, is_platform_admin)
               VALUES (?, ?, ?, ?, 'admin', ?, 1)""",
            (
                user_id,
                organization_id,
                payload.email.lower(),
                password_hash,
                created,
            ),
        )
    token, expires_at = issue_session(user_id)
    set_session_cookie(response, token)
    record_security_event(
        {"id": user_id, "organization_id": organization_id},
        "bootstrap_completed",
        "organization",
        organization_id,
    )
    return {
        "expires_at": expires_at,
        "user": {"id": user_id, "email": payload.email.lower(), "role": "admin"},
        "organization": {"id": organization_id, "name": payload.organization_name},
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    client_key = request.client.host if request.client else "unknown"
    if not allow_login_attempt(client_key):
        raise HTTPException(429, "Demasiados intentos. Inténtalo más tarde.")
    with connect() as connection:
        row = connection.execute(
            """SELECT id, organization_id, email, password_hash, role
               FROM users WHERE email=? COLLATE NOCASE AND active=1""",
            (payload.email.strip().lower(),),
        ).fetchone()
    password_hash = row["password_hash"] if row else dummy_password_hash()
    password_valid = verify_password(payload.password, password_hash)
    if row is None or not password_valid:
        raise HTTPException(401, "Credenciales inválidas.")
    clear_login_attempts(client_key)
    token, expires_at = issue_session(row["id"])
    set_session_cookie(response, token)
    user = dict(row)
    record_security_event(user, "login", "session", hashlib.sha256(token.encode()).hexdigest())
    return {
        "expires_at": expires_at,
        "user": {"id": row["id"], "email": row["email"], "role": row["role"]},
    }


@app.get("/api/auth/me")
def who_am_i(user: CurrentUser):
    return {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "organization": {
            "id": user["organization_id"],
            "name": user["organization_name"],
        },
    }


@app.post("/api/auth/logout", status_code=204)
def logout(response: Response, user: CurrentUser):
    revoke_session(user)
    record_security_event(user, "logout", "session", user["token_hash"])
    response.delete_cookie("aegis_session", path="/", httponly=True, samesite="strict")
    response.status_code = 204
    return response


@app.post("/api/users", status_code=201)
def create_user(
    payload: UserCreateRequest,
    user: CurrentUser,
):
    require_roles(user, "admin")
    user_id = new_id()
    password_hash = hash_password(payload.password)
    try:
        with connect() as connection:
            connection.execute(
                """INSERT INTO users(id, organization_id, email, password_hash, role, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    user_id,
                    user["organization_id"],
                    payload.email.lower(),
                    password_hash,
                    payload.role,
                    utc_now(),
                ),
            )
    except sqlite3.IntegrityError as error:
        if "users.email" in str(error):
            raise HTTPException(409, "El correo ya está registrado.") from error
        raise
    record_security_event(user, "user_created", "user", user_id, {"role": payload.role})
    return {"id": user_id, "email": payload.email.lower(), "role": payload.role}


@app.post("/api/organizations", status_code=201)
def create_organization(
    payload: OrganizationCreateRequest,
    user: CurrentUser,
):
    if user["role"] != "admin" or not user["is_platform_admin"]:
        raise HTTPException(403, "Solo el administrador inicial de la plataforma puede crear organizaciones.")
    organization_id = new_id()
    administrator_id = new_id()
    password_hash = hash_password(payload.admin_password)
    try:
        with connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO organizations(id, name, created_at) VALUES (?, ?, ?)",
                (organization_id, payload.name, utc_now()),
            )
            connection.execute(
                """INSERT INTO users(id, organization_id, email, password_hash, role, created_at)
                   VALUES (?, ?, ?, ?, 'admin', ?)""",
                (
                    administrator_id,
                    organization_id,
                    payload.admin_email.lower(),
                    password_hash,
                    utc_now(),
                ),
            )
    except sqlite3.IntegrityError as error:
        if "users.email" in str(error):
            raise HTTPException(409, "El correo ya está registrado.") from error
        raise
    record_security_event(user, "organization_created", "organization", organization_id)
    return {
        "id": organization_id,
        "name": payload.name,
        "administrator": {"id": administrator_id, "email": payload.admin_email.lower()},
    }


@app.post("/api/organizations/{organization_id}/plan")
def assign_organization_plan(
    organization_id: str,
    payload: PlanAssignmentRequest,
    user: CurrentUser,
):
    if user["role"] != "admin" or not user["is_platform_admin"]:
        raise HTTPException(403, "Solo el administrador de plataforma puede asignar planes.")
    with connect() as connection:
        updated = connection.execute(
            "UPDATE organizations SET plan_id=? WHERE id=?",
            (payload.plan_id, organization_id),
        )
        if updated.rowcount != 1:
            raise HTTPException(404, "Organización no encontrada.")
    record_security_event(
        user,
        "organization_plan_assigned",
        "organization",
        organization_id,
        {"plan_id": payload.plan_id},
    )
    return {"organization_id": organization_id, "plan": payload.plan_id}


@app.get("/api/projects")
def list_projects(user: CurrentUser):
    with connect() as connection:
        if user["role"] in {"admin", "auditor"}:
            projects = connection.execute(
                """SELECT id, name, created_at FROM projects
                   WHERE organization_id=? ORDER BY created_at""",
                (user["organization_id"],),
            ).fetchall()
        else:
            projects = connection.execute(
                """SELECT p.id, p.name, p.created_at FROM projects p
                   JOIN project_memberships m ON m.project_id=p.id
                   WHERE p.organization_id=? AND m.user_id=? ORDER BY p.created_at""",
                (user["organization_id"], user["id"]),
            ).fetchall()
    return {"items": [dict(project) for project in projects]}


@app.post("/api/projects", status_code=201)
def create_project(
    payload: ProjectCreateRequest,
    user: CurrentUser,
):
    require_roles(user, "admin", "auditor")
    project_id = new_id()
    try:
        with connect() as connection:
            connection.execute(
                """INSERT INTO projects(id, organization_id, name, created_at, created_by)
                   VALUES (?, ?, ?, ?, ?)""",
                (project_id, user["organization_id"], payload.name, utc_now(), user["id"]),
            )
    except sqlite3.IntegrityError as error:
        if "projects.organization_id, projects.name" in str(error):
            raise HTTPException(409, "Ya existe un proyecto con ese nombre.") from error
        raise
    record_security_event(user, "project_created", "project", project_id)
    return {"id": project_id, "name": payload.name}


@app.post("/api/projects/{project_id}/members", status_code=201)
def assign_project_member(
    project_id: str,
    payload: ProjectMemberRequest,
    user: CurrentUser,
):
    require_roles(user, "admin")
    require_project(project_id, user)
    with connect() as connection:
        member = connection.execute(
            "SELECT id FROM users WHERE id=? AND organization_id=? AND active=1",
            (payload.user_id, user["organization_id"]),
        ).fetchone()
        if member is None:
            raise HTTPException(404, "Usuario no encontrado.")
        connection.execute(
            """INSERT OR IGNORE INTO project_memberships
               (project_id, user_id, assigned_by, created_at) VALUES (?, ?, ?, ?)""",
            (project_id, payload.user_id, user["id"], utc_now()),
        )
    record_security_event(user, "project_member_assigned", "project", project_id, {
        "user_id": payload.user_id,
    })
    return {"project_id": project_id, "user_id": payload.user_id}


@app.post("/api/conversations", status_code=201)
def create_conversation(
    payload: ConversationCreateRequest,
    user: CurrentUser,
):
    project = require_project(payload.project_id, user)
    if not allow_request(f"conversation-create:{user['id']}", 20, 3600):
        raise HTTPException(429, "Límite de conversaciones alcanzado; inténtalo más tarde.")
    conversation_id = new_id()
    created = utc_now()
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        reservation_id = reserve_quota_or_http(
            connection,
            organization_id=user["organization_id"],
            user_id=user["id"],
            metric="conversation_creations",
            idempotency_key=conversation_id,
        )
        settle_quota(connection, reservation_id, confirm=True)
        connection.execute(
            """INSERT INTO conversations
               (id, organization_id, project_id, owner_user_id, specialty, status,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'open', ?, ?)""",
            (
                conversation_id,
                user["organization_id"],
                project["id"],
                user["id"],
                payload.specialty,
                created,
                created,
            ),
        )
        row = connection.execute(
            """SELECT id, project_id, specialty, status, created_at, updated_at
               FROM conversations WHERE id=?""",
            (conversation_id,),
        ).fetchone()
    record_security_event(
        user,
        "conversation_created",
        "conversation",
        conversation_id,
        {"project_id": project["id"], "specialty": payload.specialty},
    )
    return dict(row)


@app.get("/api/conversations")
def list_conversations(
    user: CurrentUser,
    limit: int = Query(default=50, ge=1, le=100),
):
    with connect() as connection:
        rows = connection.execute(
            """SELECT c.id, c.project_id, c.specialty, c.status,
                      c.created_at, c.updated_at
               FROM conversations c
               WHERE c.organization_id=? AND c.owner_user_id=?
                 AND (
                     ? IN ('admin', 'auditor')
                     OR EXISTS (
                         SELECT 1 FROM project_memberships m
                         WHERE m.project_id=c.project_id AND m.user_id=?
                     )
                 )
               ORDER BY c.updated_at DESC, c.id DESC LIMIT ?""",
            (user["organization_id"], user["id"], user["role"], user["id"], limit),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}


@app.get("/api/conversations/{conversation_id}")
def get_conversation(conversation_id: str, user: CurrentUser):
    with connect() as connection:
        row = get_accessible_conversation(connection, conversation_id, user)
    return dict(row)


@app.get("/api/conversations/{conversation_id}/messages")
def list_conversation_messages(
    conversation_id: str,
    user: CurrentUser,
    limit: int = Query(default=100, ge=1, le=100),
    before: str | None = Query(default=None, max_length=64),
):
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        get_accessible_conversation(connection, conversation_id, user)
        recover_abandoned_ai_reviews(connection, conversation_id, user)
        cursor = None
        if before is not None:
            cursor = connection.execute(
                """SELECT created_at, id FROM conversation_messages
                   WHERE id=? AND conversation_id=?""",
                (before, conversation_id),
            ).fetchone()
            if cursor is None:
                raise HTTPException(400, "Cursor de mensajes inválido.")
        if cursor is None:
            rows = connection.execute(
                """SELECT m.id, m.role, m.content, m.created_at,
                          r.status AS review_status
                   FROM conversation_messages m
                   LEFT JOIN ai_code_reviews r ON r.user_message_id=m.id
                   WHERE m.conversation_id=?
                   ORDER BY m.created_at DESC, m.id DESC LIMIT ?""",
                (conversation_id, limit),
            ).fetchall()
        else:
            rows = connection.execute(
                """SELECT m.id, m.role, m.content, m.created_at,
                          r.status AS review_status
                   FROM conversation_messages m
                   LEFT JOIN ai_code_reviews r ON r.user_message_id=m.id
                   WHERE m.conversation_id=?
                     AND (m.created_at < ? OR (m.created_at=? AND m.id < ?))
                   ORDER BY m.created_at DESC, m.id DESC LIMIT ?""",
                (
                    conversation_id,
                    cursor["created_at"],
                    cursor["created_at"],
                    cursor["id"],
                    limit,
                ),
            ).fetchall()
    items = [_conversation_message_response(row) for row in reversed(rows)]
    return {
        "items": items,
        "next_before": items[0]["id"] if len(items) == limit else None,
    }


@app.post("/api/conversations/{conversation_id}/messages", status_code=201)
def add_conversation_message(
    conversation_id: str,
    payload: ConversationMessageRequest,
    user: CurrentUser,
):
    with connect() as connection:
        conversation = get_accessible_conversation(connection, conversation_id, user)
    if conversation["status"] != "open":
        raise HTTPException(409, "La conversación está cerrada.")
    review_provider: dict[str, str] | None = None
    if payload.request_ai_review:
        if conversation["specialty"] != "code_auditor":
            raise HTTPException(409, "La revisión de código solo está habilitada en su conversación.")
        try:
            source_size = len(payload.content.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise HTTPException(422, "El código contiene Unicode no válido.") from error
        if source_size > MAX_REVIEW_SOURCE_BYTES:
            raise HTTPException(413, "El fragmento excede el límite de revisión de 16000 bytes.")
        if contains_sensitive_content(payload.content):
            raise HTTPException(422, "Se detectó contenido sensible; no se envió al proveedor.")

    client_message_id = str(payload.client_message_id)
    message_id = new_id()
    ai_quota_reservation_id: str | None = None
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        conversation = get_accessible_conversation(connection, conversation_id, user)
        if conversation["status"] != "open":
            raise HTTPException(409, "La conversación está cerrada.")
        recover_abandoned_ai_reviews(connection, conversation_id, user)
        created = utc_now()
        existing = connection.execute(
            """SELECT id, role, content, created_at
               FROM conversation_messages
               WHERE conversation_id=? AND client_message_id=?""",
            (conversation_id, client_message_id),
        ).fetchone()
        if existing is not None:
            stored_user_message = _conversation_message_response(existing)
            review = connection.execute(
                """SELECT status, assistant_message_id FROM ai_code_reviews
                   WHERE user_message_id=?""",
                (existing["id"],),
            ).fetchone()
            if existing["content"] != payload.content:
                raise HTTPException(409, "El identificador ya está asociado a otro mensaje.")
            if bool(review) != payload.request_ai_review:
                raise HTTPException(409, "El identificador ya se utilizó para otra operación.")
            if review and review["status"] == "running":
                raise HTTPException(409, "La revisión ya está en curso.")
            if review and review["status"] in {"failed", "inconclusive"}:
                return {
                    "message": stored_user_message,
                    "review_status": review["status"],
                }
            if review and review["status"] == "completed":
                assistant_message = connection.execute(
                    """SELECT id, role, content, created_at FROM conversation_messages
                       WHERE id=? AND conversation_id=? AND role='assistant'""",
                    (review["assistant_message_id"], conversation_id),
                ).fetchone()
                if assistant_message is None:
                    inconclusive_at = utc_now()
                    connection.execute(
                        """UPDATE ai_code_reviews
                           SET status='inconclusive',
                               failure_kind='completed_result_missing',
                               updated_at=?
                           WHERE user_message_id=? AND status='completed'""",
                        (inconclusive_at, existing["id"]),
                    )
                    connection.execute(
                        """INSERT INTO security_events
                           (id, organization_id, actor_user_id, action, target_type, target_id,
                            created_at, metadata_json)
                           VALUES (?, ?, ?, 'ai_review_marked_inconclusive',
                                   'conversation', ?, ?, ?)""",
                        (
                            new_id(),
                            user["organization_id"],
                            user["id"],
                            conversation_id,
                            inconclusive_at,
                            json.dumps(
                                {
                                    "user_message_id": existing["id"],
                                    "failure_kind": "completed_result_missing",
                                },
                                sort_keys=True,
                            ),
                        ),
                    )
                    return {
                        "message": stored_user_message,
                        "review_status": "inconclusive",
                    }
                return {
                    "message": stored_user_message,
                    "assistant_message": _conversation_message_response(assistant_message),
                    "review_status": "completed",
                }
            return stored_user_message

        if payload.request_ai_review:
            review_provider = provider_status()
            if review_provider["status"] != "configured":
                raise HTTPException(503, "El proveedor de IA no está configurado.")

        if not allow_request_in(
            connection,
            f"conversation-message:{user['id']}",
            60,
            900,
        ):
            raise HTTPException(429, "Límite de mensajes alcanzado; inténtalo más tarde.")
        if payload.request_ai_review and not allow_request_in(
            connection,
            f"ai-code-review:{user['id']}",
            5,
            900,
        ):
            raise HTTPException(429, "Límite de revisiones de IA alcanzado; inténtalo más tarde.")

        message_quota_reservation_id = reserve_quota_or_http(
            connection,
            organization_id=user["organization_id"],
            user_id=user["id"],
            metric="conversation_messages",
            idempotency_key=f"{conversation_id}:{client_message_id}",
        )
        if payload.request_ai_review:
            ai_quota_reservation_id = reserve_quota_or_http(
                connection,
                organization_id=user["organization_id"],
                user_id=user["id"],
                metric="ai_reviews",
                idempotency_key=f"{conversation_id}:{client_message_id}",
            )
        connection.execute(
            """INSERT INTO conversation_messages
               (id, conversation_id, role, content, created_at, client_message_id)
               VALUES (?, ?, 'user', ?, ?, ?)""",
            (message_id, conversation_id, payload.content, created, client_message_id),
        )
        row = connection.execute(
            """SELECT id, role, content, created_at FROM conversation_messages
               WHERE id=? AND conversation_id=?""",
            (message_id, conversation_id),
        ).fetchone()
        if payload.request_ai_review:
            connection.execute(
                """INSERT INTO ai_code_reviews
                   (user_message_id, status, provider, model, created_at, updated_at)
                   VALUES (?, 'running', ?, ?, ?, ?)""",
                (
                    message_id,
                    review_provider["provider"],
                    review_provider["model"],
                    created,
                    created,
                ),
            )
        settle_quota(connection, message_quota_reservation_id, confirm=True)

    stored_user_message = _conversation_message_response(row)
    if not payload.request_ai_review:
        record_security_event(
            user,
            "conversation_message_added",
            "conversation",
            conversation_id,
            {"message_id": message_id},
        )
        return stored_user_message

    try:
        report, provider_name, model_name = review_code(payload.content)
    except ProviderError as error:
        with connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            failed = connection.execute(
                """UPDATE ai_code_reviews SET status='failed', failure_kind=?, updated_at=?
                   WHERE user_message_id=? AND status='running'""",
                (error.kind, utc_now(), message_id),
            )
            if ai_quota_reservation_id is not None:
                settle_quota(
                    connection,
                    ai_quota_reservation_id,
                    confirm=error.kind not in {
                        "not_configured",
                        "misconfigured",
                        "sensitive_content",
                        "pre_transport_error",
                    },
                )
        if failed.rowcount != 1:
            raise HTTPException(
                409,
                "La revisión cambió de estado y quedó inconclusa; no se reintentó.",
            ) from None
        messages = {
            "not_configured": "El mensaje quedó guardado, pero el proveedor de IA no está configurado.",
            "misconfigured": "El mensaje quedó guardado, pero la configuración del proveedor de IA no es válida.",
            "invalid_credentials": "El mensaje quedó guardado, pero el proveedor rechazó sus credenciales.",
            "access_denied": "El mensaje quedó guardado, pero el proveedor denegó el acceso solicitado.",
            "rate_limited": "El mensaje quedó guardado, pero el proveedor alcanzó su límite temporal.",
            "timeout": "El mensaje quedó guardado, pero el proveedor de IA excedió el tiempo de espera.",
            "remote_error": "El mensaje quedó guardado, pero el proveedor de IA no pudo completar la solicitud.",
            "invalid_response": "El mensaje quedó guardado, pero el proveedor devolvió una respuesta no válida.",
            "sensitive_content": "La revisión se bloqueó por un patrón sensible; el resultado no se guardó.",
            "sensitive_provider_response": "La respuesta del proveedor se bloqueó por un patrón sensible; el resultado no se guardó.",
            "pre_transport_error": "No se pudo iniciar el transporte; la solicitud no se envió.",
            "transport_unknown": (
                "No se pudo determinar si comenzó el envío; la cuota se contabilizó "
                "conservadoramente."
            ),
        }
        record_security_event(
            user,
            "code_review_failed",
            "conversation",
            conversation_id,
            {"message_id": message_id, "failure_kind": error.kind},
        )
        raise HTTPException(
            error.http_status,
            messages.get(error.kind, "La revisión no pudo completarse."),
        ) from None

    assistant_message_id = new_id()
    assistant_created = utc_now()
    assistant_content = json.dumps(report, sort_keys=True, ensure_ascii=False)
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        review_state = connection.execute(
            "SELECT status FROM ai_code_reviews WHERE user_message_id=?",
            (message_id,),
        ).fetchone()
        if review_state is None or review_state["status"] != "running":
            raise HTTPException(
                409,
                "La revisión quedó inconclusa; inicia una solicitud explícita nueva para reintentar.",
            )
        connection.execute(
            """INSERT INTO conversation_messages
               (id, conversation_id, role, content, created_at)
               VALUES (?, ?, 'assistant', ?, ?)""",
            (assistant_message_id, conversation_id, assistant_content, assistant_created),
        )
        updated = connection.execute(
            """UPDATE ai_code_reviews
               SET status='completed', assistant_message_id=?, provider=?, model=?, updated_at=?
               WHERE user_message_id=? AND status='running'""",
            (
                assistant_message_id,
                provider_name,
                model_name,
                assistant_created,
                message_id,
            ),
        )
        if ai_quota_reservation_id is not None:
            settle_quota(connection, ai_quota_reservation_id, confirm=True)
        if updated.rowcount != 1:
            raise HTTPException(
                409,
                "La revisión quedó inconclusa; inicia una solicitud explícita nueva para reintentar.",
            )
        assistant_row = connection.execute(
            """SELECT id, role, content, created_at FROM conversation_messages
               WHERE id=? AND conversation_id=?""",
            (assistant_message_id, conversation_id),
        ).fetchone()
    record_security_event(
        user,
        "code_review_completed",
        "conversation",
        conversation_id,
        {"user_message_id": message_id, "assistant_message_id": assistant_message_id},
    )
    return {
        "message": stored_user_message,
        "assistant_message": _conversation_message_response(assistant_row),
        "review_status": "completed",
    }


@app.post("/api/users/{user_id}/deactivate", status_code=204)
def deactivate_user(user_id: str, user: CurrentUser):
    require_roles(user, "admin")
    if user_id == user["id"]:
        raise HTTPException(409, "No puedes desactivar tu propia cuenta.")
    with connect() as connection:
        target = connection.execute(
            """SELECT id, role, is_platform_admin FROM users
               WHERE id=? AND organization_id=? AND active=1""",
            (user_id, user["organization_id"]),
        ).fetchone()
        if target is None:
            raise HTTPException(404, "Usuario no encontrado.")
        if target["is_platform_admin"]:
            raise HTTPException(409, "No puedes desactivar al administrador de plataforma.")
        if target["role"] == "admin":
            active_admins = connection.execute(
                """SELECT COUNT(*) FROM users
                   WHERE organization_id=? AND role='admin' AND active=1""",
                (user["organization_id"],),
            ).fetchone()[0]
            if active_admins <= 1:
                raise HTTPException(409, "La organización debe conservar al menos un administrador.")
        connection.execute("UPDATE users SET active=0 WHERE id=?", (user_id,))
        connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    record_security_event(user, "user_deactivated", "user", user_id)
    return Response(status_code=204)


@app.get("/api/runs")
def list_runs(user: CurrentUser):
    with connect() as connection:
        if user["role"] in {"admin", "auditor"}:
            rows = connection.execute(
                """SELECT record_json FROM audit_runs
                   WHERE organization_id=? ORDER BY created_at DESC LIMIT 50""",
                (user["organization_id"],),
            ).fetchall()
        else:
            rows = connection.execute(
                """SELECT r.record_json FROM audit_runs r
                   JOIN project_memberships m ON m.project_id=r.project_id
                   WHERE r.organization_id=? AND m.user_id=?
                   ORDER BY r.created_at DESC LIMIT 50""",
                (user["organization_id"], user["id"]),
            ).fetchall()
    return {"items": [_audit_record_http_response(json.loads(row["record_json"])) for row in rows]}


@app.post("/api/audits", status_code=202)
def create_audit(
    payload: AuditRequest,
    background_tasks: BackgroundTasks,
    user: CurrentUser,
):
    require_roles(user, "admin", "auditor", "collaborator")
    if not payload.acknowledge_lab_only:
        raise HTTPException(400, "Confirma autorización y uso exclusivo de código de laboratorio.")
    if len(payload.source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise HTTPException(413, "Código demasiado grande.")
    if contains_sensitive_content(payload.source):
        raise HTTPException(
            422,
            "Se detectó contenido sensible; elimina o protege las credenciales antes de persistir el código.",
        )
    project = require_project(payload.project_id, user)
    if not allow_request(f"audit:{user['organization_id']}:{user['id']}", 10, 900):
        raise HTTPException(429, "Límite de análisis alcanzado; inténtalo más tarde.")
    run_id = new_id()
    source_hash = sha256_text(payload.source)
    created = utc_now()
    record = {
        "id": run_id,
        "project_id": project["id"],
        "organization_id": user["organization_id"],
        "created_by": user["id"],
        "created_at": created,
        "filename": payload.filename,
        "status": "queued",
        "source_sha256": source_hash,
        "authorization_acknowledged": payload.acknowledge_lab_only,
        "findings": [],
        "engine": "slither",
        "message": "Analysis queued; no result is available yet.",
        "duration_ms": 0,
        "approval": None,
    }
    body = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        reservation_id = reserve_quota_or_http(
            connection,
            organization_id=user["organization_id"],
            user_id=user["id"],
            metric="audits",
            idempotency_key=run_id,
        )
        settle_quota(connection, reservation_id, confirm=True)
        connection.execute(
            """INSERT INTO audit_runs
               (id, created_at, record_json, evidence_hash, organization_id, project_id, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, created, body, sha256_text(body),
                user["organization_id"], project["id"], user["id"],
            ),
        )
        connection.execute(
            "INSERT INTO audit_sources(run_id, source_text, source_sha256) VALUES (?, ?, ?)",
            (run_id, payload.source, source_hash),
        )
        add_event(connection, run_id, "audit_created", {
            "source_sha256": source_hash,
            "project_id": project["id"],
            "created_by": user["id"],
        })
    record_security_event(user, "audit_created", "audit", run_id, {"project_id": project["id"]})
    background_tasks.add_task(run_audit_job, run_id, payload.source, payload.filename)
    return record


@app.get("/api/runs/{run_id}")
def get_run(run_id: str, user: CurrentUser):
    record = get_accessible_record(run_id, user)
    if record is None:
        raise HTTPException(404, "Ejecución no encontrada.")
    return _audit_record_http_response(record)


@app.get("/api/audits/{run_id}/source", response_class=PlainTextResponse)
def get_source(run_id: str, user: CurrentUser):
    if get_accessible_record(run_id, user) is None:
        raise HTTPException(404, "Código fuente no encontrado.")
    with connect() as connection:
        row = connection.execute(
            """SELECT s.source_text, r.record_json FROM audit_sources s
               JOIN audit_runs r ON r.id=s.run_id
               WHERE s.run_id=? AND r.organization_id=?""",
            (run_id, user["organization_id"]),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "Código fuente no encontrado.")
    if contains_sensitive_content(row["source_text"]):
        raise HTTPException(
            409,
            "El código fuente contiene contenido sensible reconocido y no puede mostrarse.",
        )
    filename = json.loads(row["record_json"])["filename"]
    return PlainTextResponse(
        row["source_text"],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/audits/{run_id}/report.json")
def get_report(run_id: str, user: CurrentUser):
    record = get_accessible_record(run_id, user)
    if record is None:
        raise HTTPException(404, "Ejecución no encontrada.")
    with connect() as connection:
        artifacts = connection.execute(
            """SELECT raw_stdout, raw_stderr, evidence_sha256
               FROM audit_execution_evidence WHERE run_id=?""",
            (run_id,),
        ).fetchone()
    redacted_record = contains_sensitive_content_in_value(record)
    redacted_artifacts = contains_sensitive_content_in_value(dict(artifacts)) if artifacts else False
    evidence_response = redact_sensitive_content_in_value(dict(artifacts)) if artifacts else None
    if isinstance(evidence_response, dict):
        evidence_response["sensitive_content_redacted"] = redacted_artifacts
    return {
        "record": _audit_record_http_response(record),
        "execution_evidence": evidence_response,
        "record_redacted": redacted_record,
        "sensitive_content_redacted": redacted_record or redacted_artifacts,
    }


@app.post("/api/audits/{run_id}/approval")
def approve_audit(
    run_id: str,
    payload: ApprovalRequest,
    user: CurrentUser,
):
    require_roles(user, "admin", "auditor")
    record = get_record(run_id, user["organization_id"])
    if record is None:
        raise HTTPException(404, "Ejecución no encontrada.")
    if record["status"] != "completed":
        raise HTTPException(409, "No se puede revisar un resultado inconcluso.")
    if record["approval"] is not None:
        raise HTTPException(409, "La decisión ya existe; no se sobrescribe.")
    approval = {
        "reviewer": user["email"],
        "decision": payload.decision,
        "reason": payload.reason,
        "created_at": utc_now(),
    }
    record["approval"] = approval
    body = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    with connect() as connection:
        cursor = connection.execute(
            """UPDATE audit_runs SET record_json=?, evidence_hash=?
               WHERE id=? AND organization_id=?""",
            (body, sha256_text(body), run_id, user["organization_id"]),
        )
        if cursor.rowcount != 1:
            raise HTTPException(404, "Ejecución no encontrada.")
        add_event(connection, run_id, "human_review", approval)
    record_security_event(user, "audit_reviewed", "audit", run_id, {"decision": payload.decision})
    return {"id": run_id, "approval": approval}


@app.get("/api/evidence/{run_id}")
def evidence(run_id: str, user: CurrentUser):
    record = get_accessible_record(run_id, user)
    if record is None:
        raise HTTPException(404, "Ejecución no encontrada.")
    with connect() as connection:
        events = connection.execute(
            """SELECT event_type, created_at, event_json, previous_hash, event_hash
               FROM audit_events WHERE run_id=? ORDER BY id""",
            (run_id,),
        ).fetchall()
        artifact = connection.execute(
            """SELECT raw_stdout, raw_stderr, evidence_sha256
               FROM audit_execution_evidence WHERE run_id=?""",
            (run_id,),
        ).fetchone()
        stored_record = connection.execute(
            "SELECT record_json, evidence_hash FROM audit_runs WHERE id=? AND organization_id=?",
            (run_id, user["organization_id"]),
        ).fetchone()
        source_artifact = connection.execute(
            """SELECT source_text, source_sha256 FROM audit_sources
               WHERE run_id=?""",
            (run_id,),
        ).fetchone()
    validated_events = [
        {
            "event_type": event["event_type"],
            "created_at": event["created_at"],
            "previous_hash": event["previous_hash"],
            "event_hash": event["event_hash"],
            "hash_valid": sha256_text(event["previous_hash"] + event["event_json"]) == event["event_hash"],
        }
        for event in events
    ]
    execution_hash = None
    if artifact:
        execution_hash = sha256_text(
            json.dumps(
                {"stdout": artifact["raw_stdout"], "stderr": artifact["raw_stderr"]},
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
    return {
        "record": _audit_record_http_response(record),
        "record_sha256": sha256_text(stored_record["record_json"]),
        "record_sha256_scope": "persisted_record_json",
        "record_http_response_modified": True,
        "record_redacted": contains_sensitive_content_in_value(record),
        "record_hash_valid": (
            sha256_text(stored_record["record_json"]) == stored_record["evidence_hash"]
        ),
        "source_hash_valid": (
            source_artifact is not None
            and source_artifact["source_sha256"] == record["source_sha256"]
            and sha256_text(source_artifact["source_text"]) == source_artifact["source_sha256"]
        ),
        "execution_evidence_sha256": artifact["evidence_sha256"] if artifact else None,
        "execution_evidence_hash_valid": (
            execution_hash == artifact["evidence_sha256"] if artifact else None
        ),
        "events": validated_events,
        "events_hash_valid": all(event["hash_valid"] for event in validated_events),
        "note": (
            "Hashes detect accidental changes only when compared with a separately trusted "
            "copy; a database administrator can rewrite this local chain."
        ),
    }


@app.get("/api/blockchains/evm/{network}/status")
def evm_network_status(
    network: str,
    user: CurrentUser,
):
    del user
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", network):
        raise HTTPException(400, "Nombre de red inválido.")
    return evm_status(network)


@app.get("/api/blockchains/stellar/status")
def stellar_network_status(user: CurrentUser):
    del user
    return stellar_status()


def _agent_run_response(row: sqlite3.Row) -> dict[str, object]:
    result_json = row["result_json"]
    result = json.loads(result_json) if result_json else None
    return {
        "id": row["id"],
        "task_type": row["task_type"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "execution_mode": result.get("execution_mode") if isinstance(result, dict) else None,
        "result": redact_sensitive_content_in_value(result),
        "result_redacted": contains_sensitive_content_in_value(result) if result is not None else False,
        "sensitive_content_detected": (
            contains_sensitive_content_in_value(result) if result is not None else False
        ),
    }


def _agent_subtask_responses(
    connection: sqlite3.Connection,
    run_id: str,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """SELECT id, agent_name, status, input_json, result_json, result_sha256,
                  error_kind, started_at, completed_at
           FROM agent_subtasks WHERE run_id=? ORDER BY started_at, agent_name""",
        (run_id,),
    ).fetchall()
    return [
        {
            "id": row["id"],
            "agent": row["agent_name"],
            "status": row["status"],
            "execution_mode": (
                json.loads(row["result_json"]).get("execution_mode")
                if row["result_json"]
                else None
            ),
            "input": redact_sensitive_content_in_value(json.loads(row["input_json"])),
            "input_redacted": contains_sensitive_content_in_value(
                json.loads(row["input_json"])
            ),
            "result": redact_sensitive_content_in_value(
                json.loads(row["result_json"]) if row["result_json"] else None
            ),
            "result_redacted": (
                contains_sensitive_content_in_value(json.loads(row["result_json"]))
                if row["result_json"]
                else False
            ),
            "result_sha256": row["result_sha256"],
            "result_sha256_matches_returned_result": bool(row["result_sha256"])
            and not (
                contains_sensitive_content_in_value(json.loads(row["result_json"]))
                if row["result_json"]
                else False
            ),
            "error_kind": row["error_kind"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }
        for row in rows
    ]


def _agent_run_input(connection: sqlite3.Connection, run_id: str) -> dict[str, object]:
    row = connection.execute(
        """SELECT source_text, source_sha256, context_json
           FROM agent_run_inputs WHERE run_id=?""",
        (run_id,),
    ).fetchone()
    if row is None:
        return {}
    return {
        "source": redact_sensitive_content_in_value(row["source_text"]),
        "source_redacted": contains_sensitive_content(row["source_text"]),
        "source_sha256": row["source_sha256"],
        "source_sha256_matches_returned_source": not contains_sensitive_content(
            row["source_text"]
        ),
        "context": json.loads(row["context_json"]),
    }


def _agent_result_is_valid(
    result: object,
    expected_agents: set[str],
) -> bool:
    if not isinstance(result, dict):
        return False
    run_status = result.get("status")
    if not isinstance(run_status, str) or run_status not in {
        "completed",
        "failed",
        "inconclusive",
    }:
        return False
    subtasks = result.get("subtasks")
    if not isinstance(subtasks, list) or len(subtasks) != len(expected_agents):
        return False
    actual_agents: set[str] = set()
    try:
        result_json = json.dumps(
            result,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(result_json.encode("utf-8")) > 100_000:
            return False
        for subtask in subtasks:
            if not isinstance(subtask, dict):
                return False
            agent_name = subtask.get("agent")
            if (
                not isinstance(agent_name, str)
                or agent_name not in expected_agents
                or agent_name in actual_agents
                or subtask.get("status") not in {"completed", "failed", "inconclusive"}
            ):
                return False
            subtask_json = json.dumps(
                subtask,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
            if len(subtask_json.encode("utf-8")) > 90_000:
                return False
            actual_agents.add(agent_name)
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return False
    if actual_agents != expected_agents:
        return False
    subtask_statuses = {subtask["status"] for subtask in subtasks}
    if run_status == "completed" and subtask_statuses != {"completed"}:
        return False
    if run_status == "failed" and "failed" not in subtask_statuses:
        return False
    return run_status != "inconclusive" or "inconclusive" in subtask_statuses


@app.post("/api/agent-runs", status_code=201)
def create_agent_run(payload: AgentRunRequest, user: CurrentUser):
    project = require_project(payload.project_id, user)
    inputs: dict[str, Any]
    if payload.task_type == "blockchain_health":
        if payload.network not in SUPPORTED_NETWORKS:
            raise HTTPException(422, "La red no está habilitada para análisis.")
        if any((payload.source, payload.conversation_id, payload.user_message_id)):
            raise HTTPException(422, "La solicitud contiene campos ajenos a la tarea.")
        inputs = {"network": payload.network}
        input_identity: dict[str, object] = inputs
        persisted_source = None
        persisted_source_sha256 = None
        persisted_context = inputs
        subtask_inputs = {"blockchain_analyst": inputs}
    elif payload.task_type == "code_review":
        if not payload.acknowledge_external_ai:
            raise HTTPException(400, "Confirma que autorizas el envío del código al proveedor de IA.")
        if payload.source is None or payload.network or payload.conversation_id or payload.user_message_id:
            raise HTTPException(422, "La solicitud no coincide con la tarea de revisión.")
        if not payload.source.strip():
            raise HTTPException(422, "El código para revisión no puede estar vacío.")
        try:
            source_size = len(payload.source.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise HTTPException(422, "El código contiene Unicode no válido.") from error
        if source_size > MAX_REVIEW_SOURCE_BYTES:
            raise HTTPException(413, "El fragmento excede el límite de revisión de 16000 bytes.")
        if contains_sensitive_content(payload.source):
            raise HTTPException(422, "Se detectó contenido sensible; no se envió al proveedor.")
        inputs = {"source": payload.source}
        input_identity = {"source_sha256": sha256_text(payload.source)}
        persisted_source = payload.source
        persisted_source_sha256 = sha256_text(payload.source)
        persisted_context = {"task_type": payload.task_type, "project_id": project["id"]}
        subtask_inputs = {
            "code_auditor": {"source_sha256": sha256_text(payload.source)},
            "independent_validator": {"source_sha256": sha256_text(payload.source)},
        }
    else:
        if (
            payload.conversation_id is None
            or payload.user_message_id is None
            or payload.network
            or payload.source is not None
        ):
            raise HTTPException(422, "La solicitud no coincide con la tarea de validación.")
        with connect() as connection:
            conversation = get_accessible_conversation(
                connection,
                payload.conversation_id,
                user,
            )
            if conversation["project_id"] != project["id"]:
                raise HTTPException(404, "Revisión no encontrada.")
            review = connection.execute(
                """SELECT source.content AS source_text, review.status,
                          result.content AS result_text
                   FROM conversation_messages source
                   JOIN ai_code_reviews review ON review.user_message_id=source.id
                   LEFT JOIN conversation_messages result
                     ON result.id=review.assistant_message_id
                    AND result.conversation_id=source.conversation_id
                    AND result.role='assistant'
                   WHERE source.id=? AND source.conversation_id=? AND source.role='user'""",
                (payload.user_message_id, payload.conversation_id),
            ).fetchone()
        if review is None or review["status"] != "completed" or not review["result_text"]:
            raise HTTPException(409, "No existe un resultado completado para validar.")
        try:
            report = json.loads(review["result_text"])
        except (UnicodeDecodeError, json.JSONDecodeError):
            report = None
        inputs = {"source": review["source_text"], "report": report}
        input_identity = {
            "source_sha256": sha256_text(review["source_text"]),
            "report_sha256": sha256_text(review["result_text"]),
            "conversation_id": payload.conversation_id,
            "user_message_id": payload.user_message_id,
        }
        persisted_source = None
        persisted_source_sha256 = sha256_text(review["source_text"])
        persisted_context = {
            "conversation_id": payload.conversation_id,
            "user_message_id": payload.user_message_id,
        }
        subtask_inputs = {
            "independent_validator": {
                "conversation_id": payload.conversation_id,
                "user_message_id": payload.user_message_id,
            },
        }

    input_sha256 = sha256_text(
        json.dumps(
            {"task_type": payload.task_type, "project_id": project["id"], **input_identity},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    idempotency_key = str(payload.idempotency_key)
    created = utc_now()
    run_id = new_id()
    ai_quota_reservation_id: str | None = None
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            """SELECT id, task_type, input_sha256, status, result_json, created_at, updated_at
               FROM agent_runs
               WHERE organization_id=? AND requested_by=? AND idempotency_key=?""",
            (user["organization_id"], user["id"], idempotency_key),
        ).fetchone()
        if existing is not None:
            if existing["input_sha256"] != input_sha256:
                raise HTTPException(409, "El identificador ya se utilizó para otra tarea.")
            response = _agent_run_response(existing)
            response["input"] = _agent_run_input(connection, existing["id"])
            response["subtasks"] = _agent_subtask_responses(connection, existing["id"])
            return response

        quota_reservation_id = reserve_quota_or_http(
            connection,
            organization_id=user["organization_id"],
            user_id=user["id"],
            metric="agent_runs",
            idempotency_key=idempotency_key,
        )
        if payload.task_type == "code_review":
            ai_quota_reservation_id = reserve_quota_or_http(
                connection,
                organization_id=user["organization_id"],
                user_id=user["id"],
                metric="ai_reviews",
                idempotency_key=idempotency_key,
            )
        connection.execute(
            """INSERT INTO agent_runs
               (id, organization_id, project_id, requested_by, task_type, idempotency_key,
                input_sha256, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)""",
            (
                run_id,
                user["organization_id"],
                project["id"],
                user["id"],
                payload.task_type,
                idempotency_key,
                input_sha256,
                created,
                created,
            ),
        )
        connection.execute(
            """INSERT INTO agent_run_inputs
               (run_id, source_text, source_sha256, context_json)
               VALUES (?, ?, ?, ?)""",
            (
                run_id,
                persisted_source,
                persisted_source_sha256,
                json.dumps(persisted_context, sort_keys=True),
            ),
        )
        for agent_name, subtask_input in subtask_inputs.items():
            subtask_id = new_id()
            connection.execute(
                """INSERT INTO agent_subtasks
                   (id, run_id, agent_name, status, input_json, started_at)
                   VALUES (?, ?, ?, 'running', ?, ?)""",
                (
                    subtask_id,
                    run_id,
                    agent_name,
                    json.dumps(subtask_input, sort_keys=True),
                    created,
                ),
            )

    error_kind: str | None = None
    try:
        result = execute_task(payload.task_type, inputs)
    except ProviderError as error:
        error_kind = error.kind
        result = {
            "status": "failed",
            "error_kind": error.kind,
            "execution_mode": "failed",
            "subtasks": [
                {
                    "agent": "code_auditor",
                    "status": "failed",
                    "error_kind": error.kind,
                    "execution_mode": "failed",
                },
                {
                    "agent": "independent_validator",
                    "status": "inconclusive",
                    "execution_mode": "inconclusive",
                    "limitations": ["The code auditor did not produce a review to validate."],
                },
            ],
        }
    except Exception:  # noqa: BLE001 - always settle the run; details are not exposed
        error_kind = "internal_error"
        result = {
            "status": "failed",
            "error_kind": error_kind,
            "execution_mode": "failed",
            "subtasks": [
                {
                    "agent": agent_name,
                    "status": "failed",
                    "error_kind": error_kind,
                    "execution_mode": "failed",
                }
                for agent_name in subtask_inputs
            ],
        }
    if contains_sensitive_content_in_value(result):
        error_kind = "sensitive_result"
        result = {
            "status": "failed",
            "error_kind": error_kind,
            "execution_mode": "failed",
            "subtasks": [
                {
                    "agent": agent_name,
                    "status": "failed",
                    "error_kind": error_kind,
                    "execution_mode": "failed",
                }
                for agent_name in subtask_inputs
            ],
        }
    if not _agent_result_is_valid(result, set(subtask_inputs)):
        error_kind = "invalid_result"
        result = {
            "status": "failed",
            "error_kind": error_kind,
            "execution_mode": "failed",
            "subtasks": [
                {
                    "agent": agent_name,
                    "status": "failed",
                    "error_kind": error_kind,
                    "execution_mode": "failed",
                }
                for agent_name in subtask_inputs
            ],
        }
    run_status = result["status"]
    finished = utc_now()
    result_json = json.dumps(
        result,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        current_run = connection.execute(
            "SELECT status FROM agent_runs WHERE id=?",
            (run_id,),
        ).fetchone()
        if current_run is None or current_run["status"] != "running":
            raise HTTPException(
                409,
                "La ejecución quedó inconclusa y no se reintentó automáticamente.",
            )
        for subtask in result["subtasks"]:
            if not isinstance(subtask, dict):
                continue
            agent_name = subtask.get("agent")
            if agent_name not in {
                "blockchain_analyst",
                "code_auditor",
                "independent_validator",
            }:
                continue
            subtask_json = json.dumps(
                subtask,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            connection.execute(
                """UPDATE agent_subtasks
                   SET status=?, result_json=?, result_sha256=?, error_kind=?, completed_at=?
                   WHERE run_id=? AND agent_name=?""",
                (
                    subtask.get("status", run_status),
                    subtask_json,
                    sha256_text(subtask_json),
                    subtask.get("error_kind"),
                    finished,
                    run_id,
                    agent_name,
                ),
            )
        connection.execute(
            """UPDATE agent_runs SET status=?, result_json=?, updated_at=? WHERE id=?""",
            (run_status, result_json, finished, run_id),
        )
        settle_quota(connection, quota_reservation_id, confirm=True)
        if ai_quota_reservation_id is not None:
            settle_quota(
                connection,
                ai_quota_reservation_id,
                confirm=error_kind not in {
                    "not_configured",
                    "misconfigured",
                    "sensitive_content",
                    "pre_transport_error",
                },
            )
    with connect() as connection:
        stored_run = connection.execute(
            """SELECT id, task_type, status, result_json, created_at, updated_at
               FROM agent_runs WHERE id=?""",
            (run_id,),
        ).fetchone()
        stored_input = _agent_run_input(connection, run_id)
        stored_subtasks = _agent_subtask_responses(connection, run_id)
    record_security_event(
        user,
        "agent_run_finished",
        "agent_run",
        run_id,
        {"task_type": payload.task_type, "status": run_status, "error_kind": error_kind},
    )
    response = _agent_run_response(stored_run)
    response["input"] = stored_input
    response["subtasks"] = stored_subtasks
    return response


@app.get("/api/agent-runs/{run_id}")
def get_agent_run(run_id: str, user: CurrentUser):
    marked_inconclusive = False
    with connect() as connection:
        row = connection.execute(
            """SELECT id, project_id, requested_by, task_type, idempotency_key, status,
                      result_json, created_at, updated_at
               FROM agent_runs WHERE id=? AND organization_id=?""",
            (run_id, user["organization_id"]),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Ejecución de agente no encontrada.")
        require_project(row["project_id"], user)
        if user["role"] not in {"admin", "auditor"} and row["requested_by"] != user["id"]:
            raise HTTPException(404, "Ejecución de agente no encontrada.")
        updated_at = datetime.fromisoformat(row["updated_at"])
        if row["status"] == "running" and updated_at < datetime.now(UTC) - timedelta(minutes=5):
            connection.execute("BEGIN IMMEDIATE")
            inconclusive_at = utc_now()
            stale_result = json.dumps(
                {
                    "status": "inconclusive",
                    "error_kind": "abandoned_before_result",
                    "subtasks": [],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            stale_update = connection.execute(
                """UPDATE agent_runs
                   SET status='inconclusive', result_json=?, updated_at=?
                   WHERE id=? AND status='running'""",
                (stale_result, inconclusive_at, run_id),
            )
            if stale_update.rowcount:
                connection.execute(
                    """UPDATE agent_subtasks
                       SET status='inconclusive', error_kind='abandoned_before_result',
                           completed_at=?
                       WHERE run_id=? AND status='running'""",
                    (inconclusive_at, run_id),
                )
                reservations = connection.execute(
                    """SELECT id FROM quota_reservations
                       WHERE organization_id=? AND user_id=?
                         AND metric IN ('agent_runs', 'ai_reviews') AND idempotency_key=?""",
                    (user["organization_id"], row["requested_by"], row["idempotency_key"]),
                ).fetchall()
                for reservation in reservations:
                    settle_quota(connection, reservation["id"], confirm=True)
                marked_inconclusive = True
            row = connection.execute(
                """SELECT id, task_type, status, result_json, created_at, updated_at
                   FROM agent_runs WHERE id=?""",
                (run_id,),
            ).fetchone()
        subtasks = _agent_subtask_responses(connection, run_id)
        run_input = _agent_run_input(connection, run_id)
    if marked_inconclusive:
        record_security_event(
            user,
            "agent_run_marked_inconclusive",
            "agent_run",
            run_id,
            {"failure_kind": "abandoned_before_result"},
        )
    response = _agent_run_response(row)
    response["input"] = run_input
    response["subtasks"] = subtasks
    return response
