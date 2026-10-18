from __future__ import annotations
import hashlib, json, os, shutil, sqlite3, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
MAX_BYTES = 200_000
DB_PATH = Path(os.getenv("AEGIS_DB_PATH", ROOT / "aegis.db"))

def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS audit_runs (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, record_json TEXT NOT NULL, evidence_hash TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, event_type TEXT NOT NULL, created_at TEXT NOT NULL, event_json TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL, FOREIGN KEY(run_id) REFERENCES audit_runs(id))")

init_db()

def save_record(record: dict[str, Any]):
    body = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    digest = sha256_text(body)
    with db() as conn:
        conn.execute("INSERT INTO audit_runs(id,created_at,record_json,evidence_hash) VALUES(?,?,?,?)", (record["id"], record["created_at"], body, digest))
        add_event(conn, record["id"], "audit_created", record)

def add_event(conn, run_id: str, event_type: str, payload: dict[str, Any]):
    previous = conn.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = previous[0] if previous else "0" * 64
    created = datetime.now(timezone.utc).isoformat()
    body = json.dumps({"run_id":run_id,"event_type":event_type,"created_at":created,"payload":payload}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    event_hash = sha256_text(previous_hash + body)
    conn.execute("INSERT INTO audit_events(run_id,event_type,created_at,event_json,previous_hash,event_hash) VALUES(?,?,?,?,?,?)", (run_id,event_type,created,body,previous_hash,event_hash))

def get_record(run_id: str):
    with db() as conn:
        row = conn.execute("SELECT record_json FROM audit_runs WHERE id=?", (run_id,)).fetchone()
    return json.loads(row[0]) if row else None
app = FastAPI(title="Aegis-Web3 Core", version="0.2.0", description="MVP de auditoría; no certifica seguridad.")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("AEGIS_ALLOWED_ORIGINS", "http://localhost:8000").split(","), allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.update({"X-Content-Type-Options":"nosniff", "X-Frame-Options":"DENY", "Referrer-Policy":"no-referrer", "Cache-Control":"no-store", "Content-Security-Policy":"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'"})
    return response

class AuditRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=120)
    source: str = Field(min_length=1, max_length=200_000)
    acknowledge_lab_only: bool = False
class ApprovalRequest(BaseModel):
    reviewer: str = Field(min_length=2, max_length=120)
    decision: str = Field(pattern="^(approve|reject)$")
    reason: str = Field(min_length=5, max_length=1000)
def sha256_text(value: str) -> str: return hashlib.sha256(value.encode()).hexdigest()

def audit_source(source: str, filename: str) -> dict[str, Any]:
    if Path(filename).suffix.lower() != ".sol": raise HTTPException(400, "Solo se aceptan archivos .sol.")
    if len(source.encode()) > MAX_BYTES: raise HTTPException(413, "Código demasiado grande.")
    if not source.strip(): raise HTTPException(400, "Código vacío.")
    digest = sha256_text(source)
    if not shutil.which("slither"):
        return {"status":"tool_unavailable", "engine":"slither", "findings":[], "message":"Slither no está instalado. No se ejecutó una auditoría; no se declara seguro.", "source_sha256":digest, "duration_ms":0}
    with tempfile.TemporaryDirectory(prefix="aegis-audit-") as temp:
        path = Path(temp) / Path(filename).name
        path.write_text(source, encoding="utf-8")
        start = time.monotonic()
        try:
            proc = subprocess.run(["slither", str(path), "--json", "-"], cwd=temp, capture_output=True, text=True, timeout=45, check=False, env={"PATH":os.environ.get("PATH", ""), "HOME":temp, "LANG":"C.UTF-8"})
            elapsed = int((time.monotonic()-start)*1000)
            try: parsed = json.loads(proc.stdout) if proc.stdout.strip() else None
            except json.JSONDecodeError: parsed = None
            findings = []
            if isinstance(parsed, dict):
                for d in parsed.get("results", {}).get("detectors", []):
                    findings.append({"check":d.get("check","unknown"), "impact":d.get("impact","Unknown"), "confidence":d.get("confidence","Unknown"), "description":d.get("description","")[:4000]})
            status = "completed" if proc.returncode in (0,1) and parsed is not None else "engine_error"
            return {"status":status,"engine":"slither","findings":findings,"message":"Resultado de herramienta externa; requiere revisión humana." if status=="completed" else "Resultado inconcluso; no se declara seguro.","source_sha256":digest,"duration_ms":elapsed,"exit_code":proc.returncode,"stderr_excerpt":proc.stderr[-2000:]}
        except subprocess.TimeoutExpired:
            return {"status":"timeout","engine":"slither","findings":[],"message":"Tiempo agotado; resultado inconcluso.","source_sha256":digest,"duration_ms":45000}

@app.get("/", response_class=HTMLResponse)
def dashboard(): return (ROOT/"app"/"index.html").read_text(encoding="utf-8")
@app.get("/api/health")
def health(): return {"status":"ok","service":"aegis-web3-core","mode":"MVP","audit_engine":"slither" if shutil.which("slither") else "unavailable","production_ready":False}
@app.get("/api/runs")
def list_runs():
    with db() as conn:
        rows = conn.execute("SELECT record_json FROM audit_runs ORDER BY created_at DESC LIMIT 50").fetchall()
    return {"items":[json.loads(r[0]) for r in rows]}
@app.post("/api/audits")
def create_audit(payload: AuditRequest):
    if not payload.acknowledge_lab_only: raise HTTPException(400,"Confirma que tienes autorización y es código de laboratorio.")
    result = audit_source(payload.source, payload.filename)
    run_id = str(uuid.uuid4())
    record = {"id":run_id,"created_at":datetime.now(timezone.utc).isoformat(),"filename":Path(payload.filename).name,"status":result["status"],"source_sha256":result["source_sha256"],"findings":result["findings"],"engine":result["engine"],"message":result["message"],"duration_ms":result["duration_ms"],"approval":None}
    save_record(record)
    return record
@app.post("/api/audits/{run_id}/approval")
def approve_audit(run_id: str, payload: ApprovalRequest):
    record = get_record(run_id)
    if not record: raise HTTPException(404,"Ejecución no encontrada.")
    if record["status"] != "completed": raise HTTPException(409,"No se puede aprobar un resultado inconcluso.")
    if record["approval"] is not None: raise HTTPException(409,"La decisión ya existe; no se sobrescribe.")
    record["approval"] = {"reviewer":payload.reviewer,"decision":payload.decision,"reason":payload.reason,"created_at":datetime.now(timezone.utc).isoformat()}
    body = json.dumps(record,sort_keys=True,ensure_ascii=False,separators=(",",":"))
    with db() as conn:
        conn.execute("UPDATE audit_runs SET record_json=?, evidence_hash=? WHERE id=?", (body,sha256_text(body),run_id))
        add_event(conn,run_id,"human_review",record["approval"])
    return {"id":run_id,"approval":record["approval"]}
@app.get("/api/evidence/{run_id}")
def evidence(run_id: str):
    record = get_record(run_id)
    if not record: raise HTTPException(404,"Ejecución no encontrada.")
    body = json.dumps(record,sort_keys=True,ensure_ascii=False,separators=(",",":"))
    with db() as conn:
        events = conn.execute("SELECT event_type,created_at,previous_hash,event_hash FROM audit_events WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
    return {"record":record,"evidence_sha256":sha256_text(body),"events":[dict(e) for e in events],"note":"El hash verifica integridad del registro, no la corrección del análisis. La cadena detecta cambios solo si se conserva una copia confiable de sus hashes."}
@app.exception_handler(Exception)
async def generic_error_handler(request, exc):
    return JSONResponse(status_code=500,content={"detail":"Error interno. Consulte los registros del servidor."})
