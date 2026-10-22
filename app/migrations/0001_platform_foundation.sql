CREATE TABLE IF NOT EXISTS audit_runs (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    record_json TEXT NOT NULL,
    evidence_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    event_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES audit_runs(id)
);

CREATE TABLE organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'auditor', 'client', 'collaborator')),
    created_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1))
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    UNIQUE(organization_id, name)
);

CREATE TABLE login_attempts (
    client_key TEXT PRIMARY KEY,
    window_started_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL
);

CREATE TABLE audit_sources (
    run_id TEXT PRIMARY KEY REFERENCES audit_runs(id) ON DELETE CASCADE,
    source_text TEXT NOT NULL,
    source_sha256 TEXT NOT NULL
);

CREATE TABLE audit_execution_evidence (
    run_id TEXT PRIMARY KEY REFERENCES audit_runs(id) ON DELETE CASCADE,
    raw_stdout TEXT NOT NULL,
    raw_stderr TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL
);

ALTER TABLE audit_runs ADD COLUMN organization_id TEXT REFERENCES organizations(id);
ALTER TABLE audit_runs ADD COLUMN project_id TEXT REFERENCES projects(id);
ALTER TABLE audit_runs ADD COLUMN created_by TEXT REFERENCES users(id);

CREATE INDEX idx_users_organization ON users(organization_id, role);
CREATE INDEX idx_projects_organization ON projects(organization_id, created_at);
CREATE INDEX idx_audit_runs_organization ON audit_runs(organization_id, created_at);
CREATE INDEX idx_audit_runs_project ON audit_runs(project_id, created_at);
CREATE INDEX idx_audit_events_run ON audit_events(run_id, id);
