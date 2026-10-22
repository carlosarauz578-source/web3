CREATE TABLE agent_runs (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    task_type TEXT NOT NULL CHECK(
        task_type IN ('blockchain_health', 'validate_review', 'code_review')
    ),
    idempotency_key TEXT NOT NULL,
    input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
    status TEXT NOT NULL CHECK(
        status IN ('running', 'completed', 'failed', 'inconclusive')
    ),
    result_json TEXT CHECK(
        result_json IS NULL OR length(CAST(result_json AS BLOB)) <= 100000
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(organization_id, requested_by, idempotency_key),
    FOREIGN KEY(project_id, organization_id)
        REFERENCES projects(id, organization_id) ON DELETE CASCADE,
    FOREIGN KEY(requested_by, organization_id)
        REFERENCES users(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE agent_subtasks (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    agent_name TEXT NOT NULL CHECK(
        agent_name IN ('blockchain_analyst', 'code_auditor', 'independent_validator')
    ),
    status TEXT NOT NULL CHECK(
        status IN ('running', 'completed', 'failed', 'inconclusive')
    ),
    input_json TEXT NOT NULL CHECK(length(CAST(input_json AS BLOB)) <= 4000),
    result_json TEXT CHECK(
        result_json IS NULL OR length(CAST(result_json AS BLOB)) <= 90000
    ),
    result_sha256 TEXT CHECK(result_sha256 IS NULL OR length(result_sha256) = 64),
    error_kind TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(run_id, agent_name)
);

CREATE INDEX idx_agent_runs_owner_updated
ON agent_runs(organization_id, requested_by, updated_at DESC);
