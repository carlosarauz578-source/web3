CREATE TABLE agent_run_inputs (
    run_id TEXT PRIMARY KEY REFERENCES agent_runs(id) ON DELETE CASCADE,
    source_text TEXT CHECK(
        source_text IS NULL OR length(CAST(source_text AS BLOB)) <= 16000
    ),
    source_sha256 TEXT CHECK(source_sha256 IS NULL OR length(source_sha256) = 64),
    context_json TEXT NOT NULL CHECK(length(CAST(context_json AS BLOB)) <= 4000),
    CHECK(source_text IS NULL OR source_sha256 IS NOT NULL)
);
