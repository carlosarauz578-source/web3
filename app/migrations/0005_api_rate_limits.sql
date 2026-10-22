CREATE TABLE api_rate_limits (
    client_key TEXT PRIMARY KEY,
    window_started_at INTEGER NOT NULL,
    requests INTEGER NOT NULL
);
