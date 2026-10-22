ALTER TABLE organizations
ADD COLUMN plan_id TEXT NOT NULL DEFAULT 'free'
CHECK(plan_id IN ('free', 'pro', 'enterprise'));

CREATE TABLE quota_counters (
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    metric TEXT NOT NULL CHECK(
        metric IN (
            'audits',
            'ai_reviews',
            'agent_runs',
            'conversation_messages',
            'conversation_creations'
        )
    ),
    period_start TEXT NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed >= 0),
    reserved INTEGER NOT NULL DEFAULT 0 CHECK(reserved >= 0),
    PRIMARY KEY(organization_id, user_id, metric, period_start),
    FOREIGN KEY(user_id, organization_id)
        REFERENCES users(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE quota_reservations (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    metric TEXT NOT NULL CHECK(
        metric IN (
            'audits',
            'ai_reviews',
            'agent_runs',
            'conversation_messages',
            'conversation_creations'
        )
    ),
    period_start TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('reserved', 'confirmed', 'released')),
    created_at TEXT NOT NULL,
    finalized_at TEXT,
    UNIQUE(organization_id, user_id, metric, idempotency_key),
    FOREIGN KEY(user_id, organization_id)
        REFERENCES users(id, organization_id) ON DELETE CASCADE
);

CREATE INDEX idx_quota_reservations_status
ON quota_reservations(status, created_at);
