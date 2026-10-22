CREATE TABLE organization_quota_counters (
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
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
    PRIMARY KEY(organization_id, metric, period_start)
);
