CREATE UNIQUE INDEX idx_users_id_organization
ON users(id, organization_id);

CREATE UNIQUE INDEX idx_projects_id_organization
ON projects(id, organization_id);

CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    specialty TEXT NOT NULL CHECK(
        specialty IN ('code_auditor', 'blockchain_analyst', 'independent_validator')
    ),
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'closed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(project_id, organization_id)
        REFERENCES projects(id, organization_id) ON DELETE CASCADE,
    FOREIGN KEY(owner_user_id, organization_id)
        REFERENCES users(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE conversation_messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role = 'user'),
    content TEXT NOT NULL CHECK(
        length(trim(content)) > 0 AND length(CAST(content AS BLOB)) <= 20000
    ),
    created_at TEXT NOT NULL
);

CREATE INDEX idx_conversations_owner_updated
ON conversations(organization_id, owner_user_id, updated_at DESC);

CREATE INDEX idx_conversations_project
ON conversations(project_id, organization_id);

CREATE INDEX idx_conversation_messages_history
ON conversation_messages(conversation_id, created_at DESC, id DESC);

CREATE TRIGGER conversation_message_updates_conversation
AFTER INSERT ON conversation_messages
BEGIN
    UPDATE conversations
    SET updated_at = NEW.created_at
    WHERE id = NEW.conversation_id;
END;
