DROP TRIGGER conversation_message_updates_conversation;
DROP INDEX idx_conversation_messages_history;

CREATE TABLE conversation_messages_v2 (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
    content TEXT NOT NULL CHECK(length(trim(content)) > 0),
    created_at TEXT NOT NULL,
    client_message_id TEXT,
    CHECK(
        (role = 'user' AND length(CAST(content AS BLOB)) <= 20000)
        OR (role = 'assistant' AND length(CAST(content AS BLOB)) <= 100000)
    )
);

INSERT INTO conversation_messages_v2
    (id, conversation_id, role, content, created_at)
SELECT id, conversation_id, role, content, created_at
FROM conversation_messages;

DROP TABLE conversation_messages;
ALTER TABLE conversation_messages_v2 RENAME TO conversation_messages;

CREATE UNIQUE INDEX idx_conversation_messages_client_id
ON conversation_messages(conversation_id, client_message_id)
WHERE client_message_id IS NOT NULL;

CREATE INDEX idx_conversation_messages_history
ON conversation_messages(conversation_id, created_at DESC, id DESC);

CREATE TABLE ai_code_reviews (
    user_message_id TEXT PRIMARY KEY REFERENCES conversation_messages(id) ON DELETE CASCADE,
    assistant_message_id TEXT UNIQUE REFERENCES conversation_messages(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed')),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    failure_kind TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TRIGGER conversation_message_updates_conversation
AFTER INSERT ON conversation_messages
BEGIN
    UPDATE conversations
    SET updated_at = NEW.created_at
    WHERE id = NEW.conversation_id;
END;
