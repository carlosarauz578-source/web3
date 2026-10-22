CREATE TABLE ai_code_reviews_v2 (
    user_message_id TEXT PRIMARY KEY REFERENCES conversation_messages(id) ON DELETE CASCADE,
    assistant_message_id TEXT UNIQUE REFERENCES conversation_messages(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK(
        status IN ('running', 'completed', 'failed', 'inconclusive')
    ),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    failure_kind TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO ai_code_reviews_v2
    (user_message_id, assistant_message_id, status, provider, model, failure_kind,
     created_at, updated_at)
SELECT user_message_id, assistant_message_id, status, provider, model, failure_kind,
       created_at, updated_at
FROM ai_code_reviews;

DROP TABLE ai_code_reviews;
ALTER TABLE ai_code_reviews_v2 RENAME TO ai_code_reviews;

CREATE INDEX idx_ai_code_reviews_status_updated
ON ai_code_reviews(status, updated_at);
