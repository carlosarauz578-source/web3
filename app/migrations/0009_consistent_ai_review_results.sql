CREATE TABLE ai_code_reviews_v3 (
    user_message_id TEXT PRIMARY KEY REFERENCES conversation_messages(id) ON DELETE CASCADE,
    assistant_message_id TEXT UNIQUE REFERENCES conversation_messages(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK(
        status IN ('running', 'completed', 'failed', 'inconclusive')
    ),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    failure_kind TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(
        (status = 'completed' AND assistant_message_id IS NOT NULL)
        OR (status != 'completed' AND assistant_message_id IS NULL)
    )
);

INSERT INTO ai_code_reviews_v3
    (user_message_id, assistant_message_id, status, provider, model, failure_kind,
     created_at, updated_at)
SELECT r.user_message_id,
       CASE WHEN r.status = 'completed' AND EXISTS (
           SELECT 1
           FROM conversation_messages source
           JOIN conversation_messages result
             ON result.id = r.assistant_message_id
            AND result.conversation_id = source.conversation_id
            AND result.role = 'assistant'
           WHERE source.id = r.user_message_id AND source.role = 'user'
       ) THEN r.assistant_message_id ELSE NULL END,
       CASE WHEN r.status = 'completed' AND NOT EXISTS (
           SELECT 1
           FROM conversation_messages source
           JOIN conversation_messages result
             ON result.id = r.assistant_message_id
            AND result.conversation_id = source.conversation_id
            AND result.role = 'assistant'
           WHERE source.id = r.user_message_id AND source.role = 'user'
       ) OR (r.status != 'completed' AND r.assistant_message_id IS NOT NULL)
       THEN 'inconclusive' ELSE r.status END,
       r.provider,
       r.model,
       CASE WHEN (r.status = 'completed' AND NOT EXISTS (
           SELECT 1
           FROM conversation_messages source
           JOIN conversation_messages result
             ON result.id = r.assistant_message_id
            AND result.conversation_id = source.conversation_id
            AND result.role = 'assistant'
           WHERE source.id = r.user_message_id AND source.role = 'user'
       )) OR (r.status != 'completed' AND r.assistant_message_id IS NOT NULL)
       THEN 'migration_found_missing_or_inconsistent_result'
       ELSE r.failure_kind END,
       r.created_at,
       r.updated_at
FROM ai_code_reviews r;

DROP TABLE ai_code_reviews;
ALTER TABLE ai_code_reviews_v3 RENAME TO ai_code_reviews;

CREATE INDEX idx_ai_code_reviews_status_updated
ON ai_code_reviews(status, updated_at);

CREATE TRIGGER ai_code_review_insert_guard
BEFORE INSERT ON ai_code_reviews
WHEN NEW.status != 'running'
  OR NOT EXISTS (
      SELECT 1 FROM conversation_messages source
      WHERE source.id=NEW.user_message_id AND source.role='user'
  )
BEGIN
    SELECT RAISE(ABORT, 'new AI review must start from a user message in running state');
END;

CREATE TRIGGER ai_code_review_transition_guard
BEFORE UPDATE OF status ON ai_code_reviews
WHEN NEW.status != OLD.status
 AND NOT (
     (OLD.status = 'running' AND NEW.status IN ('completed', 'failed', 'inconclusive'))
     OR (OLD.status = 'completed' AND NEW.status = 'inconclusive')
 )
BEGIN
    SELECT RAISE(ABORT, 'invalid AI review state transition');
END;

CREATE TRIGGER ai_code_review_completed_result_guard
BEFORE INSERT ON ai_code_reviews
WHEN NEW.status = 'completed'
 AND NOT EXISTS (
     SELECT 1
     FROM conversation_messages source
     JOIN conversation_messages result
       ON result.id = NEW.assistant_message_id
      AND result.conversation_id = source.conversation_id
      AND result.role = 'assistant'
     WHERE source.id = NEW.user_message_id AND source.role = 'user'
 )
BEGIN
    SELECT RAISE(ABORT, 'completed AI review requires a persisted assistant result');
END;

CREATE TRIGGER ai_code_review_completed_result_update_guard
BEFORE UPDATE OF status, assistant_message_id ON ai_code_reviews
WHEN NEW.status = 'completed'
 AND NOT EXISTS (
     SELECT 1
     FROM conversation_messages source
     JOIN conversation_messages result
       ON result.id = NEW.assistant_message_id
      AND result.conversation_id = source.conversation_id
      AND result.role = 'assistant'
     WHERE source.id = NEW.user_message_id AND source.role = 'user'
 )
BEGIN
    SELECT RAISE(ABORT, 'completed AI review requires a persisted assistant result');
END;
