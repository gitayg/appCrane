-- v2.85.0 — per-dispatch model choice, and a follow-up queue that survives a reload.
--
-- `model` on a message row is what makes the transcript readable once a picker
-- exists: a conversation where three turns were answered by three different
-- models, and nothing says which, is worse than one model and no picker.
-- Stored on the user row (what was asked for) and the assistant row (what
-- answered) — they can differ only if an operator changes the default
-- mid-turn, which is exactly the case worth being able to see.
ALTER TABLE coder_session_messages ADD COLUMN model TEXT;

-- Typed-ahead follow-ups. Deliberately a table and not an in-memory array:
-- a message the user typed while a turn was running has to survive a page
-- reload and be visible to anyone else watching the same session. It is NOT
-- written into coder_session_messages, because a row there reads as a turn
-- that happened — a pending follow-up has not been sent to the model at all.
--
-- 'dispatched' rows are kept rather than deleted so the queue has a history:
-- "did my typed-ahead message actually run" is otherwise unanswerable.
CREATE TABLE IF NOT EXISTS coder_session_followups (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id   TEXT    NOT NULL,
  prompt       TEXT    NOT NULL,
  model        TEXT,
  user_id      INTEGER,
  status       TEXT    NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'dispatched', 'cancelled')),
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  resolved_at  TEXT,
  FOREIGN KEY (session_id) REFERENCES coder_sessions(id) ON DELETE CASCADE
);

-- The only read that matters is "next pending for this session, in order".
CREATE INDEX IF NOT EXISTS idx_coder_followups_pending
  ON coder_session_followups (session_id, status, id);
