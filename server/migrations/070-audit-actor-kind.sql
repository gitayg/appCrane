-- Agent action attribution (v2.28.0).
--
-- audit_log records user_id, but nothing marks WHETHER that actor was a human
-- or an AI agent. With most platform work now arriving over MCP, "show me
-- everything agents did" is unanswerable — and that is the question auditors
-- and incident responders actually ask. GitHub added the same distinction as
-- `actor_is_agent` in its audit log; OWASP's Agentic Top 10 (ASI05) asks for
-- every agent-executed command to be logged and attributable.
--
-- users.kind already carries 'human' | 'agent' (migration 038). Denormalize it
-- onto each row so the trail stays true even if the user record is later
-- deleted or its kind changes — an audit log must record what was true at the
-- time, not what is true now.
ALTER TABLE audit_log ADD COLUMN actor_kind TEXT;

-- Backfill from the current user records. Rows whose user is gone stay NULL
-- (honestly "unknown") rather than being guessed at.
UPDATE audit_log
SET actor_kind = (SELECT u.kind FROM users u WHERE u.id = audit_log.user_id)
WHERE actor_kind IS NULL AND user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_actor_kind ON audit_log (actor_kind, created_at);
