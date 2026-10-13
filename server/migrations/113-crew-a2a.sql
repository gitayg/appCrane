-- Crew, phase 2: the platform A2A endpoint, agent tokens, push notifications,
-- plus two security fixes to the phase 1 first-contact rules.
-- Rules live in server/services/crew*.js; this file is only the shape.

-- A2A groups tasks by contextId (spec §3.4.1). A task created over MCP gets its
-- own id as its context; a task created over A2A may carry the client's.
ALTER TABLE crew_tasks ADD COLUMN context_id TEXT;
CREATE INDEX IF NOT EXISTS idx_crew_tasks_context ON crew_tasks(context_id);

-- A2A Message.messageId is REQUIRED and created by the message's author
-- (spec §4.1.4 / a2a.proto Message.message_id). Stored so history shows the id
-- the author chose; NULL for MCP messages (the A2A view derives one).
ALTER TABLE crew_messages ADD COLUMN message_id TEXT CHECK (message_id IS NULL OR length(message_id) <= 128);
-- The task's state right after this message was written. Events are rendered
-- after the fact (crewA2aView.eventsSince); without this, a "working" message
-- followed at once by "completed" would be streamed as two COMPLETED updates.
ALTER TABLE crew_messages ADD COLUMN state_after TEXT;

-- One credential per crew agent for A2A callers. Only the SHA-256 of the token
-- is stored (the token is shown once); revoked rows are kept for the audit
-- trail of which token acted when, and are never accepted again. A partial
-- unique index allows exactly one live token per agent, so "rotate" is
-- revoke-then-issue in one transaction and two live tokens cannot coexist.
CREATE TABLE IF NOT EXISTS crew_agent_tokens (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id      INTEGER NOT NULL REFERENCES crew_agents(id) ON DELETE CASCADE,
  token_hash    TEXT    NOT NULL UNIQUE,
  -- The first characters after the prefix, for "which token is this?" in the
  -- dashboard. 6 base64url chars of a 32-byte token reveal nothing usable.
  hint          TEXT    NOT NULL,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
  last_used_at  TEXT,
  revoked_at    TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_crew_agent_tokens_live ON crew_agent_tokens(agent_id) WHERE revoked_at IS NULL;

-- A2A TaskPushNotificationConfig (a2a.proto: id, task_id, url, token,
-- authentication{scheme, credentials}). token and credentials are secrets the
-- CLIENT chose for its own webhook; they are stored encrypted and never
-- returned. agent_id is the crew agent that created the config: deliveries are
-- rendered from ITS view of the task and stop when it can no longer see it.
CREATE TABLE IF NOT EXISTS crew_push_configs (
  id                TEXT    PRIMARY KEY,
  task_id           TEXT    NOT NULL REFERENCES crew_tasks(id) ON DELETE CASCADE,
  agent_id          INTEGER NOT NULL REFERENCES crew_agents(id) ON DELETE CASCADE,
  -- The agent token whose caller created the config. Deliveries continue only
  -- while that exact token is live: revoking or rotating it ends them (the
  -- token code deletes the agent's configs in the same transaction, and every
  -- delivery re-checks).
  token_id          INTEGER NOT NULL REFERENCES crew_agent_tokens(id) ON DELETE CASCADE,
  url               TEXT    NOT NULL CHECK (length(url) <= 2048),
  token_enc         TEXT,
  auth_scheme       TEXT    CHECK (auth_scheme IS NULL OR length(auth_scheme) <= 32),
  auth_credentials_enc TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  last_attempt_at   TEXT,
  last_status       TEXT,
  disabled_at       TEXT,
  created_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_crew_push_configs_task ON crew_push_configs(task_id);

-- SECURITY FIX (review of v2.105.0): a block or refusal was keyed only by the
-- agent's row id and cascaded away with the agent, so the blocked person could
-- remove their agent, register the same name again and get a fresh first
-- contact (and a fresh e-mail). When an agent is removed, every block and
-- refusal of it is kept here by (owner, name) and re-applied if that owner
-- registers the same name again. The decider is the person who blocked.
CREATE TABLE IF NOT EXISTS crew_decision_tombstones (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  decider_user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  agent_owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  agent_name       TEXT    NOT NULL,
  kind             TEXT    NOT NULL CHECK (kind IN ('block', 'refused')),
  created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (decider_user_id, agent_owner_id, agent_name, kind)
);
CREATE INDEX IF NOT EXISTS idx_crew_tombstones_owner ON crew_decision_tombstones(agent_owner_id, agent_name);

-- SECURITY FIX (review of v2.105.0): first-contact e-mail was capped per
-- connection, i.e. per (sending AGENT, receiving person), so a person could
-- register agent after agent and send one e-mail each. This records every
-- first-contact e-mail per (sending PERSON, receiving person) so the cap
-- survives agents being removed; at most one per pair per 24 hours.
CREATE TABLE IF NOT EXISTS crew_first_contact_emails (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  from_owner_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sent_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_crew_fce_pair ON crew_first_contact_emails(from_owner_id, to_owner_id, sent_at);
