-- Crew: every Crane-hosted app gets a Crew agent "<slug>-coder" that other
-- agents can send tasks to; AppCrane runs the app's coder session on them.
-- Rules live in server/services/crewAppCoder*.js; this file is only the shape.
--
-- crew_agents.app_id marks the row as an app coder, run by AppCrane rather than
-- by an agent of its owner. The roster shows it as runs_as 'app-coder'; the
-- stored kind stays 'hosted', so the kind CHECK does not need widening (a
-- CHECK change on crew_agents would be a table rebuild under every table
-- whose foreign keys cascade from it).
--
-- No FOREIGN KEY to apps, for the reason 097 gives: apps is rebuilt by DROP +
-- RENAME (086 / 088 / 090), which a reference would break. App deletion removes
-- the row explicitly (services/appDelete.js), and the identity sync removes any
-- row whose app is gone.
ALTER TABLE crew_agents ADD COLUMN app_id INTEGER;
CREATE UNIQUE INDEX IF NOT EXISTS idx_crew_agents_app ON crew_agents(app_id) WHERE app_id IS NOT NULL;

-- Per task to an app coder:
--   coder_status        NULL = no coder turn yet, 'running' = a turn is running
--                       for it now, 'idle' = a turn ran and the task waits (an
--                       answer, a question to a person, or nothing more to do)
--   coder_seen_msg_id   the newest crew_messages.id already given to the coder,
--                       so a follow-up turn carries only what came after it
--   coder_session_id    the coder session the last turn ran in
--   coder_billed_user_id the person whose credential the last turn used: the
--                       app coder's owner, who approved the task
ALTER TABLE crew_tasks ADD COLUMN coder_status TEXT CHECK (coder_status IS NULL OR coder_status IN ('running', 'idle'));
ALTER TABLE crew_tasks ADD COLUMN coder_seen_msg_id INTEGER;
ALTER TABLE crew_tasks ADD COLUMN coder_session_id TEXT;
ALTER TABLE crew_tasks ADD COLUMN coder_billed_user_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_crew_tasks_coder_running ON crew_tasks(to_agent_id) WHERE coder_status = 'running';

-- First contact with an app coder is decided per app coder, not per person: a
-- person's Allow for their own agents must not let a sender start billed coder
-- sessions on their apps, and allowing one app's coder must not open another's.
-- crew_connections.to_agent_id is NULL for the person-level connection (as
-- before) and names the app coder for an app-coder connection. The table-level
-- UNIQUE (from_agent_id, to_owner_id) cannot be dropped in place, so the table
-- is rebuilt with an expression index instead. Nothing references
-- crew_connections, so the rebuild needs no foreign_keys change and runs in
-- the migration's transaction. Columns as of 112 (no later migration alters it).
CREATE TABLE crew_connections_new (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  from_agent_id  INTEGER NOT NULL REFERENCES crew_agents(id) ON DELETE CASCADE,
  from_owner_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  state          TEXT    NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'allowed', 'refused')),
  -- Set once, when the single first-contact e-mail is queued. Never cleared:
  -- it is what makes "exactly one e-mail per connection" hold across restarts.
  notified_at    TEXT,
  decided_at     TEXT,
  created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
  to_agent_id    INTEGER REFERENCES crew_agents(id) ON DELETE CASCADE
);
INSERT INTO crew_connections_new (id, from_agent_id, from_owner_id, to_owner_id, state, notified_at, decided_at, created_at)
  SELECT id, from_agent_id, from_owner_id, to_owner_id, state, notified_at, decided_at, created_at FROM crew_connections;
DROP TABLE crew_connections;
ALTER TABLE crew_connections_new RENAME TO crew_connections;
CREATE UNIQUE INDEX IF NOT EXISTS idx_crew_connections_key ON crew_connections(from_agent_id, to_owner_id, COALESCE(to_agent_id, 0));
CREATE INDEX IF NOT EXISTS idx_crew_connections_to ON crew_connections(to_owner_id, state);
CREATE INDEX IF NOT EXISTS idx_crew_connections_from_owner ON crew_connections(from_owner_id, state);
