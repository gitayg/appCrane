-- Crew, phase 1 (v2.105.0): a platform-wide hub where agents register, find
-- each other and hand off tasks, with the people who own them in the loop.
-- Rules live in server/services/crew.js; this file is only the shape.
--
-- Everything hangs off a PERSON (users.id). An agent is never an identity of
-- its own here: it acts only through its owner's MCP key, so it can never do
-- more than its owner may. ON DELETE CASCADE from users removes a person's
-- agents, connections, blocks and (through the agents) their tasks — a person
-- who left the platform must not leave agents answering on their behalf.

CREATE TABLE IF NOT EXISTS crew_agents (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  -- Lowercase slug, unique platform-wide: agents address each other by name,
  -- so two "qa-runner"s would make every send ambiguous.
  name           TEXT    NOT NULL UNIQUE CHECK (name = lower(name) AND length(name) BETWEEN 2 AND 40),
  owner_user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- 'mcp'    = a local agent (Claude Code, Cursor) that registered itself over MCP
  -- 'hosted' = registered by its owner from the dashboard form
  kind           TEXT    NOT NULL CHECK (kind IN ('mcp', 'hosted')),
  -- A2A Agent Card subset: { name, description, skills: [{id, description}], capabilities }
  card_json      TEXT    NOT NULL DEFAULT '{}',
  knows_about    TEXT,
  status         TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  last_seen_at   TEXT,
  created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_crew_agents_owner ON crew_agents(owner_user_id);

-- First contact. Keyed per (sending AGENT, receiving PERSON): the trust
-- decision is about one specific agent (a person can own a careful agent and a
-- scraper), and the decision-maker is the person, so one e-mail per person no
-- matter how many of their agents the sender addresses. from_owner_id is
-- denormalised for the per-owner pending cap and for display.
CREATE TABLE IF NOT EXISTS crew_connections (
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
  UNIQUE (from_agent_id, to_owner_id)
);
CREATE INDEX IF NOT EXISTS idx_crew_connections_to ON crew_connections(to_owner_id, state);
CREATE INDEX IF NOT EXISTS idx_crew_connections_from_owner ON crew_connections(from_owner_id, state);

-- A person refusing one agent outright. Checked BEFORE the connection, so a
-- block wins over an earlier Allow.
CREATE TABLE IF NOT EXISTS crew_blocks (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_agent_id INTEGER NOT NULL REFERENCES crew_agents(id) ON DELETE CASCADE,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (owner_user_id, blocked_agent_id)
);

-- A task. id is an opaque random handle (crypto.randomBytes(16) base64url),
-- never a sequential integer: task ids travel between agents of different
-- people, and a guessable id invites probing other people's tasks.
-- state uses the A2A names. held = 1 means "submitted, waiting on the
-- receiving person's first-contact decision": the receiver's agents cannot see
-- it yet. Phase 3 (standing rules, INPUT_REQUIRED approvals) adds columns
-- here; nothing in phase 1 depends on the absence of more states.
CREATE TABLE IF NOT EXISTS crew_tasks (
  id            TEXT    PRIMARY KEY,
  from_agent_id INTEGER NOT NULL REFERENCES crew_agents(id) ON DELETE CASCADE,
  to_agent_id   INTEGER NOT NULL REFERENCES crew_agents(id) ON DELETE CASCADE,
  title         TEXT    NOT NULL,
  state         TEXT    NOT NULL CHECK (state IN ('submitted', 'working', 'input_required', 'completed', 'failed', 'canceled', 'rejected')),
  held          INTEGER NOT NULL DEFAULT 0 CHECK (held IN (0, 1)),
  created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_crew_tasks_to ON crew_tasks(to_agent_id, state);
CREATE INDEX IF NOT EXISTS idx_crew_tasks_from ON crew_tasks(from_agent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_crew_tasks_updated ON crew_tasks(updated_at);

CREATE TABLE IF NOT EXISTS crew_messages (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id        TEXT    NOT NULL REFERENCES crew_tasks(id) ON DELETE CASCADE,
  from_agent_id  INTEGER NOT NULL REFERENCES crew_agents(id) ON DELETE CASCADE,
  body           TEXT    NOT NULL CHECK (length(body) <= 16384),
  artifact_name  TEXT    CHECK (artifact_name IS NULL OR length(artifact_name) <= 200),
  artifact_body  TEXT    CHECK (artifact_body IS NULL OR length(artifact_body) <= 65536),
  created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_crew_messages_task ON crew_messages(task_id, id);
CREATE INDEX IF NOT EXISTS idx_crew_messages_from ON crew_messages(from_agent_id, created_at);
