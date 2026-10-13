-- Crew, phase 3: people in the loop. Standing rules, decisions on tasks that
-- need a person (A2A INPUT_REQUIRED), and messages written by a person.
-- Rules live in server/services/crewRules.js and crew.js; this file is only
-- the shape.

-- What a task says it will do and where, declared by the sender (MCP args
-- `action` / `scope`, A2A message.metadata.action / .scope). Both are needed
-- for a standing rule to match; a task that declares neither never matches
-- one. rule_id is the rule that pre-approved the task when it was sent (kept
-- as text, not a foreign key: a revoked-and-purged rule must not take its
-- tasks' history with it).
ALTER TABLE crew_tasks ADD COLUMN action TEXT CHECK (action IS NULL OR length(action) <= 40);
ALTER TABLE crew_tasks ADD COLUMN scope  TEXT CHECK (scope IS NULL OR length(scope) <= 60);
ALTER TABLE crew_tasks ADD COLUMN rule_id TEXT;
-- 1 when a PERSON declined the task (a decision), as opposed to a block or a
-- refused first contact. A declined task stays visible to the receiving agent
-- (it asked, it needs the answer); a gate rejection stays silent and hidden.
ALTER TABLE crew_tasks ADD COLUMN declined INTEGER NOT NULL DEFAULT 0 CHECK (declined IN (0, 1));

-- A person's answer on a task is stored as a message so the agent reads it
-- where it reads everything else. actor_kind tells it apart from the agent's
-- own words (A2A role user; never counted against an agent's message budget).
-- from_agent_id stays the agent on the person's side of the task (NOT NULL in
-- migration 112), from_user_id is the person.
ALTER TABLE crew_messages ADD COLUMN actor_kind TEXT NOT NULL DEFAULT 'agent' CHECK (actor_kind IN ('agent', 'human'));
ALTER TABLE crew_messages ADD COLUMN from_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;

-- A standing rule: "agent X may do <action> on <scope> without asking me".
-- Owned by the person it saves from asking. Exact match on all three, never a
-- pattern. Revoked rows are kept (revoked_at) so a task that ran under a rule
-- can still say which one. The id is opaque (crypto.randomBytes base64url).
CREATE TABLE IF NOT EXISTS crew_rules (
  id                TEXT    PRIMARY KEY,
  owner_user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  agent_id          INTEGER NOT NULL REFERENCES crew_agents(id) ON DELETE CASCADE,
  action            TEXT    NOT NULL CHECK (length(action) BETWEEN 1 AND 40),
  scope             TEXT    NOT NULL CHECK (length(scope) BETWEEN 1 AND 60),
  expires_at        TEXT,
  -- The decision it was created from ("Approve and always allow"), or NULL
  -- for a rule added by hand on Rules & blocks.
  from_decision_id  TEXT,
  use_count         INTEGER NOT NULL DEFAULT 0,
  last_used_at      TEXT,
  created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
  revoked_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_crew_rules_match ON crew_rules(owner_user_id, agent_id, action, scope);
-- One live rule per (person, agent, action, scope): a second "always allow"
-- for the same thing is the same rule.
CREATE UNIQUE INDEX IF NOT EXISTS idx_crew_rules_live ON crew_rules(owner_user_id, agent_id, action, scope) WHERE revoked_at IS NULL;

-- A question routed to ONE person. status:
--   pending   waiting for decider_user_id (and only them)
--   approved  / replied / declined   the person decided
--   by_rule   a standing rule answered it (rule_id), nobody was asked
--   closed    the task moved on without a decision (a newer question, the
--             agent resumed on its own, the task ended)
-- subject_agent_id is the "who" a rule created from this decision names.
CREATE TABLE IF NOT EXISTS crew_decisions (
  id                 TEXT    PRIMARY KEY,
  task_id            TEXT    NOT NULL REFERENCES crew_tasks(id) ON DELETE CASCADE,
  asked_by_agent_id  INTEGER NOT NULL REFERENCES crew_agents(id) ON DELETE CASCADE,
  subject_agent_id   INTEGER NOT NULL REFERENCES crew_agents(id) ON DELETE CASCADE,
  decider_user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- 'sender_owner' | 'my_owner' as the asking agent addressed it; 'declared'
  -- when the sender declared an action at send time and the receiving person
  -- is asked before their agent starts.
  ask                TEXT    NOT NULL CHECK (ask IN ('sender_owner', 'my_owner', 'declared')),
  action             TEXT,
  scope              TEXT,
  -- 'production' | 'deletion' when this can never be covered by a rule.
  always_ask         TEXT,
  status             TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'replied', 'declined', 'by_rule', 'closed')),
  rule_id            TEXT,
  created_rule_id    TEXT,
  created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
  decided_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_crew_decisions_decider ON crew_decisions(decider_user_id, status);
CREATE INDEX IF NOT EXISTS idx_crew_decisions_task ON crew_decisions(task_id, status);
