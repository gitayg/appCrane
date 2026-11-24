-- Restart incidents (services/restartIncidents.js): one row each time an app
-- container is restarted, stopped or found dead, whoever did it, with what was
-- captured just before (cgroup memory, the container's exit state, the last log
-- lines, scrubbed). trigger says who: the health checker, Docker's own restart
-- policy after a crash or an OOM kill, container recovery, or a planned action
-- (manual restart, deploy, sleep, restore, a stop outside AppCrane), or
-- restart_refused when image trust in enforce mode refused the health
-- checker's restart (the container was left as it was). action says
-- what happened: restarted, skipped (restart-loop backoff), observed (Docker
-- did it), recovered / failed (container recovery). Anything that could not be
-- captured is listed in not_captured with the reason.
CREATE TABLE IF NOT EXISTS restart_incidents (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env             TEXT    NOT NULL CHECK (env IN ('production', 'sandbox')),
  trigger         TEXT    NOT NULL CHECK (trigger IN ('health', 'crash', 'oom', 'recovery', 'manual', 'deploy', 'sleep', 'restore', 'stop', 'restart_refused')),
  action          TEXT    NOT NULL CHECK (action IN ('restarted', 'skipped', 'observed', 'recovered', 'failed')),
  kind            TEXT    NOT NULL,
  summary         TEXT    NOT NULL,
  detail          TEXT,
  memory_current  INTEGER,
  memory_max      INTEGER,
  memory_source   TEXT,
  oom_kill_events INTEGER,
  exit_state      TEXT,
  log_tail        TEXT,
  not_captured    TEXT,
  container_id    TEXT,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_restart_incidents_app_env ON restart_incidents (app_id, env, created_at);
CREATE INDEX IF NOT EXISTS idx_restart_incidents_created ON restart_incidents (created_at);

-- Restart-loop state per app environment. unstable = 1 while a loop rule is
-- tripped: the health checker then restarts only after next_restart_at, which
-- doubles with each restart (backoff_level). episode counts loops, so the owner
-- mail goes out once per episode. Cleared by a deploy, a manual restart, or a
-- quiet period with the env healthy (cleared_reason says which).
CREATE TABLE IF NOT EXISTS restart_stability (
  app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env             TEXT    NOT NULL CHECK (env IN ('production', 'sandbox')),
  unstable        INTEGER NOT NULL DEFAULT 0,
  unstable_since  TEXT,
  episode         INTEGER NOT NULL DEFAULT 0,
  tripped_rule    TEXT,
  backoff_level   INTEGER NOT NULL DEFAULT 0,
  next_restart_at TEXT,
  last_incident_id INTEGER,
  cleared_at      TEXT,
  cleared_reason  TEXT,
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (app_id, env)
);
