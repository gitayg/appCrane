-- migration:no-transaction
--
-- restart_incidents.trigger may be 'host-gateway-repair': the hourly
-- host-gateway check (services/hostGateway.js) recreated the container because
-- its /etc/hosts mapped host.docker.internal to an invalid address. A planned
-- restart, recorded by the repair itself (restartIncidents.js TRIGGERS).
--
-- The CHECK is part of the table, so the table is rebuilt, as in 169: no
-- writable_schema (better-sqlite3 runs defensive), foreign_keys OFF outside a
-- transaction, legacy_alter_table ON for the RENAME, the rebuild itself in its
-- own BEGIN/COMMIT. Columns are copied by name; the column list is 270's,
-- unchanged since. Nothing references restart_incidents by foreign key, trigger
-- or view (grep of server/migrations); its two indexes are recreated verbatim.

PRAGMA foreign_keys = OFF;
PRAGMA legacy_alter_table = ON;

BEGIN;

CREATE TABLE restart_incidents_new (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env             TEXT    NOT NULL CHECK (env IN ('production', 'sandbox')),
  trigger         TEXT    NOT NULL CHECK (trigger IN ('health', 'crash', 'oom', 'recovery', 'manual', 'deploy', 'sleep', 'restore', 'stop', 'restart_refused', 'host-gateway-repair')),
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

INSERT INTO restart_incidents_new (
  id, app_id, env, trigger, action, kind, summary, detail, memory_current, memory_max,
  memory_source, oom_kill_events, exit_state, log_tail, not_captured, container_id, created_at
)
SELECT
  id, app_id, env, trigger, action, kind, summary, detail, memory_current, memory_max,
  memory_source, oom_kill_events, exit_state, log_tail, not_captured, container_id, created_at
FROM restart_incidents;

DROP TABLE restart_incidents;
ALTER TABLE restart_incidents_new RENAME TO restart_incidents;

CREATE INDEX IF NOT EXISTS idx_restart_incidents_app_env ON restart_incidents (app_id, env, created_at);
CREATE INDEX IF NOT EXISTS idx_restart_incidents_created ON restart_incidents (created_at);

COMMIT;

PRAGMA legacy_alter_table = OFF;
PRAGMA foreign_keys = ON;
