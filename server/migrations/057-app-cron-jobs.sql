-- v2.7.26: declarative scheduled jobs per app/env. Each row is one entry from
-- the `cron` array in an app's deployhub.json, synced into the DB at deploy
-- time by syncCronJobsFromManifest(). A host-side scheduler (cronScheduler.js)
-- ticks every minute, picks jobs whose `schedule` matches the wall clock, and
-- runs `command` via `docker exec` against the app's container — the right
-- side of "/data outlives the container; cron writes to /data."
--
-- Jobs are namespaced per (app_id, env, name) so prod and sandbox can have
-- different commands (or one env can disable a job). last_run_* columns
-- record the most recent invocation; the full job history would be a
-- different table if/when we add a UI for it.

CREATE TABLE IF NOT EXISTS app_cron_jobs (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id          INTEGER NOT NULL,
  env             TEXT    NOT NULL CHECK (env IN ('sandbox', 'production')),
  name            TEXT    NOT NULL,
  schedule        TEXT    NOT NULL,
  command         TEXT    NOT NULL,
  enabled         INTEGER NOT NULL DEFAULT 1,
  timeout_seconds INTEGER NOT NULL DEFAULT 600,
  last_run_at     TEXT,
  last_exit_code  INTEGER,
  last_log        TEXT,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(app_id, env, name),
  FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_cron_jobs_lookup ON app_cron_jobs(app_id, env, enabled);
