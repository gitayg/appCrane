-- Background job health (Settings > Job Health).
--
-- One row per recorded run of a background job, kept to the last few per job
-- by services/jobHealth.js, which deletes older rows on every insert.
CREATE TABLE IF NOT EXISTS job_runs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  job         TEXT    NOT NULL,
  started_at  TEXT    NOT NULL,
  finished_at TEXT    NOT NULL,
  ok          INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_job_runs_job ON job_runs(job, id);

-- Job-health alerts are platform mail (app_id NULL), which idx_email_queue_idem
-- cannot dedupe; this makes the per-job, per-status, per-day key unique.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_job_health
  ON email_queue(idempotency_key) WHERE source = 'job-health' AND idempotency_key IS NOT NULL;
