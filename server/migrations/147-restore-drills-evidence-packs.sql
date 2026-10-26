-- Scheduled restore drills (services/restoreDrills.js) and compliance
-- evidence packs (services/evidencePack/*).
--
-- restore_drills: one row per backup source (local nightly archive, latest
-- verified off-site set) per drill run. A drill restores the backup into a
-- scratch directory under DATA_DIR/drills, checks it, and deletes it; the row
-- is the evidence: backup age at the start (RPO), restore + verify duration
-- (RTO) and the outcome of every check. Never a host path or a secret.
CREATE TABLE IF NOT EXISTS restore_drills (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id            TEXT    NOT NULL,
  source            TEXT    NOT NULL CHECK (source IN ('local', 's3')),
  trigger           TEXT    NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual')),
  status            TEXT    NOT NULL CHECK (status IN ('running', 'passed', 'failed', 'refused', 'skipped')),
  backup_ref        TEXT,
  backup_created_at TEXT,
  backup_bytes      INTEGER,
  rpo_seconds       INTEGER,
  rto_ms            INTEGER,
  checks_json       TEXT    NOT NULL DEFAULT '[]',
  error             TEXT,
  cleaned_up        INTEGER NOT NULL DEFAULT 0,
  triggered_by      INTEGER,
  started_at        TEXT    NOT NULL,
  finished_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_restore_drills_started ON restore_drills(started_at);
CREATE INDEX IF NOT EXISTS idx_restore_drills_run ON restore_drills(run_id);

-- A failed drill mails every platform admin once per day (platform mail,
-- app_id NULL, which idx_email_queue_idem cannot dedupe).
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_restore_drill
  ON email_queue(idempotency_key) WHERE source = 'restore-drill' AND idempotency_key IS NOT NULL;

-- evidence_packs: one row per generated compliance evidence pack. `token` is
-- the opaque public handle (never the row id); the archive lives under
-- DATA_DIR/evidence/packs.
CREATE TABLE IF NOT EXISTS evidence_packs (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  token           TEXT    NOT NULL UNIQUE,
  status          TEXT    NOT NULL CHECK (status IN ('running', 'ready', 'failed')),
  progress        INTEGER NOT NULL DEFAULT 0,
  step            TEXT,
  period_from     TEXT    NOT NULL,
  period_to       TEXT    NOT NULL,
  file_name       TEXT,
  bytes           INTEGER,
  sha256          TEXT,
  manifest_sha256 TEXT,
  degraded_json   TEXT,
  error           TEXT,
  requested_by    INTEGER,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  finished_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_evidence_packs_created ON evidence_packs(created_at);
