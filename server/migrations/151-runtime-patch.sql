-- Runtime auto-patch (services/autoPatch/runtime*.js): rebuild an app on a
-- fresh base image when the runtime it runs (PHP today) is affected by a
-- remote-code-execution advisory, under the RCE auto-patch policy.
--
-- deployments.base_image / base_digest: the base the release's image was built
-- on (the final stage's FROM) and the digest it resolved to, read from the
-- labels docker.js writes on every image it builds. NULL for image deploys and
-- for releases built before these columns.
ALTER TABLE deployments ADD COLUMN base_image TEXT;
ALTER TABLE deployments ADD COLUMN base_digest TEXT;

-- runtime_patch_runs: one row per (app, advisory set, production image) the
-- policy acted on. Same statuses as auto_patch_runs.
CREATE TABLE IF NOT EXISTS runtime_patch_runs (
  id                        INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id                    INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  request_id                INTEGER,
  advisory_key              TEXT NOT NULL,
  runtime                   TEXT NOT NULL,
  from_version              TEXT,
  to_version                TEXT,
  fixed_version             TEXT,
  base_image                TEXT,
  from_digest               TEXT,
  to_digest                 TEXT,
  prod_image_id             TEXT NOT NULL,
  status                    TEXT NOT NULL CHECK (status IN ('running', 'ineligible', 'deferred', 'fallback', 'applied', 'rolled_back')),
  reason                    TEXT,
  commit_sha                TEXT,
  sandbox_deployment_id     INTEGER,
  production_deployment_id  INTEGER,
  release_check_id          INTEGER,
  started_at                TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at               TEXT,
  retry_after               TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_patch_one_running
  ON runtime_patch_runs(app_id) WHERE status = 'running';
CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_patch_once
  ON runtime_patch_runs(app_id, advisory_key, prod_image_id);
CREATE INDEX IF NOT EXISTS idx_runtime_patch_app ON runtime_patch_runs(app_id, id);

-- Platform admins are e-mailed once per advisory: the advisory id is recorded
-- here when the mail is queued, and the queue's key is unique for this source.
CREATE TABLE IF NOT EXISTS runtime_advisory_notices (
  advisory_id  TEXT PRIMARY KEY,
  notified_at  TEXT NOT NULL DEFAULT (datetime('now')),
  app_count    INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_runtime_advisory
  ON email_queue(idempotency_key) WHERE source = 'runtime-advisory' AND idempotency_key IS NOT NULL;
