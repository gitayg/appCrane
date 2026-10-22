-- RCE auto-patch (services/autoPatch/*): a written policy approves a dependency
-- bump that fixes a remote-code-execution advisory, in place of a person.
--
-- app_auto_patch: the per-app override of the platform setting
-- auto_approve_rce_fixes (default on). opted_out = 1 keeps the app on the human
-- flow. set_by_role records who opted out, because an app a platform admin
-- opted out can only be opted back in by a platform admin.
CREATE TABLE IF NOT EXISTS app_auto_patch (
  app_id       INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  opted_out    INTEGER NOT NULL DEFAULT 0 CHECK (opted_out IN (0, 1)),
  set_by       INTEGER,
  set_by_role  TEXT CHECK (set_by_role IN ('owner', 'platform_admin')),
  reason       TEXT,
  updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- auto_patch_runs: one row per vulnerability request the policy looked at.
--   running      in progress (at most one per app, enforced below)
--   ineligible   not an RCE advisory, or withdrawn: the human flow, silently
--   deferred     a guardrail that time can satisfy (cooldown); retried later
--   fallback     a guardrail failed: back to the human flow, with the reason
--   applied      shipped to production and healthy
--   rolled_back  production failed its health check and was rolled back
CREATE TABLE IF NOT EXISTS auto_patch_runs (
  id                        INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id                    INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  request_id                INTEGER,
  advisory_id               TEXT NOT NULL,
  ecosystem                 TEXT NOT NULL,
  package                   TEXT NOT NULL,
  from_version              TEXT,
  to_version                TEXT,
  status                    TEXT NOT NULL CHECK (status IN ('running', 'ineligible', 'deferred', 'fallback', 'applied', 'rolled_back')),
  reason                    TEXT,
  classification_json       TEXT,
  commit_sha                TEXT,
  sandbox_deployment_id     INTEGER,
  production_deployment_id  INTEGER,
  release_check_id          INTEGER,
  started_at                TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at               TEXT,
  retry_after               TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_auto_patch_one_running
  ON auto_patch_runs(app_id) WHERE status = 'running';
CREATE UNIQUE INDEX IF NOT EXISTS idx_auto_patch_request
  ON auto_patch_runs(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auto_patch_app ON auto_patch_runs(app_id, id);
