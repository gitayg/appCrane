-- Webhook receiver for this instance's GitHub App (POST /api/github-app/webhook).
--
-- New tables only; `apps` is not touched.
--
-- github_app_webhook_deliveries: replay / redelivery protection. GitHub says a
-- redelivered webhook keeps the original X-GitHub-Delivery value, and deliveries
-- can be redelivered from the past 3 days, so ids are remembered for 7 days and
-- a second arrival of the same id is answered 200 without acting again.
--
-- github_app_installation_state: an installation GitHub reported as uninstalled
-- or suspended. Apps attached to it are NOT detached -- detaching would put the
-- app back on its stored personal access token without anyone choosing that --
-- they are marked, and credential resolution fails with the reason.
--
-- github_app_removed_repos: repositories an installation_repositories 'removed'
-- event took out of an installation; same treatment, for those repos only.

CREATE TABLE IF NOT EXISTS github_app_webhook_deliveries (
  delivery_id TEXT    PRIMARY KEY,
  event       TEXT,
  action      TEXT,
  result      TEXT,
  received_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_github_app_webhook_deliveries_received
  ON github_app_webhook_deliveries (received_at);

CREATE TABLE IF NOT EXISTS github_app_installation_state (
  installation_id INTEGER PRIMARY KEY,
  status          TEXT    NOT NULL CHECK (status IN ('deleted', 'suspended')),
  changed_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS github_app_removed_repos (
  installation_id INTEGER NOT NULL,
  repo_full_name  TEXT    NOT NULL,   -- lower-cased 'owner/repo'
  removed_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (installation_id, repo_full_name)
);

-- When the admin last pointed GitHub at this receiver (PATCH /app/hook/config),
-- and whether the App was registered with webhooks active.
ALTER TABLE github_app_config ADD COLUMN webhook_url TEXT;
ALTER TABLE github_app_config ADD COLUMN webhook_config_synced_at TEXT;
ALTER TABLE github_app_config ADD COLUMN webhook_active_at_creation INTEGER;
