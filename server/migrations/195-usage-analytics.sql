-- Usage analytics (services/usageAnalytics.js, routes/usage.js).
--
-- env_activity_users.requests: requests per user per day, so the top-users
-- table can rank by requests and not only by active days. Rows written before
-- this column existed read 0.
-- app_usage_settings.aggregates_only: 1 hides the per-user table from every
-- reader of the app's usage, platform admins included; counts stay.
ALTER TABLE env_activity_users ADD COLUMN requests INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS app_usage_settings (
  app_id INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  aggregates_only INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT,
  updated_by INTEGER
);
