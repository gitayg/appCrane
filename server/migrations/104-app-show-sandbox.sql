-- Per-app "Show Sandbox to users".
--
-- When off, members and viewers are no longer offered the Sandbox deployment
-- on the launch surfaces (launcher tiles, the app frame's env switch, the
-- Applications page links). Visibility only: sandbox still deploys, and
-- /<slug>-sandbox still routes for anyone with access.
--
-- Its own table rather than an apps column, for the same reason as 103: an apps
-- column means a full apps rebuild (the schema guard in
-- test/app-catalog-slug.test.js). No row means shown, so every existing app
-- keeps today's behaviour without a backfill. The row goes with the app.
CREATE TABLE IF NOT EXISTS app_settings (
  app_id       INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  show_sandbox INTEGER NOT NULL DEFAULT 1 CHECK(show_sandbox IN (0, 1)),
  updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
