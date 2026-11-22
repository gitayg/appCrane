-- Widget tokens: the short-lived credential the drop-in widgets
-- (/__appcrane/widgets.js) use on an app's own host.
--
-- Issued from that host's app-session cookie (scope 'app', migration 155) to
-- the page's script, sent back as `Authorization: Bearer cwt_...`, and good
-- only for the /__appcrane/widgets/api/* endpoints of the SAME app and
-- environment. Stored hashed. It never outlives the app session it came from:
-- every use joins the parent row, so signing out, revoking that session or the
-- platform session above it ends the token with no separate step.
CREATE TABLE IF NOT EXISTS widget_tokens (
  token_hash        TEXT PRIMARY KEY,
  user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_id            INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  app_env           TEXT NOT NULL CHECK (app_env IN ('sandbox', 'production')),
  parent_token_hash TEXT NOT NULL,
  scopes            TEXT NOT NULL,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_widget_tokens_parent ON widget_tokens(parent_token_hash);
CREATE INDEX IF NOT EXISTS idx_widget_tokens_expires ON widget_tokens(expires_at);
