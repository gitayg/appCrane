-- v2.3.4: per-user, per-app "last seen version" tracker for the
-- What's New dialog.
--
-- When a user opens an app and the live production version is newer than
-- the last one they acknowledged, AppCrane shows them the deployments
-- (version + commit_message + finished_at) that landed since the last
-- time they were here. On dismiss, the row updates to the current live
-- version so the same dialog doesn't fire on the next open.
--
-- First-ever visit = no row → no dialog (we silently record the current
-- version on first GET so they don't get a wall of historic changes for
-- an app that's been live for months).

CREATE TABLE IF NOT EXISTS user_app_seen (
  user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_id            INTEGER NOT NULL REFERENCES apps(id)  ON DELETE CASCADE,
  last_seen_version TEXT,
  last_seen_at      TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, app_id)
);

CREATE INDEX IF NOT EXISTS idx_user_app_seen_user ON user_app_seen(user_id);
