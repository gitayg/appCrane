-- v2.13.0: per-platform-admin "last seen AppCrane version" so the dashboard can
-- show a What's New dialog post-login when AppCrane itself has been updated.
CREATE TABLE IF NOT EXISTS platform_whats_new_seen (
  user_id           INTEGER PRIMARY KEY,
  last_seen_version TEXT,
  last_seen_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
