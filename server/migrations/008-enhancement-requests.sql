CREATE TABLE IF NOT EXISTS enhancement_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_slug TEXT,
  user_id INTEGER,
  user_name TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
