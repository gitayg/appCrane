CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  event      TEXT,
  delivery_id TEXT,
  payload_hash TEXT,
  branch     TEXT,
  commit_hash TEXT,
  result     TEXT NOT NULL DEFAULT 'ok',
  triggered  TEXT
);
CREATE INDEX IF NOT EXISTS idx_wdel_app ON webhook_deliveries(app_id, id DESC);
