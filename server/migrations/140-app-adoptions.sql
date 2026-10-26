-- Adopt an app (services/adopt/*): one row per analysed project.
--
-- Analyse and adopt are two requests, so the analysed archive is kept between
-- them under DATA_DIR/adopt/<id>.zip (mode 0600) and checked against
-- source_sha256 before it is imported. id is an opaque random handle, and only
-- the user who analysed a project (or a platform admin) can read or adopt it.
-- report_json never holds a secret value: env values found in an upload are
-- recorded as "a value was found" and read again from the archive at adopt.

CREATE TABLE IF NOT EXISTS app_adoptions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('github', 'zip')),
  source_label TEXT,
  source_sha256 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'analyzed' CHECK (status IN ('analyzed', 'adopting', 'adopted', 'failed')),
  report_json TEXT NOT NULL,
  app_id INTEGER,
  error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  adopted_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_app_adoptions_user ON app_adoptions(user_id, created_at);
