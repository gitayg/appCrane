-- Browser errors reported by the admin SPA and the topbar bundle
-- (POST /api/client-errors). One row per distinct error, keyed by a hash of the
-- message and the top stack frame, so a crash loop is one row with a count
-- rather than thousands of rows. Rows not seen for 30 days are pruned by
-- services/clientErrors.js, which also caps the table size.
CREATE TABLE IF NOT EXISTS client_errors (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint  TEXT    NOT NULL UNIQUE,
  message      TEXT    NOT NULL,
  stack        TEXT,
  source       TEXT    NOT NULL DEFAULT 'admin',
  count        INTEGER NOT NULL DEFAULT 1,
  first_seen   TEXT    NOT NULL DEFAULT (datetime('now')),
  last_seen    TEXT    NOT NULL DEFAULT (datetime('now')),
  last_page    TEXT,
  pages        TEXT    NOT NULL DEFAULT '[]',
  versions     TEXT    NOT NULL DEFAULT '[]',
  user_agent   TEXT,
  last_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  app_slug     TEXT
);
CREATE INDEX IF NOT EXISTS idx_client_errors_last_seen ON client_errors(last_seen);
