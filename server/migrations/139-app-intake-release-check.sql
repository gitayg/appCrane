-- App intake, data classification and the release check before production
-- (services/appIntake.js, dataClassification.js, releaseCheck.js).
--
-- app_intake: one row per app. The classification lives here rather than in a
-- new apps column so a later apps-table rebuild cannot drop it.
-- Apps that exist at upgrade are grandfathered: approved, classified
-- 'internal', grandfathered = 1. An app with no row (created by a path that
-- does not submit intake) reads as 'internal' with no intake.
CREATE TABLE IF NOT EXISTS app_intake (
  app_id                INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  data_classification   TEXT NOT NULL DEFAULT 'internal'
                        CHECK (data_classification IN ('public', 'internal', 'confidential', 'restricted')),
  classification_locked INTEGER NOT NULL DEFAULT 0,
  purpose               TEXT,
  personal_data         INTEGER NOT NULL DEFAULT 0,
  external_integrations TEXT,
  access_notes          TEXT,
  answers_json          TEXT,
  status                TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'rejected')),
  grandfathered         INTEGER NOT NULL DEFAULT 0,
  submitted_by          INTEGER,
  submitted_at          TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_by           INTEGER,
  reviewed_at           TEXT,
  review_comment        TEXT,
  updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_app_intake_status ON app_intake (status);

INSERT OR IGNORE INTO app_intake (app_id, data_classification, status, grandfathered, reviewed_at, review_comment)
  SELECT id, 'internal', 'approved', 1, datetime('now'), 'Grandfathered at upgrade' FROM apps;

-- One row per release check run: a promote, a production deploy request, or
-- the in-deploy check of the tree actually being shipped.
CREATE TABLE IF NOT EXISTS release_checks (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id               INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env                  TEXT NOT NULL DEFAULT 'production',
  deployment_id        INTEGER,
  trigger              TEXT NOT NULL,
  candidate            TEXT,
  data_classification  TEXT NOT NULL,
  mode                 TEXT NOT NULL CHECK (mode IN ('enforce', 'warn', 'off')),
  result               TEXT NOT NULL CHECK (result IN ('pass', 'warn', 'fail', 'skipped')),
  blocked              INTEGER NOT NULL DEFAULT 0,
  checks_json          TEXT NOT NULL,
  created_by           INTEGER,
  created_at           TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_release_checks_app_time ON release_checks (app_id, created_at);

-- An accepted risk on one check of one app, with a reason and an expiry.
CREATE TABLE IF NOT EXISTS release_check_exceptions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  check_id   TEXT NOT NULL,
  reason     TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  revoked_by INTEGER
);
CREATE INDEX IF NOT EXISTS idx_release_check_exceptions_app ON release_check_exceptions (app_id, check_id);
