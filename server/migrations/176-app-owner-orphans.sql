-- Every app has a named owner. An app is orphaned when no active user holds
-- app_role 'owner' on it: an owner row whose user is deactivated or deleted
-- counts as none. services/appOwnership.js records each
-- orphaning here (once, with its cause), e-mails platform admins and the app's
-- remaining admins, and resolves the row when an owner exists again.
--
-- No foreign key to apps on purpose: the history must outlive the app, the
-- same reasoning as app_access_changes (migration 171).

CREATE TABLE IF NOT EXISTS app_owner_orphans (
  id            INTEGER PRIMARY KEY,
  app_id        INTEGER NOT NULL,
  orphaned_at   TEXT NOT NULL DEFAULT (datetime('now')),
  cause         TEXT NOT NULL,
  detail        TEXT,
  notified_at   TEXT,
  notify_note   TEXT,
  resolved_at   TEXT,
  resolved_by   INTEGER,
  resolution    TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_owner_orphans_open
  ON app_owner_orphans(app_id) WHERE resolved_at IS NULL;

-- A nomination of a new owner. kind 'orphan' when the app had no owner,
-- 'handover' when an owner passes the app on. One pending per app.
CREATE TABLE IF NOT EXISTS app_owner_transfers (
  id              INTEGER PRIMARY KEY,
  app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  nominee_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nominated_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  kind            TEXT NOT NULL CHECK (kind IN ('orphan', 'handover')),
  step_down       INTEGER NOT NULL DEFAULT 0,
  note            TEXT,
  status          TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'accepted', 'declined', 'cancelled', 'superseded', 'expired')),
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at      TEXT NOT NULL DEFAULT (datetime('now', '+14 days')),
  decided_at      TEXT,
  decided_by      INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_owner_transfers_pending
  ON app_owner_transfers(app_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_app_owner_transfers_nominee
  ON app_owner_transfers(nominee_user_id, status);

-- Apps already without an owner when this ships are recorded, but not mailed:
-- one e-mail per such app to every platform admin on upgrade would be a flood.
-- They appear on the platform admins' orphaned-apps list.
INSERT INTO app_owner_orphans (app_id, cause, detail, notified_at, notify_note)
  SELECT a.id, 'present-at-upgrade', NULL, datetime('now'), 'not mailed: orphaned before owner tracking existed'
  FROM apps a
  WHERE NOT EXISTS (
    SELECT 1 FROM app_user_roles r JOIN users u ON u.id = r.user_id
    WHERE r.app_id = a.id AND r.app_role = 'owner' AND u.active = 1
  );

-- Platform mail (app_id NULL), which idx_email_queue_idem cannot dedupe.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_app_owner
  ON email_queue(idempotency_key) WHERE source = 'app-owner' AND idempotency_key IS NOT NULL;
