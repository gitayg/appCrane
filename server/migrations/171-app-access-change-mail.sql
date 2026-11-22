-- Every change to a person's app access, captured at the database so the many
-- code paths that write app_user_roles (the dashboard, MCP tools, SCIM groups,
-- access reviews, the owner backfill, app and user deletion) are all covered
-- without each one remembering to say so. services/appAccessMail.js reads these
-- rows, waits for a quiet period, and e-mails the person when their access
-- really changed.
--
-- No foreign keys on purpose: a row must outlive the app or user it names, so
-- the worker can see a deletion and decide to send nothing.
-- A stored app_role 'none' counts as no access, the same as no row.

CREATE TABLE IF NOT EXISTS app_access_changes (
  id           INTEGER PRIMARY KEY,
  app_id       INTEGER NOT NULL,
  user_id      INTEGER NOT NULL,
  old_role     TEXT,
  new_role     TEXT,
  created_at   TEXT DEFAULT (datetime('now')),
  processed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_app_access_changes_processed ON app_access_changes(processed_at);

CREATE TRIGGER IF NOT EXISTS trg_app_user_roles_access_insert
AFTER INSERT ON app_user_roles
BEGIN
  INSERT INTO app_access_changes (app_id, user_id, old_role, new_role)
  VALUES (NEW.app_id, NEW.user_id, 'none', NEW.app_role);
END;

CREATE TRIGGER IF NOT EXISTS trg_app_user_roles_access_update
AFTER UPDATE OF app_role ON app_user_roles
WHEN OLD.app_role IS NOT NEW.app_role
BEGIN
  INSERT INTO app_access_changes (app_id, user_id, old_role, new_role)
  VALUES (NEW.app_id, NEW.user_id, OLD.app_role, NEW.app_role);
END;

CREATE TRIGGER IF NOT EXISTS trg_app_user_roles_access_delete
AFTER DELETE ON app_user_roles
BEGIN
  INSERT INTO app_access_changes (app_id, user_id, old_role, new_role)
  VALUES (OLD.app_id, OLD.user_id, OLD.app_role, 'none');
END;

-- Platform mail (app_id NULL), which idx_email_queue_idem cannot dedupe: the
-- key names the change rows a mail covers, so a retried tick adds no second mail.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_app_access_change
  ON email_queue(idempotency_key) WHERE source = 'app-access-change' AND idempotency_key IS NOT NULL;
