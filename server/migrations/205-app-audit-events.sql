-- App audit events (services/appAudit/*): a hosted app's server writes its own
-- structured audit events (action, actor, targets, context, metadata) with its
-- APPCRANE_SERVICE_TOKEN. They live in their own table, never in audit_log or
-- events, so an app can never write a row that reads as a platform event.
--
-- No foreign key to apps: an app's audit history outlives the app (app_slug
-- keeps its name), like events. Rows are never updated; retention deletes
-- them by created_at (the time AppCrane received them, not the time the app
-- claims in occurred_at).
--
-- actor_verified: 1 when AppCrane vouches for the actor (the app itself, or a
-- user named by a signed identity the app forwarded), 0 when the actor is
-- only what the app reported.
CREATE TABLE IF NOT EXISTS app_audit_events (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id          INTEGER NOT NULL,
  app_slug        TEXT    NOT NULL,
  action          TEXT    NOT NULL,
  occurred_at     TEXT    NOT NULL,
  actor_type      TEXT    NOT NULL,
  actor_id        TEXT    NOT NULL,
  actor_name      TEXT,
  actor_verified  INTEGER NOT NULL DEFAULT 0,
  identity_env    TEXT,
  targets         TEXT    NOT NULL DEFAULT '[]',
  context         TEXT    NOT NULL DEFAULT '{}',
  metadata        TEXT,
  idempotency_key TEXT,
  payload_hash    TEXT    NOT NULL,
  unregistered    INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_app_audit_events_app ON app_audit_events(app_id, id);
CREATE INDEX IF NOT EXISTS idx_app_audit_events_app_action ON app_audit_events(app_id, action, id);
CREATE INDEX IF NOT EXISTS idx_app_audit_events_created ON app_audit_events(created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_audit_events_idem
  ON app_audit_events(app_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS app_audit_events_append_only
BEFORE UPDATE ON app_audit_events
BEGIN
  SELECT RAISE(ABORT, 'app audit events are append-only');
END;

-- The hash chain over app_audit_events, sealed by services/auditChain.js
-- exactly like audit_chain (same link rule, same signed checkpoints in
-- audit_chain_checkpoints with src 'app_audit_events'). A table of its own
-- because audit_chain.src is CHECKed to its two sources and widening a CHECK
-- means rebuilding a large append-only table. meta = [created_at, 'app_audit']
-- so a row removed by the signed retention window is told apart from a row
-- deleted by hand.
CREATE TABLE IF NOT EXISTS app_audit_chain (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  src        TEXT    NOT NULL CHECK (src = 'app_audit_events'),
  row_id     INTEGER NOT NULL,
  row_hash   TEXT    NOT NULL,
  alt_hash   TEXT,
  meta       TEXT,
  chain_hash TEXT    NOT NULL,
  sealed_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (src, row_id)
);

CREATE TRIGGER IF NOT EXISTS app_audit_chain_append_only
BEFORE UPDATE ON app_audit_chain
BEGIN
  SELECT RAISE(ABORT, 'app_audit_chain is append-only');
END;

-- The actions an app's owner registered. An event whose action is not listed
-- is refused, unless the app opted in to accepting it with unregistered = 1.
CREATE TABLE IF NOT EXISTS app_audit_event_types (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id      INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  action      TEXT    NOT NULL,
  description TEXT,
  created_by  INTEGER,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (app_id, action)
);

CREATE TABLE IF NOT EXISTS app_audit_settings (
  app_id             INTEGER PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
  allow_unregistered INTEGER NOT NULL DEFAULT 0,
  updated_by         INTEGER,
  updated_at         TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Owner-managed SIEM / log streams, each scoped to ONE app's audit events.
-- Same sink shape as siem_sinks (the same validator and senders), with the
-- cursor over app_audit_events.id instead of events.id. filter_actions: JSON
-- array of action names or prefixes (NULL = every action).
CREATE TABLE IF NOT EXISTS app_audit_streams (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id               INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  name                 TEXT    NOT NULL,
  type                 TEXT    NOT NULL CHECK (type IN ('syslog', 'https', 's3')),
  preset               TEXT    NOT NULL DEFAULT 'generic',
  format               TEXT    NOT NULL DEFAULT 'json' CHECK (format IN ('json', 'cef')),
  enabled              INTEGER NOT NULL DEFAULT 1,
  config               TEXT    NOT NULL DEFAULT '{}',
  secrets_enc          TEXT,
  ca_pem               TEXT,
  tls_skip_verify      INTEGER NOT NULL DEFAULT 0,
  filter_actions       TEXT,
  cursor_event_id      INTEGER NOT NULL DEFAULT 0,
  delivered_count      INTEGER NOT NULL DEFAULT 0,
  last_success_at      TEXT,
  last_attempt_at      TEXT,
  last_error           TEXT,
  last_error_at        TEXT,
  failing_since        TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  created_by           INTEGER,
  created_at           TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_app_audit_streams_app ON app_audit_streams(app_id);
