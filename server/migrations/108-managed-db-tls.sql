-- Managed databases: TLS, per-app client certificates, and failed-login alerts.
--
-- client_cert_required: 1 once a login has been converted to "TLS + its own
-- client certificate + its password". Set by managedDb.secureLogin() for
-- logins whose database comes from the app's own deployhub.json (custom apps,
-- including their sandbox database). STICKY on purpose: nothing ever sets it
-- back to 0 automatically, so a restart that could not read the release's
-- manifest cannot quietly downgrade a login to password-only. Default 0 is the
-- catalogue behaviour (TLS offered, not required), which is what every
-- existing row had, so nothing is backfilled: existing manifest logins are
-- converted on their next deploy or restart.
-- No CHECK constraint, on purpose: migration 085 kept this table free of
-- CHECKs (SQLite cannot ALTER one, so any CHECK here forces a table rebuild
-- later) and test/managed-db-mongo.test.js asserts that. Only
-- managedDb.secureLogin() ever writes the value, and only ever 1.
ALTER TABLE managed_databases ADD COLUMN client_cert_required INTEGER NOT NULL DEFAULT 0;

-- AppCrane's private CA and every certificate it issued, by name:
--   'ca'                the CA itself
--   'server:<engine>'   an engine server's certificate
--   'client:<login>'    a manifest login's client certificate (CN = login)
-- The private key is stored ONLY encrypted (services/encryption.js); the
-- certificate is public by nature and stored as PEM so the API can report its
-- expiry without decrypting anything. `sans` records what a server
-- certificate was issued for, so a change of bridge gateway reissues it.
CREATE TABLE IF NOT EXISTS managed_db_certs (
  name TEXT PRIMARY KEY,
  cert_pem TEXT NOT NULL,
  key_enc TEXT NOT NULL,
  not_after TEXT NOT NULL,
  sans TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Authentication failures parsed out of the engines' own logs by
-- services/dbAuthAlerts.js. Login and database only: the engines do not log
-- the password, and the raw log line is deliberately not stored either.
CREATE TABLE IF NOT EXISTS managed_db_auth_failures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engine TEXT NOT NULL,
  login TEXT NOT NULL,
  database_name TEXT,
  reason TEXT NOT NULL,
  occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mdb_auth_failures_login ON managed_db_auth_failures(engine, login, occurred_at);

-- One row per (engine, login): when it was last alerted on. The rate limit is
-- "one mail per login per hour", and it must survive a restart of AppCrane.
CREATE TABLE IF NOT EXISTS managed_db_auth_alerts (
  engine TEXT NOT NULL,
  login TEXT NOT NULL,
  alerted_at TEXT NOT NULL,
  PRIMARY KEY (engine, login)
);
