-- migration:no-transaction
--
-- users.api_key_hash may be NULL: a personal API key (dhk_user_* /
-- dhk_admin_*) exists only once its owner asks for one.
--
-- Until now every account got a random key at creation (SSO and SAML first
-- sign-in, SCIM provisioning, admin-created people) that nobody was ever
-- shown, only because 001 declared the column NOT NULL. The writers now leave
-- it NULL (routes/oidc.js, saml.js, scim.js, users.js for kind 'human') and a
-- person creates a key from Settings > Account (POST /api/me/api-key/rotate,
-- which creates when there is none). Existing keys are left as they are.
--
-- UNIQUE stays: SQLite lets any number of rows hold NULL in a UNIQUE column,
-- and every lookup is `WHERE api_key_hash = ?`, which never matches NULL. The
-- expiry triggers of 136 already guard on `NEW.api_key_hash IS NOT NULL`, and
-- the rotate trigger's `IS NOT OLD.api_key_hash` is true for NULL -> key, so a
-- first key gets its expiry like a rotated one.
--
-- Table rebuild, as in 046. The writable_schema shortcut is unavailable:
-- better-sqlite3 runs with SQLITE_DBCONFIG_DEFENSIVE and rejects the UPDATE
-- with "table sqlite_master may not be modified" even after
-- PRAGMA defensive = OFF (re-measured for this migration). no-transaction is
-- for PRAGMA foreign_keys, which SQLite ignores inside a transaction; the
-- rebuild itself runs in its own BEGIN/COMMIT so it is all-or-nothing.
--
-- The column list is the live schema as of 168 (PRAGMA table_info(users) on a
-- freshly migrated database): 046's 20 columns plus department, region,
-- location (scim directory attributes) and 136's four api_key_* columns.
-- Columns are copied BY NAME, so a database whose physical column order
-- differs copies correctly. test/user-api-key-on-request.test.js compares
-- this table against a pre-169 one so a dropped column fails a test.
-- DROP TABLE takes the table's indexes and triggers with it; every one that
-- existed as of 168 is recreated below, verbatim.
--
-- legacy_alter_table = ON for the RENAME: in the default mode SQLite re-checks
-- every other trigger and view and refuses the rename with "error in trigger
-- identity_sessions_apply_policy: no such table: main.users", because between
-- the DROP and the RENAME no table is called users (measured). Legacy mode
-- renames without that check; nothing refers to users_new, so there is no
-- reference it would have needed to rewrite.

PRAGMA foreign_keys = OFF;
PRAGMA legacy_alter_table = ON;

BEGIN;

CREATE TABLE users_new (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  name                 TEXT NOT NULL,
  email                TEXT UNIQUE,
  role                 TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('platform_admin', 'admin', 'user')),
  api_key_hash         TEXT UNIQUE,
  created_at           TEXT NOT NULL DEFAULT (datetime('now')),
  password_hash        TEXT,
  username             TEXT,
  avatar_url           TEXT,
  phone                TEXT,
  year_of_birth        INTEGER,
  preferences          TEXT DEFAULT '{}',
  last_login_at        TEXT,
  api_key_encrypted    TEXT,
  sso_sub              TEXT,
  saml_name_id         TEXT,
  active               INTEGER NOT NULL DEFAULT 1,
  scim_external_id     TEXT,
  kind                 TEXT NOT NULL DEFAULT 'human',
  mcp_app_scope        TEXT,
  department           TEXT,
  region               TEXT,
  location             TEXT,
  api_key_issued_at    TEXT,
  api_key_expires_at   TEXT,
  api_key_last_used_at TEXT,
  api_key_expired_hash TEXT
);

INSERT INTO users_new (
  id, name, email, role, api_key_hash, created_at,
  password_hash, username, avatar_url, phone, year_of_birth, preferences, last_login_at,
  api_key_encrypted, sso_sub, saml_name_id, active, scim_external_id, kind, mcp_app_scope,
  department, region, location,
  api_key_issued_at, api_key_expires_at, api_key_last_used_at, api_key_expired_hash
)
SELECT
  id, name, email, role, api_key_hash, created_at,
  password_hash, username, avatar_url, phone, year_of_birth, preferences, last_login_at,
  api_key_encrypted, sso_sub, saml_name_id, active, scim_external_id, kind, mcp_app_scope,
  department, region, location,
  api_key_issued_at, api_key_expires_at, api_key_last_used_at, api_key_expired_hash
FROM users;

-- Keep the AUTOINCREMENT high-water mark: copying gives users_new the highest
-- id still present, and a deleted top id must never be handed out again
-- (sessions, audit rows and grants are keyed to user ids).
CREATE TEMP TABLE _users_seq_169 AS SELECT seq FROM sqlite_sequence WHERE name = 'users';

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

UPDATE sqlite_sequence
   SET seq = MAX(seq, COALESCE((SELECT seq FROM temp._users_seq_169), 0))
 WHERE name = 'users';
DROP TABLE temp._users_seq_169;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso_sub        ON users(sso_sub)          WHERE sso_sub          IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_saml_name_id   ON users(saml_name_id)     WHERE saml_name_id     IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_scim_ext       ON users(scim_external_id) WHERE scim_external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_api_key_expired_hash ON users(api_key_expired_hash);

CREATE TRIGGER IF NOT EXISTS users_no_global_admin_insert
BEFORE INSERT ON users
WHEN NEW.role = 'admin'
BEGIN
  SELECT RAISE(ABORT, 'The global admin role was retired: use role user with per-app admin, or platform_admin');
END;

CREATE TRIGGER IF NOT EXISTS users_no_global_admin_update
BEFORE UPDATE OF role ON users
WHEN NEW.role = 'admin'
BEGIN
  SELECT RAISE(ABORT, 'The global admin role was retired: use role user with per-app admin, or platform_admin');
END;

CREATE TRIGGER IF NOT EXISTS trg_users_api_key_issue
AFTER INSERT ON users
WHEN NEW.api_key_hash IS NOT NULL AND NEW.api_key_hash NOT LIKE 'expired:%'
BEGIN
  UPDATE users
     SET api_key_issued_at = datetime('now'),
         api_key_expires_at = datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days'),
         api_key_last_used_at = NULL,
         api_key_expired_hash = NULL
   WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_users_api_key_rotate
AFTER UPDATE OF api_key_hash ON users
WHEN NEW.api_key_hash IS NOT NULL AND NEW.api_key_hash IS NOT OLD.api_key_hash AND NEW.api_key_hash NOT LIKE 'expired:%'
BEGIN
  UPDATE users
     SET api_key_issued_at = datetime('now'),
         api_key_expires_at = datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days'),
         api_key_last_used_at = NULL,
         api_key_expired_hash = NULL
   WHERE id = NEW.id;
END;

COMMIT;

PRAGMA legacy_alter_table = OFF;
PRAGMA foreign_keys = ON;
