-- External secret stores an env var can reference (services/externalSecrets).
-- app_id NULL is a platform connection (platform admin); otherwise it belongs
-- to that app alone (its owner) and goes with it. settings_json holds only
-- non-secret settings (address, region, auth method); credentials_enc is one
-- encryption.js blob of the credential JSON and is never returned by an API.
--
-- A platform connection is never open to "every app": it is scoped either by a
-- path_prefix containing {slug} or by an allowed_apps list of app ids. The CHECK
-- refuses an unscoped one even when a write skips connections.js, and awsssm
-- (the host's own AWS identity) always needs the {slug} prefix.
CREATE TABLE IF NOT EXISTS secret_connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider IN ('vault', 'infisical', 'onepassword', 'awsssm')),
  app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
  settings_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(settings_json)),
  credentials_enc TEXT,
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  -- COALESCE(..., 0): a CHECK that evaluates to NULL passes, and a missing key is NULL.
  CHECK (COALESCE(
    app_id IS NOT NULL
    OR instr(COALESCE(json_extract(settings_json, '$.path_prefix'), ''), '{slug}') > 0
    OR (provider <> 'awsssm' AND json_type(settings_json, '$.allowed_apps') = 'array' AND json_array_length(settings_json, '$.allowed_apps') > 0),
  0)),
  CHECK (COALESCE(provider <> 'awsssm' OR (app_id IS NULL AND instr(COALESCE(json_extract(settings_json, '$.path_prefix'), ''), '{slug}') > 0), 0))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_secret_connections_scope_name ON secret_connections (COALESCE(app_id, 0), name);
CREATE INDEX IF NOT EXISTS ix_secret_connections_app ON secret_connections (app_id);
