-- Connections gateway (services/connections): a platform admin registers an
-- upstream API once, with its credential; an app reaches it only through
-- /api/service/connections/<name>/<path> and only within an approved
-- capability grant 'connection:<name>' (methods + path prefixes).
--
-- base_url is fixed per connection (https only, checked again at every call
-- on the address actually dialled). credentials_enc is one encryption.js blob
-- of the credential JSON and is never returned by an API. identity_secret_enc
-- signs the acting-user header sent upstream when forward_identity is on.
-- Every call is logged to the event store (kind 'connection.call'), never a body.
CREATE TABLE IF NOT EXISTS api_connections (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  name                TEXT    NOT NULL UNIQUE,
  provider            TEXT    NOT NULL CHECK (provider IN ('generic', 'github', 'slack', 'google', 'atlassian')),
  description         TEXT,
  base_url            TEXT    NOT NULL CHECK (base_url LIKE 'https://%'),
  auth_type           TEXT    NOT NULL CHECK (auth_type IN ('bearer', 'header', 'basic', 'google_service_account')),
  auth_header         TEXT,
  settings_json       TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(settings_json)),
  credentials_enc     TEXT    NOT NULL,
  forward_identity    INTEGER NOT NULL DEFAULT 0 CHECK (forward_identity IN (0, 1)),
  identity_secret_enc TEXT,
  rate_per_minute     INTEGER NOT NULL DEFAULT 120 CHECK (rate_per_minute BETWEEN 1 AND 10000),
  max_request_kb      INTEGER NOT NULL DEFAULT 1024 CHECK (max_request_kb BETWEEN 1 AND 51200),
  max_response_kb     INTEGER NOT NULL DEFAULT 10240 CHECK (max_response_kb BETWEEN 1 AND 102400),
  timeout_ms          INTEGER NOT NULL DEFAULT 30000 CHECK (timeout_ms BETWEEN 1000 AND 300000),
  enabled             INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_by          INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);
