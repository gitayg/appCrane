-- MCP scope blueprints (services/mcpBlueprints.js): a named set of fine-grained
-- MCP scopes (services/mcpScopes.js) and, optionally, the apps it is limited to.
-- A platform admin defines them; a consenting user can pick one for an OAuth
-- connection, a platform admin can pin one to a client, and a dhk_mcp_* key can
-- be issued under one. The credential's effective scope is its requested scopes
-- intersected with the blueprint as it is NOW (read at use), and the user's role
-- still applies on top. blueprint_id columns carry no foreign key on purpose:
-- deleting a blueprint must not turn a scoped credential into an unscoped one,
-- so a missing blueprint resolves to no tools at all.
CREATE TABLE IF NOT EXISTS mcp_scope_blueprints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  scopes TEXT NOT NULL,
  apps TEXT,
  builtin INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO mcp_scope_blueprints (name, description, scopes, builtin) VALUES
  ('read-only', 'Read apps, deploys, logs and masked settings; send feedback. No changes, no secret values.', 'mcp:read mcp:feedback', 1),
  ('deploy-sandbox', 'Read-only, plus deploy and roll back sandbox. Production is refused.', 'mcp:read mcp:feedback mcp:deploy:sandbox', 1),
  ('app-admin', 'Run the apps you administer: deploy any env, change code, settings, secrets and members. No platform settings, no creating or deleting apps.', 'mcp:read mcp:feedback mcp:secrets:read mcp:deploy mcp:app:write mcp:app:access', 1);

ALTER TABLE oauth_codes ADD COLUMN blueprint_id INTEGER;
ALTER TABLE oauth_grants ADD COLUMN blueprint_id INTEGER;
ALTER TABLE oauth_clients ADD COLUMN blueprint_id INTEGER;
ALTER TABLE user_mcp_keys ADD COLUMN blueprint_id INTEGER;
