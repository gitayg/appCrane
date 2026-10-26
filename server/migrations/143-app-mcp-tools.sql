-- MCP front door for hosted apps (services/appMcp/manifest.js).
--
-- One row per app and environment, written by a deploy from deployhub.json
-- `mcp` and replaced by the next deploy of that environment; a release with no
-- `mcp` block deletes the row. mode 'tools': tools_json is the validated list
-- AppCrane translates into HTTP requests to the app. mode 'proxy': the app
-- speaks MCP itself at mcp_path and AppCrane forwards to it.
CREATE TABLE IF NOT EXISTS app_mcp_tools (
  app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env        TEXT NOT NULL CHECK (env IN ('production', 'sandbox')),
  mode       TEXT NOT NULL CHECK (mode IN ('tools', 'proxy')),
  tools_json TEXT NOT NULL DEFAULT '[]',
  mcp_path   TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (app_id, env)
);
