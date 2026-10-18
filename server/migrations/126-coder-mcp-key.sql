-- Coder session MCP keys: the hosted coder gets a read-only AppCrane MCP
-- connection for its own app.
--
-- A coder key is an ordinary user_mcp_keys row (dhk_mcp_*, hashed, expiring,
-- revocable) for the session owner, with two extra columns that narrow it:
-- the coder session it was issued for and the one app it may name. Both NULL
-- on every personal key, so nothing about an existing key changes.
--
-- requireAuth and the MCP dispatcher read these columns: a coder key is
-- refused everywhere but POST /api/mcp, is pinned to this app's slug, and may
-- call only the tools in services/coderMcpKey.js CODER_MCP_TOOLS.
ALTER TABLE user_mcp_keys ADD COLUMN coder_session_id TEXT;
ALTER TABLE user_mcp_keys ADD COLUMN app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_user_mcp_keys_coder_session ON user_mcp_keys(coder_session_id);
