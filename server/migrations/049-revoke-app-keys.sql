-- v2.2.12: Revoke all app-scoped MCP keys (dhk_app_*).
--
-- The app-scoped key model was removed in v2.2.12 — per-user MCP keys
-- (dhk_mcp_*) plus per-app role assignments (app_user_roles) cover the
-- same scoping more cleanly. Server-side, the auth middleware now returns
-- 410 KEY_TYPE_REMOVED for any dhk_app_* presented; this migration also
-- revokes them in the database so the rows reflect their inactive state
-- and are filtered out of any future audit reporting.
--
-- The app_keys table itself is intentionally NOT dropped — keep the
-- historical rows for audit-trail continuity. The /api/apps/:slug/keys
-- routes that managed them are removed in the same release.

UPDATE app_keys
   SET revoked_at = COALESCE(revoked_at, datetime('now'))
 WHERE revoked_at IS NULL;
