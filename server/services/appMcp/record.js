// One audit_log row and one 'mcp.app_tool' event per app tool call. Neither
// carries the arguments, the translated query or the response: only the tool,
// the method, the declared path template, the outcome and who called. The
// audit row is written directly rather than through logAudit, which would add
// a second, generic event for the same call.

import { getDb } from '../../db.js';
import { recordEvent } from '../eventStore.js';
import log from '../../utils/logger.js';

export function recordToolCall({ user, app, env, tool, method, pathTemplate, outcome, status = null, ms = null, via, client = null, agent = null }) {
  const ok = outcome === 'ok';
  const detail = {
    tool, env, method, path: pathTemplate, outcome, status, ms, via,
    ...(client ? { client } : {}), ...(agent ? { agent } : {}),
  };
  let auditId = null;
  try {
    auditId = Number(getDb().prepare(`
      INSERT INTO audit_log (user_id, app_id, action, detail, actor_kind)
      VALUES (?, ?, 'mcp.app_tool', ?, COALESCE(?, (SELECT kind FROM users WHERE id = ?)))
    `).run(user?.id ?? null, app.id, JSON.stringify(detail), agent ? 'agent' : null, user?.id ?? null).lastInsertRowid);
  } catch (e) {
    log.warn(`[app-mcp] audit write failed: ${e.message}`);
  }
  recordEvent({
    kind: 'mcp.app_tool',
    severity: ok ? 'info' : 'warning',
    appId: app.id,
    appSlug: app.slug,
    userId: user?.id ?? null,
    summary: ok
      ? `MCP tool ${tool} called on ${env}${status ? ` (HTTP ${status})` : ''}`
      : `MCP tool ${tool} on ${env} ${outcome.replace(/_/g, ' ')}${status ? ` (HTTP ${status})` : ''}`,
    refTable: auditId ? 'audit_log' : null,
    refId: auditId,
    data: detail,
  });
}
