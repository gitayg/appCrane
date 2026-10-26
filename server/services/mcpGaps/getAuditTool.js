// appcrane_get_audit: the MCP face of GET /api/:slug/audit. Registered in
// mcpTools.js's TOOLS array. Same gate (app.audit.view); detail is passed
// through the audit redactor on the way out, so rows written before redaction
// existed do not hand a credential to an agent.

import { getDb } from '../../db.js';
import { userHasAppPermission } from '../permissions.js';
import { redactAuditArgs } from '../../utils/auditRedact.js';
import { resolveMcpApp } from './access.js';

export const AUDIT_DEFAULT_LIMIT = 50;
export const AUDIT_MAX_LIMIT = 200;

function clampLimit(raw) {
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1) return AUDIT_DEFAULT_LIMIT;
  return Math.min(n, AUDIT_MAX_LIMIT);
}

function scrubDetail(raw) {
  if (raw == null) return null;
  let parsed;
  try { parsed = JSON.parse(raw); } catch (_) { return redactAuditArgs(String(raw)); }
  return redactAuditArgs(parsed);
}

export const getAuditTool = {
  name: 'appcrane_get_audit',
  description:
    "Read an app's audit trail: who deployed, who changed env vars or secrets, who was granted access, every MCP tool call against it, newest first. " +
    'Needs the app.audit.view permission on that app (default: the app owner, app admins and platform admins; plain members are refused unless the role matrix grants it). ' +
    'Paginate with before: pass the next_before value from the previous page to get older rows; next_before is null on the last page. limit defaults to 50, max 200. ' +
    'action filters by a substring of the action name, e.g. "deploy", "env", "mcp.appcrane_set_secret". Credential-bearing fields in detail are shown as [redacted].',
  inputSchema: {
    type: 'object',
    properties: {
      slug: { type: 'string', description: 'App slug.' },
      limit: { type: 'number', description: `Rows per page. Default ${AUDIT_DEFAULT_LIMIT}, max ${AUDIT_MAX_LIMIT}.` },
      before: { type: 'number', description: 'Return rows with an id lower than this (the next_before of the previous page).' },
      action: { type: 'string', description: 'Only rows whose action contains this text.' },
    },
    required: ['slug'],
    additionalProperties: false,
  },
  requiredRole: 'any',
  readOnly: true,
  handler: async (user, args) => {
    const app = resolveMcpApp(user, args.slug);
    if (!userHasAppPermission(user, app, 'app.audit.view')) {
      throw new Error(`Forbidden: viewing the audit trail for ${app.slug} is not permitted by your role (needs app.audit.view).`);
    }
    const limit = clampLimit(args.limit);
    const where = ['al.app_id = ?'];
    const params = [app.id];
    if (args.before != null) {
      const before = Number.parseInt(args.before, 10);
      if (!Number.isFinite(before) || before < 1) throw new Error('before must be a positive row id');
      where.push('al.id < ?');
      params.push(before);
    }
    if (typeof args.action === 'string' && args.action) {
      where.push("al.action LIKE ? ESCAPE '\\'");
      params.push(`%${args.action.replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
    }
    const rows = getDb().prepare(`
      SELECT al.id, al.action, al.detail, al.created_at, al.actor_kind, al.user_id, u.name AS user_name
      FROM audit_log al LEFT JOIN users u ON al.user_id = u.id
      WHERE ${where.join(' AND ')}
      ORDER BY al.id DESC
      LIMIT ?
    `).all(...params, limit + 1);
    const more = rows.length > limit;
    const page = more ? rows.slice(0, limit) : rows;
    return {
      app: app.slug,
      entries: page.map((r) => ({
        id: r.id, created_at: r.created_at, action: r.action,
        actor: { user_id: r.user_id, name: r.user_name, kind: r.actor_kind },
        detail: scrubDetail(r.detail),
      })),
      limit,
      next_before: more ? page[page.length - 1].id : null,
    };
  },
};
