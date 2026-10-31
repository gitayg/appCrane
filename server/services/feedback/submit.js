// appcrane_submit_feedback, routed by target.
//
// About an app (slug set): a request in that app's queue, the same row the
// intake form writes, so appcrane_list_requests and the Requests page show it
// and the app's owners/admins get the usual new-request mail. The caller must
// have access to that app under the same MCP rules as every other per-app tool.
//
// About AppCrane (slug omitted, 'appcrane' or '_platform'): a request on the
// reserved '_platform' slug, which only platform admins see in Requests, and
// at most one mail per admin per hour instead of one per request.
//
// Either way the submitter sees it in My Requests and at /requests/<id>.

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { getDb } from '../../db.js';
import { logAudit } from '../../middleware/audit.js';
import { resolveMcpApp } from '../mcpGaps/access.js';
import { requestUrl } from '../vulnRequests.js';
import { insertRequest, announceRequest, PLATFORM_SLUG } from '../requestCreate.js';
import { normalizeFeedbackArgs } from './input.js';
import { redactFeedbackText } from './redact.js';
import { notifyAdminsOfFeedback } from './mail.js';
import log from '../../utils/logger.js';

export const FEEDBACK_KIND = 'feedback';
export const RATE_LIMIT_PER_HOUR = 20;
const PLATFORM_TARGETS = new Set(['appcrane', PLATFORM_SLUG]);

const PKG_VERSION = JSON.parse(readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'package.json'), 'utf8')).version;

function assertUnderRateLimit(db, userId) {
  const { n } = db.prepare(`
    SELECT COUNT(*) AS n FROM enhancement_requests
    WHERE user_id = ? AND kind = ? AND created_at >= datetime('now', '-1 hour')
  `).get(userId, FEEDBACK_KIND);
  if (n >= RATE_LIMIT_PER_HOUR) {
    throw new Error(`RATE_LIMITED: you have sent ${n} pieces of feedback in the last hour (limit ${RATE_LIMIT_PER_HOUR}). Try again later.`);
  }
}

const indent = (s) => s.split('\n').map((l) => `  ${l}`).join('\n');

/** The stored request text: the message, then what the agent attached, then who and when. */
export function composeFeedbackText({ message, kind, env, context }, { who, actorKind, at }) {
  const lines = [`[Feedback: ${kind}] ${redactFeedbackText(message)}`];
  const ctx = [];
  if (context.tool) ctx.push(`- Tool: ${redactFeedbackText(context.tool)}`);
  if (context.task) ctx.push(`- Task: ${redactFeedbackText(context.task)}`);
  if (context.deploy_id) ctx.push(`- Deploy: ${redactFeedbackText(context.deploy_id)}`);
  if (env) ctx.push(`- Environment: ${env}`);
  if (context.client) ctx.push(`- Client: ${redactFeedbackText(context.client)}`);
  if (context.error) ctx.push(`- Error:\n${indent(redactFeedbackText(context.error))}`);
  if (ctx.length) lines.push('', 'Context attached by the agent:', ...ctx);
  lines.push('', `Sent over MCP by ${who} (${actorKind}) on AppCrane v${PKG_VERSION} at ${at}.`);
  return lines.join('\n');
}

export function submitFeedback(user, args) {
  const input = normalizeFeedbackArgs(args);
  const db = getDb();
  const platform = input.slug == null || PLATFORM_TARGETS.has(input.slug);
  const app = platform ? null : resolveMcpApp(user, input.slug);
  assertUnderRateLimit(db, user.id);

  const who = user.name || user.email || `user ${user.id}`;
  const actorKind = user.kind || 'agent';
  const appSlug = platform ? PLATFORM_SLUG : app.slug;
  const text = composeFeedbackText(input, { who, actorKind, at: new Date().toISOString() });
  const id = insertRequest(db, { appSlug, userId: user.id, userName: user.name || '', message: text, kind: FEEDBACK_KIND });

  announceRequest(db, id, appSlug, { platformMail: false });
  if (platform) {
    try {
      notifyAdminsOfFeedback(db, { id, kind: input.kind, who, message: redactFeedbackText(input.message) });
    } catch (e) {
      log.warn(`[feedback] admin mail for #${id} skipped: ${e.message}`);
    }
  }
  logAudit(user.id, app?.id ?? null, 'feedback-submitted', {
    id, target: platform ? 'appcrane' : 'app', slug: app?.slug ?? null, kind: input.kind,
    env: input.env, tool: input.context.tool ?? null, message_chars: input.message.length,
  }, actorKind);

  return { id, target: platform ? 'appcrane' : 'app', where: requestUrl(id) };
}

/**
 * What auditMcpCall records for this tool: sizes and routing, never the text,
 * which is stored once, redacted, on the request itself.
 */
export function redactFeedbackAuditArgs(toolName, args) {
  if (toolName !== 'appcrane_submit_feedback' || !args || typeof args !== 'object') return args;
  const ctx = args.context && typeof args.context === 'object' ? args.context : null;
  return {
    kind: args.kind, slug: args.slug, env: args.env,
    message_chars: typeof args.message === 'string' ? args.message.length : null,
    context_fields: ctx ? Object.keys(ctx) : [],
  };
}
