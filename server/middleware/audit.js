import { getDb } from '../db.js';
import { redactAuditArgs } from '../utils/auditRedact.js';
import log from '../utils/logger.js';

/**
 * Log an action to the audit log.
 *
 * v2.28.0: records `actor_kind` ('human' | 'agent') alongside the user, so
 * "what did agents do here" is answerable. When the caller doesn't pass it
 * explicitly, it is resolved from users.kind in the same statement.
 */
export function logAudit(userId, appId, action, detail, actorKind = null) {
  const db = getDb();
  db.prepare(`
    INSERT INTO audit_log (user_id, app_id, action, detail, actor_kind)
    VALUES (?, ?, ?, ?, COALESCE(?, (SELECT kind FROM users WHERE id = ?)))
  `).run(
    userId, appId, action,
    typeof detail === 'string' ? detail : JSON.stringify(detail),
    actorKind, userId
  );
}

/**
 * Express middleware that auto-logs mutating requests.
 *
 * APPCRANE_AUDIT_REQUIRED=1 — and why REST behaves differently from MCP
 * ---------------------------------------------------------------------
 * `logMcpCall` in server/services/mcpTools.js honours the same flag by
 * THROWING when the audit write fails, which aborts the tool call. It can do
 * that because it runs *around* the action: nothing has been mutated yet, so
 * refusing is a real refusal.
 *
 * This middleware cannot make that promise. It hooks `res.json`, so by the
 * time it runs the route handler has already finished — the container was
 * restarted, the env var was written, the app was deleted. There is no
 * transaction to roll back and no generic undo to call.
 *
 * So under the flag we do the only honest thing available: report the failure
 * instead of hiding it. The response becomes HTTP 500 / AUDIT_UNAVAILABLE and
 * the message says outright that the change may already be in effect. An
 * operator who set this flag wants to be paged into an investigation, not
 * reassured that nothing happened.
 *
 * Do NOT "fix" this into a rollback, and do NOT soften the message into
 * "request failed" — that would be a lie about durable state, and it is worse
 * than the silent best-effort logging this replaced. If real fail-closed REST
 * auditing is wanted, it has to move to a pre-handler write (reserve the audit
 * row before the mutation, mark its outcome after), not to this hook.
 *
 * With the flag unset — the default — behaviour is unchanged: audit failures
 * are swallowed and a successful mutation never becomes an HTTP error.
 */
export function auditMiddleware(action) {
  return (req, res, next) => {
    // Store original json method to intercept response
    const originalJson = res.json.bind(res);
    res.json = (body) => {
      // Only log successful mutations
      if (res.statusCode < 400) {
        const appId = req.app?.id || null;
        const userId = req.user?.id || null;
        const detail = {
          method: req.method,
          path: req.path,
          params: req.params,
        };
        // v2.28.0: redaction is pattern-based (redactAuditArgs) rather than a
        // hand-maintained delete-list. The old list had to be updated every
        // time a secret-bearing field was added anywhere — a rule that fails
        // silently and permanently the first time someone forgets. Matching on
        // key NAME (…_token, …secret, password, value, credential…) fails safe
        // for fields nobody remembered, masks nested bodies, and truncates
        // oversized payloads. `vars` is still dropped wholesale: an env-var
        // bundle is all secret, and its keys are arbitrary.
        if (req.body && !req.path.includes('/env/')) {
          const body = { ...req.body };
          delete body.vars;
          detail.body = redactAuditArgs(body);
        }
        // Belt-and-suspenders: by default any logging error must NOT break
        // the actual response. logAudit can throw on malformed JSON, FK
        // constraints, or db lock contention; none of those should
        // turn a successful PUT into a failed HTTP request the user
        // can't tell finished.
        let auditError = null;
        try {
          logAudit(userId, appId, action, detail, req.user?.kind || null);
        } catch (e) {
          auditError = e;
          if (e.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') {
            // Entity was just deleted — log without the FK reference
            try {
              logAudit(userId, null, action, detail, req.user?.kind || null);
              auditError = null;
            } catch (retryErr) {
              auditError = retryErr;
            }
          }
          // Otherwise swallow — telemetry failure shouldn't surface as an
          // HTTP failure to the caller (unless the flag below says it must).
        }

        // Fail-loud mode. See the block comment on auditMiddleware: this
        // reports, it does not roll back, and the message must keep saying so.
        if (auditError && process.env.APPCRANE_AUDIT_REQUIRED === '1') {
          log.error(
            `Audit write failed under APPCRANE_AUDIT_REQUIRED=1 — reporting ${req.method} ${req.path} as failed; the action itself was NOT reverted: ${auditError.message}`
          );
          res.status(500);
          return originalJson({
            error: {
              code: 'AUDIT_UNAVAILABLE',
              message:
                'The audit log could not be written, and this install runs with APPCRANE_AUDIT_REQUIRED=1. ' +
                'IMPORTANT: the requested action may have already been applied — it was NOT rolled back — but no record of it exists. ' +
                'Verify the current state directly and investigate the audit log storage before retrying.',
            },
          });
        }
      }
      return originalJson(body);
    };
    next();
  };
}
