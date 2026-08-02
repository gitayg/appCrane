import { getDb } from '../db.js';
import { redactAuditArgs } from '../utils/auditRedact.js';

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
        // Belt-and-suspenders: any logging error must NOT break the
        // actual response. logAudit can throw on malformed JSON, FK
        // constraints, or db lock contention; none of those should
        // turn a successful PUT into a failed HTTP request the user
        // can't tell finished.
        try {
          logAudit(userId, appId, action, detail, req.user?.kind || null);
        } catch (e) {
          if (e.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') {
            // Entity was just deleted — log without the FK reference
            try { logAudit(userId, null, action, detail, req.user?.kind || null); } catch (_) {}
          }
          // Swallow everything else — telemetry failure shouldn't
          // surface as an HTTP failure to the caller.
        }
      }
      return originalJson(body);
    };
    next();
  };
}
