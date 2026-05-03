import { getDb } from '../db.js';

/**
 * Log an action to the audit log.
 */
export function logAudit(userId, appId, action, detail) {
  const db = getDb();
  db.prepare(
    'INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (?, ?, ?, ?)'
  ).run(userId, appId, action, typeof detail === 'string' ? detail : JSON.stringify(detail));
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
        // Don't log sensitive body fields. Strip-list MUST include any
        // future secret-bearing keys — otherwise plaintext tokens leak
        // into audit_log forever. Today: github tokens, generic api_key,
        // env-var bundles, passwords, and Claude OAuth credentials JSON.
        if (req.body && !req.path.includes('/env/')) {
          detail.body = { ...req.body };
          delete detail.body.github_token;
          delete detail.body.api_key;
          delete detail.body.vars;
          delete detail.body.password;
          delete detail.body.password_hash;
          delete detail.body.credentials;     // Claude OAuth credentials.json
          delete detail.body.access_token;    // direct token shape
          delete detail.body.refresh_token;
        }
        // Belt-and-suspenders: any logging error must NOT break the
        // actual response. logAudit can throw on malformed JSON, FK
        // constraints, or db lock contention; none of those should
        // turn a successful PUT into a failed HTTP request the user
        // can't tell finished.
        try {
          logAudit(userId, appId, action, detail);
        } catch (e) {
          if (e.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') {
            // Entity was just deleted — log without the FK reference
            try { logAudit(userId, null, action, detail); } catch (_) {}
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
