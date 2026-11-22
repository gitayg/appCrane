import { getDb } from '../db.js';
import { clientIp } from '../utils/clientIp.js';

// The newest SCIM requests, for the IT setup page. Path only: a query string
// can carry a filter that names a person (userName eq "...").
export const KEEP = 500;

export function scimRequestLogger(req, res, next) {
  const started = Date.now();
  res.on('finish', () => {
    try {
      const db = getDb();
      const path = (req.baseUrl + req.path).slice(0, 300);
      db.prepare('INSERT INTO scim_request_log (method, path, status, duration_ms, ip) VALUES (?, ?, ?, ?, ?)')
        .run(req.method, path, res.statusCode, Date.now() - started, clientIp(req));
      db.prepare('DELETE FROM scim_request_log WHERE id <= (SELECT id FROM scim_request_log ORDER BY id DESC LIMIT 1 OFFSET ?)').run(KEEP);
    } catch (_) { /* logging never breaks a SCIM request */ }
  });
  next();
}

export function recentScimRequests(limit = 50, db = getDb()) {
  const n = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
  return db.prepare('SELECT at, method, path, status, duration_ms, ip FROM scim_request_log ORDER BY id DESC LIMIT ?').all(n);
}
