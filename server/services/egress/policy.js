// Who is egress-enforced, which hosts they may reach, and the proxy tokens
// (migration 231). Enforcement is off until a platform admin turns it on for
// the platform (settings egress_mode = 'enforced') or for one app
// (app_egress.enforced = 1); either takes effect at the app's next container
// start. The allow-list is the union of the app's active 'egress' grants, read
// at every proxied connection, so a revoke or an expiry applies at once.

import crypto from 'crypto';
import { getDb } from '../../db.js';
import { encrypt, decrypt, hashApiKey } from '../encryption.js';
import { AppError } from '../../utils/errors.js';
import { logAudit } from '../../middleware/audit.js';
import { activeScopes } from '../capabilities/store.js';
import { hostEntryAllows } from '../capabilities/registry.js';

export const MODES = ['open', 'enforced'];
export const TOKEN_PREFIX = 'aceg_';
const ENVS = ['production', 'sandbox'];

export function egressMode(db = getDb()) {
  const v = db.prepare("SELECT value FROM settings WHERE key = 'egress_mode'").get()?.value;
  return MODES.includes(v) ? v : 'open';
}

export function setEgressMode(mode, user, db = getDb()) {
  if (!MODES.includes(mode)) throw new AppError(`mode must be one of ${MODES.join(', ')}`, 400, 'VALIDATION');
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES ('egress_mode', ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`).run(mode, user.id);
  logAudit(user.id, null, 'egress-mode', { mode });
  return mode;
}

export function appEnforcedFlag(appId, db = getDb()) {
  return db.prepare('SELECT enforced FROM app_egress WHERE app_id = ?').get(appId)?.enforced === 1;
}

export function setAppEnforced(app, enforced, user, db = getDb()) {
  if (typeof enforced !== 'boolean') throw new AppError('enforced must be true or false', 400, 'VALIDATION');
  db.prepare(`INSERT INTO app_egress (app_id, enforced, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(app_id) DO UPDATE SET enforced = excluded.enforced, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(app.id, enforced ? 1 : 0, user.id);
  logAudit(user.id, app.id, 'egress-app-enforced', { enforced });
}

export function isEnforced(app, db = getDb()) {
  return egressMode(db) === 'enforced' || appEnforcedFlag(app.id, db);
}

/** The allow-list entries of the app's active egress grants (registry.parseHostEntry shapes). */
export function allowedHosts(appId, db = getDb()) {
  const all = new Set();
  for (const s of activeScopes(db, appId, 'egress')) for (const h of s.hosts || []) all.add(h);
  return [...all].sort();
}

export function hostAllowed(entries, host, port) {
  return entries.some((e) => hostEntryAllows(e, host, port));
}

export function issueEgressToken(appId, env, db = getDb()) {
  if (!ENVS.includes(env)) throw new Error(`unknown env ${env}`);
  const token = TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url');
  db.prepare(`INSERT INTO app_egress_tokens (app_id, env, token_hash, token_encrypted) VALUES (?, ?, ?, ?)
    ON CONFLICT(app_id, env) DO UPDATE SET token_hash = excluded.token_hash, token_encrypted = excluded.token_encrypted, created_at = datetime('now')`)
    .run(appId, env, hashApiKey(token), encrypt(token));
  return token;
}

export function egressToken(appId, env, db = getDb()) {
  const row = db.prepare('SELECT token_encrypted FROM app_egress_tokens WHERE app_id = ? AND env = ?').get(appId, env);
  if (row) { try { return decrypt(row.token_encrypted); } catch (_) { /* re-issued below */ } }
  return issueEgressToken(appId, env, db);
}

/** { app, env } for a presented token, or null. */
export function resolveEgressToken(token, db = getDb()) {
  if (typeof token !== 'string' || !token.startsWith(TOKEN_PREFIX)) return null;
  const row = db.prepare('SELECT app_id, env FROM app_egress_tokens WHERE token_hash = ?').get(hashApiKey(token));
  if (!row) return null;
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(row.app_id);
  return app ? { app, env: row.env } : null;
}

export function appEgressView(app, db = getDb()) {
  const mode = egressMode(db);
  return {
    app: app.slug,
    platform_mode: mode,
    app_enforced: appEnforcedFlag(app.id, db),
    enforced: isEnforced(app, db),
    allowed_hosts: allowedHosts(app.id, db),
    takes_effect: 'at the next deploy or restart of each environment',
  };
}
