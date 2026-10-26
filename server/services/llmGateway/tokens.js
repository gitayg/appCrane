import crypto from 'crypto';
import { getDb } from '../../db.js';
import { encrypt, decrypt, hashApiKey } from '../encryption.js';

// The gateway token an app presents in place of a provider key. One per app and
// environment, so usage and budgets are per environment. Stored hashed for
// lookup and encrypted for re-injection at every deploy and restart. It opens
// only /api/service/llm/*: nothing else reads this table.

export const TOKEN_PREFIX = 'aclg_';

export function issueGatewayToken(appId, env, db = getDb()) {
  const token = TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url');
  db.prepare(`
    INSERT INTO llm_gateway_tokens (app_id, env, token_hash, token_encrypted) VALUES (?, ?, ?, ?)
    ON CONFLICT(app_id, env) DO UPDATE SET token_hash = excluded.token_hash, token_encrypted = excluded.token_encrypted, created_at = datetime('now')
  `).run(appId, env, hashApiKey(token), encrypt(token));
  return token;
}

export function gatewayTokenPlaintext(appId, env, db = getDb()) {
  const row = db.prepare('SELECT token_encrypted FROM llm_gateway_tokens WHERE app_id = ? AND env = ?').get(appId, env);
  if (!row) return null;
  try { return decrypt(row.token_encrypted); } catch { return null; }
}

/** { app, env } for a presented token, or null. */
export function resolveGatewayToken(token, db = getDb()) {
  if (!token || typeof token !== 'string' || !token.startsWith(TOKEN_PREFIX)) return null;
  const row = db.prepare('SELECT app_id, env FROM llm_gateway_tokens WHERE token_hash = ?').get(hashApiKey(token));
  if (!row) return null;
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(row.app_id);
  return app ? { app, env: row.env } : null;
}
