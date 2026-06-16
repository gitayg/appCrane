/**
 * Per-app service token (v2.8.0) — how an app's server authenticates to
 * AppCrane's internal service API (currently just the email service).
 *
 * The token is stored two ways on the app row:
 *   service_token_hash      — SHA-256, for O(1) lookup when verifying
 *   service_token_encrypted — AES-256-GCM, so the deployer can decrypt and
 *                             inject the plaintext into the container as
 *                             APPCRANE_SERVICE_TOKEN at start time
 *
 * It's a server-only secret: injected as a container env var, never exposed to
 * the browser, never returned by any dashboard API.
 */

import crypto from 'crypto';
import { getDb } from '../db.js';
import { encrypt, decrypt, hashApiKey } from './encryption.js';

/** Issue (or rotate) the service token for an app. Returns the plaintext. */
export function issueServiceToken(appId) {
  const db = getDb();
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('UPDATE apps SET service_token_hash = ?, service_token_encrypted = ? WHERE id = ?')
    .run(hashApiKey(token), encrypt(token), appId);
  return token;
}

/** Resolve an app from a presented service token, or null. */
export function appForServiceToken(token) {
  if (!token || typeof token !== 'string') return null;
  const db = getDb();
  return db.prepare('SELECT * FROM apps WHERE service_token_hash = ?').get(hashApiKey(token)) || null;
}

/** Decrypt the stored token for container injection (deployer). Null if unset. */
export function getServiceTokenPlaintext(app) {
  if (!app?.service_token_encrypted) return null;
  try { return decrypt(app.service_token_encrypted); } catch { return null; }
}
