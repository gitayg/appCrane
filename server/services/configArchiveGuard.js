import crypto from 'crypto';
import { createReadStream, existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { hostname } from 'os';
import Database from 'better-sqlite3';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { stepUpRefusal, ctxFromReq, windowMinutes } from './stepUp.js';
import { repoRoot, dataDir } from './backupFiles.js';
import { keyFingerprint, shortFingerprint } from './backupCrypto.js';

// Whole-platform archives (v2.147.0): an export carries ENCRYPTION_KEY and
// every encrypted secret, an import replaces the database and can replace
// ENCRYPTION_KEY. Both take an interactive dashboard session only (no user
// API key, MCP key, OAuth token or agent: a leaked key must not be a
// takeover), a step-up within the window, and an import also names this
// instance, so a request recorded against another AppCrane does not apply here.

/** The name an import must repeat in `confirm`: CRANE_DOMAIN, else the host name. */
export function instanceName() {
  const d = String(process.env.CRANE_DOMAIN || '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase();
  return d || hostname().toLowerCase();
}

export const confirmMatches = (v) => typeof v === 'string' && v.trim().toLowerCase() === instanceName();

export function requireArchiveSession(req, res, next) {
  if (req.auth_kind !== 'session') {
    return next(new AppError('A platform backup is exported or imported only from a signed-in dashboard session, not with an API key, MCP key or agent.', 403, 'SESSION_REQUIRED'));
  }
  next();
}

export function requireArchiveStepUp(req, res, next) {
  const db = getDb();
  const err = stepUpRefusal(db, ctxFromReq(req), 'platform_archive');
  if (err) err.message = `Confirm it's you: to export or import a platform backup you need to have signed in within the last ${windowMinutes(db)} minutes.`;
  next(err || undefined);
}

export function sha256File(path) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    createReadStream(path).on('data', (d) => h.update(d)).on('error', reject).on('end', () => resolve(h.digest('hex')));
  });
}

const fp = (k) => (k ? shortFingerprint(keyFingerprint(k)) : null);

/** Short fingerprint of the ENCRYPTION_KEY in .env, else of the running process's key, or null. */
export function liveKeyFingerprint() {
  const p = join(repoRoot, '.env');
  const m = existsSync(p) ? /^\s*ENCRYPTION_KEY\s*=\s*(.*)$/m.exec(readFileSync(p, 'utf8')) : null;
  return m ? fp(m[1].trim().replace(/^["']|["']$/g, '')) : runningKeyFingerprint();
}

/** Short fingerprint of the ENCRYPTION_KEY this process runs with, or null. */
export const runningKeyFingerprint = () => fp(String(process.env.ENCRYPTION_KEY || '').trim());

/**
 * Audit fields for an import that may replace ENCRYPTION_KEY. index.js never
 * overrides a variable already in the environment, so when the running key
 * differs from the one in .env (systemd Environment=, a secrets provider) a
 * replaced .env does not change the key a restart uses: key_outside_env_file.
 */
export function keyAuditFields(before, after) {
  const running = runningKeyFingerprint();
  return {
    encryption_key_replaced: before !== after, encryption_key_before: before, encryption_key_after: after,
    encryption_key_running: running, key_outside_env_file: !!running && running !== before,
  };
}

/**
 * After a successful import the live connection still holds the replaced
 * file, so an audit row written through it is gone after the restart. Write
 * the outcome into the restored database too. user_id stays null: ids in the
 * restored database may name someone else; the actor is in the detail.
 */
export function recordInRestoredDb(action, detail) {
  let conn;
  try {
    conn = new Database(join(dataDir(), 'deployhub.db'));
    conn.prepare('INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (NULL, NULL, ?, ?)').run(action, JSON.stringify(detail));
    return true;
  } catch (_) {
    return false;
  } finally {
    try { conn?.close(); } catch (_) {}
  }
}
