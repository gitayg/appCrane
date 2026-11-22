import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import log from '../utils/logger.js';

/**
 * The platform Anthropic API key, stored encrypted in `settings` and set by a
 * platform admin. It is never in .env or process.env once the server has
 * booted: platformAnthropicKeyBoot.js moves an old .env / environment value
 * into the database and then calls sealEnvironment().
 *
 * Before the seal (a script or test that never booted the server) the getter
 * still falls back to process.env, so nothing that imports a call site has to
 * boot first. After it, process.env is never read.
 */

export const SETTING_KEY = 'platform_anthropic_key_encrypted';
export const ENV_NAME = 'ANTHROPIC_API_KEY';

// Printable ASCII, no space: the key goes into a docker --env-file, where a
// newline would start another variable.
const VALID_KEY = /^[\x21-\x7e]{8,500}$/;

let cached;           // undefined: not read yet; null: none stored
let legacy = null;    // an environment value the boot migration could not store
let sealed = false;

function stored(db) {
  if (cached !== undefined) return cached;
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(SETTING_KEY);
  if (!row?.value) { cached = null; return cached; }
  try {
    cached = decrypt(row.value);
  } catch (e) {
    log.warn(`Platform Anthropic key unreadable (${e.message}): set it again in Settings`);
    cached = null;
  }
  return cached;
}

export function getPlatformAnthropicKey(db = getDb()) {
  const key = stored(db);
  if (key) return key;
  if (legacy) return legacy;
  if (!sealed && process.env[ENV_NAME]) return process.env[ENV_NAME];
  return null;
}

export function hasStoredPlatformAnthropicKey(db = getDb()) {
  return !!db.prepare('SELECT 1 FROM settings WHERE key = ?').get(SETTING_KEY);
}

export class InvalidAnthropicKeyError extends Error {}

export function setPlatformAnthropicKey(value, userId = null, db = getDb()) {
  const key = typeof value === 'string' ? value.trim() : '';
  if (!VALID_KEY.test(key)) throw new InvalidAnthropicKeyError('key must be 8-500 printable characters with no spaces');
  db.prepare(`
    INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')
  `).run(SETTING_KEY, encrypt(key), userId);
  cached = key;
  legacy = null;
  return status(db);
}

export function clearPlatformAnthropicKey(db = getDb()) {
  const removed = db.prepare('DELETE FROM settings WHERE key = ?').run(SETTING_KEY).changes > 0;
  cached = null;
  legacy = null;
  return removed;
}

export function status(db = getDb()) {
  const key = stored(db);
  if (key) return { configured: true, source: 'database', suffix: key.slice(-4) };
  const other = getPlatformAnthropicKey(db);
  if (other) return { configured: true, source: 'env-legacy', suffix: other.slice(-4) };
  return { configured: false, source: null, suffix: null };
}

/** Called once at boot: from here on process.env is never consulted. */
export function sealEnvironment({ keepInMemory = null } = {}) {
  if (keepInMemory) legacy = keepInMemory;
  delete process.env[ENV_NAME];
  sealed = true;
}

/** Forget the cached value (tests, and a database swapped underneath). */
export function resetPlatformAnthropicKeyCache() {
  cached = undefined;
}

/**
 * Write secret env vars to a 0600 file in a fresh 0700 directory, for
 * `docker run|exec --env-file`, so the values never appear in an argv that
 * `ps` shows. Docker reads the file when it parses its flags; call cleanup()
 * once the container has started (or the command has exited).
 */
export function writeSecretEnvFile(vars) {
  const lines = [];
  for (const [k, v] of Object.entries(vars)) {
    if (!/^[A-Z_][A-Z0-9_]*$/.test(k)) throw new Error(`invalid env name ${k}`);
    const s = String(v ?? '');
    if (/[\r\n\0]/.test(s)) throw new Error(`env value for ${k} contains a line break`);
    lines.push(`${k}=${s}`);
  }
  const dir = mkdtempSync(join(tmpdir(), 'appcrane-env-'));
  const path = join(dir, 'env');
  writeFileSync(path, lines.join('\n') + '\n', { mode: 0o600, flag: 'wx' });
  let done = false;
  return {
    path,
    cleanup() {
      if (done) return;
      done = true;
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
