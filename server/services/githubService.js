/**
 * GitHub service-account helper (v2.2.15+).
 *
 * AppCrane optionally fronts a single GitHub org/user that owns every
 * per-app repository — the end user never authenticates against GitHub,
 * AppCrane does it on their behalf with a stored PAT.
 *
 * Phase 1 (this module): config get/set with encrypted-at-rest token,
 * plus a tiny REST helper that hits the GitHub API on the service
 * account's behalf. Phase 2 will layer in repo creation, push helpers,
 * and PR plumbing on top of `apiFetch`.
 *
 * The token is stored in `settings.github_service_token_enc` using the
 * same AES-256-GCM envelope as oidc_client_secret_enc — never returned
 * to any client and never logged.
 */

import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import log from '../utils/logger.js';

const KEYS = {
  owner:      'github_service_owner',
  tokenEnc:   'github_service_token_enc',
  visibility: 'github_service_visibility',
  enabled:    'github_service_enabled',
};

const VALID_VISIBILITIES = new Set(['private', 'internal', 'public']);

function readRow(db, key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row?.value ?? '';
}

function writeRow(db, key, value, userId) {
  db.prepare(`
    INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')
  `).run(key, String(value ?? ''), userId ?? null);
}

/**
 * Sanitized public view of the config — never includes the token.
 * Returns { owner, visibility, enabled, configured } where `configured`
 * means a non-empty token is present at rest (so the UI can render
 * "service account active" without round-tripping through decrypt).
 */
export function getServiceConfig() {
  const db = getDb();
  const tokenEnc = readRow(db, KEYS.tokenEnc);
  return {
    owner:      readRow(db, KEYS.owner),
    visibility: readRow(db, KEYS.visibility) || 'private',
    enabled:    readRow(db, KEYS.enabled) === '1',
    configured: !!tokenEnc,
  };
}

/**
 * Replace one or more fields. Pass `token` (plaintext) to rotate; omit it
 * to leave the existing token untouched. Pass `token: null` (explicit) to
 * clear the token and disable the integration.
 */
export function setServiceConfig({ owner, token, visibility, enabled }, userId) {
  const db = getDb();

  if (visibility !== undefined && !VALID_VISIBILITIES.has(visibility)) {
    throw new Error(`visibility must be one of: ${[...VALID_VISIBILITIES].join(', ')}`);
  }

  db.transaction(() => {
    if (owner !== undefined)      writeRow(db, KEYS.owner,      String(owner).trim(), userId);
    if (visibility !== undefined) writeRow(db, KEYS.visibility, visibility,           userId);
    if (enabled !== undefined)    writeRow(db, KEYS.enabled,    enabled ? '1' : '0', userId);

    if (token === null) {
      writeRow(db, KEYS.tokenEnc, '', userId);
      writeRow(db, KEYS.enabled,  '0', userId);
    } else if (typeof token === 'string' && token.length > 0) {
      writeRow(db, KEYS.tokenEnc, encrypt(token), userId);
    }
  })();

  return getServiceConfig();
}

/**
 * Server-internal: returns the decrypted PAT or null if unconfigured.
 * NEVER expose the return value to any HTTP response or log line.
 */
export function getServiceTokenInternal() {
  const db = getDb();
  const enc = readRow(db, KEYS.tokenEnc);
  if (!enc) return null;
  try {
    return decrypt(enc);
  } catch (e) {
    log.error(`[github-service] failed to decrypt service token: ${e.message}`);
    return null;
  }
}

/**
 * Thin GitHub REST wrapper. Returns parsed JSON or throws on non-2xx.
 * Callers should never hand the request body to user input verbatim —
 * this helper does no payload validation.
 */
export async function apiFetch(path, { method = 'GET', body, headers = {} } = {}) {
  const cfg = getServiceConfig();
  if (!cfg.enabled) throw new Error('github service is disabled');
  const token = getServiceTokenInternal();
  if (!token) throw new Error('github service token is not configured');

  const url = path.startsWith('http') ? path : `https://api.github.com${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept:        'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent':  'appcrane-service',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_) { /* keep raw */ }

  if (!res.ok) {
    const msg = data?.message || text || res.statusText;
    const err = new Error(`github ${method} ${path} → ${res.status}: ${msg}`);
    err.status = res.status;
    err.body = data;
    throw err;
  }
  return data;
}
