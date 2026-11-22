// Platform connections (migration 230): validation, storage and the public
// view. Credentials go in encrypted and never come back out through an API;
// credentialsFor() is for the gateway alone.

import { randomBytes } from 'crypto';
import { isIP } from 'net';
import { getDb } from '../../db.js';
import { encrypt, decrypt } from '../encryption.js';
import { AppError } from '../../utils/errors.js';
import { logAudit } from '../../middleware/audit.js';
import { CONNECTION_NAME_RE, CONNECTION_PREFIX } from '../capabilities/registry.js';
import { isBlockedAddress } from '../remoteFetch.js';
import { PRESETS, PROVIDERS, AUTH_TYPES } from './presets.js';

const bad = (msg) => new AppError(msg, 400, 'VALIDATION');
const HEADER_NAME_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const RESERVED_HEADERS = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'cookie', 'te', 'upgrade', 'proxy-authorization', 'keep-alive', 'trailer']);
const LIMITS = {
  rate_per_minute: [1, 10000, 120],
  max_request_kb: [1, 51200, 1024],
  max_response_kb: [1, 102400, 10240],
  timeout_ms: [1000, 300000, 30000],
};

function str(v, field, max = 2000) {
  if (typeof v !== 'string' || !v.trim()) throw bad(`${field} is required`);
  if (v.length > max) throw bad(`${field} is too long`);
  return v.trim();
}

/** https only, no credentials, no query or fragment, and not a private or loopback IP literal. */
export function validateBaseUrl(raw) {
  let u;
  try { u = new URL(str(raw, 'base_url')); } catch (e) { if (e instanceof AppError) throw e; throw bad('base_url is not a valid URL'); }
  if (u.protocol !== 'https:') throw bad('base_url must be https');
  if (u.username || u.password) throw bad('base_url must not carry credentials: put them in credentials');
  if (u.search || u.hash) throw bad('base_url must not have a query or fragment');
  const host = u.hostname.replace(/^\[(.*)\]$/, '$1');
  if (isIP(host) && isBlockedAddress(host)) throw bad('base_url is a private, loopback or link-local address');
  return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
}

function limitOf(input, key, current) {
  const [min, max, def] = LIMITS[key];
  const v = input[key];
  if (v === undefined) return current ?? def;
  if (!Number.isInteger(v) || v < min || v > max) throw bad(`${key} must be an integer between ${min} and ${max}`);
  return v;
}

function googleCredential(raw) {
  let j = raw;
  if (typeof raw === 'string') { try { j = JSON.parse(raw); } catch (_) { throw bad('credentials.service_account_json is not JSON'); } }
  if (!j || typeof j !== 'object' || j.type !== 'service_account') throw bad('credentials.service_account_json must be a Google service account key (type service_account)');
  if (typeof j.client_email !== 'string' || !j.client_email) throw bad('the service account key has no client_email');
  if (typeof j.private_key !== 'string' || !j.private_key.includes('PRIVATE KEY')) throw bad('the service account key has no private_key');
  if (j.token_uri && j.token_uri !== 'https://oauth2.googleapis.com/token') throw bad('the service account key names a token_uri other than https://oauth2.googleapis.com/token');
  return { client_email: j.client_email, private_key: j.private_key, private_key_id: j.private_key_id || null };
}

function credentialsOf(authType, raw) {
  const c = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : null;
  if (!c) throw bad('credentials must be an object');
  switch (authType) {
    case 'bearer': return { token: str(c.token, 'credentials.token', 16384) };
    case 'header': return { value: str(c.value, 'credentials.value', 16384) };
    case 'basic': return { username: str(c.username, 'credentials.username', 512), password: str(c.password, 'credentials.password', 16384) };
    case 'google_service_account': return googleCredential(c.service_account_json);
    default: throw bad(`auth_type must be one of ${AUTH_TYPES.join(', ')}`);
  }
}

function settingsOf(provider, authType, input, current = {}) {
  const out = { ...current };
  if (input.scopes !== undefined) {
    if (!Array.isArray(input.scopes) || input.scopes.length === 0 || input.scopes.length > 20
      || !input.scopes.every((s) => typeof s === 'string' && /^https:\/\/[\x21-\x7e]{1,200}$/.test(s))) {
      throw bad('scopes must be a list of 1-20 https OAuth scope URLs');
    }
    out.scopes = input.scopes;
  }
  if (input.subject !== undefined) {
    if (input.subject !== null && (typeof input.subject !== 'string' || !/^[^@\s]+@[^@\s]+$/.test(input.subject))) throw bad('subject must be an e-mail address or null');
    out.subject = input.subject || null;
  }
  if (authType === 'google_service_account' && !(out.scopes?.length)) throw bad('a google connection needs scopes');
  return out;
}

function row(db, name) {
  return db.prepare('SELECT * FROM api_connections WHERE name = ?').get(name) || null;
}

export function getConnectionRow(name, db = getDb()) {
  if (typeof name !== 'string' || !CONNECTION_NAME_RE.test(name)) return null;
  return row(db, name);
}

/** The view an API may return: no credential, no identity secret. */
export function publicConnection(r) {
  if (!r) return null;
  let settings = {};
  try { settings = JSON.parse(r.settings_json || '{}'); } catch (_) {}
  return {
    name: r.name,
    capability: CONNECTION_PREFIX + r.name,
    provider: r.provider,
    description: r.description,
    base_url: r.base_url,
    auth_type: r.auth_type,
    auth_header: r.auth_header,
    settings,
    has_credentials: !!r.credentials_enc,
    forward_identity: !!r.forward_identity,
    rate_per_minute: r.rate_per_minute,
    max_request_kb: r.max_request_kb,
    max_response_kb: r.max_response_kb,
    timeout_ms: r.timeout_ms,
    enabled: !!r.enabled,
    gateway_path: `/api/service/connections/${r.name}/`,
    created_at: r.created_at,
    updated_at: r.updated_at,
  };
}

export function listConnections(db = getDb()) {
  return db.prepare('SELECT * FROM api_connections ORDER BY name').all().map(publicConnection);
}

/** The decrypted credential, for the gateway only. */
export function credentialsFor(r) {
  return JSON.parse(decrypt(r.credentials_enc));
}

export function identitySecretOf(r) {
  return r.identity_secret_enc ? decrypt(r.identity_secret_enc) : null;
}

const newIdentitySecret = () => randomBytes(32).toString('base64url');

/** Create. Returns { connection, identity_secret? } (the secret only when forward_identity is on, shown this once). */
export function createConnection(input, user, db = getDb()) {
  const b = input && typeof input === 'object' ? input : {};
  const name = str(b.name, 'name', 63).toLowerCase();
  if (!CONNECTION_NAME_RE.test(name)) throw bad('name must be lower-case letters, digits and hyphens, starting with a letter or digit (at most 63)');
  if (row(db, name)) throw new AppError(`A connection named ${name} already exists`, 409, 'CONFLICT');
  const provider = b.provider ?? 'generic';
  if (!PROVIDERS.includes(provider)) throw bad(`provider must be one of ${PROVIDERS.join(', ')}`);
  const preset = PRESETS[provider];
  const authType = b.auth_type ?? preset.auth_type;
  if (!preset.auth_types.includes(authType)) throw bad(`a ${provider} connection uses auth_type ${preset.auth_types.join(' or ')}`);
  const baseUrl = validateBaseUrl(b.base_url ?? preset.base_url);
  preset.checkBaseUrl?.(baseUrl, bad);
  let authHeader = null;
  if (authType === 'header') {
    authHeader = str(b.auth_header, 'auth_header', 64);
    if (!HEADER_NAME_RE.test(authHeader) || RESERVED_HEADERS.has(authHeader.toLowerCase()) || authHeader.toLowerCase().startsWith('x-appcrane-')) {
      throw bad('auth_header must be a plain header name other than Host, Cookie, Connection or an X-AppCrane-* header');
    }
  }
  const creds = credentialsOf(authType, b.credentials);
  const settings = settingsOf(provider, authType, b);
  const forward = b.forward_identity === true;
  const secret = forward ? newIdentitySecret() : null;
  db.prepare(`INSERT INTO api_connections (name, provider, description, base_url, auth_type, auth_header, settings_json, credentials_enc,
      forward_identity, identity_secret_enc, rate_per_minute, max_request_kb, max_response_kb, timeout_ms, enabled, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    name, provider, typeof b.description === 'string' ? b.description.slice(0, 500) : null, baseUrl, authType, authHeader,
    JSON.stringify(settings), encrypt(JSON.stringify(creds)), forward ? 1 : 0, secret ? encrypt(secret) : null,
    limitOf(b, 'rate_per_minute'), limitOf(b, 'max_request_kb'), limitOf(b, 'max_response_kb'), limitOf(b, 'timeout_ms'),
    b.enabled === false ? 0 : 1, user.id,
  );
  logAudit(user.id, null, 'connection-create', { name, provider, base_url: baseUrl, auth_type: authType, forward_identity: forward });
  return { connection: publicConnection(row(db, name)), ...(secret ? { identity_secret: secret } : {}) };
}

/** Update. base_url, provider and auth_type are fixed once created: a new upstream is a new connection that apps request anew. */
export function updateConnection(name, input, user, db = getDb()) {
  const r = getConnectionRow(name, db);
  if (!r) throw new AppError('Connection not found', 404, 'NOT_FOUND');
  const b = input && typeof input === 'object' ? input : {};
  for (const k of ['name', 'provider', 'base_url', 'auth_type', 'auth_header']) {
    if (b[k] !== undefined && b[k] !== r[k]) throw bad(`${k} cannot change: register a new connection for a different upstream`);
  }
  let settings = {};
  try { settings = JSON.parse(r.settings_json || '{}'); } catch (_) {}
  settings = settingsOf(r.provider, r.auth_type, b, settings);
  const credsEnc = b.credentials !== undefined ? encrypt(JSON.stringify(credentialsOf(r.auth_type, b.credentials))) : r.credentials_enc;
  const forward = b.forward_identity === undefined ? !!r.forward_identity : b.forward_identity === true;
  let secret = null;
  let secretEnc = r.identity_secret_enc;
  if (forward && (!secretEnc || b.rotate_identity_secret === true)) { secret = newIdentitySecret(); secretEnc = encrypt(secret); }
  db.prepare(`UPDATE api_connections SET description = ?, settings_json = ?, credentials_enc = ?, forward_identity = ?, identity_secret_enc = ?,
      rate_per_minute = ?, max_request_kb = ?, max_response_kb = ?, timeout_ms = ?, enabled = ?, updated_at = datetime('now') WHERE id = ?`).run(
    b.description !== undefined ? (typeof b.description === 'string' ? b.description.slice(0, 500) : null) : r.description,
    JSON.stringify(settings), credsEnc, forward ? 1 : 0, secretEnc,
    limitOf(b, 'rate_per_minute', r.rate_per_minute), limitOf(b, 'max_request_kb', r.max_request_kb),
    limitOf(b, 'max_response_kb', r.max_response_kb), limitOf(b, 'timeout_ms', r.timeout_ms),
    b.enabled === undefined ? r.enabled : (b.enabled === false ? 0 : 1), r.id,
  );
  logAudit(user.id, null, 'connection-update', {
    name, credentials_rotated: b.credentials !== undefined, forward_identity: forward, identity_secret_rotated: !!secret,
    fields: Object.keys(b).filter((k) => k !== 'credentials'),
  });
  return { connection: publicConnection(row(db, name)), ...(secret ? { identity_secret: secret } : {}) };
}

/** Delete, and end every grant for it: a later connection with the same name starts with none. */
export function deleteConnection(name, user, db = getDb()) {
  const r = getConnectionRow(name, db);
  if (!r) throw new AppError('Connection not found', 404, 'NOT_FOUND');
  const ended = db.transaction(() => {
    const n = db.prepare(`UPDATE capability_requests SET status = CASE WHEN status = 'pending' THEN 'cancelled' ELSE 'revoked' END,
        ended_by = ?, ended_at = datetime('now'), decision_note = COALESCE(decision_note, 'connection deleted')
      WHERE capability = ? AND status IN ('pending', 'approved')`).run(user.id, CONNECTION_PREFIX + name).changes;
    db.prepare('DELETE FROM api_connections WHERE id = ?').run(r.id);
    return n;
  })();
  logAudit(user.id, null, 'connection-delete', { name, grants_ended: ended });
  return { deleted: name, grants_ended: ended };
}
