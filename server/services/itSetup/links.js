import crypto from 'crypto';
import { getDb } from '../../db.js';
import { hashApiKey } from '../encryption.js';

// IT setup links. The link value is opaque (crypto random), shown once, and
// stored as a sha256 hash. Opening it trades the value, sent from the URL
// fragment by the page's script, for a short session held in an HttpOnly
// cookie scoped to /api/it-setup; the link value itself never reaches a
// request line, so access logs and Referer never carry it.

export const SCOPES = ['oidc', 'saml', 'scim', 'domains', 'siem'];
export const LINK_PREFIX = 'acits_';
export const DEFAULT_DAYS = 7;
export const MAX_DAYS = 30;
export const SESSION_MS = 2 * 60 * 60 * 1000;
export const COOKIE = 'cc_itsetup';
export const COOKIE_PATH = '/api/it-setup';

const iso = (ms) => new Date(ms).toISOString();

function badRequest(message) {
  return Object.assign(new Error(message), { status: 400, code: 'VALIDATION' });
}

export function parseScopes(raw) {
  const list = Array.isArray(raw) ? [...new Set(raw.map((s) => String(s).toLowerCase()))] : [];
  if (!list.length) throw badRequest(`Choose at least one scope: ${SCOPES.join(', ')}`);
  const bad = list.filter((s) => !SCOPES.includes(s));
  if (bad.length) throw badRequest(`Unknown scope: ${bad.join(', ')}. Expected ${SCOPES.join(', ')}`);
  return list;
}

export function createLink({ label, scopes, expiresInDays = DEFAULT_DAYS, userId }, db = getDb()) {
  const name = String(label || '').trim().slice(0, 120);
  if (!name) throw badRequest('label is required (for example the customer or the IT contact)');
  const days = Number(expiresInDays);
  if (!Number.isFinite(days) || days <= 0 || days > MAX_DAYS) throw badRequest(`expires_in_days must be more than 0 and at most ${MAX_DAYS}`);
  const list = parseScopes(scopes);
  const token = LINK_PREFIX + crypto.randomBytes(32).toString('base64url');
  const id = db.prepare('INSERT INTO it_setup_links (token_hash, label, scopes, created_by, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(hashApiKey(token), name, JSON.stringify(list), userId, iso(Date.now() + days * 86400_000)).lastInsertRowid;
  return { id, token };
}

export function getLink(id, db = getDb()) {
  return /^\d+$/.test(String(id)) ? db.prepare('SELECT * FROM it_setup_links WHERE id = ?').get(Number(id)) : undefined;
}

export function linkState(link, now = Date.now()) {
  if (link.revoked_at) return 'revoked';
  if (link.completed_at) return 'completed';
  if (Date.parse(link.expires_at) <= now) return 'expired';
  return 'active';
}

export function linkView(link, db = getDb()) {
  const counts = Object.fromEntries(db.prepare('SELECT status, COUNT(*) AS n FROM it_setup_changes WHERE link_id = ? GROUP BY status')
    .all(link.id).map((r) => [r.status, r.n]));
  return {
    id: link.id, label: link.label, scopes: JSON.parse(link.scopes), state: linkState(link),
    created_by: link.created_by, created_at: link.created_at, expires_at: link.expires_at,
    revoked_at: link.revoked_at, first_opened_at: link.first_opened_at, last_used_at: link.last_used_at,
    completed_at: link.completed_at, changes: counts,
  };
}

export function listLinks(db = getDb()) {
  return db.prepare('SELECT * FROM it_setup_links ORDER BY id DESC LIMIT 200').all().map((l) => linkView(l, db));
}

export function revokeLink(link, userId, db = getDb()) {
  db.prepare("UPDATE it_setup_links SET revoked_at = COALESCE(revoked_at, datetime('now')), revoked_by = COALESCE(revoked_by, ?) WHERE id = ?").run(userId, link.id);
  db.prepare('DELETE FROM it_setup_sessions WHERE link_id = ?').run(link.id);
}

/** Trade a link value for a session. Returns { link, session } or { refused: state }. */
export function openSession(token, ip, db = getDb()) {
  if (typeof token !== 'string' || !token.startsWith(LINK_PREFIX) || token.length > 200) return { refused: 'invalid' };
  const link = db.prepare('SELECT * FROM it_setup_links WHERE token_hash = ?').get(hashApiKey(token));
  if (!link) return { refused: 'invalid' };
  const state = linkState(link);
  if (state !== 'active') return { refused: state, link };
  const session = crypto.randomBytes(32).toString('base64url');
  const expires = Math.min(Date.now() + SESSION_MS, Date.parse(link.expires_at));
  db.prepare('INSERT INTO it_setup_sessions (link_id, token_hash, expires_at, ip) VALUES (?, ?, ?, ?)')
    .run(link.id, hashApiKey(session), iso(expires), ip || null);
  db.prepare("UPDATE it_setup_links SET first_opened_at = COALESCE(first_opened_at, datetime('now')), last_used_at = datetime('now') WHERE id = ?").run(link.id);
  db.prepare("DELETE FROM it_setup_sessions WHERE expires_at < ?").run(iso(Date.now()));
  return { link, session, expiresAt: expires, firstOpen: !link.first_opened_at };
}

/** The session and its link for a cookie value, when both are still good. */
export function resolveSession(value, db = getDb()) {
  if (!value || value.length > 100) return null;
  const hash = hashApiKey(value);
  const row = db.prepare('SELECT s.id AS session_id, s.expires_at AS session_expires, l.* FROM it_setup_sessions s JOIN it_setup_links l ON l.id = s.link_id WHERE s.token_hash = ?').get(hash);
  if (!row || Date.parse(row.session_expires) <= Date.now() || linkState(row) !== 'active') return null;
  return { sessionId: row.session_id, sessionHash: hash, link: row, scopes: JSON.parse(row.scopes) };
}

export function csrfFor(sessionHash) {
  return crypto.createHmac('sha256', process.env.ENCRYPTION_KEY).update(`it-setup-csrf|${sessionHash}`).digest('base64url');
}

export function csrfOk(sessionHash, header) {
  const want = Buffer.from(csrfFor(sessionHash));
  const got = Buffer.from(String(header || ''));
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

export function endSessions(linkId, db = getDb()) {
  db.prepare('DELETE FROM it_setup_sessions WHERE link_id = ?').run(linkId);
}
