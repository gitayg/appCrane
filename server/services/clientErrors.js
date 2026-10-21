import { createHash } from 'crypto';
import { getDb } from '../db.js';
import { recordClientErrorEvent } from './eventStore.js';

// Browser error reports (POST /api/client-errors), aggregated by fingerprint.
// Everything that reaches the table has been through scrub() here, whatever
// the browser claims it already did.

export const LIMITS = Object.freeze({
  message: 500,
  stack: 4000,
  page: 300,
  version: 40,
  userAgent: 300,
  listedPages: 10,
  listedVersions: 10,
  maxRows: 500,
  retentionDays: 30,
});

export const SOURCES = Object.freeze(['admin', 'topbar', 'login']);

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const VERSION_RE = /^v?[0-9A-Za-z.+_-]{1,40}$/;

const SCRUBBERS = [
  [/\bdhk_[A-Za-z0-9_-]+/g, 'dhk_[redacted]'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [redacted]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?/g, '[redacted-jwt]'],
  [/((?:https?:)?\/\/[^\s?#'"()<>]+|\/[^\s?#'"()<>]*)[?#][^\s'"()<>]*/g, '$1'],
  [/\b((?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|passwd)["']?\s*[:=]\s*["']?)[^\s"'&,;]+/gi, '$1[redacted]'],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[email]'],
  [/\b[0-9a-fA-F]{32,}\b/g, '[redacted-hex]'],
  [/[A-Za-z0-9+_-]{40,}={0,2}/g, m => (/\d/.test(m) && /[A-Za-z]/.test(m) ? '[redacted-b64]' : m)],
];

export function scrub(value) {
  if (typeof value !== 'string' || !value) return '';
  let s = value;
  for (const [re, rep] of SCRUBBERS) s = s.replace(re, rep);
  return s;
}

const clip = (s, n) => (s.length > n ? s.slice(0, n) : s);

export function cleanPage(raw) {
  if (typeof raw !== 'string') return null;
  const path = raw.split(/[?#]/, 1)[0];
  if (!path.startsWith('/')) return null;
  return clip(scrub(path), LIMITS.page);
}

function topFrame(stack) {
  for (const line of stack.split('\n')) {
    const t = line.trim();
    if (/^at\s|@|:\d+:\d+/.test(t)) return t.replace(/:\d+:\d+\)?$/, '');
  }
  return '';
}

export function fingerprintOf(message, stack) {
  return createHash('sha256').update(message + '\n' + topFrame(stack || '')).digest('hex').slice(0, 32);
}

/**
 * Validate + scrub + truncate a raw report body. Returns null when it is not a
 * report at all (no message), so the route can answer 400.
 */
export function normalizeReport(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  if (typeof body.message !== 'string' || !body.message.trim()) return null;
  const message = clip(scrub(body.message.trim()), LIMITS.message);
  const stack = typeof body.stack === 'string' ? clip(scrub(body.stack), LIMITS.stack) : '';
  const version = typeof body.version === 'string' && VERSION_RE.test(body.version) ? body.version : null;
  const userAgent = typeof body.userAgent === 'string' ? clip(scrub(body.userAgent), LIMITS.userAgent) : null;
  const source = SOURCES.includes(body.source) ? body.source : 'admin';
  const appSlug = typeof body.appSlug === 'string' && SLUG_RE.test(body.appSlug) ? body.appSlug : null;
  return { message, stack, page: cleanPage(body.page), version, userAgent, source, appSlug };
}

function pushCapped(json, value, cap) {
  let list;
  try { list = JSON.parse(json || '[]'); } catch { list = []; }
  if (!Array.isArray(list)) list = [];
  if (!value) return JSON.stringify(list);
  const next = [value, ...list.filter(v => v !== value)].slice(0, cap);
  return JSON.stringify(next);
}

let lastPrune = 0;

export function pruneClientErrors(now = Date.now()) {
  lastPrune = now;
  const db = getDb();
  const cutoff = new Date(now - LIMITS.retentionDays * 86_400_000).toISOString().replace('T', ' ').slice(0, 19);
  return db.prepare('DELETE FROM client_errors WHERE last_seen < ?').run(cutoff).changes;
}

function maybePrune() {
  if (Date.now() - lastPrune > 3_600_000) pruneClientErrors();
}

export function recordClientError(report, userId = null) {
  const db = getDb();
  maybePrune();
  const fingerprint = fingerprintOf(report.message, report.stack);
  const existing = db.prepare('SELECT id, count, pages, versions FROM client_errors WHERE fingerprint = ?').get(fingerprint);
  if (existing) {
    db.prepare(`
      UPDATE client_errors
         SET count = count + 1, last_seen = datetime('now'), last_page = COALESCE(?, last_page),
             pages = ?, versions = ?, user_agent = COALESCE(?, user_agent),
             last_user_id = COALESCE(?, last_user_id), app_slug = COALESCE(?, app_slug),
             stack = CASE WHEN stack IS NULL OR stack = '' THEN ? ELSE stack END
       WHERE id = ?
    `).run(
      report.page,
      pushCapped(existing.pages, report.page, LIMITS.listedPages),
      pushCapped(existing.versions, report.version, LIMITS.listedVersions),
      report.userAgent, userId, report.appSlug, report.stack, existing.id,
    );
    recordClientErrorEvent(existing.id, report, existing.count + 1, userId);
    return { fingerprint, created: false };
  }
  const inserted = db.prepare(`
    INSERT INTO client_errors (fingerprint, message, stack, source, last_page, pages, versions, user_agent, last_user_id, app_slug)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    fingerprint, report.message, report.stack, report.source, report.page,
    pushCapped('[]', report.page, LIMITS.listedPages),
    pushCapped('[]', report.version, LIMITS.listedVersions),
    report.userAgent, userId, report.appSlug,
  );
  const over = db.prepare('SELECT COUNT(*) AS n FROM client_errors').get().n - LIMITS.maxRows;
  if (over > 0) {
    db.prepare('DELETE FROM client_errors WHERE id IN (SELECT id FROM client_errors ORDER BY last_seen ASC, id ASC LIMIT ?)').run(over);
  }
  recordClientErrorEvent(inserted.lastInsertRowid, report, 1, userId);
  return { fingerprint, created: true };
}

export function listClientErrors(limit = 200) {
  maybePrune();
  const rows = getDb().prepare(`
    SELECT ce.id, ce.fingerprint, ce.message, ce.stack, ce.source, ce.count, ce.first_seen, ce.last_seen,
           ce.last_page, ce.pages, ce.versions, ce.user_agent, ce.app_slug,
           u.name AS last_user_name, u.email AS last_user_email
      FROM client_errors ce
      LEFT JOIN users u ON u.id = ce.last_user_id
     ORDER BY ce.last_seen DESC, ce.id DESC
     LIMIT ?
  `).all(limit);
  return rows.map(r => ({
    ...r,
    pages: safeList(r.pages),
    versions: safeList(r.versions),
  }));
}

function safeList(json) {
  try { const v = JSON.parse(json || '[]'); return Array.isArray(v) ? v : []; } catch { return []; }
}

export function resolveClientError(id) {
  return getDb().prepare('DELETE FROM client_errors WHERE id = ?').run(id).changes;
}

export function clearClientErrors() {
  return getDb().prepare('DELETE FROM client_errors').run().changes;
}
