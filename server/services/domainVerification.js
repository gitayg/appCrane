import crypto from 'crypto';
import { Resolver } from 'dns/promises';
import { isIP } from 'net';
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';

// DNS TXT domain verification (WorkOS-style). Adding a domain issues a random
// token; the domain is verified once a TXT record on the domain itself reads
// appcrane-domain-verification=<token>. Checked on demand and by the
// 'domain-verification' job.
//
// What it gates: the OIDC "join without approval" list. A domain entry there
// lets a new person in only while its row here is verified or legacy (on the
// list before this existed); otherwise the person goes to the sign-up request
// queue. A verified domain whose record later disappears or changes drops to
// 'unverified' (it may have changed hands); a timeout or resolver error never
// changes a status.

export const TXT_PREFIX = 'appcrane-domain-verification=';
export const DEFAULT_TIMEOUT_MS = 5000;
const ADMITS = new Set(['verified', 'legacy']);
const TICK_MS = 60 * 60 * 1000;
const BATCH = 50;

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/** A lower-cased domain name, or throws 400. */
export function normalizeDomain(raw) {
  const d = String(raw || '').trim().toLowerCase().replace(/^@/, '').replace(/\.$/, '');
  const bad = () => { throw Object.assign(new Error(`Not a domain name: ${String(raw).slice(0, 100)}`), { status: 400, code: 'VALIDATION' }); };
  if (!d || d.length > 253 || isIP(d) || !d.includes('.')) bad();
  if (!d.split('.').every((l) => LABEL.test(l))) bad();
  return d;
}

function isDomainEntry(entry) {
  return entry && entry !== '*' && !entry.includes('@');
}

export function listDomains(db = getDb()) {
  return db.prepare('SELECT * FROM sso_domains ORDER BY domain').all();
}

export function getDomain(id, db = getDb()) {
  return /^\d+$/.test(String(id)) ? db.prepare('SELECT * FROM sso_domains WHERE id = ?').get(Number(id)) : undefined;
}

/** Add a domain as pending (or return the existing row). */
export function addDomain(raw, { userId = null, linkId = null } = {}, db = getDb()) {
  const domain = normalizeDomain(raw);
  const existing = db.prepare('SELECT * FROM sso_domains WHERE domain = ?').get(domain);
  if (existing) return { row: existing, created: false };
  const token = crypto.randomBytes(16).toString('base64url');
  const id = db.prepare('INSERT INTO sso_domains (domain, token, status, created_by, created_by_link) VALUES (?, ?, ?, ?, ?)')
    .run(domain, token, 'pending', userId, linkId).lastInsertRowid;
  return { row: db.prepare('SELECT * FROM sso_domains WHERE id = ?').get(id), created: true };
}

/** Every domain entry on an allowed list gets a row (pending when new). */
export function registerListedDomains(list, userId, db = getDb()) {
  for (const entry of list) {
    if (!isDomainEntry(entry)) continue;
    try { addDomain(entry, { userId }, db); } catch (e) { if (e.status !== 400) throw e; }
  }
}

/**
 * The allowed list as sign-up may use it: '*' and single addresses as they
 * are, domain entries only when verified or legacy.
 */
export function effectiveAllowedDomains(list, db = getDb()) {
  const domains = list.filter(isDomainEntry);
  if (!domains.length) return list;
  const ok = new Set(db.prepare(`SELECT domain FROM sso_domains WHERE status IN ('verified', 'legacy') AND domain IN (${domains.map(() => '?').join(',')})`)
    .all(...domains).map((r) => r.domain));
  return list.filter((e) => !isDomainEntry(e) || ok.has(e));
}

/** The domain entries on a list that do not let anyone join yet, with their status. */
export function domainWarnings(list, db = getDb()) {
  const out = [];
  for (const entry of list.filter(isDomainEntry)) {
    const row = db.prepare('SELECT domain, status FROM sso_domains WHERE domain = ?').get(entry);
    const status = row?.status || 'pending';
    if (status === 'legacy') out.push({ domain: entry, status, message: 'Added before domain verification; still lets people join. Verify it with a DNS TXT record.' });
    else if (status !== 'verified') out.push({ domain: entry, status, message: 'Not verified: new people from this domain wait for approval.' });
  }
  return out;
}

function defaultResolveTxt(name, timeoutMs) {
  const r = new Resolver({ timeout: timeoutMs, tries: 1 });
  return r.resolveTxt(name);
}

/**
 * Look the record up. Returns { result, detail } where result is verified,
 * wrong_token, not_found, timeout or error. `resolveTxt(name, timeoutMs)` is
 * injectable; the default is node:dns/promises with one try.
 */
export async function lookupToken(domain, token, { resolveTxt = defaultResolveTxt, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error('DNS lookup timed out'), { code: 'ETIMEOUT' })), timeoutMs);
  });
  try {
    const records = await Promise.race([resolveTxt(domain, timeoutMs), deadline]);
    const values = (records || []).map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)).trim());
    if (values.includes(TXT_PREFIX + token)) return { result: 'verified' };
    const ours = values.filter((v) => v.startsWith(TXT_PREFIX));
    if (ours.length) return { result: 'wrong_token', detail: `${ours.length} ${TXT_PREFIX} record(s), none with this domain's token` };
    return { result: 'not_found', detail: 'no TXT record with the verification token' };
  } catch (e) {
    if (['ENOTFOUND', 'ENODATA', 'NXDOMAIN'].includes(e.code)) return { result: 'not_found', detail: e.code };
    if (e.code === 'ETIMEOUT' || e.code === 'ETIMEDOUT') return { result: 'timeout', detail: 'DNS lookup timed out' };
    return { result: 'error', detail: String(e.code || e.message).slice(0, 120) };
  } finally {
    clearTimeout(timer);
  }
}

/** Check one row and store the outcome. Returns the updated row and result. */
export async function checkDomain(row, opts = {}, db = getDb()) {
  const { result, detail } = await lookupToken(row.domain, row.token, opts);
  let status = row.status;
  if (result === 'verified') status = 'verified';
  else if ((result === 'wrong_token' || result === 'not_found') && row.status === 'verified') status = 'unverified';
  db.prepare(`UPDATE sso_domains SET status = ?, last_checked_at = datetime('now'), last_result = ?,
    verified_at = CASE WHEN ? = 'verified' AND status <> 'verified' THEN datetime('now') ELSE verified_at END WHERE id = ?`)
    .run(status, detail ? `${result}: ${detail}` : result, status, row.id);
  return { row: db.prepare('SELECT * FROM sso_domains WHERE id = ?').get(row.id), result, changed: status !== row.status };
}

export function domainView(row) {
  return {
    id: row.id, domain: row.domain, status: row.status,
    admits_signups: ADMITS.has(row.status),
    txt_name: row.domain, txt_value: TXT_PREFIX + row.token,
    verified_at: row.verified_at, last_checked_at: row.last_checked_at, last_result: row.last_result,
    created_at: row.created_at, created_by_link: row.created_by_link,
  };
}

/** One pass of the job: the rows checked longest ago first. */
export async function runDomainChecks(opts = {}, db = getDb()) {
  const rows = db.prepare('SELECT * FROM sso_domains ORDER BY last_checked_at IS NOT NULL, last_checked_at LIMIT ?').all(BATCH);
  const changed = [];
  for (const row of rows) {
    const r = await checkDomain(row, opts, db);
    if (r.changed) changed.push({ domain: row.domain, from: row.status, to: r.row.status });
  }
  if (changed.length) log.info(`[domain-verification] ${changed.map((c) => `${c.domain} ${c.from} -> ${c.to}`).join(', ')}`);
  setJobDetail('domain-verification', { checked: rows.length, changed: changed.length, at: new Date().toISOString() });
  return { checked: rows.length, changed };
}

let timer = null;
export function startDomainVerifier() {
  if (timer) return;
  jobStarted('domain-verification', { cadenceMs: TICK_MS });
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try { await trackJob('domain-verification', () => runDomainChecks()); }
    catch (e) { log.error(`[domain-verification] pass failed: ${e.message}`); }
    finally { running = false; }
  };
  timer = setInterval(tick, TICK_MS);
  timer.unref?.();
}
