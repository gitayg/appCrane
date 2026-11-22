import { createHash } from 'crypto';
import { getDb } from '../../db.js';
import { readPolicy } from './config.js';
import { KINDS, signal } from './signals.js';

// Credential-stuffing signal: many DISTINCT accounts (or API keys) failing
// from one network in a window. The network is the /24 of an IPv4 address
// (or the /64 of an IPv6 one), since there is no ASN data offline. Crossing
// the threshold flags the network for a penalty period: one security event,
// and the password sign-in throttle for addresses in it drops from 5 per
// minute to stuffing_logins_per_minute. In memory, one process, bounded.
//
// The address is clientIp()'s, so X-Forwarded-For counts only from a trusted
// hop (utils/clientIp.js); a client cannot pick its own network.

const MAX_NETS = 20_000;
const MAX_IDS_PER_NET = 2_000;
const nets = new Map();     // net -> { hits: [{ t, id }] }
const flagged = new Map();  // net -> { until, flaggedAt, accounts }
const tight = new Map();    // ip -> { count, resetAt }

export function networkOf(ip) {
  let s = String(ip || '').trim();
  if (s.startsWith('::ffff:') && s.includes('.')) s = s.slice(7);
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(s);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.0/24`;
  if (s.includes(':')) {
    const [head] = s.split('::');
    const groups = head.split(':').filter(Boolean);
    while (groups.length < 4) groups.push('0');
    return `${groups.slice(0, 4).join(':')}::/64`;
  }
  return s || 'unknown';
}

const idHash = (v) => createHash('sha256').update(String(v)).digest('hex').slice(0, 24);

/** Note one failed sign-in from ip for an identifier (a login name or an API key hash). */
export function noteFailure(ip, identifier, { method = 'password' } = {}, nowMs = Date.now()) {
  const policy = readPolicy(getDb());
  const windowMs = policy.stuffing_window_minutes * 60_000;
  const net = networkOf(ip);
  let rec = nets.get(net);
  if (!rec) {
    if (nets.size >= MAX_NETS) sweep(nowMs, windowMs);
    if (nets.size >= MAX_NETS) nets.delete(nets.keys().next().value);
    rec = { hits: [] };
    nets.set(net, rec);
  }
  rec.hits = rec.hits.filter((h) => nowMs - h.t < windowMs);
  rec.hits.push({ t: nowMs, id: `${method}:${idHash(identifier)}` });
  if (rec.hits.length > MAX_IDS_PER_NET) rec.hits.splice(0, rec.hits.length - MAX_IDS_PER_NET);
  const distinct = new Set(rec.hits.map((h) => h.id)).size;
  const f = flagged.get(net);
  if (distinct >= policy.stuffing_accounts && !(f && f.until > nowMs)) {
    const until = nowMs + policy.stuffing_penalty_minutes * 60_000;
    flagged.set(net, { until, flaggedAt: nowMs, accounts: distinct, lastIp: String(ip || '') });
    signal({
      kind: KINDS.stuffing, severity: 'critical',
      summary: `Possible credential stuffing: ${distinct} different accounts failed sign-in from ${net} in ${policy.stuffing_window_minutes} min`,
      data: { network: net, ip: String(ip || ''), accounts: distinct, window_minutes: policy.stuffing_window_minutes, penalty_minutes: policy.stuffing_penalty_minutes, method },
    });
    return { flagged: true, just_flagged: true, distinct };
  }
  return { flagged: !!(f && f.until > nowMs), just_flagged: false, distinct };
}

export function isFlagged(ip, nowMs = Date.now()) {
  const f = flagged.get(networkOf(ip));
  return !!(f && f.until > nowMs);
}

/**
 * The raised throttle. 0 when the request may go on; otherwise the seconds
 * to wait. Only bites while the address's network is flagged.
 */
export function elevatedThrottle(ip, nowMs = Date.now()) {
  if (!isFlagged(ip, nowMs)) return 0;
  const limit = readPolicy(getDb()).stuffing_logins_per_minute;
  const key = String(ip || 'unknown');
  const rec = tight.get(key);
  if (!rec || nowMs > rec.resetAt) {
    if (tight.size > MAX_NETS) for (const [k, r] of tight) if (nowMs > r.resetAt) tight.delete(k);
    tight.set(key, { count: 1, resetAt: nowMs + 60_000 });
    return 0;
  }
  if (rec.count >= limit) return Math.max(1, Math.ceil((rec.resetAt - nowMs) / 1000));
  rec.count++;
  return 0;
}

export function listFlagged(nowMs = Date.now()) {
  const out = [];
  for (const [net, f] of flagged) {
    if (f.until > nowMs) out.push({ network: net, accounts: f.accounts, flagged_at: new Date(f.flaggedAt).toISOString(), until: new Date(f.until).toISOString() });
  }
  return out;
}

export function clearFlag(net) {
  return flagged.delete(net);
}

function sweep(nowMs, windowMs) {
  for (const [k, rec] of nets) if (!rec.hits.some((h) => nowMs - h.t < windowMs)) nets.delete(k);
  for (const [k, f] of flagged) if (f.until <= nowMs) flagged.delete(k);
}

export function _resetStuffingForTests() {
  nets.clear(); flagged.clear(); tight.clear();
}
