import { isIPv4, isIPv6 } from 'node:net';

// APPCRANE-DB, the second chain AppCrane's server owns. Host hardening's
// DOCKER-USER skeleton jumps here for every forwarded flow Docker's DNAT sent
// to the default bridge (`-o docker0 -m conntrack --ctstate DNAT`), which is
// where the managed database servers live. An app reaches them as
// host.docker.internal:<port>; Docker rewrites that to the server's container
// address before FORWARD, so the port is matched on conntrack's ORIGINAL
// destination port, and the source is still the app container's own address.
//
// Per port with an allowlist: one RETURN per allowed source, then a DROP. A
// port with no lines falls through, and an empty chain returns everything:
// this chain fails OPEN, and every isolation guarantee still lives in the
// engine (credentials and certificates).

export const DB_CHAIN = 'APPCRANE-DB';
export const DB_HELPER = '/usr/local/lib/appcrane/appcrane-db-chain.sh';
export const DB_HELPER_MAX_ARGS = 2048;
export const DB_FAMILIES = Object.freeze([
  { id: 'v4', bin: 'iptables', restore: 'iptables-restore', bits: 32 },
  { id: 'v6', bin: 'ip6tables', restore: 'ip6tables-restore', bits: 128 },
]);

const V4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const V6_RE = /^[0-9a-f:]+$/;

export const validPort = (p) => Number.isInteger(p) && p >= 1 && p <= 65535;
export const validV4 = (ip) => typeof ip === 'string' && V4_RE.test(ip) && isIPv4(ip);
export const validV6 = (ip) => typeof ip === 'string' && V6_RE.test(ip) && isIPv6(ip);
export const familyOf = (ip) => (validV4(ip) ? 'v4' : validV6(ip) ? 'v6' : null);

function famById(id) { return DB_FAMILIES.find(f => f.id === id); }

/** The closed ports, sorted, each with its sorted, de-duplicated sources. */
export function closedPorts(plan) {
  const out = new Map();
  for (const p of plan) {
    if (p.state !== 'closed') continue;
    if (!validPort(p.port)) throw new Error(`refusing to write a rule for port ${p.port}`);
    const set = out.get(p.port) || new Set();
    for (const ip of p.allow) {
      if (!familyOf(ip)) throw new Error(`refusing to write a rule for source ${JSON.stringify(ip)}`);
      set.add(ip);
    }
    out.set(p.port, set);
  }
  return [...out.entries()].sort((a, b) => a[0] - b[0]).map(([port, set]) => ({ port, allow: [...set].sort() }));
}

export const LOG_PREFIX = 'APPCRANE-DB-WOULD-DROP ';
export const LOG_LIMIT = Object.freeze({ rate: '10/min', burst: 10 });

const match = (port) => `-p tcp -m conntrack --ctorigdstport ${port} --ctdir ORIGINAL`;

/**
 * The rule lines one family gets, in chain order. Per port with an allowlist,
 * one RETURN per allowed source, then:
 *   enforce  a DROP
 *   observe  a rule with no target (it only counts what enforce would drop)
 *            and a rate-limited LOG, after which the packet falls through
 *   off      nothing at all: the chain is empty
 */
export function dbRuleLines(famId, plan, mode = 'enforce') {
  const fam = famById(famId);
  const lines = [];
  if (mode === 'off') return lines;
  for (const { port, allow } of closedPorts(plan)) {
    for (const ip of allow) {
      if (familyOf(ip) !== famId) continue;
      lines.push(`-A ${DB_CHAIN} -s ${ip}/${fam.bits} ${match(port)} -j RETURN`);
    }
    if (mode === 'observe') {
      lines.push(`-A ${DB_CHAIN} ${match(port)}`);
      lines.push(`-A ${DB_CHAIN} ${match(port)} -m limit --limit ${LOG_LIMIT.rate} --limit-burst ${LOG_LIMIT.burst} -j LOG --log-prefix "${LOG_PREFIX}"`);
    } else {
      lines.push(`-A ${DB_CHAIN} ${match(port)} -j DROP`);
    }
  }
  return lines;
}

// --noflush leaves every other chain alone; declaring the chain empties it and
// COMMIT swaps it in one step, so no packet sees a half-written list.
export function renderDbRestore(famId, plan, mode = 'enforce') {
  return ['*filter', `:${DB_CHAIN} - [0:0]`, ...dbRuleLines(famId, plan, mode), 'COMMIT', ''].join('\n');
}

const LINE_RE = new RegExp(`^-A ${DB_CHAIN}(?: -s (\\S+?)(?:/(32|128))?)? -p tcp -m conntrack --ctorigdstport (\\d+) --ctdir ORIGINAL(?: -j (RETURN|DROP))?$`);
const LOG_RE = new RegExp(`^-A ${DB_CHAIN} -p tcp -m conntrack --ctorigdstport (\\d+) --ctdir ORIGINAL -m limit --limit ${LOG_LIMIT.rate.replace('/', '\\/')} --limit-burst ${LOG_LIMIT.burst} -j LOG --log-prefix "${LOG_PREFIX}"$`);

/** { exists, rules: [{src|null, port, target: RETURN|DROP|COUNT|LOG}], foreign: [lines] } from `iptables -S`. */
export function parseDbChain(text) {
  const out = { exists: false, rules: [], foreign: [] };
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trim();
    if (line === `-N ${DB_CHAIN}`) { out.exists = true; continue; }
    if (!line.startsWith(`-A ${DB_CHAIN} `)) continue;
    out.exists = true;
    const log = LOG_RE.exec(line);
    if (log) { out.rules.push({ src: null, port: Number(log[1]), target: 'LOG' }); continue; }
    const m = LINE_RE.exec(line);
    const target = m ? (m[4] || 'COUNT') : null;
    if (m && (target === 'RETURN') === Boolean(m[1])) out.rules.push({ src: m[1] ? m[1].toLowerCase() : null, port: Number(m[3]), target });
    else out.foreign.push(line);
  }
  return out;
}

export function sameRules(parsed, famId, plan, mode = 'enforce') {
  const want = parseDbChain(dbRuleLines(famId, plan, mode).join('\n')).rules;
  const key = (r) => `${r.src}|${r.port}|${r.target}`;
  return parsed.rules.length === want.length && parsed.rules.every((r, i) => key(r) === key(want[i]));
}

export function dbCounterArgs() { return ['-w', '-L', DB_CHAIN, '-v', '-x', '-n']; }

// prot is printed as 6 (measured, iptables 1.8.10 on ubuntu:24.04) or tcp.
const COUNTER_RE = /^\s*(\d+)\s+\d+\s+(?:(\S+)\s+)?(?:tcp|6)\s.*\bctorigdstport (\d+)\b/;

/**
 * Packets per port on the observe-mode counting rules (the ones with no
 * target), from `iptables -L APPCRANE-DB -v -x -n`: what enforce would have
 * dropped since the chain was last written.
 */
export function parseDbCounters(text) {
  const out = new Map();
  for (const line of String(text || '').split('\n')) {
    const m = COUNTER_RE.exec(line);
    if (!m || m[2] !== undefined) continue;
    const port = Number(m[3]);
    out.set(port, (out.get(port) || 0) + Number(m[1]));
  }
  return out;
}

/**
 * sudo argv for the root helper: allow:<port>:<ip> for each source, then
 * close:<port> (enforce) or log:<port> (observe). off passes no port, which
 * empties the chain.
 */
export function dbHelperArgs(plan, mode = 'enforce') {
  const args = [];
  if (mode !== 'off') {
    for (const { port, allow } of closedPorts(plan)) {
      for (const ip of allow) args.push(`allow:${port}:${ip}`);
      args.push(`${mode === 'observe' ? 'log' : 'close'}:${port}`);
    }
  }
  if (args.length > DB_HELPER_MAX_ARGS) throw new Error(`${args.length} arguments is more than the helper takes (${DB_HELPER_MAX_ARGS})`);
  return ['-n', DB_HELPER, ...args];
}
