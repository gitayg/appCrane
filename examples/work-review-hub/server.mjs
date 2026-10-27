// Work Review hub — receives the daily redacted snapshots that the work-review
// skill uploads, and shows each developer their trend (and admins the team's).
//
// Runs as an ordinary AppCrane app (auth_mode default, i.e. behind forward_auth).
// It has no login of its own: AppCrane verifies the caller — SSO session in a
// browser, the developer's dhk_uak_* app sign-in key from the uploader — and injects
// X-AppCrane-User-* headers, stripping any the client sent. So identity here is
// read only from those headers, and a request without them is refused: it did
// not come through the platform.
//
// Storage: DATA_DIR/reports/<user-hash>/<YYYY-MM-DD>.json, one snapshot per user
// per day (re-uploads the same day replace it), pruned after RETENTION_DAYS.

import { createServer } from 'http';
import { mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync, existsSync, renameSync } from 'fs';
import { join, dirname } from 'path';
import { createHash } from 'crypto';
import { fileURLToPath } from 'url';

const VERSION = '1.0.0';
const HERE = dirname(fileURLToPath(import.meta.url));
const DATA = join(process.env.DATA_DIR || '/data', 'reports');
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS || 180);
const MAX_BODY = 64 * 1024;
const SCHEMA = 'work-review/v1';
const INDEX = readFileSync(join(HERE, 'index.html'));

// ── identity ─────────────────────────────────────────────────────
function who(req) {
  const email = String(req.headers['x-appcrane-user-email'] || req.headers['x-appcrane-user'] || '').trim().toLowerCase();
  if (!email || !email.includes('@')) return null;
  let name = email;
  try { name = decodeURIComponent(String(req.headers['x-appcrane-user-name'] || '')) || email; } catch {}
  const appRole = String(req.headers['x-appcrane-app-role'] || '');
  return { email, name, admin: appRole === 'owner' || appRole === 'admin' };
}
const userDir = email => join(DATA, createHash('sha256').update(email).digest('hex').slice(0, 32));

// ── validation: re-check everything the uploader promises ────────
// The uploader allow-lists its fields, but this is the trust boundary: an
// older or modified client must not be able to park arbitrary data here.
const isNum = v => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v < 1e13;
function nums(o, keys, path) {
  if (!o || typeof o !== 'object') throw new Error(`${path} missing`);
  const out = {};
  for (const k of keys) { if (!isNum(o[k] ?? 0)) throw new Error(`${path}.${k} not a number`); out[k] = o[k] ?? 0; }
  return out;
}
const SECRETISH = /(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|dhk_[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|-----BEGIN|eyJ[A-Za-z0-9_-]{10,}\.)/;
function excerpt(s) {
  if (typeof s !== 'string' || s.length > 200) throw new Error('excerpt too long');
  if (SECRETISH.test(s)) throw new Error('excerpt looks like it contains a secret');
  return s;
}
export function validate(p) {
  if (!p || p.schema !== SCHEMA) throw new Error(`schema must be ${SCHEMA}`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(p.day)) throw new Error('bad day');
  const g = (o, path) => nums(o, ['prompts', 'medianCost', 'medianUsd', 'medianExploreBeforeFirstEdit', 'reworkRate'], path);
  const Q = p.instructionQuality || {}, O = p.overcomplication || {}, T = p.totals || {};
  if (!Array.isArray(Q.costliestBadPrompts) || Q.costliestBadPrompts.length > 5) throw new Error('costliestBadPrompts must be ≤5');
  if (!Array.isArray(O.returnsCurve) || O.returnsCurve.length > 5) throw new Error('returnsCurve must be ≤5');
  return {
    schema: SCHEMA, day: p.day, windowDays: nums(p, ['windowDays'], '').windowDays,
    machine: /^[a-f0-9]{12}$/.test(p.machine) ? p.machine : 'unknown',
    totals: {
      ...nums(T, ['sessions', 'subagentRuns', 'turns', 'toolCalls', 'userPrompts', 'cacheHitRate', 'toolErrors', 'errorRate', 'redundantReads',
        'idleCommandReruns', 'retryLoops', 'editMisses', 'permissionDenials', 'oversizedOutputs', 'corrections', 'interrupts', 'compactions',
        'searchBursts', 'parallelToolTurnShare'], 'totals'),
      tokens: nums(T.tokens, ['input', 'output', 'cacheRead', 'cacheWrite'], 'totals.tokens'),
      wastedTokensEstimate: nums(T.wastedTokensEstimate, ['redundantReads', 'idleReruns', 'errorOutputs'], 'totals.wastedTokensEstimate'),
      usd: nums(T, ['usd'], 'totals').usd,
    },
    instructionQuality: {
      ...nums(Q, ['totalCost', 'reworkCost', 'reworkShare', 'totalUsd', 'reworkUsd'], 'instructionQuality'),
      vague: g(Q.vague, 'vague'), anchored: g(Q.anchored, 'anchored'), withCriteria: g(Q.withCriteria, 'withCriteria'), withoutCriteria: g(Q.withoutCriteria, 'withoutCriteria'),
      costliestBadPrompts: Q.costliestBadPrompts.map(b => ({
        ...nums(b, ['cost', 'usd'], 'prompt'),
        why: (Array.isArray(b.why) ? b.why : []).slice(0, 4).map(w => String(w).replace(/[^\w\s;-]/g, '').slice(0, 60)),
        excerpt: excerpt(b.excerpt),
      })),
    },
    overcomplication: {
      flags: Object.fromEntries(Object.entries(O.flags || {}).filter(([k, v]) => /^[a-z-]{1,40}$/.test(k) && isNum(v)).slice(0, 20)),
      returnsCurve: O.returnsCurve.map(b => nums(b, ['bin', 'sessions', 'avgTokens', 'avgEditsAndCommits', 'outputPerMillionTokens'], 'returnsCurve')),
      ...nums(O, ['medianBaselineContextTokens', 'subagentRuns', 'ceremonyCalls', 'nudgePrompts', 'toolCallsPerPrompt'], 'overcomplication'),
    },
    subagents: {
      ...nums(p.subagents || {}, ['runs', 'usd', 'startupUsd', 'parallelShare', 'flaggedUsd', 'repeatedDelegations'], 'subagents'),
      flags: Object.fromEntries(Object.entries(p.subagents?.flags || {}).filter(([k, v]) => /^[a-z-]{1,40}$/.test(k) && isNum(v)).slice(0, 10)),
    },
    outcomes: nums(p.outcomes || {}, ['commits', 'linesAdded', 'linesDeleted', 'sessionsWithCommits', 'withClaudeTrailer', 'usdPerCommit', 'usdWithoutCommit', 'sessionsWithoutCommit'], 'outcomes'),
    setup: p.setup ? {
      ...nums(p.setup, ['alwaysOnTokens', 'agents', 'skills', 'mcpServers', 'hooks', 'multiAgentFrameworks'], 'setup'),
      findings: Object.fromEntries(Object.entries(p.setup.findings || {}).filter(([k, v]) => /^[a-z-]{1,40}$/.test(k) && isNum(v)).slice(0, 40)),
    } : null,
    recurring: nums(p.recurring || {}, ['corrections', 'repeatedInstructions'], 'recurring'),
  };
}

// ── storage ──────────────────────────────────────────────────────
function save(user, snap) {
  const dir = userDir(user.email);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(dir, 'meta.json'), JSON.stringify({ email: user.email, name: user.name }), { mode: 0o600 });
  const tmp = join(dir, `.${snap.day}.tmp`);
  writeFileSync(tmp, JSON.stringify({ ...snap, receivedAt: new Date().toISOString() }), { mode: 0o600 });
  renameSync(tmp, join(dir, `${snap.day}.json`));
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 86400_000).toISOString().slice(0, 10);
  for (const f of readdirSync(dir)) if (/^\d{4}-\d{2}-\d{2}\.json$/.test(f) && f.slice(0, 10) < cutoff) rmSync(join(dir, f));
}
function history(dir, limit = 90) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter(f => /^\d{4}-\d{2}-\d{2}\.json$/.test(f)).sort().slice(-limit)
    .map(f => { try { return JSON.parse(readFileSync(join(dir, f), 'utf8')); } catch { return null; } }).filter(Boolean);
}
// Team view: aggregates over the people active recently, never a row per
// person. A per-person table sorted by spend is a leaderboard, and this hub is
// for each developer's own improvement, not for performance reviews. Below
// TEAM_MIN_PEOPLE the aggregates themselves would point at individuals, so
// nothing is shown but the count.
export const TEAM_MIN_PEOPLE = Math.max(3, Number(process.env.TEAM_MIN_PEOPLE || 5));
const TEAM_ACTIVE_DAYS = 14;
const median = xs => { const s = xs.filter(Number.isFinite).sort((a, b) => a - b); return s.length ? s[Math.floor(s.length / 2)] : 0; };
function team() {
  if (!existsSync(DATA)) return { people: 0, minPeople: TEAM_MIN_PEOPLE, enough: false };
  const since = new Date(Date.now() - TEAM_ACTIVE_DAYS * 86400_000).toISOString().slice(0, 10);
  const latest = readdirSync(DATA).map(h => history(join(DATA, h), 1)[0]).filter(s => s && s.day >= since);
  const base = { people: latest.length, minPeople: TEAM_MIN_PEOPLE, activeDays: TEAM_ACTIVE_DAYS };
  if (latest.length < TEAM_MIN_PEOPLE) return { ...base, enough: false };
  // How many people have each setup finding / subagent flag: "4 of 9 run unused subagents".
  const peopleWith = pick => latest.reduce((m, s) => { for (const k of Object.keys(pick(s) || {})) m[k] = (m[k] || 0) + 1; return m; }, {});
  return {
    ...base, enough: true,
    usdTotal: +latest.reduce((a, s) => a + (s.totals.usd || 0), 0).toFixed(2),
    median: {
      usd: median(latest.map(s => s.totals.usd || 0)),
      usdPerCommit: median(latest.map(s => s.outcomes?.usdPerCommit).filter(x => x > 0)),
      reworkShare: median(latest.map(s => s.instructionQuality.reworkShare)),
      vagueShare: median(latest.map(s => { const v = s.instructionQuality.vague.prompts, a = s.instructionQuality.anchored.prompts; return v + a ? v / (v + a) : 0; })),
      cacheHitRate: median(latest.map(s => s.totals.cacheHitRate)),
      errorRate: median(latest.map(s => s.totals.errorRate)),
      alwaysOnTokens: median(latest.map(s => s.setup?.alwaysOnTokens).filter(x => x != null)),
    },
    subagentUsdNoBenefit: +latest.reduce((a, s) => a + (s.subagents?.flaggedUsd || 0), 0).toFixed(2),
    peopleWithSetupFinding: peopleWith(s => s.setup?.findings),
    peopleWithSubagentFlag: peopleWith(s => s.subagents?.flags),
    peopleWithRecurringCorrections: latest.filter(s => s.recurring.corrections > 0).length,
  };
}

// ── http ─────────────────────────────────────────────────────────
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'",
};
function send(res, status, body, type = 'application/json') {
  res.writeHead(status, { 'Content-Type': type, ...SEC_HEADERS });
  res.end(type === 'application/json' ? JSON.stringify(body) : body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { reject(Object.assign(new Error('payload too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export function handler(req, res) {
  const url = new URL(req.url, 'http://x');
  const path = url.pathname;
  if (path === '/api/health') return send(res, 200, { status: 'ok', version: VERSION });

  const user = who(req);
  if (!user) return send(res, 401, { error: 'No AppCrane identity on the request. This app must run behind AppCrane forward_auth.' });

  // An app sign-in key (the uploader's credential) may upload and nothing else:
  // a key copied off a laptop cannot read the excerpts its owner uploaded, or
  // delete them. AppCrane sets this header only on that path and strips any
  // copy a client sends.
  if (req.headers['x-appcrane-auth-via'] === 'app-key' && !(req.method === 'POST' && path === '/api/reports')) {
    return send(res, 403, { error: 'An app sign-in key can only upload. Open the hub in a browser to read your reports.' });
  }

  if (req.method === 'GET' && (path === '/' || path === '/index.html')) return send(res, 200, INDEX, 'text/html; charset=utf-8');
  if (req.method === 'GET' && path === '/api/me') return send(res, 200, { email: user.email, name: user.name, admin: user.admin });
  if (req.method === 'GET' && path === '/api/reports/me') return send(res, 200, { reports: history(userDir(user.email)) });
  if (req.method === 'DELETE' && path === '/api/reports/me') { rmSync(userDir(user.email), { recursive: true, force: true }); return send(res, 200, { deleted: true }); }
  if (req.method === 'GET' && path === '/api/team') return user.admin ? send(res, 200, team()) : send(res, 403, { error: 'admins only' });

  if (req.method === 'POST' && path === '/api/reports') {
    // Custom header + JSON content type: a cross-site form or image request
    // can set neither without a CORS preflight, which this app never answers.
    if (req.headers['x-work-review-client'] !== SCHEMA || !String(req.headers['content-type'] || '').startsWith('application/json')) {
      return send(res, 400, { error: 'expected application/json with X-Work-Review-Client' });
    }
    return readBody(req).then(raw => {
      let snap;
      try { snap = validate(JSON.parse(raw)); } catch (e) { return send(res, 422, { error: e.message }); }
      save(user, snap);
      send(res, 201, { stored: snap.day });
    }).catch(e => send(res, e.status || 400, { error: e.message }));
  }
  return send(res, 404, { error: 'not found' });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  mkdirSync(DATA, { recursive: true, mode: 0o700 });
  const port = Number(process.env.PORT || 3000);
  createServer(handler).listen(port, () => console.log(`work-review-hub ${VERSION} on :${port}, data in ${DATA}`));
}
