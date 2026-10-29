#!/usr/bin/env node
// Daily upload of a redacted work-review summary to the Work Review hub (an
// AppCrane app on app.opswat.com).
//
//   node upload.mjs --setup --url https://work-review.app.opswat.com   (reads a dhk_uak_* app key from stdin)
//   node upload.mjs --dry-run      print exactly what would be sent, send nothing
//   node upload.mjs                upload now if the last upload is >24h old
//   node upload.mjs --force        upload now regardless
//   node upload.mjs --hook         for a SessionStart hook: detach and return at once
//   node upload.mjs --disable      stop uploading (keeps the key)
//
// What leaves the machine: numeric totals, flags, the returns curve, and at
// most TOP_EXCERPTS prompt excerpts of ≤160 chars each, scrubbed of secrets,
// emails, IPs, paths, URLs and long tokens. Never: transcripts, file contents,
// file paths, shell commands, tool error text, project or session names.
// Every payload sent is kept under ~/.config/work-review/sent/ for audit.

import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, chmodSync, appendFileSync, readdirSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { homedir, hostname } from 'os';
import { spawn, execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF_DIR = process.env.WORK_REVIEW_CONFIG_DIR || join(homedir(), '.config', 'work-review');
const CONF = join(CONF_DIR, 'config.json');
const KEY = join(CONF_DIR, 'key');
const STAMP = join(CONF_DIR, 'last-upload');
const LOG = join(CONF_DIR, 'upload.log');
const SENT = join(CONF_DIR, 'sent');
const PENDING = join(CONF_DIR, 'pending-excerpts.json');   // waiting for the person's approval
const DECIDED = join(CONF_DIR, 'excerpt-decisions.json');  // sha256 → 'approved' | 'dropped'
const DAY_MS = 86400_000;
const WINDOW_DAYS = 7;          // each upload is a rolling 7-day snapshot; the hub keeps one per day
const TOP_EXCERPTS = 5;
const EXCERPT_CHARS = 160;
export const SCHEMA = 'work-review/v1';
// Only an app sign-in key: it opens the hub's gate and nothing else on AppCrane,
// and the hub accepts it on its upload endpoint only. A full dhk_user_* key in a
// file on disk would be the whole account. (base64url body, so '-' too.)
export const APP_KEY_RE = /^dhk_uak_[A-Za-z0-9_-]+$/;

// The only hosts a payload may go to. Pinned in code, not config, so a
// tampered config.json cannot redirect the upload.
const ALLOWED_HOST = 'app.opswat.com';
export function checkUrl(raw) {
  let u; try { u = new URL(raw); } catch { throw new Error(`not a URL: ${raw}`); }
  if (u.protocol !== 'https:') throw new Error('upload URL must be https');
  if (u.username || u.password) throw new Error('upload URL must not carry credentials');
  if (u.hostname !== ALLOWED_HOST && !u.hostname.endsWith('.' + ALLOWED_HOST)) throw new Error(`upload host must be ${ALLOWED_HOST} or a subdomain of it, got ${u.hostname}`);
  return u;
}

// Second, stricter pass over anything quoted from a prompt. The analyzer already
// redacts obvious secrets; this also strips identifying detail.
const SCRUBS = [
  [/-----BEGIN [A-Z ]+-----[\s\S]*?(-----END [A-Z ]+-----|$)/g, '«key»'],
  [/(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|dhk_[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)/g, '«secret»'],
  [/(?<!«)\b(password|passwd|secret|token|api[_-]?key|authorization|bearer)\b(?:\s*[:=]\s*|\s+)(?!«)\S+/gi, '$1 «secret»'],
  [/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, '«email»'],
  [/https?:\/\/\S+/g, '«url»'],
  [/\b\d{1,3}(\.\d{1,3}){3}\b/g, '«ip»'],
  [/(^|[\s"'`(])(~|\.{1,2})?\/[\w.@-]+(\/[\w.@-]+)+/g, '$1«path»'],
  [/\b[A-Za-z]:\\[^\s]+/g, '«path»'],
  [/\b[A-Fa-f0-9]{24,}\b/g, '«hex»'],
  [/\b[A-Za-z0-9+/_-]{32,}={0,2}/g, '«token»'],
];
export function scrub(s) {
  let t = String(s ?? '');
  for (const [re, rep] of SCRUBS) t = t.replace(re, rep);
  t = t.replace(/\s+/g, ' ').trim();
  return t.length > EXCERPT_CHARS ? t.slice(0, EXCERPT_CHARS) + '…' : t;
}

// A figure the analyzer could not measure travels as null, never as 0: a week
// with no commits has no cost per commit, and a stored 0 would read a month
// later exactly like a perfect week.
const num = v => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const pickNums = (o, keys) => Object.fromEntries(keys.map(k => [k, num(o?.[k])]));
const group = g => pickNums(g, ['prompts', 'medianCost', 'medianUsd', 'medianExploreBeforeFirstEdit', 'reworkRate']);

// Allow-list, field by field: anything the analyzer adds later stays local
// until it is deliberately added here.
const excerptId = text => createHash('sha256').update(text).digest('hex').slice(0, 16);

// allowExcerpt(text) decides each prompt excerpt. The default sends none: an
// excerpt leaves the machine only after its owner approved that exact text.
export function buildPayload(report, { now = new Date(), setup = null, allowExcerpt = () => false } = {}) {
  const T = report.totals || {}, Q = report.instructionQuality || {}, O = report.overcomplication || {};
  return {
    schema: SCHEMA,
    day: now.toISOString().slice(0, 10),
    windowDays: WINDOW_DAYS,
    // Distinguishes a person's laptop from their desktop without naming either.
    machine: createHash('sha256').update(hostname()).digest('hex').slice(0, 12),
    totals: {
      ...pickNums(T, ['sessions', 'subagentRuns', 'turns', 'toolCalls', 'userPrompts', 'cacheHitRate', 'toolErrors', 'errorRate',
        'redundantReads', 'idleCommandReruns', 'retryLoops', 'editMisses', 'permissionDenials', 'oversizedOutputs',
        'corrections', 'interrupts', 'compactions', 'searchBursts', 'parallelToolTurnShare']),
      tokens: pickNums(T.tokens, ['input', 'output', 'cacheRead', 'cacheWrite']),
      wastedTokensEstimate: pickNums(T.wastedTokensEstimate, ['redundantReads', 'idleReruns', 'errorOutputs']),
      // API-list-price dollars (see analyze.mjs): the API-equivalent value, not a bill.
      usd: num(T.usd),
      // Tokens from models with no known price: their cost is missing from usd,
      // so the hub says the total is incomplete instead of showing it as whole.
      unpricedTokens: Object.values(T.unpricedModels || {}).reduce((a, n) => a + (num(n) || 0), 0),
    },
    instructionQuality: {
      totalCost: num(Q.totalCost), reworkCost: num(Q.reworkCost), reworkShare: num(Q.reworkShare),
      totalUsd: num(Q.totalUsd), reworkUsd: num(Q.reworkUsd),
      vague: group(Q.vague), anchored: group(Q.anchored), withCriteria: group(Q.withCriteria), withoutCriteria: group(Q.withoutCriteria),
      costliestBadPrompts: (Q.costliestBadPrompts || []).slice(0, TOP_EXCERPTS).map(p => ({ ...p, excerpt: scrub(p.prompt) })).filter(p => allowExcerpt(p.excerpt)).map(p => ({
        cost: num(p.cost),
        usd: num(p.usd),
        why: (p.why || []).filter(w => typeof w === 'string').map(w => w.replace(/[^\w\s;-]/g, '').slice(0, 60)).slice(0, 4),
        excerpt: p.excerpt,
      })),
    },
    overcomplication: {
      flags: Object.fromEntries(Object.entries(O.flags || {}).filter(([k]) => /^[a-z-]{1,40}$/.test(k)).map(([k, v]) => [k, num(v)])),
      returnsCurve: (O.returnsCurve || []).slice(0, 5).map(b => pickNums(b, ['bin', 'sessions', 'avgTokens', 'avgEditsAndCommits', 'outputPerMillionTokens'])),
      ...pickNums(O, ['medianBaselineContextTokens', 'subagentRuns', 'ceremonyCalls', 'nudgePrompts', 'toolCallsPerPrompt']),
    },
    // Ranked findings as fixed ids with cost and share (no text): the hub's weekly digest names the fix.
    findings: (report.findings?.shown || []).filter(f => /^[a-z-]{1,40}$/.test(f.id)).slice(0, 6).map(f => ({ id: f.id, usd: num(f.usd), share: num(f.share) })),
    outcomes: pickNums(report.outcomes, ['commits', 'linesAdded', 'linesDeleted', 'sessionsWithCommits', 'withClaudeTrailer', 'usdPerCommit', 'usdWithoutCommit', 'sessionsWithoutCommit']),
    subagents: {
      ...pickNums(report.subagents, ['runs', 'usd', 'startupUsd', 'parallelShare', 'flaggedUsd']),
      flags: Object.fromEntries(Object.entries(report.subagents?.flags || {}).filter(([k]) => /^[a-z-]{1,40}$/.test(k)).map(([k, v]) => [k, num(v)])),
      repeatedDelegations: (report.subagents?.repeatedDelegations || []).length,
    },
    // How the setup is built: counts and finding kinds only. No names, paths or
    // file contents, so a team view can say "4 people run unused subagents"
    // without showing anyone's configuration.
    setup: setup ? {
      alwaysOnTokens: num(setup.inventory?.alwaysOnTokens),
      agents: num(setup.inventory?.agents?.length), skills: num(setup.inventory?.skills?.filter(s => !s.managed).length),
      mcpServers: num(setup.inventory?.mcpServers?.length), hooks: num(setup.inventory?.hooks?.length),
      multiAgentFrameworks: num(Object.keys(setup.inventory?.frameworks || {}).length),
      findings: (setup.findings || []).reduce((m, f) => { if (/^[a-z-]{1,40}$/.test(f.kind)) m[f.kind] = (m[f.kind] || 0) + 1; return m; }, {}),
    } : null,
    recurring: {
      // Counts only for these: their examples are quoted from prompts the user
      // may not want on a dashboard, and the count is what a trend needs.
      corrections: (report.cross?.recurringCorrections || []).filter(c => c.sessions >= 2).length,
      repeatedInstructions: (report.cross?.repeatedPrompts || []).length,
    },
  };
}

// ── local state ──────────────────────────────────────────────────
function log(msg) { try { ensureDir(); appendFileSync(LOG, `${new Date().toISOString()} ${msg}\n`, { mode: 0o600 }); } catch {} }
function ensureDir() { mkdirSync(CONF_DIR, { recursive: true, mode: 0o700 }); chmodSync(CONF_DIR, 0o700); }
function readConfig() { try { return JSON.parse(readFileSync(CONF, 'utf8')); } catch { return null; } }
function readKey() {
  if (!existsSync(KEY)) throw new Error(`no key at ${KEY}; run with --setup`);
  const mode = statSync(KEY).mode & 0o777;
  if (mode & 0o077) throw new Error(`${KEY} is readable by others (mode ${mode.toString(8)}); run: chmod 600 ${KEY}`);
  const k = readFileSync(KEY, 'utf8').trim();
  if (!APP_KEY_RE.test(k)) throw new Error(`${KEY} does not hold an AppCrane app sign-in key (dhk_uak_*)`);
  return k;
}
const lastUpload = () => { try { return Number(readFileSync(STAMP, 'utf8')) || 0; } catch { return 0; } };

// Who is signed in to Claude Code right now. Transcripts do not record the
// account per session, so this is checked at upload time: with accountDomain
// set, nothing is sent unless the current login is a work account.
function currentAccountEmail() {
  try { return JSON.parse(readFileSync(join(homedir(), '.claude.json'), 'utf8')).oauthAccount?.emailAddress || null; } catch { return null; }
}
export function accountProblem(config, email = currentAccountEmail()) {
  if (!config.accountDomain) return null;
  if (!email) return `cannot confirm the Claude account is a ${config.accountDomain} one (no signed-in account found)`;
  return email.toLowerCase().endsWith('@' + config.accountDomain.toLowerCase()) ? null : `the signed-in Claude account is not a ${config.accountDomain} account`;
}

function runAnalyzer(config = {}) {
  ensureDir();
  const out = join(CONF_DIR, 'last-report.json');      // full local report, stays here (0600)
  const allow = (config.allowRemotes || []).flatMap(r => ['--allow-remote', r]);
  try {
    execFileSync(process.execPath, [join(HERE, 'analyze.mjs'), '--since', String(WINDOW_DAYS), '--include-subagents', '--json', out, ...allow], { stdio: ['ignore', 'ignore', 'pipe'], timeout: 120_000 });
  } catch (e) {
    if (/No sessions/.test(String(e.stderr || ''))) return null;   // nothing in the allowed repos this week
    throw e;
  }
  chmodSync(out, 0o600);
  return JSON.parse(readFileSync(out, 'utf8'));
}

// The setup audit of the directory the hook fired in (the project being worked
// on). Best effort: a failure here must never block the upload.
function runSetupAudit() {
  try {
    const out = join(CONF_DIR, 'last-setup.json');
    execFileSync(process.execPath, [join(HERE, 'audit-setup.mjs'), '--report', join(CONF_DIR, 'last-report.json'), '--json', out], { stdio: 'ignore', timeout: 60_000 });
    chmodSync(out, 0o600);
    return JSON.parse(readFileSync(out, 'utf8'));
  } catch { return null; }
}

async function send(url, key, payload) {
  const target = new URL('/api/reports', checkUrl(url));
  const res = await fetch(target, {
    method: 'POST',
    // redirect:'error' — a redirect here means the auth gate bounced us to a
    // login page; following it would only send the payload somewhere else.
    redirect: 'error',
    signal: AbortSignal.timeout(20_000),
    headers: { 'Content-Type': 'application/json', 'X-API-Key': key, 'X-Work-Review-Client': SCHEMA },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`hub answered ${res.status}: ${(await res.text()).slice(0, 200)}`);
}

function keepCopy(payload) {
  mkdirSync(SENT, { recursive: true, mode: 0o700 });
  writeFileSync(join(SENT, `${payload.day}.json`), JSON.stringify(payload, null, 2), { mode: 0o600 });
  // Keep 90 days of receipts.
  const files = readdirSync(SENT).filter(f => f.endsWith('.json')).sort();
  for (const f of files.slice(0, Math.max(0, files.length - 90))) rmSync(join(SENT, f));
}

// ── excerpt approval queue ───────────────────────────────────────
const readJson = (f, d) => { try { return JSON.parse(readFileSync(f, 'utf8')); } catch { return d; } };
const writeJson = (f, v) => { ensureDir(); writeFileSync(f, JSON.stringify(v, null, 2) + '\n', { mode: 0o600 }); };
function queueExcerpts(report) {
  const decided = readJson(DECIDED, {});
  const pending = readJson(PENDING, []);
  const known = new Set(pending.map(p => p.id));
  for (const p of (report.instructionQuality?.costliestBadPrompts || []).slice(0, TOP_EXCERPTS)) {
    const text = scrub(p.prompt), id = excerptId(text);
    if (!decided[id] && !known.has(id)) { pending.push({ id, text, cost: num(p.usd) }); known.add(id); }
  }
  writeJson(PENDING, pending.slice(-50));
  return pending.length;
}
function reviewExcerpts(argv) {
  const pending = readJson(PENDING, []);
  const decided = readJson(DECIDED, {});
  const pick = flag => { const i = argv.indexOf(flag); if (i === -1) return null; const v = argv[i + 1] || ''; return v === 'all' ? pending.map((_, n) => n + 1) : v.split(',').map(Number).filter(Boolean); };
  const approve = pick('--approve'), drop = pick('--drop');
  if (!approve && !drop) {
    if (!pending.length) { console.log('No excerpts waiting.'); return; }
    console.log('Excerpts waiting for your approval (nothing here has been sent):\n');
    pending.forEach((p, n) => console.log(`${n + 1}. ${p.text}`));
    console.log(`\nApprove: --review-excerpts --approve 1,3 (or all) · Drop: --review-excerpts --drop 2 (or all)`);
    return;
  }
  for (const n of approve || []) if (pending[n - 1]) decided[pending[n - 1].id] = 'approved';
  for (const n of drop || []) if (pending[n - 1]) decided[pending[n - 1].id] = 'dropped';
  writeJson(DECIDED, decided);
  writeJson(PENDING, pending.filter(p => !decided[p.id]));
  console.log(`Recorded. Approved excerpts go with the next upload; dropped ones never leave this machine.`);
}
const approvedExcerpt = config => {
  if (!config.excerpts) return () => false;
  const decided = readJson(DECIDED, {});
  return text => decided[excerptId(text)] === 'approved';
};

async function setup(url, argv = []) {
  checkUrl(url);
  const allowRemotes = argv.flatMap((a, i) => a === '--allow-remote' && argv[i + 1] ? [argv[i + 1]] : []);
  if (!allowRemotes.length) throw new Error('give at least one --allow-remote <pattern> (e.g. \'github.com[:/]opswat/\'): only sessions in matching repositories are uploaded');
  for (const r of allowRemotes) new RegExp(r);   // fail now, not at the first upload
  const ai = argv.indexOf('--account-domain');
  const accountDomain = ai === -1 ? null : argv[ai + 1];
  const key = readFileSync(0, 'utf8').trim();            // stdin, so the key never appears in argv or shell history
  if (!APP_KEY_RE.test(key)) {
    throw new Error(/^dhk_/.test(key)
      ? 'that is a full AppCrane key; issue an app sign-in key (dhk_uak_*) for the hub instead (AppCrane → MCP page → App sign-in keys)'
      : 'expected an AppCrane app sign-in key (dhk_uak_*) on stdin');
  }
  ensureDir();
  writeFileSync(KEY, key + '\n', { mode: 0o600 }); chmodSync(KEY, 0o600);
  writeFileSync(CONF, JSON.stringify({ url, enabled: true, allowRemotes, accountDomain, excerpts: argv.includes('--excerpts') }, null, 2) + '\n', { mode: 0o600 });
  console.log(`Saved. Uploads go to ${url}, from repositories matching ${allowRemotes.join(' or ')}${accountDomain ? `, only while signed in with a ${accountDomain} account` : ''}. ` +
    `Prompt excerpts: ${argv.includes('--excerpts') ? 'on, each one only after you approve it (--review-excerpts)' : 'off'}. Preview with: node ${join(HERE, 'upload.mjs')} --dry-run`);
}

// ── main ─────────────────────────────────────────────────────────
async function main(argv) {
  const has = f => argv.includes(f);
  const val = f => { const i = argv.indexOf(f); return i === -1 ? null : argv[i + 1]; };

  if (has('--setup')) return setup(val('--url') || '', argv);
  if (has('--review-excerpts')) return reviewExcerpts(argv);
  if (has('--disable')) { const c = readConfig() || {}; ensureDir(); writeFileSync(CONF, JSON.stringify({ ...c, enabled: false }, null, 2) + '\n', { mode: 0o600 }); console.log('Uploads disabled.'); return; }

  if (has('--hook')) {
    // Never slow down or break a session start: detach and return.
    const c = readConfig();
    if (!c?.enabled || Date.now() - lastUpload() < DAY_MS) return;
    spawn(process.execPath, [fileURLToPath(import.meta.url)], { detached: true, stdio: 'ignore' }).unref();
    return;
  }

  const c = readConfig();
  const dry = has('--dry-run');
  if (!dry && !c?.enabled) { console.error('Uploads are not set up or are disabled. See --setup.'); process.exitCode = 1; return; }
  if (c && !c.allowRemotes?.length) { console.error('No --allow-remote patterns configured, so nothing may be uploaded. Run --setup again with --allow-remote.'); process.exitCode = 1; return; }
  if (!dry && !has('--force') && Date.now() - lastUpload() < DAY_MS) { console.log('Already uploaded in the last 24h; use --force to send again.'); return; }
  const blocked = c && accountProblem(c);
  if (blocked) { log(`skipped: ${blocked}`); console.log(`Not uploading: ${blocked}.`); return; }

  const report = runAnalyzer(c || {});
  if (!report) { log('skipped: no sessions in the allowed repositories this week'); console.log('Nothing to upload: no sessions in the allowed repositories this week.'); return; }
  const waiting = c?.excerpts ? queueExcerpts(report) : 0;
  const payload = buildPayload(report, { setup: runSetupAudit(), allowExcerpt: approvedExcerpt(c || {}) });
  if (dry) { console.log(JSON.stringify(payload, null, 2)); if (waiting) console.error(`${waiting} excerpt(s) are waiting for your approval and are not in this payload: --review-excerpts`); return; }
  await send(c.url, readKey(), payload);
  keepCopy(payload);
  writeFileSync(STAMP, String(Date.now()), { mode: 0o600 });
  log(`uploaded ${payload.day} to ${new URL(c.url).hostname}`);
  console.log(`Uploaded the ${payload.day} snapshot. A copy of what was sent: ${join(SENT, payload.day + '.json')}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).catch(e => { log(`error: ${e.message}`); console.error(`work-review upload: ${e.message}`); process.exitCode = 1; });
}
