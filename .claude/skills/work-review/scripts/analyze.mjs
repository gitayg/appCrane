#!/usr/bin/env node
// Work-review analyzer: reads Claude Code transcripts (~/.claude/projects/**/*.jsonl)
// and reports measurable waste — redundant reads, repeated commands, failing tool
// calls, retry loops, permission friction, oversized outputs, user corrections and
// instructions repeated across sessions. No dependencies, nothing leaves the machine.
//
//   node analyze.mjs [--root DIR] [--project SUBSTR] [--since DAYS] [--session ID]
//                    [--include-subagents] [--json OUT.json] [--top N]
//
// Prints a markdown summary to stdout; --json also writes the full findings.

import { readdirSync, readFileSync, statSync, writeFileSync, existsSync } from 'fs';
import { join, basename, dirname } from 'path';
import { homedir } from 'os';

// ── args ─────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? dflt : args[i + 1];
};
const flag = name => args.includes(`--${name}`);
const ROOT = opt('root', join(process.env.CLAUDE_CONFIG_DIR || join(homedir(), '.claude'), 'projects'));
const PROJECT = opt('project', null);
const SINCE_DAYS = Number(opt('since', 30));
const ONLY_SESSION = opt('session', null);
const SUBAGENTS = flag('include-subagents');
const JSON_OUT = opt('json', null);
const TOP = Number(opt('top', 10));
const PRICE_FILE = opt('prices', process.env.WORK_REVIEW_PRICES || null);
const sinceMs = Date.now() - SINCE_DAYS * 86400_000;

// ── helpers ──────────────────────────────────────────────────────
const SECRET_RE = /(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+|(?:password|secret|token|api[_-]?key)\s*[=:]\s*\S+)/gi;
const redact = s => String(s ?? '').replace(SECRET_RE, '«redacted»');
const clip = (s, n = 160) => { s = redact(s).replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n) + '…' : s; };
const textOf = c => typeof c === 'string' ? c
  : Array.isArray(c) ? c.map(x => x?.text ?? (typeof x === 'string' ? x : '')).join('\n') : '';
const words = s => String(s).toLowerCase().replace(/[^a-z0-9_./-]+/g, ' ').split(' ').filter(w => w.length > 2);
const shingles = s => { const w = words(s); const out = new Set(); for (let i = 0; i + 2 < w.length; i++) out.add(w.slice(i, i + 3).join(' ')); if (!out.size && w.length) out.add(w.join(' ')); return out; };
const jaccard = (a, b) => { if (!a.size || !b.size) return 0; let n = 0; for (const x of a) if (b.has(x)) n++; return n / (a.size + b.size - n); };
const inc = (m, k, by = 1) => m.set(k, (m.get(k) || 0) + by);

function walk(dir, out = []) {
  let ents; try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of ents) {
    const p = join(dir, e.name);
    if (e.isDirectory()) { if (e.name !== 'subagents' || SUBAGENTS) walk(p, out); }
    else if (e.name.endsWith('.jsonl')) out.push(p);
  }
  return out;
}

// Normalise a shell command so `cd /x && npm test 2>&1 | tail -20` and `npm test` group.
// Leading `cd dir` and `VAR=value` segments are dropped; the first real command is kept.
function normCmd(cmd) {
  const segs = String(cmd).split(/\s*(?:\|\||&&|;|\||\n)\s*/).map(x => x.trim()).filter(Boolean);
  const c = segs.find(x => !/^cd(\s|$)/.test(x) && !/^[A-Za-z_][A-Za-z0-9_]*=\S*$/.test(x)) || segs[0] || '';
  return c.replace(/\s+2>&1/g, '').replace(/\s+/g, ' ').trim();
}
const cmdHead = c => normCmd(c).split(' ').slice(0, 2).join(' ');
const READ_CMD_RE = /^(cat|head|tail|less|sed\s+-n\s+\S+|nl)\s+(?:-\S+\s+)*([^\s|;&>]+)/;

const CORRECTION_RE = /^(no[,.! ]|nope|don'?t|do not|stop|wrong|actually|instead|that'?s not|not what i|i said|i told you|why did you|you (?:forgot|missed|broke)|please don'?t|never )/i;
// Concrete anchors in a prompt: a path or file name, code in backticks, an identifier,
// an error/line reference, a URL. A prompt with none of them makes Claude go find out.
// Case-sensitive on purpose: `camelCase` must not match every lowercase word.
const ANCHOR_RE = /(`[^`]+`|\b[\w-]+\.(?:js|mjs|ts|tsx|jsx|py|go|rs|java|rb|php|css|html|json|ya?ml|md|sql|sh|toml)\b|(?:^|\s)\.{0,2}\/[\w.-]+\/|https?:\/\/|\b[a-z]+[A-Z]\w*\b|\b\w+\(\)|\b(?:[Ee]rror|[Ee]xception|Traceback|line \d+|status \d{3})\b)/;
// Done-criteria: tells Claude when to stop and how to check.
const CRITERIA_RE = /\b(should|must|expect(?:ed)?|so that|done when|until|make sure|verify|passes?|returns?|instead of|acceptance)\b/i;
// Relative price of a token vs fresh input: output ×5, cache write ×1.25, cache read ×0.1.
const costUnits = u => (u.input_tokens || 0) + 5 * (u.output_tokens || 0) + 1.25 * (u.cache_creation_input_tokens || 0) + 0.1 * (u.cache_read_input_tokens || 0);
// ── pricing: what the same tokens would cost on the Claude API ──
// Team, Max and Enterprise seats are billed per seat, so /usage on those plans
// shows plan limits rather than a bill. Pricing the transcript's own usage at
// API list rates gives a comparable dollar figure: the API-equivalent value of
// the work, not an invoice. $ per million tokens, first-party Claude API rates
// as of PRICES_AS_OF; --prices <file.json> (or WORK_REVIEW_PRICES) overrides or
// extends it with { "<model-id prefix>": { "in", "out", "read" } }.
// Cache writes are priced from `in`: ×1.25 for the 5-minute TTL, ×2 for 1-hour.
const PRICES_AS_OF = '2026-10-06';
const BASE_PRICES = {
  'claude-fable-5-1': { in: 10, out: 50, read: 0.25 },
  'claude-mythos-5-1': { in: 10, out: 50, read: 0.25 },
  'claude-fable-5': { in: 10, out: 50, read: 1 },
  'claude-mythos-5': { in: 10, out: 50, read: 1 },
  'claude-opus-5-5': { in: 4, out: 20, read: 0.2 },
  'claude-opus-5': { in: 5, out: 25, read: 0.5 },
  'claude-opus-4-8': { in: 5, out: 25, read: 0.5 },
  'claude-opus-4-7': { in: 5, out: 25, read: 0.5 },
  'claude-opus-4-6': { in: 5, out: 25, read: 0.5 },
  'claude-sonnet-5-5': { in: 2, out: 10, read: 0.2 },
  'claude-sonnet-5': { in: 2, out: 10, read: 0.2 },
  'claude-sonnet-4-6': { in: 3, out: 15, read: 0.3 },
  // Haiku 5.5: prompts over 100K tokens are billed at the higher pair.
  'claude-haiku-5-5': { in: 0.1, out: 0.5, read: 0.01, longAt: 100_000, longIn: 0.5, longOut: 2.5 },
  'claude-haiku-4-5': { in: 1, out: 5, read: 0.1 },
};
const PRICES = { ...BASE_PRICES, ...(PRICE_FILE ? JSON.parse(readFileSync(PRICE_FILE, 'utf8')) : {}) };
const PRICE_KEYS = Object.keys(PRICES).sort((a, b) => b.length - a.length);   // claude-opus-5-5 before claude-opus-5
export function priceFor(model) {
  const id = String(model || '').toLowerCase()
    .replace(/\[[^\]]*\]/g, '')                       // claude-opus-5-5[1m]
    .replace(/^(?:(?:us|eu|apac|global)\.)?anthropic\./, '') // Bedrock-style prefixes
    .replace(/@.*$/, '').replace(/-\d{8}$/, '').trim();    // dated snapshots
  const key = PRICE_KEYS.find(k => id === k || id.startsWith(k + '-'));
  return key ? PRICES[key] : null;
}
/** Dollars for one message's usage, or null when the model is not priced. */
export function usdOf(u, model) {
  const p = priceFor(model);
  if (!p) return null;
  const fresh = u.input_tokens || 0, read = u.cache_read_input_tokens || 0, write = u.cache_creation_input_tokens || 0;
  const long = p.longAt && fresh + read + write > p.longAt;
  const rin = long ? p.longIn : p.in, rout = long ? p.longOut : p.out, rread = long ? p.longIn * (p.read / p.in) : p.read;
  const w1h = Math.min(write, u.cache_creation?.ephemeral_1h_input_tokens || 0);
  const fast = u.speed === 'fast' ? 2 : 1;   // fast mode: 2× standard on the Opus models that offer it
  return fast * (fresh * rin + (u.output_tokens || 0) * rout + read * rread + (write - w1h) * rin * 1.25 + w1h * rin * 2) / 1e6;
}

const NUDGE_RE = /^(continue|go on|go ahead|proceed|yes|yep|y|ok(?:ay)?|sure|do it|next|keep going|carry on)[.!\s]*$/i;
const CEREMONY_RE = /^(TodoWrite|TaskCreate|TaskUpdate|EnterPlanMode|ExitPlanMode)$/;
const BIG_MODEL_RE = /opus|fable/i;
const INTERRUPT_RE = /\[Request interrupted by user/;
const DENIED_RE = /(permission|was denied|user (?:rejected|declined|doesn't want)|not allowed|requires approval)/i;
const EDIT_MISS_RE = /(string to replace not found|old_string.*not (?:found|unique)|found \d+ matches|File has not been read yet|file has been modified since)/i;

// ── per-session analysis ─────────────────────────────────────────
function analyzeFile(path) {
  const lines = readFileSync(path, 'utf8').split('\n');
  const s = {
    file: path, project: basename(dirname(path).replace(/\/subagents$/, '')), sessionId: basename(path, '.jsonl'),
    subagent: path.includes('/subagents/'), start: null, end: null, models: new Map(),
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, usd: 0, usdByModel: new Map(), unpriced: new Map(), turns: 0, userPrompts: [],
    toolCalls: 0, toolCounts: new Map(), errors: [], redundantReads: [], repeatedCmds: [],
    retryLoops: [], editMisses: 0, denials: [], bigOutputs: [], corrections: [], interrupts: 0,
    compactions: 0, searchBursts: 0, wastedTokens: { read: 0, rerun: 0, errors: 0 },
    edits: 0, commits: 0, prompts: [], agentCalls: 0, agentUses: [], commands: new Map(), filesRead: new Set(), toolOutChars: 0, lastText: '', startupUsd: null, ceremony: 0, skills: new Map(), promptChars: 0, maxPrompt: 0, nudges: 0, baselineCtx: null, singleToolTurns: 0, multiToolTurns: 0, cmdHeads: new Map(),
  };
  const seenMsg = new Set();
  const pending = new Map();          // tool_use_id -> {name, input, key}
  const readState = new Map();        // file -> {count, editedSince}
  const cmdState = new Map();         // normalised cmd -> {count, editSince}
  let lastErrKey = null, errStreak = 0, searchRun = 0;
  let editCounter = 0;
  const usesPerMsg = new Map();
  let cur = null;                     // the human prompt the current work is charged to
  function onHuman(t) {
    s.userPrompts.push(t);
    const corr = CORRECTION_RE.test(t.trim());
    if (cur && corr && !cur.followedBy) cur.followedBy = 'correction';
    cur = { text: t, chars: t.length, anchored: ANCHOR_RE.test(t), criteria: CRITERIA_RE.test(t), nudge: NUDGE_RE.test(t.trim()), correction: corr, cost: 0, usd: 0, tools: 0, explore: 0, edits: 0, followedBy: null };
    s.prompts.push(cur);
    s.promptChars += t.length; s.maxPrompt = Math.max(s.maxPrompt, t.length);
    if (NUDGE_RE.test(t.trim())) s.nudges++;
    if (corr) s.corrections.push(clip(t, 220));
  }

  for (const line of lines) {
    if (!line.trim()) continue;
    let d; try { d = JSON.parse(line); } catch { continue; }
    if (d.timestamp) { const t = Date.parse(d.timestamp); if (!s.start || t < s.start) s.start = t; if (!s.end || t > s.end) s.end = t; }
    if (d.type === 'system' && (d.subtype === 'compact_boundary' || /compact/i.test(d.content || ''))) s.compactions++;
    if (d.isCompactSummary) s.compactions++;
    // A message the user typed while Claude was mid-turn is stored as an attachment.
    if (d.type === 'attachment' && d.attachment?.type === 'queued_command' && d.attachment.humanTurn && !d.isSidechain) {
      const t = textOf(d.attachment.prompt); if (t.trim()) onHuman(t); continue;
    }
    const m = d.message;
    if (!m || typeof m !== 'object') continue;

    if (d.type === 'assistant') {
      const id = m.id || d.uuid;
      if (m.usage && !seenMsg.has(id)) {      // streamed messages repeat usage; count once
        seenMsg.add(id); s.turns++;
        s.usage.input += m.usage.input_tokens || 0; s.usage.output += m.usage.output_tokens || 0;
        s.usage.cacheRead += m.usage.cache_read_input_tokens || 0; s.usage.cacheWrite += m.usage.cache_creation_input_tokens || 0;
        if (m.model) inc(s.models, m.model);
        if (cur) cur.cost += costUnits(m.usage);
        const usd = usdOf(m.usage, m.model);
        if (usd == null) { if (m.model && m.model !== '<synthetic>') inc(s.unpriced, m.model, (m.usage.input_tokens || 0) + (m.usage.output_tokens || 0) + (m.usage.cache_read_input_tokens || 0) + (m.usage.cache_creation_input_tokens || 0)); }
        else { s.usd += usd; inc(s.usdByModel, m.model, usd); if (cur) cur.usd += usd; }
        // First turn's prompt size ≈ the always-on context: system prompt, tools, CLAUDE.md, MCP, skills.
        if (s.baselineCtx === null) s.baselineCtx = (m.usage.input_tokens || 0) + (m.usage.cache_read_input_tokens || 0) + (m.usage.cache_creation_input_tokens || 0);
        // What it costs just to start: the first request's input side (system prompt, tools, brief).
        if (s.startupUsd === null) s.startupUsd = usdOf({ ...m.usage, output_tokens: 0 }, m.model) ?? 0;
      }
      for (const b of Array.isArray(m.content) ? m.content : []) if (b.type === 'text' && b.text?.trim()) s.lastText = b.text;
      const uses = (Array.isArray(m.content) ? m.content : []).filter(x => x.type === 'tool_use');
      if (uses.length) inc(usesPerMsg, id, uses.length);   // streamed: one block per record, same id
      for (const u of uses) {
        s.toolCalls++; inc(s.toolCounts, u.name);
        const inp = u.input || {};
        let key = u.name;
        if (cur) {
          cur.tools++;
          if (/^(Edit|Write|MultiEdit|NotebookEdit)$/.test(u.name)) cur.edits++;
          else if (!cur.edits && /^(Read|Grep|Glob|Agent|Task|WebSearch|WebFetch)$/.test(u.name)) cur.explore++;
          else if (!cur.edits && u.name === 'Bash' && /^(ls|find|grep|rg|cat|head|tail|sed -n|git (log|show|grep))\b/.test(normCmd(inp.command || ''))) cur.explore++;
        }
        if (/^(Agent|Task)$/.test(u.name)) {
          s.agentCalls++;
          s.agentUses.push({ id: u.id, msg: id, background: !!inp.run_in_background, type: inp.subagent_type || 'general-purpose', prompt: String(inp.prompt || '') });
        }
        if (CEREMONY_RE.test(u.name)) s.ceremony++;
        if (u.name === 'Skill' && inp.skill) inc(s.skills, inp.skill);
        if (u.name === 'Bash' && /\bgit\s+commit\b/.test(inp.command || '')) s.commits++;
        if (/^(Grep|Glob)$/.test(u.name)) { if (++searchRun === 8) s.searchBursts++; } else if (u.name !== 'Read') searchRun = 0;

        if (u.name === 'Read' && inp.file_path) {
          key = `Read ${inp.file_path}`;
          const r = readState.get(inp.file_path) || { count: 0, editMark: -1, ranges: new Set() };
          const range = `${inp.offset ?? 0}:${inp.limit ?? 'all'}`;
          if (r.count && r.editMark === editCounter && r.ranges.has(range)) { s.redundantReads.push({ file: inp.file_path, nth: r.count + 1 }); u._wasted = 'read'; }
          if (r.editMark !== editCounter) r.ranges = new Set();
          r.count++; r.editMark = editCounter; r.ranges.add(range); readState.set(inp.file_path, r); s.filesRead.add(inp.file_path);
        } else if (/^(Edit|Write|MultiEdit|NotebookEdit)$/.test(u.name)) {
          editCounter++; s.edits++;
        } else if (u.name === 'Bash' && inp.command) {
          const nc = normCmd(inp.command); key = `Bash ${nc}`;
          // Re-run key: the whole command minus a leading `cd` and trailing output trimming.
          const full = inp.command.replace(/^\s*cd\s+\S+\s*(?:&&|;)\s*/, '').replace(/(\s*2>&1|\s*\|\s*(?:tail|head)\b[^|]*)+\s*$/, '').replace(/\s+/g, ' ').trim();
          if (/(\bsed -i|\btee\b|[^2&]>\s*[^&\s]|<<|\bgit (commit|checkout|merge|pull|reset)|\bnpm (i|install)\b)/.test(inp.command)) { editCounter++; s.edits++; if (cur) cur.edits++; }
          inc(s.cmdHeads, cmdHead(inp.command));
          const rm = nc.match(READ_CMD_RE);
          if (rm) {                         // shell reads count toward redundant reads too
            const f = rm[2]; const r = readState.get(f) || { count: 0, editMark: -1, ranges: new Set() };
            if (r.count && r.editMark === editCounter && r.ranges.has(nc)) { s.redundantReads.push({ file: f, nth: r.count + 1, via: 'Bash' }); u._wasted = 'read'; }
            if (r.editMark !== editCounter) r.ranges = new Set();
            r.count++; r.editMark = editCounter; r.ranges.add(nc); readState.set(f, r);
          }
          const c = cmdState.get(full) || { count: 0, editMark: -1, idle: 0, display: nc };
          if (c.count && c.editMark === editCounter) { c.idle++; u._wasted ??= 'rerun'; }   // rerun with no edit in between
          c.count++; c.editMark = editCounter; cmdState.set(full, c);
        }
        pending.set(u.id, { name: u.name, key, input: inp, wasted: u._wasted });
      }
    }

    if (d.type === 'user') {
      const c = m.content;
      if (typeof c === 'string' || (Array.isArray(c) && !c.some(x => x.type === 'tool_result'))) {
        const t = textOf(c);
        const human = !d.isMeta && !d.isSidechain && !/^<(command-|local-command|system-reminder)/.test(t.trim()) && !d.isCompactSummary;
        const cmd = t.match(/<command-name>\/?([^<\s]+)<\/command-name>/);
        if (cmd && !d.isSidechain) inc(s.commands, cmd[1]);
        if (INTERRUPT_RE.test(t)) { s.interrupts++; if (cur) cur.followedBy = 'interrupt'; }
        else if (human && t.trim()) onHuman(t);
        continue;
      }
      for (const r of c.filter(x => x.type === 'tool_result')) {
        const p = pending.get(r.tool_use_id) || { name: '?', key: '?' };
        const out = textOf(r.content);
        s.toolOutChars += out.length;
        // ~4 chars/token; the output sits in context for the rest of the session, this is the floor.
        if (p.wasted) s.wastedTokens[p.wasted] += Math.round(out.length / 4);
        if (r.is_error) s.wastedTokens.errors += Math.round(out.length / 4);
        if (out.length > 20000) s.bigOutputs.push({ tool: p.name, key: clip(p.key, 120), chars: out.length });
        if (r.is_error) {
          const first = clip(out.split('\n').find(l => l.trim()) || out, 140);
          s.errors.push({ tool: p.name, key: clip(p.key, 120), msg: first });
          if (EDIT_MISS_RE.test(out)) s.editMisses++;
          if (DENIED_RE.test(out)) s.denials.push({ tool: p.name, key: clip(p.key, 120) });
          const ek = `${p.name}|${first.slice(0, 60)}`;
          errStreak = ek === lastErrKey ? errStreak + 1 : 1; lastErrKey = ek;
          if (errStreak === 3) s.retryLoops.push({ tool: p.name, msg: first });
        } else { lastErrKey = null; errStreak = 0; }
      }
    }
  }
  for (const n of usesPerMsg.values()) n > 1 ? s.multiToolTurns++ : s.singleToolTurns++;
  for (const c of cmdState.values()) if (c.idle >= 2) s.repeatedCmds.push({ cmd: clip(c.display, 120), runs: c.count, noEditBetween: c.idle });
  return s;
}

// ── cross-session analysis ───────────────────────────────────────
function crossSession(sessions) {
  // Prompts that recur across sessions → slash command / skill / CLAUDE.md candidates.
  const items = [];
  for (const s of sessions) if (!s.subagent) for (const p of s.userPrompts) {
    const sh = shingles(p);
    if (sh.size >= 2 && p.length < 4000 && !CORRECTION_RE.test(p.trim())) items.push({ sid: s.sessionId, text: p, sh });
  }
  const clusters = [];
  for (const it of items) {
    let best = null, bestSim = 0;
    for (const c of clusters) { const sim = jaccard(it.sh, c.rep.sh); if (sim > bestSim) { bestSim = sim; best = c; } }
    if (best && bestSim >= 0.35) { best.members.push(it); best.sessions.add(it.sid); }
    else clusters.push({ rep: it, members: [it], sessions: new Set([it.sid]) });
  }
  const repeatedPrompts = clusters.filter(c => c.sessions.size >= 2)
    .sort((a, b) => b.sessions.size - a.sessions.size).slice(0, TOP)
    .map(c => ({ sessions: c.sessions.size, occurrences: c.members.length, example: clip(c.rep.text, 240) }));

  // Corrections that recur across sessions are the strongest CLAUDE.md signal.
  const corr = sessions.flatMap(s => s.corrections.map(t => ({ sid: s.sessionId, t, sh: shingles(t) })));
  const corrClusters = [];
  for (const it of corr) {
    const c = corrClusters.find(c => jaccard(c.rep.sh, it.sh) >= 0.3);
    if (c) { c.n++; c.sessions.add(it.sid); } else corrClusters.push({ rep: it, n: 1, sessions: new Set([it.sid]) });
  }
  const recurringCorrections = corrClusters.sort((a, b) => b.sessions.size - a.sessions.size || b.n - a.n)
    .slice(0, TOP).map(c => ({ sessions: c.sessions.size, count: c.n, example: c.rep.t }));

  const agg = (pick) => { const m = new Map(); for (const s of sessions) for (const x of pick(s)) { const k = x.k; const e = m.get(k) || { ...x, count: 0, sessions: new Set() }; e.count++; e.sessions.add(s.sessionId); m.set(k, e); } return [...m.values()].sort((a, b) => b.count - a.count).slice(0, TOP).map(e => ({ ...e, sessions: e.sessions.size, k: undefined })); };

  return {
    repeatedPrompts, recurringCorrections,
    topErrors: agg(s => s.errors.map(e => ({ k: `${e.tool}|${e.msg.slice(0, 70)}`, tool: e.tool, msg: e.msg }))),
    redundantReadFiles: agg(s => s.redundantReads.map(r => ({ k: r.file, file: r.file }))),
    repeatedCommands: agg(s => s.repeatedCmds.map(r => ({ k: r.cmd, cmd: r.cmd, runs: r.runs }))),
    permissionFriction: agg(s => s.denials.map(d => ({ k: d.key.split(' ').slice(0, 3).join(' '), call: d.key }))),
    bigOutputs: agg(s => s.bigOutputs.map(b => ({ k: b.key, call: b.key, chars: b.chars }))),
    frequentCommands: (() => { const m = new Map(); for (const s of sessions) for (const [k, v] of s.cmdHeads) inc(m, k, v); return [...m].sort((a, b) => b[1] - a[1]).slice(0, TOP).map(([cmd, n]) => ({ cmd, n })); })(),
  };
}

// ── main ─────────────────────────────────────────────────────────
if (!existsSync(ROOT)) { console.error(`No transcripts at ${ROOT}. Pass --root.`); process.exit(1); }
const files = walk(ROOT).filter(f => {
  if (PROJECT && !f.includes(PROJECT)) return false;
  if (ONLY_SESSION && !f.includes(ONLY_SESSION)) return false;
  try { return statSync(f).mtimeMs >= sinceMs; } catch { return false; }
});
const sessions = files.map(analyzeFile).filter(s => s.turns > 0);
if (!sessions.length) { console.error(`No sessions with assistant turns under ${ROOT} in the last ${SINCE_DAYS} days.`); process.exit(1); }

const sum = (f) => sessions.reduce((a, s) => a + f(s), 0);
const tokTotal = s => s.usage.input + s.usage.output + s.usage.cacheRead + s.usage.cacheWrite;

// ── overcomplication: effort that doesn't turn into output ───────
// Output proxy = edits + commits. Q&A and research sessions are legitimately
// edit-free, so every flag here is a lead to verify, not a verdict.
const mains = sessions.filter(s => !s.subagent);
const byTok = [...mains].sort((a, b) => tokTotal(a) - tokTotal(b));
const p80 = byTok.length ? tokTotal(byTok[Math.floor(byTok.length * 0.8)] || byTok.at(-1)) : Infinity;
for (const s of sessions) {
  const f = [];
  const out = s.edits + s.commits;
  const prompts = s.userPrompts.length;
  if (!s.subagent && byTok.length >= 5 && tokTotal(s) >= p80 && out <= 2) f.push('heavy-for-output');
  if (s.maxPrompt > 3000 && s.edits <= 2) f.push('long-brief-small-change');
  if (s.agentCalls >= 3 && s.edits <= 3) f.push('subagent-fanout');
  if (s.ceremony >= 5 && s.ceremony > s.edits) f.push('ceremony');
  if (s.nudges >= 3 || (prompts >= 6 && s.toolCalls / prompts < 3)) f.push('micromanaged');
  if ([...s.models.keys()].some(m => BIG_MODEL_RE.test(m)) && s.toolCalls <= 5 && s.turns <= 6) f.push('big-model-small-task');
  s.overcomplication = f;
}
// Jellyfish-style returns curve: sessions binned by token use, output per bin.
const nb = Math.min(5, byTok.length);
const returnsCurve = Array.from({ length: nb }, (_, i) => {
  const bin = byTok.slice(Math.floor(i * byTok.length / nb), Math.floor((i + 1) * byTok.length / nb));
  const avg = f => bin.reduce((a, s) => a + f(s), 0) / Math.max(1, bin.length);
  const t = avg(tokTotal), e = avg(s => s.edits + s.commits);
  return { bin: i + 1, sessions: bin.length, avgTokens: Math.round(t), avgEditsAndCommits: +e.toFixed(1), outputPerMillionTokens: t ? +(e / t * 1e6).toFixed(1) : 0 };
});
const ocCounts = {}; for (const s of sessions) for (const f of s.overcomplication) ocCounts[f] = (ocCounts[f] || 0) + 1;
const baselines = mains.map(s => s.baselineCtx || 0).sort((a, b) => a - b);
const skillUse = new Map(); for (const s of sessions) for (const [k2, v] of s.skills) inc(skillUse, k2, v);
const overcomplication = {
  flags: ocCounts, returnsCurve,
  medianBaselineContextTokens: baselines[Math.floor(baselines.length / 2)] || 0,
  subagentRuns: sum(s => s.agentCalls), ceremonyCalls: sum(s => s.ceremony), nudgePrompts: sum(s => s.nudges),
  toolCallsPerPrompt: +(sum(s => s.toolCalls) / Math.max(1, sum(s => s.userPrompts.length))).toFixed(1),
  skillsInvoked: Object.fromEntries([...skillUse].sort((a, b) => b[1] - a[1])),
  examples: sessions.filter(s => s.overcomplication.length).sort((a, b) => b.overcomplication.length - a.overcomplication.length || tokTotal(b) - tokTotal(a)).slice(0, TOP)
    .map(s => ({ sessionId: s.sessionId, project: s.project, flags: s.overcomplication, tokens: tokTotal(s), edits: s.edits, commits: s.commits, subagents: s.agentCalls, firstPrompt: clip(s.userPrompts[0] || '', 120) })),
};
const U = { input: sum(s => s.usage.input), output: sum(s => s.usage.output), cacheRead: sum(s => s.usage.cacheRead), cacheWrite: sum(s => s.usage.cacheWrite) };
const totalIn = U.input + U.cacheRead + U.cacheWrite;
const toolTotals = new Map(); for (const s of sessions) for (const [k, v] of s.toolCounts) inc(toolTotals, k, v);
const totals = {
  sessions: sessions.filter(s => !s.subagent).length, subagentRuns: sessions.filter(s => s.subagent).length,
  turns: sum(s => s.turns), toolCalls: sum(s => s.toolCalls), userPrompts: sum(s => s.userPrompts.length),
  tokens: U, cacheHitRate: totalIn ? +(U.cacheRead / totalIn).toFixed(3) : 0,
  toolErrors: sum(s => s.errors.length), errorRate: +(sum(s => s.errors.length) / Math.max(1, sum(s => s.toolCalls))).toFixed(3),
  redundantReads: sum(s => s.redundantReads.length), idleCommandReruns: sum(s => s.repeatedCmds.reduce((a, r) => a + r.noEditBetween, 0)),
  retryLoops: sum(s => s.retryLoops.length), editMisses: sum(s => s.editMisses), permissionDenials: sum(s => s.denials.length),
  oversizedOutputs: sum(s => s.bigOutputs.length), corrections: sum(s => s.corrections.length), interrupts: sum(s => s.interrupts),
  compactions: sum(s => s.compactions), searchBursts: sum(s => s.searchBursts),
  wastedTokensEstimate: { redundantReads: sum(s => s.wastedTokens.read), idleReruns: sum(s => s.wastedTokens.rerun), errorOutputs: sum(s => s.wastedTokens.errors) },
  parallelToolTurnShare: +(sum(s => s.multiToolTurns) / Math.max(1, sum(s => s.multiToolTurns + s.singleToolTurns))).toFixed(3),
  tools: Object.fromEntries([...toolTotals].sort((a, b) => b[1] - a[1])),
  usd: +sum(s => s.usd).toFixed(4),
  usdByModel: (() => { const m = new Map(); for (const s of sessions) for (const [k2, v] of s.usdByModel) inc(m, k2, v); return Object.fromEntries([...m].sort((a, b) => b[1] - a[1]).map(([k2, v]) => [k2, +v.toFixed(4)])); })(),
  unpricedModels: (() => { const m = new Map(); for (const s of sessions) for (const [k2, v] of s.unpriced) inc(m, k2, v); return Object.fromEntries(m); })(),
  pricesAsOf: PRICES_AS_OF,
  subagentsIncluded: SUBAGENTS,
};
const cross = crossSession(sessions);

// ── subagents: was each delegation worth its overhead? ───────────
// A subagent pays its own start-up context and returns only a report. That is
// worth it for parallel work, for isolating a lot of reading from the main
// context, or for a task one agent struggles with. A run that did a few tool
// calls, ran alone in the foreground, handed back about as much as it read, or
// read what the main agent read anyway got none of those and paid the overhead.
// A procedure delegated again and again is better taught once as a skill.
const TOOL_PROXY_AGENTS = new Set(['web-fetch']);   // exist to lend a tool the main agent lacks
function subagentRuns(main) {
  const dir = join(dirname(main.file), main.sessionId, 'subagents');
  let names; try { names = readdirSync(dir).filter(f => f.endsWith('.meta.json')); } catch { return []; }
  const byUse = new Map(main.agentUses.map(u => [u.id, u]));
  const siblings = new Map(); for (const u of main.agentUses) inc(siblings, u.msg);
  const runs = [];
  for (const f of names) {
    let meta; try { meta = JSON.parse(readFileSync(join(dir, f), 'utf8')); } catch { continue; }
    const log = join(dir, f.replace(/\.meta\.json$/, '.jsonl'));
    if (!existsSync(log)) continue;
    const r = analyzeFile(log);
    if (!r.turns) continue;
    const use = byUse.get(meta.toolUseId);
    const type = meta.agentType || use?.type || 'general-purpose';
    const background = meta.requestShape === 'background' || !!use?.background;
    const parallel = background || (use ? (siblings.get(use.msg) || 0) > 1 : false);
    const reportChars = r.lastText.length;
    const isolation = reportChars ? r.toolOutChars / reportChars : Infinity;   // chars read per char handed back
    const reads = [...r.filesRead];
    const dupShare = reads.length ? reads.filter(x => main.filesRead.has(x)).length / reads.length : 0;
    const flags = [];
    if (!TOOL_PROXY_AGENTS.has(type)) {
      if (r.toolCalls <= 3) flags.push('trivial');
      if (!parallel && isolation < 3) flags.push('no-isolation-gain');
      if (reads.length >= 3 && dupShare >= 0.5) flags.push('duplicated-reads');
    }
    runs.push({ sessionId: main.sessionId, type, description: clip(meta.description || '', 80), prompt: use?.prompt || '',
      usd: +r.usd.toFixed(4), startupUsd: +(r.startupUsd || 0).toFixed(4), toolCalls: r.toolCalls, turns: r.turns,
      parallel, background, isolation: Number.isFinite(isolation) ? +isolation.toFixed(1) : null, dupShare: +dupShare.toFixed(2), flags });
  }
  return runs;
}
const runs = mains.flatMap(subagentRuns);
const delegationClusters = (() => {
  const cs = [];
  for (const r of runs.filter(x => x.prompt.length > 40 && !TOOL_PROXY_AGENTS.has(x.type))) {
    const sh = shingles(r.prompt);
    const c = cs.find(c => jaccard(c.sh, sh) >= 0.3);
    if (c) { c.n++; c.usd += r.usd; c.sessions.add(r.sessionId); } else cs.push({ sh, n: 1, usd: r.usd, sessions: new Set([r.sessionId]), example: r.description || clip(r.prompt, 80) });
  }
  return cs.filter(c => c.n >= 3).sort((a, b) => b.n - a.n).slice(0, TOP)
    .map(c => ({ runs: c.n, sessions: c.sessions.size, usd: +c.usd.toFixed(4), example: c.example }));
})();
const flagged = runs.filter(r => r.flags.length);
const subagents = {
  runs: runs.length,
  usd: +runs.reduce((a, r) => a + r.usd, 0).toFixed(4),
  startupUsd: +runs.reduce((a, r) => a + r.startupUsd, 0).toFixed(4),
  parallelShare: +(runs.filter(r => r.parallel).length / Math.max(1, runs.length)).toFixed(2),
  flags: flagged.reduce((m, r) => { for (const f of r.flags) m[f] = (m[f] || 0) + 1; return m; }, {}),
  flaggedUsd: +flagged.reduce((a, r) => a + r.usd, 0).toFixed(4),
  repeatedDelegations: delegationClusters,
  examples: flagged.sort((a, b) => b.usd - a.usd).slice(0, TOP).map(({ prompt, ...r }) => r),
};
const perSession = sessions.map(s => ({
  sessionId: s.sessionId, project: s.project, subagent: s.subagent,
  start: s.start && new Date(s.start).toISOString(), minutes: s.start ? Math.round((s.end - s.start) / 60000) : 0,
  firstPrompt: clip(s.userPrompts[0] || '', 120), turns: s.turns, toolCalls: s.toolCalls, errors: s.errors.length,
  redundantReads: s.redundantReads.length, retryLoops: s.retryLoops, corrections: s.corrections, interrupts: s.interrupts,
  compactions: s.compactions, tokens: s.usage, usd: +s.usd.toFixed(4), edits: s.edits, commits: s.commits, subagents: s.agentCalls, overcomplication: s.overcomplication,
  wasteScore: s.redundantReads.length + 2 * s.retryLoops.length + s.errors.length + 3 * s.corrections.length + s.interrupts + 2 * s.compactions,
})).sort((a, b) => b.wasteScore - a.wasteScore);

// ── instruction quality: what each prompt cost, and why ──────────
const allPrompts = mains.flatMap(s => s.prompts.map(p => ({ ...p, sid: s.sessionId })));
const work = allPrompts.filter(p => !p.nudge && p.tools > 0);   // prompts that set Claude to work
const median = a => { const b = [...a].sort((x, y) => x - y); return b.length ? b[Math.floor(b.length / 2)] : 0; };
const group = ps => ({ prompts: ps.length, medianCost: Math.round(median(ps.map(p => p.cost))), medianUsd: +median(ps.map(p => p.usd)).toFixed(4), medianExploreBeforeFirstEdit: median(ps.map(p => p.explore)),
  reworkRate: +(ps.filter(p => p.followedBy).length / Math.max(1, ps.length)).toFixed(2) });
const vague = p => !p.anchored && p.chars < 300;
const totalCost = allPrompts.reduce((a, p) => a + p.cost, 0);
const reworked = allPrompts.filter(p => p.followedBy);
const instructionQuality = {
  costUnit: 'fresh-input-token equivalents (output ×5, cache write ×1.25, cache read ×0.1)',
  totalCost: Math.round(totalCost),
  vague: group(work.filter(vague)), anchored: group(work.filter(p => p.anchored)),
  withCriteria: group(work.filter(p => p.criteria)), withoutCriteria: group(work.filter(p => !p.criteria)),
  reworkCost: Math.round(reworked.reduce((a, p) => a + p.cost, 0)),
  totalUsd: +allPrompts.reduce((a, p) => a + p.usd, 0).toFixed(4),
  reworkUsd: +reworked.reduce((a, p) => a + p.usd, 0).toFixed(4),
  reworkShare: +(reworked.reduce((a, p) => a + p.cost, 0) / Math.max(1, totalCost)).toFixed(3),
  costliestBadPrompts: allPrompts.filter(p => p.followedBy || (vague(p) && !p.nudge && p.explore >= 5))
    .sort((a, b) => b.cost - a.cost).slice(0, TOP)
    .map(p => ({ sessionId: p.sid, cost: Math.round(p.cost), usd: +p.usd.toFixed(4), why: [p.followedBy && `followed by ${p.followedBy}`, vague(p) && 'no concrete anchor', !p.criteria && 'no done-criteria', p.explore >= 5 && `${p.explore} lookups before first edit`].filter(Boolean), prompt: clip(p.text, 300) })),
};

// What the setup is actually used for, so audit-setup.mjs can tell a configured
// agent, skill, MCP server or command apart from one that is only paid for.
const usage = (() => {
  const agents = new Map(), commands = new Map(), mcpServers = new Map();
  for (const s of mains) { for (const u of s.agentUses) inc(agents, u.type); for (const [c, n] of s.commands) inc(commands, c, n); }
  for (const [tool, n] of Object.entries(totals.tools)) { const m = tool.match(/^mcp__(.+?)__/); if (m) inc(mcpServers, m[1], n); }
  const obj = m => Object.fromEntries([...m].sort((a, b) => b[1] - a[1]));
  return { sessions: mains.length, agents: obj(agents), skills: overcomplication.skillsInvoked, mcpServers: obj(mcpServers), commands: obj(commands) };
})();

const report = { generatedAt: new Date().toISOString(), root: ROOT, sinceDays: SINCE_DAYS, totals, instructionQuality, cross, overcomplication, subagents, usage, worstSessions: perSession.slice(0, TOP), sessions: perSession };
if (JSON_OUT) writeFileSync(JSON_OUT, JSON.stringify(report, null, 2));

// ── markdown summary ─────────────────────────────────────────────
const k = n => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(n);
const T = totals, out = [];
const usd = n => n >= 100 ? `$${n.toFixed(0)}` : n >= 1 ? `$${n.toFixed(2)}` : `$${n.toFixed(3)}`;
const byModel = Object.entries(T.usdByModel).map(([m, v]) => `${m} ${usd(v)}`).join(', ');
out.push(`# Claude work review — last ${SINCE_DAYS} days`, '',
  `Root: \`${ROOT}\`${PROJECT ? ` · project filter: \`${PROJECT}\`` : ''}`, '',
  `| Metric | Value |`, `|---|---|`,
  `| Cost at API list prices (not your bill on a seat plan) | **${usd(T.usd)}**${byModel ? ` — ${byModel}` : ''} |`,
  `| Sessions (subagent runs) | ${T.sessions} (${T.subagentRuns}) |`,
  `| Model turns / tool calls / your prompts | ${T.turns} / ${T.toolCalls} / ${T.userPrompts} |`,
  `| Tokens in (fresh · cache read · cache write) / out | ${k(U.input)} · ${k(U.cacheRead)} · ${k(U.cacheWrite)} / ${k(U.output)} |`,
  `| Cache hit rate | ${(T.cacheHitRate * 100).toFixed(1)}% |`,
  `| Tool error rate | ${(T.errorRate * 100).toFixed(1)}% (${T.toolErrors}, ~${k(T.wastedTokensEstimate.errorOutputs)} tokens of error output) |`,
  `| Redundant reads (same file+range, no edit between) | ${T.redundantReads} (~${k(T.wastedTokensEstimate.redundantReads)} tokens) |`,
  `| Command re-runs with no edit between | ${T.idleCommandReruns} (~${k(T.wastedTokensEstimate.idleReruns)} tokens) |`,
  `| Retry loops (same error ≥3× in a row) | ${T.retryLoops} |`,
  `| Edit misses (old_string not found etc.) | ${T.editMisses} |`,
  `| Permission denials | ${T.permissionDenials} |`,
  `| Oversized tool outputs (>20k chars) | ${T.oversizedOutputs} |`,
  `| Your corrections / interrupts | ${T.corrections} / ${T.interrupts} |`,
  `| Compactions | ${T.compactions} |`,
  `| Search bursts (≥8 Grep/Glob in a row) | ${T.searchBursts} |`,
  `| Turns that batched parallel tool calls | ${(T.parallelToolTurnShare * 100).toFixed(1)}% |`, '',
  `Dollars are what these tokens would cost on the Claude API at list prices as of ${T.pricesAsOf} (cache writes and reads priced separately, fast mode ×2). On a Team, Max or Enterprise seat you pay per seat, so this is the API-equivalent value of the work, not an invoice.` +
  (T.subagentsIncluded ? '' : ' Subagent runs are not included; add --include-subagents to count them.') +
  (Object.keys(T.unpricedModels).length ? ` Not priced (unknown model): ${Object.entries(T.unpricedModels).map(([m, n]) => `${m} ${k(n)} tokens`).join(', ')}; add it with --prices.` : ''), '');
const section = (title, rows, fmt) => { if (rows.length) { out.push(`## ${title}`, ''); rows.forEach(r => out.push(`- ${fmt(r)}`)); out.push(''); } };
const OC = overcomplication;
{
  const Q = instructionQuality, row = (name, g) => `| ${name} | ${g.prompts} | ${usd(g.medianUsd)} | ${g.medianExploreBeforeFirstEdit} | ${(g.reworkRate * 100).toFixed(0)}% |`;
  out.push('## Instruction quality', '',
    `Prompts followed by a correction or interrupt cost **${usd(Q.reworkUsd)}** (${(Q.reworkShare * 100).toFixed(1)}% of all spend).`, '',
    '| Prompts | Count | Median cost | Median lookups before first edit | Led to rework |', '|---|---|---|---|---|',
    row('Vague (no file, code, error or URL; <300 chars)', Q.vague), row('Anchored (names a file, code, error or URL)', Q.anchored),
    row('States done-criteria', Q.withCriteria), row('No done-criteria', Q.withoutCriteria), '');
  if (Q.costliestBadPrompts.length) { out.push('Costliest prompts that were vague or needed correcting:', ''); Q.costliestBadPrompts.slice(0, 5).forEach(p => out.push(`- ${usd(p.usd)} (${p.why.join('; ')}) \`${p.sessionId.slice(0, 8)}\`: “${clip(p.prompt, 160)}”`)); out.push(''); }
}
if (Object.keys(OC.flags).length || OC.returnsCurve.length > 1) {
  out.push('## Overcomplication', '',
    `Always-on context per session (median): ~${k(OC.medianBaselineContextTokens)} tokens · tool calls per prompt: ${OC.toolCallsPerPrompt} · subagents: ${OC.subagentRuns} · todo/plan calls: ${OC.ceremonyCalls} · “continue/yes” prompts: ${OC.nudgePrompts}`, '');
  if (Object.keys(OC.flags).length) out.push('Flags: ' + Object.entries(OC.flags).map(([f, n]) => `${f} ×${n}`).join(', '), '');
  if (OC.returnsCurve.length > 1) {
    out.push('Output per token, sessions binned by token use (does more spend buy more change?):', '', '| Bin | Sessions | Avg tokens | Avg edits+commits | per 1M tokens |', '|---|---|---|---|---|');
    for (const b of OC.returnsCurve) out.push(`| ${b.bin} | ${b.sessions} | ${k(b.avgTokens)} | ${b.avgEditsAndCommits} | ${b.outputPerMillionTokens} |`);
    out.push('');
  }
  OC.examples.slice(0, 5).forEach(e => out.push(`- \`${e.sessionId.slice(0, 8)}\` ${e.flags.join(', ')} — ${k(e.tokens)} tokens, ${e.edits} edits, ${e.commits} commits, ${e.subagents} subagents: “${e.firstPrompt}”`));
  out.push('');
}
if (subagents.runs) {
  const S = subagents;
  out.push('## Subagents', '',
    `${S.runs} subagent runs cost ${usd(S.usd)}, of which ${usd(S.startupUsd)} was start-up context alone. ${Math.round(S.parallelShare * 100)}% ran in parallel or in the background.`, '');
  if (Object.keys(S.flags).length) out.push(`Runs that got no benefit from being a subagent (${usd(S.flaggedUsd)}): ` + Object.entries(S.flags).map(([f, n]) => `${f} ×${n}`).join(', '), '');
  S.examples.slice(0, 5).forEach(r => out.push(`- ${usd(r.usd)} ${r.type} “${r.description}” — ${r.toolCalls} tool calls, ${r.parallel ? 'parallel' : 'alone in the foreground'}, read ${r.isolation ?? '∞'}× what it reported, ${Math.round(r.dupShare * 100)}% of its files also read by the main agent: ${r.flags.join(', ')}`));
  S.repeatedDelegations.forEach(c => out.push(`- Delegated ${c.runs}× across ${c.sessions} sessions (${usd(c.usd)}): “${c.example}” — a procedure repeated this often is a skill candidate.`));
  out.push('');
}
section('Instructions you repeat across sessions', cross.repeatedPrompts, r => `${r.sessions} sessions / ${r.occurrences}×: “${r.example}”`);
section('Corrections you keep making', cross.recurringCorrections, r => `${r.sessions} sessions / ${r.count}×: “${r.example}”`);
section('Most common tool errors', cross.topErrors, r => `${r.count}× in ${r.sessions} sessions — **${r.tool}**: ${r.msg}`);
section('Files re-read without changes', cross.redundantReadFiles, r => `${r.count}× in ${r.sessions} sessions — \`${r.file}\``);
section('Commands re-run with nothing changed', cross.repeatedCommands, r => `${r.sessions} sessions (up to ${r.runs} runs) — \`${r.cmd}\``);
section('Permission friction', cross.permissionFriction, r => `${r.count}× — \`${r.call}\``);
section('Oversized outputs', cross.bigOutputs, r => `${r.count}× — \`${r.call}\` (~${k(r.chars)} chars)`);
section('Most frequent shell commands', cross.frequentCommands, r => `${r.n}× \`${r.cmd}\``);
section('Sessions with the most waste signals', report.worstSessions.filter(s => s.wasteScore > 0), s =>
  `\`${s.sessionId.slice(0, 8)}\` ${s.project} (${s.minutes} min, score ${s.wasteScore}): “${s.firstPrompt}” — ${s.errors} errors, ${s.redundantReads} redundant reads, ${s.corrections.length} corrections, ${s.compactions} compactions`);
if (JSON_OUT) out.push(`Full findings: \`${JSON_OUT}\``);
console.log(out.join('\n'));
