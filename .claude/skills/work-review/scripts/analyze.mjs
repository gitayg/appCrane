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
const INTERRUPT_RE = /\[Request interrupted by user/;
const DENIED_RE = /(permission|was denied|user (?:rejected|declined|doesn't want)|not allowed|requires approval)/i;
const EDIT_MISS_RE = /(string to replace not found|old_string.*not (?:found|unique)|found \d+ matches|File has not been read yet|file has been modified since)/i;

// ── per-session analysis ─────────────────────────────────────────
function analyzeFile(path) {
  const lines = readFileSync(path, 'utf8').split('\n');
  const s = {
    file: path, project: basename(dirname(path).replace(/\/subagents$/, '')), sessionId: basename(path, '.jsonl'),
    subagent: path.includes('/subagents/'), start: null, end: null, models: new Map(),
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, turns: 0, userPrompts: [],
    toolCalls: 0, toolCounts: new Map(), errors: [], redundantReads: [], repeatedCmds: [],
    retryLoops: [], editMisses: 0, denials: [], bigOutputs: [], corrections: [], interrupts: 0,
    compactions: 0, searchBursts: 0, singleToolTurns: 0, multiToolTurns: 0, cmdHeads: new Map(),
  };
  const seenMsg = new Set();
  const pending = new Map();          // tool_use_id -> {name, input, key}
  const readState = new Map();        // file -> {count, editedSince}
  const cmdState = new Map();         // normalised cmd -> {count, editSince}
  let lastErrKey = null, errStreak = 0, searchRun = 0;
  let editCounter = 0;
  const usesPerMsg = new Map();

  for (const line of lines) {
    if (!line.trim()) continue;
    let d; try { d = JSON.parse(line); } catch { continue; }
    if (d.timestamp) { const t = Date.parse(d.timestamp); if (!s.start || t < s.start) s.start = t; if (!s.end || t > s.end) s.end = t; }
    if (d.type === 'system' && (d.subtype === 'compact_boundary' || /compact/i.test(d.content || ''))) s.compactions++;
    if (d.isCompactSummary) s.compactions++;
    const m = d.message;
    if (!m || typeof m !== 'object') continue;

    if (d.type === 'assistant') {
      const id = m.id || d.uuid;
      if (m.usage && !seenMsg.has(id)) {      // streamed messages repeat usage; count once
        seenMsg.add(id); s.turns++;
        s.usage.input += m.usage.input_tokens || 0; s.usage.output += m.usage.output_tokens || 0;
        s.usage.cacheRead += m.usage.cache_read_input_tokens || 0; s.usage.cacheWrite += m.usage.cache_creation_input_tokens || 0;
        if (m.model) inc(s.models, m.model);
      }
      const uses = (Array.isArray(m.content) ? m.content : []).filter(x => x.type === 'tool_use');
      if (uses.length) inc(usesPerMsg, id, uses.length);   // streamed: one block per record, same id
      for (const u of uses) {
        s.toolCalls++; inc(s.toolCounts, u.name);
        const inp = u.input || {};
        let key = u.name;
        if (/^(Grep|Glob)$/.test(u.name)) { if (++searchRun === 8) s.searchBursts++; } else if (u.name !== 'Read') searchRun = 0;

        if (u.name === 'Read' && inp.file_path) {
          key = `Read ${inp.file_path}`;
          const r = readState.get(inp.file_path) || { count: 0, editMark: -1, ranges: new Set() };
          const range = `${inp.offset ?? 0}:${inp.limit ?? 'all'}`;
          if (r.count && r.editMark === editCounter && r.ranges.has(range)) s.redundantReads.push({ file: inp.file_path, nth: r.count + 1 });
          if (r.editMark !== editCounter) r.ranges = new Set();
          r.count++; r.editMark = editCounter; r.ranges.add(range); readState.set(inp.file_path, r);
        } else if (/^(Edit|Write|MultiEdit|NotebookEdit)$/.test(u.name)) {
          editCounter++;
        } else if (u.name === 'Bash' && inp.command) {
          const nc = normCmd(inp.command); key = `Bash ${nc}`;
          inc(s.cmdHeads, cmdHead(inp.command));
          const rm = nc.match(READ_CMD_RE);
          if (rm) {                         // shell reads count toward redundant reads too
            const f = rm[2]; const r = readState.get(f) || { count: 0, editMark: -1, ranges: new Set() };
            if (r.count && r.editMark === editCounter && r.ranges.has(nc)) s.redundantReads.push({ file: f, nth: r.count + 1, via: 'Bash' });
            if (r.editMark !== editCounter) r.ranges = new Set();
            r.count++; r.editMark = editCounter; r.ranges.add(nc); readState.set(f, r);
          }
          const c = cmdState.get(nc) || { count: 0, editMark: -1, idle: 0 };
          if (c.count && c.editMark === editCounter) c.idle++;   // rerun with no edit in between
          c.count++; c.editMark = editCounter; cmdState.set(nc, c);
        }
        pending.set(u.id, { name: u.name, key, input: inp });
      }
    }

    if (d.type === 'user') {
      const c = m.content;
      if (typeof c === 'string' || (Array.isArray(c) && !c.some(x => x.type === 'tool_result'))) {
        const t = textOf(c);
        const human = !d.isMeta && !d.isSidechain && !/^<(command-|local-command|system-reminder)/.test(t.trim()) && !d.isCompactSummary;
        if (INTERRUPT_RE.test(t)) s.interrupts++;
        else if (human && t.trim()) {
          s.userPrompts.push(t);
          if (CORRECTION_RE.test(t.trim())) s.corrections.push(clip(t, 220));
        }
        continue;
      }
      for (const r of c.filter(x => x.type === 'tool_result')) {
        const p = pending.get(r.tool_use_id) || { name: '?', key: '?' };
        const out = textOf(r.content);
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
  for (const [cmd, c] of cmdState) if (c.idle >= 2) s.repeatedCmds.push({ cmd: clip(cmd, 120), runs: c.count, noEditBetween: c.idle });
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
  parallelToolTurnShare: +(sum(s => s.multiToolTurns) / Math.max(1, sum(s => s.multiToolTurns + s.singleToolTurns))).toFixed(3),
  tools: Object.fromEntries([...toolTotals].sort((a, b) => b[1] - a[1])),
};
const cross = crossSession(sessions);
const perSession = sessions.map(s => ({
  sessionId: s.sessionId, project: s.project, subagent: s.subagent,
  start: s.start && new Date(s.start).toISOString(), minutes: s.start ? Math.round((s.end - s.start) / 60000) : 0,
  firstPrompt: clip(s.userPrompts[0] || '', 120), turns: s.turns, toolCalls: s.toolCalls, errors: s.errors.length,
  redundantReads: s.redundantReads.length, retryLoops: s.retryLoops, corrections: s.corrections, interrupts: s.interrupts,
  compactions: s.compactions, tokens: s.usage,
  wasteScore: s.redundantReads.length + 2 * s.retryLoops.length + s.errors.length + 3 * s.corrections.length + s.interrupts + 2 * s.compactions,
})).sort((a, b) => b.wasteScore - a.wasteScore);

const report = { generatedAt: new Date().toISOString(), root: ROOT, sinceDays: SINCE_DAYS, totals, cross, worstSessions: perSession.slice(0, TOP), sessions: perSession };
if (JSON_OUT) writeFileSync(JSON_OUT, JSON.stringify(report, null, 2));

// ── markdown summary ─────────────────────────────────────────────
const k = n => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(n);
const T = totals, out = [];
out.push(`# Claude work review — last ${SINCE_DAYS} days`, '',
  `Root: \`${ROOT}\`${PROJECT ? ` · project filter: \`${PROJECT}\`` : ''}`, '',
  `| Metric | Value |`, `|---|---|`,
  `| Sessions (subagent runs) | ${T.sessions} (${T.subagentRuns}) |`,
  `| Model turns / tool calls / your prompts | ${T.turns} / ${T.toolCalls} / ${T.userPrompts} |`,
  `| Tokens in (fresh · cache read · cache write) / out | ${k(U.input)} · ${k(U.cacheRead)} · ${k(U.cacheWrite)} / ${k(U.output)} |`,
  `| Cache hit rate | ${(T.cacheHitRate * 100).toFixed(1)}% |`,
  `| Tool error rate | ${(T.errorRate * 100).toFixed(1)}% (${T.toolErrors}) |`,
  `| Redundant reads (same file+range, no edit between) | ${T.redundantReads} |`,
  `| Command re-runs with no edit between | ${T.idleCommandReruns} |`,
  `| Retry loops (same error ≥3× in a row) | ${T.retryLoops} |`,
  `| Edit misses (old_string not found etc.) | ${T.editMisses} |`,
  `| Permission denials | ${T.permissionDenials} |`,
  `| Oversized tool outputs (>20k chars) | ${T.oversizedOutputs} |`,
  `| Your corrections / interrupts | ${T.corrections} / ${T.interrupts} |`,
  `| Compactions | ${T.compactions} |`,
  `| Search bursts (≥8 Grep/Glob in a row) | ${T.searchBursts} |`,
  `| Turns that batched parallel tool calls | ${(T.parallelToolTurnShare * 100).toFixed(1)}% |`, '');
const section = (title, rows, fmt) => { if (rows.length) { out.push(`## ${title}`, ''); rows.forEach(r => out.push(`- ${fmt(r)}`)); out.push(''); } };
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
