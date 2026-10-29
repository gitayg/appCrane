#!/usr/bin/env node
// Setup audit: how is Claude Code set up here, and is it simpler or more
// complicated than it needs to be? Inventories CLAUDE.md files, subagents,
// skills, slash commands, MCP servers, hooks and permissions (project + user
// level) and any multi-agent framework in the code being built, then checks
// each against Claude Code's published guidance (references/best-practices.md)
// and — given the analyzer's report — against what the transcripts show is
// actually used.
//
//   node audit-setup.mjs [--project DIR] [--user-dir DIR] [--report work-review.json] [--json OUT.json]
//
// Read-only. Prints a markdown summary; --json writes the findings.

import { readdirSync, readFileSync, statSync, writeFileSync, existsSync, realpathSync } from 'fs';
import { join, relative, basename, dirname } from 'path';
import { homedir } from 'os';

const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(`--${n}`); return i === -1 ? d : args[i + 1]; };
const PROJECT = opt('project', process.cwd());
const USER_DIR = opt('user-dir', process.env.CLAUDE_CONFIG_DIR || join(homedir(), '.claude'));
const REPORT = opt('report', null);
const JSON_OUT = opt('json', null);

// Thresholds. Named so a reviewer can see — and the skill can quote — the line
// each finding crossed. Sources in references/best-practices.md.
// [doc] = stated in the Claude Code docs; [ours] = this skill's own heuristic.
export const LIMITS = {
  claudeMdLines: 200,        // [doc] "target under 200 lines per CLAUDE.md file"
  alwaysOnTokens: 4000,      // [ours] root + user CLAUDE.md + their @imports, summed (imports don't reduce cost [doc])
  procedureSteps: 8,         // [ours] a numbered run this long is "a procedure rather than a fact" [doc] → skill
  emphasisPer100Lines: 6,    // [ours] docs: emphasis on "that line alone" when one rule keeps being skipped
  skillMdLines: 500,         // [doc] "Keep SKILL.md under 500 lines"
  descriptionMin: 40,        // [ours] descriptions drive delegation and skill loading [doc]
  similarDescriptions: 0.5,  // [ours] overlap at which two agents/skills compete for the same work
  minSessionsForUnused: 10,  // [ours] "never used" means nothing on a handful of sessions
};

// ── helpers ──────────────────────────────────────────────────────
const read = f => { try { return readFileSync(f, 'utf8'); } catch { return null; } };
const isDir = d => { try { return statSync(d).isDirectory(); } catch { return false; } };
const lines = t => t.split('\n');
const tokens = t => Math.round(t.length / 4);
const words = s => String(s).toLowerCase().replace(/[^a-z0-9]+/g, ' ').split(' ').filter(w => w.length > 2);
const shingles = s => { const w = words(s); const o = new Set(); for (let i = 0; i + 1 < w.length; i++) o.add(w[i] + ' ' + w[i + 1]); return o; };
const jaccard = (a, b) => { if (!a.size || !b.size) return 0; let n = 0; for (const x of a) if (b.has(x)) n++; return n / (a.size + b.size - n); };
const rel = f => f.startsWith(PROJECT) ? relative(PROJECT, f) || '.' : f.replace(homedir(), '~');
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'vendor', '.venv', 'venv', '__pycache__', 'coverage']);

function walk(dir, pick, depth = 6, out = []) {
  if (depth < 0) return out;
  let ents; try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of ents) {
    const p = join(dir, e.name);
    // Follow symlinks: skills are often installed as a link to a checkout. The
    // depth limit bounds a link loop.
    const isDirLike = e.isDirectory() || (e.isSymbolicLink() && isDir(p));
    if (isDirLike) { if (!SKIP_DIRS.has(e.name)) walk(p, pick, depth - 1, out); }
    else if (pick(p, e.name)) out.push(p);
  }
  return out;
}

/** Minimal YAML frontmatter: top-level `key: value` lines and `key:` lists. */
export function frontmatter(text) {
  const m = String(text).match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!m) return { fm: null, body: text };
  const fm = {};
  let last = null;
  for (const l of m[1].split(/\r?\n/)) {
    const kv = l.match(/^([A-Za-z_][\w-]*):\s*(.*)$/);
    if (kv) { last = kv[1]; fm[last] = kv[2].replace(/^["']|["']$/g, ''); continue; }
    const item = l.match(/^\s+-\s+(.*)$/);
    if (item && last) fm[last] = (fm[last] ? fm[last] + ', ' : '') + item[1];
    else if (last && /^\s+\S/.test(l)) fm[last] += ' ' + l.trim();      // folded description
  }
  return { fm, body: text.slice(m[0].length) };
}

const findings = [];
// `kind` is a stable slug so findings can be counted across people without
// sending names or file contents anywhere.
const add = (kind, area, severity, item, finding, fix, evidence = {}) => findings.push({ kind, area, severity, item, finding, fix, evidence });

// Usage from the analyzer, if given.
const usage = (() => {
  if (!REPORT) return null;
  try { return JSON.parse(readFileSync(REPORT, 'utf8')).usage || null; } catch { return null; }
})();
const enoughUsage = !!usage && usage.sessions >= LIMITS.minSessionsForUnused;
const usedCount = (map, name) => usage ? (map?.[name] ?? Object.entries(map || {}).find(([k]) => k.endsWith(':' + name) || k === name)?.[1] ?? 0) : null;

// ── CLAUDE.md ────────────────────────────────────────────────────
const claudeFiles = [
  ...walk(PROJECT, (p, n) => n === 'CLAUDE.md' || n === 'CLAUDE.local.md', 6),
  ...[join(USER_DIR, 'CLAUDE.md')].filter(existsSync),
];
const EMPHASIS_RE = /\b(MUST|NEVER|ALWAYS|IMPORTANT|CRITICAL|DO NOT|YOU MUST)\b/g;
let alwaysOn = 0;
// @imports are inlined into the context: they organise a file but "don't reduce
// its context cost" [doc]. Resolve them (relative to the importing file, ~ to
// home, at most four hops) so the always-on total is honest.
function importedTokens(file, text, depth = 0, seen = new Set()) {
  if (depth >= 4) return 0;
  let n = 0;
  for (const m of text.matchAll(/(?:^|\s)@((?:~\/|\.{0,2}\/)?[\w./-]+\.[A-Za-z]+)/g)) {
    const target = m[1].startsWith('~/') ? join(homedir(), m[1].slice(2)) : join(dirname(file), m[1]);
    if (seen.has(target)) continue;
    seen.add(target);
    const t = read(target);
    if (t != null) n += tokens(t) + importedTokens(target, t, depth + 1, seen);
  }
  return n;
}
const claudeMd = claudeFiles.map(f => {
  const t = read(f) || '';
  const L = lines(t);
  const nested = dirname(f) !== PROJECT && !f.startsWith(USER_DIR);
  const imported = importedTokens(f, t);
  if (!nested) alwaysOn += tokens(t) + imported;   // root + user files load every session; nested ones load on demand [doc]
  // Longest run of numbered steps: a procedure, which is a skill's job.
  let run = 0, maxRun = 0;
  for (const l of L) { if (/^\s*\d+[.)]\s/.test(l)) { run++; maxRun = Math.max(maxRun, run); } else if (l.trim()) run = 0; }
  const emphasis = (t.match(EMPHASIS_RE) || []).length;
  const imports = (t.match(/(^|\s)@[\w./~-]+\.(md|txt)\b/g) || []).length;
  const info = { file: rel(f), lines: L.length, tokens: tokens(t), importedTokens: imported, nested, emphasis, longestProcedure: maxRun, imports };
  if (L.length > LIMITS.claudeMdLines) add('claude-md-long', 'CLAUDE.md', 'high', info.file, `${L.length} lines — loaded into every request and long enough that rules get diluted`, 'Cut what Claude can learn from the code; move procedures into skills and area-specific rules into nested CLAUDE.md files', info);
  if (maxRun >= LIMITS.procedureSteps) add('claude-md-procedure', 'CLAUDE.md', 'medium', info.file, `a ${maxRun}-step procedure lives in always-loaded memory`, 'Move it into a skill: it then loads only when that task comes up', info);
  const per100 = emphasis / Math.max(1, L.length) * 100;
  if (emphasis >= 5 && per100 > LIMITS.emphasisPer100Lines) add('claude-md-shouting', 'CLAUDE.md', 'low', info.file, `${emphasis} MUST/NEVER/IMPORTANT markers (${per100.toFixed(1)} per 100 lines)`, 'Current models follow plain instructions; shouting makes them over-apply rules. State the rule and its reason calmly', info);
  return info;
});
if (alwaysOn > LIMITS.alwaysOnTokens) add('always-on-heavy', 'CLAUDE.md', 'medium', 'all always-loaded CLAUDE.md', `~${alwaysOn} tokens of memory are sent with every request`, 'Trim to what is true for every task; the rest belongs in skills or nested CLAUDE.md files', { alwaysOnTokens: alwaysOn });
if (!claudeMd.some(c => !c.nested && !c.file.startsWith('~'))) add('claude-md-missing', 'CLAUDE.md', 'low', 'project', 'no project CLAUDE.md', 'Add a short one (/init): build and test commands, layout, conventions Claude cannot infer', {});
// Lines repeated across files are paid for twice and drift apart.
{
  const seen = new Map();
  for (const f of claudeFiles) for (const l of lines(read(f) || '')) {
    const k = l.trim().toLowerCase();
    if (k.length < 40) continue;
    const set = seen.get(k) || new Set(); set.add(rel(f)); seen.set(k, set);
  }
  const dup = [...seen].filter(([, s]) => s.size > 1);
  if (dup.length >= 3) add('claude-md-duplicates', 'CLAUDE.md', 'low', 'several files', `${dup.length} lines are repeated across CLAUDE.md files`, 'Keep each rule in one place (an @import if several files need it)', { examples: dup.slice(0, 3).map(([l, s]) => ({ line: l.slice(0, 80), files: [...s] })) });
}

// ── subagents ────────────────────────────────────────────────────
const agentFiles = [join(PROJECT, '.claude', 'agents'), join(USER_DIR, 'agents')].filter(isDir)
  .flatMap(d => walk(d, (p, n) => n.endsWith('.md'), 2));
const agents = agentFiles.map(f => {
  const { fm, body } = frontmatter(read(f) || '');
  const name = fm?.name || basename(f, '.md');
  const tools = fm?.tools ? fm.tools.split(/\s*,\s*/).filter(Boolean) : null;
  const a = { name, file: rel(f), description: fm?.description || '', tools, model: fm?.model || null, bodyLines: lines(body).length, used: usedCount(usage?.agents, name) };
  if (!fm) add('agent-no-frontmatter', 'Subagents', 'medium', a.file, 'no frontmatter, so no name or description to route on', 'Add name and a description saying when to use it', a);
  else if (a.description.length < LIMITS.descriptionMin) add('agent-thin-description', 'Subagents', 'medium', name, `description is ${a.description.length} characters — too thin for Claude to know when to delegate`, 'Say what it does and when to use it, in one or two sentences', a);
  if (!tools) add('agent-all-tools', 'Subagents', 'low', name, 'no tools list, so it inherits every tool including MCP servers', 'List only the tools it needs (e.g. a reviewer: Read, Grep, Glob)', a);
  const readOnly = tools && tools.every(t => /^(Read|Grep|Glob|WebFetch|WebSearch|LS)$/i.test(t));
  if (readOnly && /opus|fable/i.test(a.model || '')) add('agent-oversized-model', 'Subagents', 'low', name, `a read-only searcher pinned to ${a.model}`, 'Search and lookup agents rarely need the top model: try haiku or sonnet', a);
  if (a.used === 0 && enoughUsage) add('agent-unused', 'Subagents', 'medium', name, `defined but not used in ${usage.sessions} recent sessions`, 'Delete it — every agent description is routing noise — or fix its description if it should have run', a);
  return a;
});
for (let i = 0; i < agents.length; i++) for (let j = i + 1; j < agents.length; j++) {
  const sim = jaccard(shingles(agents[i].description), shingles(agents[j].description));
  if (sim >= LIMITS.similarDescriptions) add('agent-overlap', 'Subagents', 'medium', `${agents[i].name} / ${agents[j].name}`, `descriptions overlap ${Math.round(sim * 100)}% — Claude cannot reliably pick between them`, 'Merge them, or make each description say what the other does not', {});
}

// ── skills ───────────────────────────────────────────────────────
// Installed plugins are read too (inventoried, never judged), so a personal
// copy of a skill a plugin also ships is caught below.
const skillFiles = [[join(PROJECT, '.claude', 'skills'), 'project', 4], [join(USER_DIR, 'skills'), 'user', 4], [join(USER_DIR, 'plugins', 'cache'), 'plugin', 7]]
  .filter(([d]) => isDir(d))
  .flatMap(([d, scope, depth]) => walk(d, (p, n) => n === 'SKILL.md', depth).map(f => ({ f, scope: scope === 'user' && /[\\/]synced[\\/]/.test(f) ? 'synced' : scope })));
const real = f => { try { return realpathSync(f); } catch { return f; } };
const skills = skillFiles.map(({ f, scope }) => {
  const text = read(f) || '';
  const { fm } = frontmatter(text);
  const name = fm?.name || basename(dirname(f));
  const s = { name, scope, file: rel(f), real: real(f), description: fm?.description || '', lines: lines(text).length, used: usedCount(usage?.skills, name) };
  // Skills synced from an organisation or plugin are inventoried, not judged:
  // the person running the review cannot edit them.
  s.managed = /[\\/](synced|plugins)[\\/]/.test(f);
  if (s.managed) return s;
  if (!fm || !s.description) add('skill-no-description', 'Skills', 'high', s.file, 'no description, so it never triggers on its own', 'Add a description: what it does and when to use it, key use case first', s);
  else if (s.description.length < LIMITS.descriptionMin) add('skill-thin-description', 'Skills', 'medium', name, `description is ${s.description.length} characters`, 'Say what it does and when to use it, key use case first', s);
  // A skill that deploys, publishes or deletes should run only when asked:
  // "You don't want Claude deciding to deploy because your code looks ready" [doc].
  if (/\b(deploy|publish|push to|delete|drop|migrate prod|send email|post to|merge to main|cut a release)\b/i.test(`${name} ${s.description}`) && String(fm?.['disable-model-invocation']) !== 'true') {
    add('skill-side-effect-auto', 'Skills', 'medium', name, 'has side effects but Claude may run it on its own', 'Add `disable-model-invocation: true` so it runs only when invoked', s);
  }
  if (s.lines > LIMITS.skillMdLines) add('skill-long', 'Skills', 'medium', name, `SKILL.md is ${s.lines} lines`, 'Keep SKILL.md to the steps; move detail into referenced files it reads only when needed', s);
  if (s.used === 0 && enoughUsage) add('skill-unused', 'Skills', 'low', name, `not invoked in ${usage.sessions} recent sessions`, 'Check the description triggers on real requests, or remove it', s);
  return s;
});
// The same skill installed twice — a personal or project copy beside a plugin's,
// say — loads twice and competes for the same requests, and a plugin update
// moves only one of them: the copies drift with nothing saying so. A symlink to
// the same file is one install, not two.
const twice = new Set(), reported = new Set();
for (let i = 0; i < skills.length; i++) for (let j = i + 1; j < skills.length; j++) {
  const a = skills[i], b = skills[j];
  if (a.real === b.real || a.scope === b.scope || a.name !== b.name) continue;
  twice.add(i + ':' + j);
  // One finding per skill name, however many cached plugin versions it has.
  if (reported.has(a.name)) continue;
  reported.add(a.name);
  const copy = a.scope === 'plugin' ? b : a, other = copy === a ? b : a;
  add('skill-installed-twice', 'Skills', 'medium', a.name, `installed at ${copy.scope} scope (${copy.file}) and ${other.scope} scope (${other.file}); both load and compete, and updating one leaves the other behind`,
    other.scope === 'plugin' ? `Delete the ${copy.scope} copy and keep the plugin's, so updates reach it` : 'Keep one copy: delete the other, or link it to the first', { files: [a.file, b.file] });
}
for (let i = 0; i < skills.length; i++) for (let j = i + 1; j < skills.length; j++) {
  // Two skills nobody here can edit (synced, or plugin copies such as two cached
  // versions of one plugin) are not the user's overlap to fix.
  if (twice.has(i + ':' + j) || skills[i].real === skills[j].real || (skills[i].managed && skills[j].managed)) continue;
  const sim = jaccard(shingles(skills[i].description), shingles(skills[j].description));
  if (sim >= LIMITS.similarDescriptions) add('skill-overlap', 'Skills', 'medium', `${skills[i].name} / ${skills[j].name}`, `descriptions overlap ${Math.round(sim * 100)}%`, 'Merge them or sharpen when each applies', {});
}
// A subagent whose body is a procedure for the main agent's kind of work is a skill in disguise.
for (const a of agents) if (a.bodyLines >= 30 && (!a.tools || a.tools.length >= 6)) {
  add('agent-is-a-skill', 'Subagents', 'low', a.name, `a ${a.bodyLines}-line playbook with ${a.tools ? a.tools.length : 'all'} tools — it teaches HOW, which is a skill's job`, 'Unless it runs in parallel or isolates heavy reading, make it a skill the main agent loads', a);
}

// ── slash commands ───────────────────────────────────────────────
const commandFiles = [join(PROJECT, '.claude', 'commands'), join(USER_DIR, 'commands')].filter(isDir)
  .flatMap(d => walk(d, (p, n) => n.endsWith('.md'), 3));
const commands = commandFiles.map(f => ({ name: basename(f, '.md'), file: rel(f), used: usedCount(usage?.commands, basename(f, '.md')) }));
for (const c of commands) if (c.used === 0 && enoughUsage) add('command-unused', 'Commands', 'low', c.name, `not run in ${usage.sessions} recent sessions`, 'Remove it, or move it to a skill: commands are merged into skills, which also take supporting files', c);

// ── MCP servers ──────────────────────────────────────────────────
const mcpServers = [];
const addServers = (obj, where) => { for (const name of Object.keys(obj || {})) mcpServers.push({ name, where, used: usedCount(usage?.mcpServers, name) }); };
{
  const pj = read(join(PROJECT, '.mcp.json')); if (pj) try { addServers(JSON.parse(pj).mcpServers, '.mcp.json'); } catch {}
  const uj = read(join(homedir(), '.claude.json'));
  if (uj) try { const j = JSON.parse(uj); addServers(j.mcpServers, '~/.claude.json'); addServers(j.projects?.[PROJECT]?.mcpServers, '~/.claude.json (this project)'); } catch {}
}
for (const m of mcpServers) if (m.used === 0 && enoughUsage) add('mcp-unused', 'MCP', 'medium', m.name, `configured in ${m.where} but no tool of it was called in ${usage.sessions} recent sessions`, 'Disable it with /mcp, or enable it only where needed; a CLI (gh, aws, gcloud) adds no tool listing at all', m);

// ── settings: hooks and permissions ──────────────────────────────
const settingsFiles = [join(PROJECT, '.claude', 'settings.json'), join(PROJECT, '.claude', 'settings.local.json'), join(USER_DIR, 'settings.json')];
const hooks = [], allow = [];
let bypass = null;
for (const f of settingsFiles) {
  const t = read(f); if (!t) continue;
  let j; try { j = JSON.parse(t); } catch { add('settings-invalid', 'Settings', 'high', rel(f), 'not valid JSON, so Claude Code ignores it', 'Fix the JSON', {}); continue; }
  for (const [event, groups] of Object.entries(j.hooks || {})) for (const g of groups || []) for (const h of g.hooks || []) hooks.push({ event, matcher: g.matcher ?? '', command: String(h.command || '').slice(0, 120), file: rel(f) });
  for (const r of j.permissions?.allow || []) allow.push({ rule: r, file: rel(f) });
  if (j.permissions?.defaultMode === 'bypassPermissions') bypass = rel(f);
}
for (const h of hooks) {
  if (/^(PreToolUse|PostToolUse)$/.test(h.event) && (h.matcher === '' || h.matcher === '*')) add('hook-every-tool', 'Hooks', 'medium', `${h.event} in ${h.file}`, 'runs on every tool call', 'Give it a matcher (e.g. "Edit|Write") so it runs only where it matters', h);
  if (/\b(curl|wget|npm (install|ci)|docker|sleep)\b/.test(h.command)) add(h.event === 'SessionStart' ? 'hook-slow-session-start' : 'hook-slow', 'Hooks', h.event === 'SessionStart' ? 'medium' : 'low', `${h.event} in ${h.file}`, `does slow work (${h.command.match(/\b(curl|wget|npm (install|ci)|docker|sleep)\b/)[0]})`, 'Keep hooks fast and deterministic; run slow work in the background', h);
}
for (const p of allow) {
  if (/^(Bash|Bash\(\*\)|\*)$/.test(p.rule)) add('allow-all-bash', 'Permissions', 'high', p.rule, `allows every shell command (${p.file})`, 'Allow specific commands (e.g. Bash(npm test)) instead, or use auto mode', p);
  // Wildcarded interpreters and package-manager runs execute arbitrary code too;
  // auto mode drops exactly these when it starts [doc].
  else if (/^Bash\((python3?|node|bash|sh|zsh|ruby|perl|deno|bun|npx|uvx)\*|^Bash\((python3?|node|bash|sh|ruby|perl) \*\)|^Bash\((npm|pnpm|yarn) run \*\)/.test(p.rule)) add('allow-interpreter', 'Permissions', 'medium', p.rule, `a wildcard that runs arbitrary code (${p.file})`, 'Narrow it to the scripts you mean, e.g. Bash(npm run test)', p);
  else if (/Bash\((rm|sudo|git push|curl|wget|chmod|chown|dd)\b/.test(p.rule)) add('allow-destructive', 'Permissions', 'medium', p.rule, `pre-approves a destructive or outbound command (${p.file})`, 'Leave this one to a prompt', p);
}
if (bypass) add('bypass-permissions', 'Permissions', 'high', bypass, 'defaultMode is bypassPermissions — nothing is ever asked', 'Use auto mode or an allowlist outside throwaway sandboxes', {});

// ── what is being BUILT: multi-agent frameworks in the code ──────
const FRAMEWORKS = [
  ['LangGraph', /\b(from langgraph|langgraph\.|StateGraph\()/],
  ['CrewAI', /\b(from crewai|import crewai|Crew\(\s*agents)/],
  ['AutoGen', /\b(from autogen|import autogen|autogen_agentchat)/],
  ['OpenAI Agents SDK', /\bfrom agents import\b|@openai\/agents/],
  ['Claude Agent SDK subagents', /claude[-_]agent[-_]sdk[\s\S]{0,4000}\bagents\s*[:=]\s*[{\[]/],
  ['Managed Agents multiagent', /multiagent_2026\d{4}|"multiagent"\s*:/],
];
const code = walk(PROJECT, (p, n) => /\.(py|ts|tsx|js|mjs|cjs)$/.test(n) && !/\.(test|spec)\./.test(n) && !p.includes(`${'/'}.claude/`), 8).slice(0, 5000);
const frameworkHits = new Map();
for (const f of code) {
  const t = read(f); if (!t || t.length > 400_000) continue;
  for (const [name, re] of FRAMEWORKS) if (re.test(t)) { const s = frameworkHits.get(name) || []; s.push(rel(f)); frameworkHits.set(name, s); }
}
for (const [name, files] of frameworkHits) add('multi-agent-framework', 'Agent architecture', 'medium', name, `multi-agent orchestration in ${files.length} file${files.length > 1 ? 's' : ''}`, 'Check each agent earns its place: one agent with skills and tools often matches a multi-agent graph at lower cost and latency. Keep separate agents for parallel or isolated work', { files: files.slice(0, 5) });

// ── report ───────────────────────────────────────────────────────
const SEV = { high: 0, medium: 1, low: 2 };
findings.sort((a, b) => SEV[a.severity] - SEV[b.severity]);
const inventory = {
  claudeMd, alwaysOnTokens: alwaysOn, agents, skills, commands, mcpServers, hooks, allowRules: allow.length,
  frameworks: Object.fromEntries([...frameworkHits].map(([k, v]) => [k, v.length])),
};
const byArea = findings.reduce((m, f) => { (m[f.area] ||= { high: 0, medium: 0, low: 0 })[f.severity]++; return m; }, {});
const result = { generatedAt: new Date().toISOString(), project: PROJECT, usageFrom: REPORT ? rel(REPORT) : null, limits: LIMITS, inventory, byArea, findings };
if (JSON_OUT) writeFileSync(JSON_OUT, JSON.stringify(result, null, 2));

const out = [`# Claude Code setup audit`, '', `Project: \`${PROJECT}\`${usage ? ` · usage from ${usage.sessions} sessions` : ' · no usage report (pass --report to find unused agents, skills and servers)'}`, '',
  '| Area | Inventory |', '|---|---|',
  `| CLAUDE.md | ${claudeMd.length} files, ~${alwaysOn} tokens always loaded |`,
  `| Subagents | ${agents.length} defined${usage ? `, ${agents.filter(a => a.used > 0).length} used` : ''} |`,
  `| Skills | ${skills.length}${usage ? `, ${skills.filter(s => s.used > 0).length} used` : ''} |`,
  `| Slash commands | ${commands.length} |`,
  `| MCP servers | ${mcpServers.length}${usage ? `, ${mcpServers.filter(m => m.used > 0).length} used` : ''} |`,
  `| Hooks / allow rules | ${hooks.length} / ${allow.length} |`,
  `| Multi-agent code | ${frameworkHits.size ? [...frameworkHits.keys()].join(', ') : 'none found'} |`, ''];
if (!findings.length) out.push('No findings: the setup is lean.');
else { out.push(`## Findings (${findings.length})`, ''); for (const f of findings) out.push(`- **${f.severity}** · ${f.area} · \`${f.item}\`: ${f.finding}. → ${f.fix}`); }
if (JSON_OUT) out.push('', `Full findings: \`${JSON_OUT}\``);
console.log(out.join('\n'));
