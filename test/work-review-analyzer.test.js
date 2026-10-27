import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';

// The work-review skill's analyzer (plugins/work-review/skills/work-review/scripts/analyze.mjs).
//
// Builds two synthetic Claude Code transcripts, each seeded with one instance of
// every waste signal the analyzer claims to detect, and checks that each one is
// counted, and counted once: streamed assistant messages repeat their usage on
// every content block, and the totals must not double-count them.

const SCRIPT = join(import.meta.dirname, '..', 'plugins', 'work-review', 'skills', 'work-review', 'scripts', 'analyze.mjs');

function writeSession(dir, id, prompts, body) {
  const lines = [];
  let n = 0;
  const ts = () => new Date().toISOString();
  const user = content => lines.push({ type: 'user', timestamp: ts(), message: { role: 'user', content } });
  const assistant = (content, mid = `m${n++}`) => lines.push({ type: 'assistant', timestamp: ts(), message: {
    id: mid, model: 'test', content,
    usage: { input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 100, cache_creation_input_tokens: 20 },
  } });
  const tool = (name, input, out, isError = false) => {
    const id = `t${n++}`;
    assistant([{ type: 'tool_use', id, name, input }]);
    user([{ type: 'tool_result', tool_use_id: id, content: out, is_error: isError }]);
  };
  prompts.forEach(user);
  body({ tool, assistant, user, raw: l => lines.push(l) });
  writeFileSync(join(dir, `${id}.jsonl`), lines.map(l => JSON.stringify(l)).join('\n'));
}

test('analyzer detects each waste signal and dedupes streamed usage', () => {
  const root = mkdtempSync(join(tmpdir(), 'work-review-'));
  const proj = join(root, '-proj');
  mkdirSync(proj);

  writeSession(proj, 's1', ['run the unit tests and fix failures in the billing module', "no, don't mock the database in tests"], ({ tool, assistant, user }) => {
    tool('Read', { file_path: '/r/a.js' }, 'x'.repeat(400));
    tool('Read', { file_path: '/r/a.js' }, 'x'.repeat(400));   // redundant: no edit between
    tool('Bash', { command: 'cd /r && npm test 2>&1 | tail' }, 'fail');
    tool('Bash', { command: 'npm test' }, 'fail');
    tool('Bash', { command: 'npm test' }, 'fail '.repeat(100));        // 2 idle re-runs
    for (let i = 0; i < 3; i++) tool('Edit', { file_path: '/r/a.js' }, 'String to replace not found in file', true);
    tool('Bash', { command: 'rm -rf build' }, 'Permission to use Bash was denied', true);
    tool('Bash', { command: 'cat big.log' }, 'y'.repeat(30000));
    // One streamed message carrying two parallel tool calls, split across two records.
    assistant([{ type: 'tool_use', id: 'p1', name: 'Grep', input: {} }], 'par');
    assistant([{ type: 'tool_use', id: 'p2', name: 'Glob', input: {} }], 'par');
    user('[Request interrupted by user]');
  });
  writeSession(proj, 's2', ['run the unit tests and fix the failures in the billing module please', 'no, do not mock the database in tests'], ({ tool }) => {
    tool('Read', { file_path: '/r/a.js' }, 'x'.repeat(400));
    tool('Read', { file_path: '/r/a.js' }, 'x'.repeat(400));
  });

  const out = join(root, 'report.json');
  execFileSync(process.execPath, [SCRIPT, '--root', root, '--json', out], { encoding: 'utf8' });
  const { totals: t, cross } = JSON.parse(readFileSync(out, 'utf8'));

  assert.equal(t.sessions, 2);
  assert.equal(t.turns, 13, 'the two records of message "par" count as one turn');
  assert.equal(t.tokens.cacheRead, 1300);
  assert.equal(t.redundantReads, 2);
  assert.equal(t.idleCommandReruns, 2);
  assert.equal(t.retryLoops, 1);
  assert.equal(t.editMisses, 3);
  assert.equal(t.permissionDenials, 1);
  assert.equal(t.oversizedOutputs, 1);
  assert.equal(t.corrections, 2);
  assert.equal(t.interrupts, 1);
  assert.ok(t.wastedTokensEstimate.redundantReads > 0, 'redundant reads are priced');
  assert.ok(t.wastedTokensEstimate.idleReruns > 0, 'idle re-runs are priced');
  assert.ok(t.parallelToolTurnShare > 0, 'parallel calls in one streamed message are recognised');

  assert.equal(cross.repeatedPrompts.length, 1);
  assert.equal(cross.repeatedPrompts[0].sessions, 2);
  assert.equal(cross.recurringCorrections[0].sessions, 2);
  assert.equal(cross.repeatedCommands[0].cmd, 'npm test', 'cd prefix, pipes and 2>&1 are normalised away');
  assert.equal(cross.redundantReadFiles[0].file, '/r/a.js');
});

test('analyzer redacts secrets in quoted prompts', () => {
  const root = mkdtempSync(join(tmpdir(), 'work-review-'));
  mkdirSync(join(root, '-p'));
  const secret = 'sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUV';
  for (const id of ['a', 'b']) {
    writeSession(join(root, '-p'), id, [`deploy the staging server using key ${secret} and restart it`], ({ tool }) => tool('Read', { file_path: '/x' }, 'x'));
  }
  const md = execFileSync(process.execPath, [SCRIPT, '--root', root], { encoding: 'utf8' });
  assert.ok(md.includes('deploy the staging server'));
  assert.ok(!md.includes(secret));
});

test('analyzer charges each prompt for its work and flags vague and reworked ones', () => {
  const root = mkdtempSync(join(tmpdir(), 'work-review-'));
  mkdirSync(join(root, '-p'));
  writeSession(join(root, '-p'), 'q', ['fix the bug'], ({ tool, raw }) => {
    for (let i = 0; i < 6; i++) tool('Grep', { pattern: 'x' }, 'x');     // went looking
    tool('Edit', { file_path: '/r/b.js' }, 'ok');
    // Typed mid-turn: stored as a queued_command attachment, not a user record.
    raw({ type: 'attachment', attachment: { type: 'queued_command', prompt: 'no, wrong file — fix `parse()` in src/a.js so it returns []', humanTurn: true } });
    tool('Edit', { file_path: '/r/a.js' }, 'ok');
  });
  const out = join(root, 'r.json');
  execFileSync(process.execPath, [SCRIPT, '--root', root, '--json', out]);
  const { instructionQuality: q, totals } = JSON.parse(readFileSync(out, 'utf8'));

  assert.equal(totals.userPrompts, 2, 'the mid-turn message counts as a prompt');
  assert.equal(q.vague.prompts, 1);
  assert.equal(q.vague.medianExploreBeforeFirstEdit, 6);
  assert.equal(q.vague.reworkRate, 1, 'the vague prompt was followed by a correction');
  assert.equal(q.anchored.prompts, 1, 'a file name and code in backticks make it anchored');
  assert.equal(q.withCriteria.prompts, 1, '"returns" is a done-criterion');
  assert.ok(q.reworkCost > 0 && q.reworkShare > 0.5, 'the reworked prompt carries most of the spend');
  assert.match(q.costliestBadPrompts[0].why.join(' '), /followed by correction/);
});

test('lowercase prose is not mistaken for a code identifier', () => {
  const root = mkdtempSync(join(tmpdir(), 'work-review-'));
  mkdirSync(join(root, '-p'));
  writeSession(join(root, '-p'), 'v', ['make the dashboard better and cleaner'], ({ tool }) => tool('Read', { file_path: '/x' }, 'x'));
  const out = join(root, 'r.json');
  execFileSync(process.execPath, [SCRIPT, '--root', root, '--json', out]);
  assert.equal(JSON.parse(readFileSync(out, 'utf8')).instructionQuality.vague.prompts, 1);
});

test('analyzer prices usage at API list rates per model, and never guesses an unknown model', () => {
  const root = mkdtempSync(join(tmpdir(), 'work-review-'));
  mkdirSync(join(root, '-p'));
  const msg = (id, model, usage) => ({ type: 'assistant', timestamp: new Date().toISOString(), message: { id, model, content: [{ type: 'text', text: 'x' }], usage } });
  const lines = [
    { type: 'user', timestamp: new Date().toISOString(), message: { role: 'user', content: 'price this' } },
    // Opus 5.5, $4 in / $20 out / $0.20 read: 1M fresh + 1M out + 1M read
    // + 1M 5-minute write (×1.25) + 1M 1-hour write (×2) = 4 + 20 + 0.2 + 5 + 8.
    msg('a', 'claude-opus-5-5[1m]', { input_tokens: 1e6, output_tokens: 1e6, cache_read_input_tokens: 1e6,
      cache_creation_input_tokens: 2e6, cache_creation: { ephemeral_5m_input_tokens: 1e6, ephemeral_1h_input_tokens: 1e6 } }),
    // Fast mode doubles: 1M Opus 5.5 output at $40.
    msg('b', 'claude-opus-5-5', { input_tokens: 0, output_tokens: 1e6, speed: 'fast' }),
    // Haiku 5.5 over 100K prompt tokens uses the long pair ($0.50 in): 200K fresh = $0.10.
    msg('c', 'claude-haiku-5-5', { input_tokens: 200_000, output_tokens: 0 }),
    // claude-opus-5 must not be priced as claude-opus-5-5, nor the reverse: 1M in at $5.
    msg('d', 'claude-opus-5-20260301', { input_tokens: 1e6, output_tokens: 0 }),
    msg('e', 'some-future-model', { input_tokens: 5, output_tokens: 5 }),
  ];
  writeFileSync(join(root, '-p', 'p.jsonl'), lines.map(l => JSON.stringify(l)).join('\n'));
  const out = join(root, 'r.json');
  const md = execFileSync(process.execPath, [SCRIPT, '--root', root, '--json', out], { encoding: 'utf8' });
  const t = JSON.parse(readFileSync(out, 'utf8')).totals;
  assert.equal(t.usdByModel['claude-opus-5-5[1m]'], 37.2);
  assert.equal(t.usdByModel['claude-opus-5-5'], 40);
  assert.equal(t.usdByModel['claude-haiku-5-5'], 0.1);
  assert.equal(t.usdByModel['claude-opus-5-20260301'], 5);
  assert.equal(t.usd, 82.3);
  assert.deepEqual(t.unpricedModels, { 'some-future-model': 10 });
  assert.match(md, /not an invoice/, 'the report says what the dollars are');

  const prices = join(root, 'prices.json');
  writeFileSync(prices, JSON.stringify({ 'some-future-model': { in: 1e6, out: 0, read: 0 } }));
  execFileSync(process.execPath, [SCRIPT, '--root', root, '--json', out, '--prices', prices]);
  assert.equal(JSON.parse(readFileSync(out, 'utf8')).totals.usd, 87.3, '--prices adds a model');
});

test('analyzer tells useful subagents from ones that only paid the overhead', () => {
  const root = mkdtempSync(join(tmpdir(), 'work-review-'));
  const proj = join(root, '-p');
  mkdirSync(proj);
  const ts = () => new Date().toISOString();
  const usage = { input_tokens: 1000, output_tokens: 100 };
  const asst = (id, content) => ({ type: 'assistant', timestamp: ts(), message: { id, model: 'claude-opus-5-5', content, usage } });
  const result = (id, text) => ({ type: 'user', timestamp: ts(), message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: id, content: text }] } });
  const read = (msg, id, f, out = 'x'.repeat(50)) => [asst(msg, [{ type: 'tool_use', id, name: 'Read', input: { file_path: f } }]), result(id, out)];
  const agent = (id, prompt, bg = false) => ({ type: 'tool_use', id, name: 'Agent', input: { description: prompt.slice(0, 30), prompt, subagent_type: 'general-purpose', run_in_background: bg } });
  const write = (dir, name, lines) => writeFileSync(join(dir, name), lines.map(l => JSON.stringify(l)).join('\n'));
  const sub = (sid, aid, toolUseId, lines) => {
    const d = join(proj, sid, 'subagents'); mkdirSync(d, { recursive: true });
    writeFileSync(join(d, `agent-${aid}.meta.json`), JSON.stringify({ agentType: 'general-purpose', description: aid, toolUseId, requestShape: 'foreground' }));
    write(d, `agent-${aid}.jsonl`, lines);
  };
  const brief = 'Summarise how the billing module computes invoice totals and list the files involved in detail';

  // s1: the main agent reads three files, then delegates "look at them" alone in
  // the foreground; the subagent reads the same three and hands back more than it
  // read. Then two parallel subagents each read a lot and report one line.
  write(proj, 's1.jsonl', [
    { type: 'user', timestamp: ts(), message: { role: 'user', content: 'fix billing' } },
    ...read('m1', 'r1', '/a.js'), ...read('m2', 'r2', '/b.js'), ...read('m3', 'r3', '/c.js'),
    asst('m4', [agent('t-bad', brief)]), result('t-bad', 'report'),
    asst('m5', [agent('t-p1', 'Search the whole repository for every caller of computeTotals and report the count'), agent('t-p2', 'Search the docs folder for anything describing invoice rounding and report it')]),
    result('t-p1', 'ok'), result('t-p2', 'ok'),
  ]);
  sub('s1', 'bad', 't-bad', [
    { type: 'user', timestamp: ts(), message: { role: 'user', content: brief } },
    ...read('b1', 'x1', '/a.js', 'short'), ...read('b2', 'x2', '/b.js', 'short'), ...read('b3', 'x3', '/c.js', 'short'),
    asst('b4', [{ type: 'text', text: 'A long restatement of everything. '.repeat(20) }]),
  ]);
  for (const id of ['p1', 'p2']) sub('s1', id, `t-${id}`, [
    { type: 'user', timestamp: ts(), message: { role: 'user', content: 'search' } },
    ...Array.from({ length: 6 }, (_, i) => read(`${id}m${i}`, `${id}r${i}`, `/src/f${i}.js`, 'y'.repeat(5000))).flat(),
    asst(`${id}end`, [{ type: 'text', text: 'Found 4.' }]),
  ]);
  // s2, s3: the same brief delegated again in two more sessions.
  for (const sid of ['s2', 's3']) {
    write(proj, `${sid}.jsonl`, [{ type: 'user', timestamp: ts(), message: { role: 'user', content: 'billing again' } }, asst(`${sid}m`, [agent(`t-${sid}`, brief)]), result(`t-${sid}`, 'r')]);
    sub(sid, `rep${sid}`, `t-${sid}`, [{ type: 'user', timestamp: ts(), message: { role: 'user', content: brief } }, ...read(`${sid}x`, `${sid}y`, '/a.js', 'z'.repeat(9000)), asst(`${sid}e`, [{ type: 'text', text: 'done' }])]);
  }

  const out = join(root, 'r.json');
  execFileSync(process.execPath, [SCRIPT, '--root', root, '--json', out]);
  const S = JSON.parse(readFileSync(out, 'utf8')).subagents;
  assert.equal(S.runs, 5);
  const bad = S.examples.find(r => r.description === 'bad');
  assert.deepEqual(bad.flags.sort(), ['duplicated-reads', 'no-isolation-gain', 'trivial'],
    'alone, three tool calls, re-read the main agent\'s files, handed back more than it read');
  assert.equal(bad.parallel, false);
  assert.ok(!S.examples.some(r => r.description === 'p1' || r.description === 'p2'), 'parallel, heavy reading, one-line report: not flagged');
  assert.ok(S.startupUsd > 0 && S.usd >= S.startupUsd);
  assert.equal(S.repeatedDelegations[0].runs, 3, 'the same brief delegated in three sessions is a skill candidate');
});

test('--allow-remote keeps only sessions from matching git repositories', () => {
  const root = mkdtempSync(join(tmpdir(), 'work-review-'));
  mkdirSync(join(root, '-p'));
  const repo = (name, url) => {
    const d = join(root, name); mkdirSync(d);
    execFileSync('git', ['init', '-q', d]);
    if (url) execFileSync('git', ['-C', d, 'remote', 'add', 'origin', url]);
    return d;
  };
  const work = repo('work', 'git@github.com:opswat/billing.git');
  const side = repo('side', 'https://github.com/kim/hobby.git');
  const bare = repo('bare', null);
  for (const [id, cwd] of [['w', work], ['s', side], ['b', bare], ['gone', join(root, 'deleted')]]) {
    writeFileSync(join(root, '-p', `${id}.jsonl`), [
      { type: 'user', cwd, timestamp: new Date().toISOString(), message: { role: 'user', content: 'hi' } },
      { type: 'assistant', cwd, timestamp: new Date().toISOString(), message: { id: id + 'm', model: 'x', content: [], usage: { input_tokens: 1, output_tokens: 1 } } },
    ].map(l => JSON.stringify(l)).join('\n'));
  }
  const out = join(root, 'r.json');
  execFileSync(process.execPath, [SCRIPT, '--root', join(root, '-p'), '--json', out, '--allow-remote', 'github.com[:/]opswat/']);
  const r = JSON.parse(readFileSync(out, 'utf8'));
  assert.deepEqual(r.sessions.map(s => s.sessionId), ['w'], 'only the work repo');
  assert.equal(r.totals.excludedByRemote, 3, 'side project, no remote and a deleted directory are all left out');
});

test('commits are attributed by the session\'s own git output, not by the trailer alone', () => {
  const root = mkdtempSync(join(tmpdir(), 'work-review-'));
  mkdirSync(join(root, '-p'));
  const repo = join(root, 'repo'); mkdirSync(repo);
  const git = (...a) => execFileSync('git', ['-C', repo, ...a], { encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@x', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@x' } }).trim();
  execFileSync('git', ['init', '-q', repo]);
  const commit = (file, msg) => { writeFileSync(join(repo, file), 'a\nb\nc\n'); git('add', file); git('commit', '-q', '-m', msg); return git('rev-parse', 'HEAD'); };
  const start = Date.now() - 60_000;
  const a = commit('a.txt', 'Add the billing export endpoint\n\nCo-Authored-By: Claude <noreply@anthropic.com>');
  commit('b.txt', 'Tidy the invoice rounding helper used by billing');                                // quiet commit by the session
  commit('c.txt', 'Somebody else\'s Claude session changed this\n\nCo-Authored-By: Claude <noreply@anthropic.com>');  // same window, not ours
  const ts = new Date(start).toISOString(), te = new Date().toISOString();
  const tool = (id, command, out) => [
    { type: 'assistant', cwd: repo, timestamp: ts, message: { id: 'm' + id, model: 'claude-opus-5-5', content: [{ type: 'tool_use', id, name: 'Bash', input: { command } }], usage: { input_tokens: 1e6, output_tokens: 0 } } },
    { type: 'user', cwd: repo, timestamp: te, message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: id, content: out }] } },
  ];
  writeFileSync(join(root, '-p', 's.jsonl'), [
    { type: 'user', cwd: repo, timestamp: ts, message: { role: 'user', content: 'ship the export' } },
    ...tool('t1', `git commit -m "Add the billing export endpoint"`, `[main ${a.slice(0, 7)}] Add the billing export endpoint\n 1 file changed, 3 insertions(+)`),
    ...tool('t2', `git commit -q -m "Tidy the invoice rounding helper used by billing"`, ''),
  ].map(l => JSON.stringify(l)).join('\n'));
  const out = join(root, 'r.json');
  execFileSync(process.execPath, [SCRIPT, '--root', join(root, '-p'), '--json', out]);
  const o = JSON.parse(readFileSync(out, 'utf8')).outcomes;
  assert.equal(o.commits, 2, 'the reported sha and the quiet commit, not the other session\'s');
  assert.equal(o.linesAdded, 6);
  assert.equal(o.withClaudeTrailer, 1);
  assert.equal(o.usdPerCommit, 4, '$8 of Opus 5.5 input over 2 commits');
});

test('findings are ranked by cost, and --baseline says which signals improved', () => {
  const mk = (withProblems) => {
    const root = mkdtempSync(join(tmpdir(), 'work-review-'));
    mkdirSync(join(root, '-p'));
    for (let i = 0; i < 5; i++) {
      const ts = new Date().toISOString();
      const u = { input_tokens: 100_000, output_tokens: 0 };
      const lines = [{ type: 'user', timestamp: ts, message: { role: 'user', content: 'fix the export in `src/export.js`' } }];
      const read = (id, f) => {
        lines.push({ type: 'assistant', timestamp: ts, message: { id: `m${id}`, model: 'claude-opus-5-5', usage: u, content: [{ type: 'tool_use', id, name: 'Read', input: { file_path: f } }] } });
        lines.push({ type: 'user', timestamp: ts, message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: id, content: 'z'.repeat(200_000) }] } });
      };
      read(`a${i}`, '/src/export.js');
      if (withProblems) {
        read(`b${i}`, '/src/export.js');                                   // re-read, nothing changed
        lines.push({ type: 'user', timestamp: ts, message: { role: 'user', content: "no, that's the wrong file" } });
        read(`c${i}`, '/src/other.js');
      }
      writeFileSync(join(root, '-p', `s${i}.jsonl`), lines.map(l => JSON.stringify(l)).join('\n'));
    }
    return root;
  };
  const before = join(mkdtempSync(join(tmpdir(), 'wr-')), 'before.json');
  execFileSync(process.execPath, [SCRIPT, '--root', mk(true), '--json', before]);
  const B = JSON.parse(readFileSync(before, 'utf8'));
  const ids = B.findings.shown.map(f => f.id);
  assert.ok(ids.includes('rework') && ids.includes('redundant-reads'), `got ${ids}`);
  assert.equal(B.findings.shown[0].id, 'rework', 'the costliest first');
  assert.ok(B.findings.shown.every((f, i, a) => i === 0 || a[i - 1].usd >= f.usd));

  const after = join(mkdtempSync(join(tmpdir(), 'wr-')), 'after.json');
  const md = execFileSync(process.execPath, [SCRIPT, '--root', mk(false), '--json', after, '--baseline', before], { encoding: 'utf8' });
  const D = JSON.parse(readFileSync(after, 'utf8')).delta;
  const v = name => D.signals.find(g => g.name === name).verdict;
  assert.equal(D.enough, true);
  assert.equal(v('redundant reads per session'), 'better');
  assert.equal(v('corrections per session'), 'better');
  assert.equal(v('usd per session'), 'better');
  assert.match(md, /## Since/);
});
