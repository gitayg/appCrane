import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';

// The work-review skill's analyzer (.claude/skills/work-review/scripts/analyze.mjs).
//
// Builds two synthetic Claude Code transcripts, each seeded with one instance of
// every waste signal the analyzer claims to detect, and checks that each one is
// counted, and counted once: streamed assistant messages repeat their usage on
// every content block, and the totals must not double-count them.

const SCRIPT = join(import.meta.dirname, '..', '.claude', 'skills', 'work-review', 'scripts', 'analyze.mjs');

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
