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
  body({ tool, assistant, user });
  writeFileSync(join(dir, `${id}.jsonl`), lines.map(l => JSON.stringify(l)).join('\n'));
}

test('analyzer detects each waste signal and dedupes streamed usage', () => {
  const root = mkdtempSync(join(tmpdir(), 'work-review-'));
  const proj = join(root, '-proj');
  mkdirSync(proj);

  writeSession(proj, 's1', ['run the unit tests and fix failures in the billing module', "no, don't mock the database in tests"], ({ tool, assistant, user }) => {
    tool('Read', { file_path: '/r/a.js' }, 'x');
    tool('Read', { file_path: '/r/a.js' }, 'x');                        // redundant: no edit between
    tool('Bash', { command: 'cd /r && npm test 2>&1 | tail' }, 'fail');
    tool('Bash', { command: 'npm test' }, 'fail');
    tool('Bash', { command: 'npm test' }, 'fail');                      // 2 idle re-runs
    for (let i = 0; i < 3; i++) tool('Edit', { file_path: '/r/a.js' }, 'String to replace not found in file', true);
    tool('Bash', { command: 'rm -rf build' }, 'Permission to use Bash was denied', true);
    tool('Bash', { command: 'cat big.log' }, 'y'.repeat(30000));
    // One streamed message carrying two parallel tool calls, split across two records.
    assistant([{ type: 'tool_use', id: 'p1', name: 'Grep', input: {} }], 'par');
    assistant([{ type: 'tool_use', id: 'p2', name: 'Glob', input: {} }], 'par');
    user('[Request interrupted by user]');
  });
  writeSession(proj, 's2', ['run the unit tests and fix the failures in the billing module please', 'no, do not mock the database in tests'], ({ tool }) => {
    tool('Read', { file_path: '/r/a.js' }, 'x');
    tool('Read', { file_path: '/r/a.js' }, 'x');
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
