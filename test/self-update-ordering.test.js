import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

// The self-update must not move the working tree before the runtime can
// support what it is about to install (v2.55.2).
//
// The Node check used to run AFTER `git reset --hard origin/main`. When it
// refused — a host below the floor that cannot be upgraded automatically — the
// tree had already been moved to the new release while node_modules stayed on
// the old one, and the pending-update file the boot sentinel reads for
// auto-rollback is written further down, past the npm install that never ran.
// So the refusal left the host on new code, with old dependencies, and no
// record to roll back from: one restart away from a boot it could not survive.
//
// Ordered correctly a refusal costs nothing, because nothing has been touched.
//
// Asserted against the source. The alternative is driving a real self-update,
// which resets a git tree and shells out to apt — not something a test should
// do to the machine it runs on.

const SRC = readFileSync(new URL('../server/index.js', import.meta.url), 'utf8');
const HANDLER = SRC.slice(
  SRC.indexOf("app.post('/api/self-update'"),
  SRC.indexOf("app.get('/api/self-update/status'"),
);

test('the handler was found — the rest of this file means nothing otherwise', () => {
  assert.ok(HANDLER.length > 500, 'could not slice the self-update handler out of index.js');
});

test('the runtime is reconciled BEFORE the working tree is moved', () => {
  const fetch = HANDLER.indexOf("'fetch', 'origin'");
  const plan = HANDLER.indexOf('planNodeUpgrade({');
  const reset = HANDLER.indexOf("'reset', '--hard', 'origin/main'");
  const install = HANDLER.indexOf("'npm', ['install'");

  assert.ok(fetch > -1 && plan > -1 && reset > -1 && install > -1, 'update steps moved — re-read this test');
  assert.ok(fetch < plan, 'the incoming floor cannot be known before fetching');
  assert.ok(plan < reset,
    'the Node decision runs after the reset: a refusal strands the host on new code with old ' +
    'dependencies and no rollback record');
  assert.ok(reset < install, 'dependencies must be installed for the release that was checked out');
});

test('the floor comes from the INCOMING release, not the running one', () => {
  assert.match(HANDLER, /git['"]?,\s*\[['"]show['"],\s*['"]origin\/main:package\.json['"]\]/,
    'the incoming package.json must be read from the fetched ref');
  assert.match(HANDLER, /floor:\s*incomingFloor/,
    'planNodeUpgrade must be given the incoming floor; NODE_FLOOR is a constant baked into the ' +
    'release being REPLACED, which is the wrong question on every upgrade that raises it');
  assert.doesNotMatch(HANDLER, /floor:\s*NODE_FLOOR/);
});

test('an unreadable incoming package.json falls back instead of throwing', () => {
  assert.match(HANDLER, /could not read the incoming Node floor/,
    'a malformed or missing incoming package.json must degrade to the known floor, not abort an ' +
    'update that might be fine');
});

test('git show reads the incoming tree without checking it out', () => {
  // The mechanism this rests on: `git show <ref>:<path>` prints file content
  // from a ref with the working tree untouched. If that were not true, reading
  // the floor early would itself be the destructive step.
  const dir = mkdtempSync(join(tmpdir(), 'gitshow-'));
  const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe' }).toString();
  git('init', '-q');
  git('config', 'user.email', 't@t.t');
  git('config', 'user.name', 'T');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ engines: { node: '>=22' } }));
  git('add', 'package.json');
  git('commit', '-qm', 'v1');

  writeFileSync(join(dir, 'package.json'), JSON.stringify({ engines: { node: '>=99' } }));
  git('add', 'package.json');
  git('commit', '-qm', 'v2');
  const branch = git('rev-parse', '--abbrev-ref', 'HEAD').trim();
  git('checkout', '-q', 'HEAD~1');

  // Ask git what the branch is called rather than guessing. `git init` produces
  // `main` on a machine with init.defaultBranch set and `master` on one without
  // — this repo's CI runner is the latter, and the earlier version of this test
  // hardcoded 'main' with a fallback that could never fire: execFileSync throws
  // on a non-zero exit, so the failing call raised before the ternary chose the
  // alternative. It passed locally and failed on every CI run for five releases.
  const shown = JSON.parse(git('show', `${branch}:package.json`));
  assert.equal(shown.engines.node, '>=99', 'git show must read the newer ref');

  const onDisk = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  assert.equal(onDisk.engines.node, '>=22',
    'and the working tree must be exactly as it was — that is the whole point of reading this way');
});
