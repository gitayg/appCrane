import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';
import { nodeProblem } from '../scripts/lib/node-check.mjs';

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

test('Node 22 with a loadable better-sqlite3 passes', () => {
  assert.equal(nodeProblem({ required: '22', version: '22.23.1' }), null);
  assert.equal(nodeProblem({ required: '22', version: 'v22.0.0', loadError: undefined }), null);
});

test('another major is refused in one line naming the fix', () => {
  const p = nodeProblem({ required: '22', version: '26.1.0' });
  assert.equal(p, 'AppCrane tests need Node 22 (found v26.1.0): run `nvm use` or PATH=/usr/local/bin:$PATH');
  assert.ok(nodeProblem({ required: '22', version: '20.19.0' }));
  assert.ok(nodeProblem({ required: '22', version: '220.0.0' }));
});

test('a NODE_MODULE_VERSION mismatch on Node 22 is refused with the rebuild fix', () => {
  const err = 'The module better_sqlite3.node was compiled against a different Node.js version using NODE_MODULE_VERSION 141. This version of Node.js requires NODE_MODULE_VERSION 127.';
  const p = nodeProblem({ required: '22', version: '22.23.1', loadError: err });
  assert.match(p, /npm rebuild better-sqlite3/);
  assert.doesNotMatch(p, /\n/);
});

test('the pretest check exits 0 silently under the current Node', () => {
  const out = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/check-node-version.mjs', import.meta.url))], { encoding: 'utf8' });
  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout + out.stderr, '');
});

test('.nvmrc, engines and npm pretest agree on Node 22', () => {
  assert.equal(read('.nvmrc').trim(), '22');
  const pkg = JSON.parse(read('package.json'));
  assert.equal(pkg.engines.node, '>=22 <23');
  assert.equal(pkg.scripts.pretest, 'node scripts/check-node-version.mjs');
});
