import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// The npm bump must change exactly the vulnerable package. The fixtures are
// real npm 10 output (2026-10-22): base = lodash 4.17.15 direct, minimist
// 1.2.5 transitive via mkdirp; direct = `npm install --package-lock-only
// lodash@4.17.21`; transitive = the same for minimist@1.2.6 followed by the
// original package.json and a second `npm install --package-lock-only`.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-auto-patch-bump-'));
const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'auto-patch');
const read = (f) => readFileSync(join(FIX, f), 'utf8');
const { verifyNpmBump, npmHelperArgs, dependencyMode, runNpmBump } = await import('../server/services/autoPatch/npmBump.js');

const base = { packageJson: read('base.package.json'), packageLock: read('base.package-lock.json') };
const direct = { packageJson: read('direct.package.json'), packageLock: read('direct.package-lock.json') };
const transitive = { packageJson: base.packageJson, packageLock: read('transitive.package-lock.json') };
const edit = (text, fn) => { const o = JSON.parse(text); fn(o); return JSON.stringify(o, null, 2) + '\n'; };

test('dependencyMode: direct, transitive, and refused shapes', () => {
  const pkg = JSON.parse(base.packageJson);
  assert.equal(dependencyMode(pkg, 'lodash'), 'direct');
  assert.equal(dependencyMode(pkg, 'ms'), 'direct');
  assert.equal(dependencyMode(pkg, 'minimist'), 'transitive');
  assert.equal(dependencyMode({ dependencies: { a: '1' }, devDependencies: { a: '1' } }, 'a'), null);
  assert.equal(dependencyMode({ peerDependencies: { a: '1' } }, 'a'), null);
});

test('direct bump: only lodash moves (package.json range + lock root + its entry) and is accepted', () => {
  const v = verifyNpmBump({ before: base, after: direct, name: 'lodash', fromVersion: '4.17.15', toVersion: '4.17.21', mode: 'direct' });
  assert.deepEqual(v.problems, []);
  assert.equal(v.ok, true);
  assert.deepEqual(v.changed, ['node_modules/lodash']);
});

test('transitive bump: only node_modules/minimist moves, package.json untouched, accepted', () => {
  const v = verifyNpmBump({ before: base, after: transitive, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.deepEqual(v.problems, []);
  assert.equal(v.ok, true);
  assert.deepEqual(v.changed, ['node_modules/minimist']);
});

test('refused: an unrelated locked dependency moved', () => {
  const after = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.packages['node_modules/ms'].version = '2.1.2'; }) };
  const v = verifyNpmBump({ before: base, after, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('node_modules/ms changed')), v.problems.join('\n'));
});

test('refused: an unrelated dependency was added to the lock', () => {
  const after = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.packages['node_modules/left-pad'] = { version: '1.3.0' }; }) };
  const v = verifyNpmBump({ before: base, after, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('node_modules/left-pad was added')));
});

test('refused: an unrelated top-level dependency changed in package.json (direct bump)', () => {
  const after = { ...direct, packageJson: edit(direct.packageJson, (p) => { p.dependencies.mkdirp = '0.5.6'; }) };
  const v = verifyNpmBump({ before: base, after, name: 'lodash', fromVersion: '4.17.15', toVersion: '4.17.21', mode: 'direct' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('package.json changed beyond')));
});

test('refused: package.json changed at all for a transitive bump', () => {
  const after = { ...transitive, packageJson: edit(base.packageJson, (p) => { p.dependencies.minimist = '^1.2.6'; }) };
  const v = verifyNpmBump({ before: base, after, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('package.json changed for a transitive')));
});

test('refused: the vulnerable version is still locked somewhere', () => {
  const after = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.packages['node_modules/mkdirp/node_modules/minimist'] = { version: '1.2.5' }; }) };
  const before = { ...base, packageLock: edit(base.packageLock, (l) => { l.packages['node_modules/mkdirp/node_modules/minimist'] = { version: '1.2.5' }; }) };
  const v = verifyNpmBump({ before, after, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('minimist@1.2.5 is still in the lockfile')));
});

test('refused: the lockfile format was rewritten', () => {
  const after = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.lockfileVersion = 2; }) };
  const v = verifyNpmBump({ before: base, after, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('top-level fields changed')));
});

test('refused: the target moved to a version other than the fixed one, or off the public registry', () => {
  const higher = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.packages['node_modules/minimist'].version = '1.2.8'; }) };
  assert.equal(verifyNpmBump({ before: base, after: higher, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' }).ok, false);
  const elsewhere = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.packages['node_modules/minimist'].resolved = 'https://registry.example.invalid/minimist-1.2.6.tgz'; }) };
  const v = verifyNpmBump({ before: base, after: elsewhere, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('outside the public registry')));
});

test('refused: nothing changed', () => {
  const v = verifyNpmBump({ before: base, after: base, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
});

test('the helper container is confined: non-root, no caps, read-only, limits, lowest CPU weight, OOM flag, no secrets', () => {
  const args = npmHelperArgs({ workDir: '/data/tmp/auto-patch/bump-x', name: '@scope/pkg', version: '1.2.3', mode: 'transitive', containerName: 'appcrane-auto-patch-test' });
  const s = args.join(' ');
  for (const flag of ['--cap-drop ALL', '--security-opt no-new-privileges', '--read-only', '--user 1000:1000', '--pids-limit 256', '--memory 1024m', '--cpus 1', '--oom-score-adj=500', '--cpu-shares=2', '--rm', 'npm_config_ignore_scripts=true', 'npm_config_userconfig=/tmp/no-user-npmrc']) {
    assert.ok(s.includes(flag), `missing ${flag}`);
  }
  assert.ok(!/token|password|_auth/i.test(s));
  assert.deepEqual(args.slice(-3), ['@scope/pkg', '1.2.3', 'transitive']);
  assert.throws(() => npmHelperArgs({ workDir: '/x', name: 'a;rm -rf /', version: '1.0.0', mode: 'direct', containerName: 'c' }));
  assert.throws(() => npmHelperArgs({ workDir: '/x', name: 'a', version: '1.0.0 && x', mode: 'direct', containerName: 'c' }));
});

test('live: npm in the helper container bumps only the target (AUTO_PATCH_LIVE_DOCKER=1)', { skip: process.env.AUTO_PATCH_LIVE_DOCKER !== '1' }, async () => {
  const t = await runNpmBump({ ...base, name: 'minimist', version: '1.2.6', mode: 'transitive' });
  const vt = verifyNpmBump({ before: base, after: t, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.deepEqual(vt.problems, []);
  const dd = await runNpmBump({ ...base, name: 'lodash', version: '4.17.21', mode: 'direct' });
  const vd = verifyNpmBump({ before: base, after: dd, name: 'lodash', fromVersion: '4.17.15', toVersion: '4.17.21', mode: 'direct' });
  assert.deepEqual(vd.problems, []);
});

test('npmVersionInfo reads the publish time and the maintainer\'s deprecation message from the packument', async () => {
  const { npmVersionInfo } = await import('../server/services/autoPatch/registry.js');
  const real = global.fetch;
  const doc = {
    versions: { '4.18.0': { deprecated: 'Bad release. Please use lodash@4.17.21 instead.' }, '4.18.1': {} },
    time: { '4.18.0': '2026-03-31T18:18:42.717Z', '4.18.1': '2026-04-01T21:01:20.458Z' },
  };
  const seen = [];
  global.fetch = async (url) => { seen.push(String(url)); return { ok: true, status: 200, json: async () => doc }; };
  try {
    const bad = await npmVersionInfo('lodash', '4.18.0');
    assert.equal(bad.published.toISOString(), '2026-03-31T18:18:42.717Z');
    assert.equal(bad.deprecated, 'Bad release. Please use lodash@4.17.21 instead.');
    assert.equal((await npmVersionInfo('lodash', '4.18.1')).deprecated, null);
    await assert.rejects(npmVersionInfo('lodash', '9.9.9'), /not on the npm registry/);
    assert.equal(seen[0], 'https://registry.npmjs.org/lodash');
  } finally {
    global.fetch = real;
  }
});
