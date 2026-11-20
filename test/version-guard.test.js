import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { spawnSync, execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import {
  parseVersion, compareVersions, nextVersion, versionProblem,
} from '../scripts/lib/version-guard.mjs';

const scripts = fileURLToPath(new URL('../scripts/', import.meta.url));

test('compareVersions orders numerically, not lexically', () => {
  assert.equal(compareVersions('2.139.10', '2.139.9'), 1);
  assert.equal(compareVersions('2.139.4', '2.139.4'), 0);
  assert.equal(compareVersions('2.99.0', '2.139.0'), -1);
  assert.equal(compareVersions('3.0.0', '2.999.999'), 1);
  assert.equal(parseVersion('2.1'), null);
  assert.throws(() => compareVersions('2.1', '2.1.0'), /X\.Y\.Z/);
});

test('nextVersion bumps above the larger of base and local', () => {
  assert.equal(nextVersion({ base: '2.139.5', local: '2.139.4' }), '2.139.6');
  assert.equal(nextVersion({ base: '2.139.4', local: '2.139.7' }), '2.139.8');
  assert.equal(nextVersion({ base: '2.139.10', local: '2.139.9' }), '2.139.11');
  assert.equal(nextVersion({ base: '2.139.5', local: '2.139.4', kind: 'minor' }), '2.140.0');
});

test('a version equal to the current base is refused with the fix command', () => {
  const p = versionProblem({ head: '2.139.4', base: '2.139.4', baseLabel: 'main', notesKeys: ['2.139.4'] });
  assert.match(p, /2\.139\.4 but main is already at 2\.139\.4/);
  assert.match(p, /npm run version:next/);
});

test('a version below the base is refused', () => {
  assert.ok(versionProblem({ head: '2.139.3', base: '2.139.4', baseLabel: 'main', notesKeys: ['2.139.3'] }));
  assert.ok(versionProblem({ head: '2.139.9', base: '2.139.10', baseLabel: 'main', notesKeys: ['2.139.9'] }));
});

test('a higher version without release notes is refused, with notes it passes', () => {
  assert.match(
    versionProblem({ head: '2.139.6', base: '2.139.5', baseLabel: 'main', notesKeys: ['2.139.5'] }),
    /release-notes\.json has no "2\.139\.6" key/,
  );
  assert.equal(versionProblem({ head: '2.139.6', base: '2.139.5', baseLabel: 'main', notesKeys: ['2.139.6'] }), null);
});

function repoAt(version, notes) {
  const dir = mkdtempSync(join(tmpdir(), 'version-guard-'));
  const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  const write = (v, n) => {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: v }, null, 2) + '\n');
    writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ name: 'x', version: v, lockfileVersion: 3, packages: { '': { name: 'x', version: v } } }, null, 2) + '\n');
    writeFileSync(join(dir, 'release-notes.json'), JSON.stringify(Object.fromEntries(n.map(k => [k, ['x']]))));
  };
  git('init', '-q');
  write(version, notes);
  git('add', '.');
  git('-c', 'user.name=t', '-c', 'user.email=t@example.test', 'commit', '-qm', 'base');
  return { dir, write, done: () => rmSync(dir, { recursive: true, force: true }) };
}

const run = (dir, script, args) => spawnSync(process.execPath, [join(scripts, script), ...args], { cwd: dir, encoding: 'utf8' });

test('check-version-bump exits 1 on a reused number and 0 on a fresh one', () => {
  const r = repoAt('2.139.4', ['2.139.4']);
  try {
    let out = run(r.dir, 'check-version-bump.mjs', ['--base', 'HEAD', '--label', 'main']);
    assert.equal(out.status, 1, out.stdout + out.stderr);
    assert.match(out.stderr, /already at 2\.139\.4/);
    r.write('2.139.5', ['2.139.5', '2.139.4']);
    out = run(r.dir, 'check-version-bump.mjs', ['--base', 'HEAD', '--label', 'main']);
    assert.equal(out.status, 0, out.stdout + out.stderr);
  } finally { r.done(); }
});

test('next-version prints the next number and --write refuses without notes', () => {
  const r = repoAt('2.139.5', ['2.139.5']);
  try {
    r.write('2.139.4', ['2.139.4']);
    let out = run(r.dir, 'next-version.mjs', ['--base', 'HEAD']);
    assert.equal(out.status, 0, out.stderr);
    assert.equal(out.stdout.trim(), '2.139.6');
    out = run(r.dir, 'next-version.mjs', ['--base', 'HEAD', '--write']);
    assert.equal(out.status, 1);
    assert.match(out.stderr, /no "2\.139\.6" key/);
    assert.equal(JSON.parse(readFileSync(join(r.dir, 'package.json'), 'utf8')).version, '2.139.4');
  } finally { r.done(); }
});

test('next-version --write sets package.json and the lockfile when notes exist', () => {
  const r = repoAt('2.139.5', ['2.139.5']);
  try {
    r.write('2.139.5', ['2.139.5', '2.140.0']);
    const out = run(r.dir, 'next-version.mjs', ['--base', 'HEAD', '--minor', '--write']);
    assert.equal(out.status, 0, out.stderr);
    assert.equal(JSON.parse(readFileSync(join(r.dir, 'package.json'), 'utf8')).version, '2.140.0');
    const lock = JSON.parse(readFileSync(join(r.dir, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '2.140.0');
    assert.equal(lock.packages[''].version, '2.140.0');
  } finally { r.done(); }
});

test('an unreachable base ref is a clear failure, not a pass', () => {
  const r = repoAt('2.139.5', ['2.139.5']);
  try {
    const out = run(r.dir, 'check-version-bump.mjs', ['--base', 'origin/main']);
    assert.equal(out.status, 1);
    assert.match(out.stderr, /git fetch origin/);
  } finally { r.done(); }
});

test('a base ref that starts with "-" is refused before git sees it as an option', async () => {
  const { versionAtRef } = await import('../scripts/lib/git-version.mjs');
  assert.throws(() => versionAtRef('--all', process.cwd()), /refusing unsafe ref/);
});
