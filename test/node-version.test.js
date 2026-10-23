import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { ensureDockerfile } from '../server/services/dockerfileGen.js';
import { pickNodeVersion, describeNodeBuild, DEFAULT_NODE_MAJOR } from '../server/services/nodeVersion.js';
import { scaffoldFiles } from '../server/services/adopt/scaffold.js';

const dirs = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function app(files) {
  const d = mkdtempSync(join(tmpdir(), 'crane-nodever-'));
  dirs.push(d);
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(join(d, name, '..'), { recursive: true });
    writeFileSync(join(d, name), typeof body === 'string' ? body : JSON.stringify(body));
  }
  return d;
}

function gen(dir, manifest = {}) {
  const res = ensureDockerfile({
    releaseDir: dir, manifest, appBasePath: '/demo/', craneUrl: 'https://crane.example', craneInternalUrl: 'http://127.0.0.1:3000',
  });
  return { ...res, source: readFileSync(join(dir, 'Dockerfile'), 'utf8') };
}

const PKG = { name: 'n', version: '1.0.0', scripts: { start: 'node s.js' } };
const engines = (node) => ({ packageJsons: [{ pkg: { engines: { node } }, label: 'package.json' }] });

test('the default is Node 22, and the deploy log says the default changed from 20', () => {
  assert.equal(DEFAULT_NODE_MAJOR, '22');
  const { source, node } = gen(app({ 'package.json': PKG, 'package-lock.json': {} }));
  assert.match(source, /^FROM node:22-alpine$/m);
  assert.equal(node.version, '22');
  assert.deepEqual(node.warnings, []);
  assert.equal(
    describeNodeBuild(node),
    "Generated Dockerfile (node:22-alpine, non-root) - Node 22: default (no Node version in deployhub.json or package.json engines); AppCrane's default changed from Node 20 to 22",
  );
});

test('only the FROM line differs between the default and an explicit Node 20 build', () => {
  const files = { 'package.json': PKG, 'package-lock.json': {} };
  const dflt = gen(app(files)).source.split('\n');
  const twenty = gen(app(files), { node_version: '20' }).source.split('\n');
  assert.equal(dflt[0], 'FROM node:22-alpine');
  assert.equal(twenty[0], 'FROM node:20-alpine');
  assert.deepEqual(dflt.slice(1), twenty.slice(1));
});

test('deployhub.json beats package.json engines; package.json engines beats the default', () => {
  const pkg = { ...PKG, engines: { node: '^24' } };
  assert.match(gen(app({ 'package.json': pkg }), { node_version: '26' }).source, /^FROM node:26-alpine$/m);
  assert.match(gen(app({ 'package.json': pkg }), { engines: { node: '22.x' } }).source, /^FROM node:22-alpine$/m);
  assert.match(gen(app({ 'package.json': pkg })).source, /^FROM node:24-alpine$/m);
});

test('a monorepo backend package.json is read when the root states no engines', () => {
  const dir = app({ 'package.json': { name: 'root' }, 'server/package.json': { ...PKG, engines: { node: '24.x' } } });
  assert.match(gen(dir, { be: { workdir: 'server', entry: 'node s.js' } }).source, /^FROM node:24-alpine$/m);
});

test('package.json engines ranges: the default 22 when allowed, else the newest buildable major', () => {
  const table = [
    ['>=18', '22', false],
    ['^20', '20', true],
    ['20.x', '20', true],
    ['~22.1', '22', false],
    ['>=18 <21', '20', true],
    ['22', '22', false],
    ['*', '22', false],
    ['>= 18', '22', false],
    ['>=21', '22', false],
    ['18 || 20', '20', true],
    ['20 - 22', '22', false],
    ['>20', '22', false],
    ['<=20', '20', true],
    ['>=24.0.0 <24.1', '24', false],
    ['>=23', '26', false],
    ['^24 || ^26', '26', false],
    ['v22.3.0', '22', false],
    ['^18.17.0', '18', true],
  ];
  for (const [range, want, warns] of table) {
    const got = pickNodeVersion(engines(range));
    assert.equal(got.version, want, `"${range}"`);
    assert.equal(got.warnings.length, warns ? 1 : 0, `"${range}" warnings: ${got.warnings}`);
  }
});

test('explicit Node 20 still builds, with the security warning in the build result', () => {
  const { source, node } = gen(app({ 'package.json': PKG }), { node_version: 20 });
  assert.match(source, /^FROM node:20-alpine$/m);
  assert.deepEqual(node.warnings, ['Node 20 gets no security fixes (CVE-2026-111497); move to 22, 24 or 26']);
  assert.match(describeNodeBuild(node), /^Generated Dockerfile \(node:20-alpine, non-root\) - Node 20: /);
  assert.deepEqual(pickNodeVersion({ manifest: { node_version: '18' } }).warnings,
    ['Node 18 gets no security fixes (CVE-2026-111497); move to 22, 24 or 26']);
});

test('deployhub.json naming an unbuildable or odd major fails the build clearly', () => {
  for (const v of ['19', '21', '23', '25', '16', '^21', 'lts']) {
    assert.throws(() => gen(app({ 'package.json': PKG }), { node_version: v }),
      (err) => err.message.startsWith('NODE_VERSION_UNSUPPORTED: deployhub.json node_version is "') && /22, 24, 26/.test(err.message),
      v);
  }
});

test('package.json engines no buildable line satisfies falls back to 22 with a warning', () => {
  for (const range of ['21', '^19 || ^21', '<18', '16.x', 'lts/*']) {
    const got = pickNodeVersion(engines(range));
    assert.equal(got.version, '22', range);
    assert.equal(got.warnings.length, 1, range);
    assert.match(got.warnings[0], new RegExp(`^package\\.json engines\\.node is "${range.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}", .*building on the default Node 22`));
  }
});

function filesOf(obj) {
  return new Map(Object.entries(obj).map(([k, v]) => [k, Buffer.from(typeof v === 'string' ? v : JSON.stringify(v))]));
}

test('the adopt scaffolder uses the same picker for every FROM line', () => {
  const spa = { kind: 'spa', build: 'npm run build', package_manager: 'npm', output_dir: 'dist' };
  const fromLines = (files, project) => scaffoldFiles(files, project, { name: 'x' })
    .find((f) => f.path === 'Dockerfile').content.split('\n').filter((l) => l.startsWith('FROM '));

  assert.deepEqual(fromLines(filesOf({ 'package.json': { version: '1.0.0' } }), spa),
    ['FROM node:22-alpine AS build', 'FROM node:22-alpine']);
  assert.deepEqual(fromLines(filesOf({ 'package.json': { engines: { node: '>=24 <25' } } }), spa),
    ['FROM node:24-alpine AS build', 'FROM node:24-alpine']);
  assert.deepEqual(fromLines(filesOf({ 'package.json': {}, 'deployhub.json': { node_version: '26' } }),
    { kind: 'api', runtime: 'node', start: 'node s.js', package_manager: 'npm', label: 'API', has_manifest: true }),
  ['FROM node:26-alpine AS build']);
  assert.deepEqual(fromLines(filesOf({ 'index.html': '<p>' }), { kind: 'static' }), ['FROM node:22-alpine']);
});

test('the studio fallback recipe takes its Node line from the picker, not a literal', () => {
  const src = readFileSync(new URL('../server/services/appstudio/generator.js', import.meta.url), 'utf8');
  assert.match(src, /`FROM node:\$\{pickNodeVersion\(\)\.version\}-alpine`/);
  assert.doesNotMatch(src, /node:20-alpine/);
  assert.equal(pickNodeVersion().version, '22');
});
