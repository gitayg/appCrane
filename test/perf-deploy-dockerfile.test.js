import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { ensureDockerfile, injectAppBasePathArg, npmCacheId } from '../server/services/dockerfileGen.js';
import { placeAppBasePathArg } from '../server/services/dockerfileBasePath.js';
import { buildKitEnabled } from '../server/services/buildkitMode.js';

function release(files) {
  const dir = mkdtempSync(join(tmpdir(), 'perf-deploy-df-'));
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(join(dir, name, '..'), { recursive: true });
    writeFileSync(join(dir, name), body);
  }
  return dir;
}

const nodeApp = {
  'package.json': JSON.stringify({ name: 'x', scripts: { start: 'node server.js', build: 'vite build' } }),
  'package-lock.json': '{}',
};

function generate(dir, opts = {}) {
  ensureDockerfile({ releaseDir: dir, manifest: null, appBasePath: '/x/', craneUrl: 'http://c', craneInternalUrl: 'http://c', slug: 'app-a', ...opts });
  return readFileSync(join(dir, 'Dockerfile'), 'utf8').split('\n');
}

const idx = (lines, re) => lines.findIndex((l) => re.test(l));

// ---- item 1: ARG APP_BASE_PATH placement ----------------------------------

test('single stage: ARG APP_BASE_PATH lands after npm ci, right before COPY . .', () => {
  const out = placeAppBasePathArg([
    'FROM node:20-alpine',
    'WORKDIR /app',
    'COPY package.json package-lock.json ./',
    'RUN npm ci',
    'COPY . .',
    'RUN npm run build',
    'CMD ["node","server.js"]',
  ].join('\n')).split('\n');
  const arg = idx(out, /^ARG APP_BASE_PATH=\/$/);
  assert.equal(out[arg + 1], 'ENV APP_BASE_PATH=$APP_BASE_PATH');
  assert.ok(arg > idx(out, /^RUN npm ci$/), 'ARG must come after the dependency install');
  assert.equal(out[arg + 2], 'COPY . .');
});

test('multi-stage: ARG stays in the build stage before its source COPY; runtime stage untouched', () => {
  const out = placeAppBasePathArg([
    'FROM node:20-alpine AS build',
    'WORKDIR /app',
    'COPY --chown=node:node package*.json ./',
    'RUN npm ci',
    'COPY src ./src',
    'RUN npm run build',
    '',
    'FROM node:20-alpine',
    'COPY --from=build /app/dist ./dist',
    'CMD ["node","server.js"]',
  ].join('\n')).split('\n');
  const arg = idx(out, /^ARG APP_BASE_PATH/);
  assert.ok(arg > idx(out, /^RUN npm ci$/));
  assert.ok(arg < idx(out, /^RUN npm run build$/));
  assert.ok(arg < idx(out, /^FROM node:20-alpine$/), 'ARG is per-stage: it must be inside the build stage');
  assert.equal(out.filter((l) => /^ARG APP_BASE_PATH/.test(l)).length, 1);
});

test('deps-only first stage: ARG goes at its end so a FROM <stage> build stage inherits the ENV', () => {
  const out = placeAppBasePathArg([
    'FROM node:20 AS deps',
    'COPY package.json yarn.lock ./',
    'RUN yarn install',
    'FROM deps AS build',
    'COPY . .',
    'RUN yarn build',
  ].join('\n')).split('\n');
  const arg = idx(out, /^ARG APP_BASE_PATH/);
  assert.ok(arg > idx(out, /^RUN yarn install$/));
  assert.ok(arg < idx(out, /^FROM deps AS build$/));
});

test('continuations, bind mounts and explicit references stop the scan', () => {
  const cont = placeAppBasePathArg('FROM node\nCOPY package.json \\\n  vite.config.js ./\nRUN npm ci\n').split('\n');
  assert.equal(idx(cont, /^ARG APP_BASE_PATH/), 1, 'a COPY of a non-manifest file across a continuation is the boundary');
  const bind = placeAppBasePathArg('FROM node\nRUN --mount=type=bind,target=/src npm run build\n').split('\n');
  assert.equal(idx(bind, /^ARG APP_BASE_PATH/), 1);
  const ref = placeAppBasePathArg('FROM node\nRUN echo $APP_BASE_PATH > /base\nCOPY . .\n').split('\n');
  assert.equal(idx(ref, /^ARG APP_BASE_PATH/), 1);
  assert.equal(placeAppBasePathArg('ARG APP_BASE_PATH=/\nFROM node\n'), null);
  assert.equal(placeAppBasePathArg('# nothing\n'), null);
});

test('injectAppBasePathArg writes the moved declaration to disk', () => {
  const dir = release({ Dockerfile: 'FROM node:20\nCOPY package*.json ./\nRUN npm ci\nCOPY . .\nRUN npm run build\n' });
  try {
    injectAppBasePathArg(join(dir, 'Dockerfile'));
    const lines = readFileSync(join(dir, 'Dockerfile'), 'utf8').split('\n');
    assert.deepEqual(lines.slice(0, 5), ['FROM node:20', 'COPY package*.json ./', 'RUN npm ci', 'ARG APP_BASE_PATH=/', 'ENV APP_BASE_PATH=$APP_BASE_PATH']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---- item 4: npm cache mount only under BuildKit ---------------------------

test('generated npm install gets the cache mount with BuildKit and not without', () => {
  const a = release(nodeApp);
  const b = release(nodeApp);
  try {
    const withBk = generate(a, { buildkit: true });
    const install = withBk.find((l) => l.includes('npm ci --omit=dev'));
    assert.match(install, /^RUN --mount=type=cache,id=npm-app-a,target=\/home\/node\/\.npm,uid=1000,gid=1000,sharing=locked /);
    const classic = generate(b, { buildkit: false });
    assert.ok(!classic.some((l) => l.includes('--mount')), 'classic builder rejects --mount');
    assert.match(classic.find((l) => l.includes('npm ci --omit=dev')), /^RUN if /);
  } finally { rmSync(a, { recursive: true, force: true }); rmSync(b, { recursive: true, force: true }); }
});

test('monorepo installs get the cache mount too', () => {
  const dir = release({
    ...nodeApp,
    'client/package.json': JSON.stringify({ scripts: { build: 'vite build' }, devDependencies: { vite: '5' } }),
    'client/package-lock.json': '{}',
  });
  try {
    const lines = generate(dir, { buildkit: true });
    const installs = lines.filter((l) => /npm (ci|install)/.test(l) && l.startsWith('RUN') && !l.includes('audit'));
    assert.equal(installs.length, 2);
    for (const l of installs) assert.match(l, /^RUN --mount=type=cache/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('buildKitEnabled follows DOCKER_BUILDKIT the way the Docker CLI parses it', () => {
  assert.equal(buildKitEnabled({ DOCKER_BUILDKIT: '1' }), true);
  assert.equal(buildKitEnabled({ DOCKER_BUILDKIT: 'true' }), true);
  assert.equal(buildKitEnabled({ DOCKER_BUILDKIT: '0' }), false);
  assert.equal(buildKitEnabled({ DOCKER_BUILDKIT: 'false' }), false);
  assert.equal(buildKitEnabled({}), false);
});

// ---- item 3 (not moved): audit still after COPY . . ------------------------

test('npm audit stays after COPY . . so a new advisory in unchanged deps is still reported', () => {
  const dir = release(nodeApp);
  try {
    const lines = generate(dir);
    assert.ok(idx(lines, /npm audit/) > idx(lines, /^COPY --chown=node:node \. \.$/));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---- item 2: .dockerignore -------------------------------------------------

test('generated Node build writes .dockerignore excluding .git and the install dirs node_modules', () => {
  const dir = release({
    ...nodeApp,
    'client/package.json': JSON.stringify({ scripts: { build: 'vite build' }, devDependencies: { vite: '5' } }),
  });
  try {
    generate(dir);
    assert.deepEqual(readFileSync(join(dir, '.dockerignore'), 'utf8').split('\n').filter(Boolean), ['.git', 'node_modules', 'client/node_modules']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('generated PHP build writes .dockerignore with .git only', () => {
  const dir = release({ 'composer.json': JSON.stringify({ require: { php: '>=8.1' } }), 'index.php': '<?php echo 1;' });
  try {
    ensureDockerfile({ releaseDir: dir, manifest: null, appBasePath: '/x/', craneUrl: '', craneInternalUrl: '' });
    assert.equal(readFileSync(join(dir, '.dockerignore'), 'utf8'), '.git\n');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("an app's own .dockerignore is never overwritten", () => {
  const dir = release({ ...nodeApp, '.dockerignore': 'dist\n' });
  try {
    generate(dir);
    assert.equal(readFileSync(join(dir, '.dockerignore'), 'utf8'), 'dist\n');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('an app-provided Dockerfile gets no .dockerignore', () => {
  const dir = release({ ...nodeApp, Dockerfile: 'FROM node:20\nUSER node\nEXPOSE 3000\n' });
  try {
    generate(dir);
    assert.equal(existsSync(join(dir, '.dockerignore')), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('npm cache is per app: different slugs, different ids; odd characters cannot add mount options', () => {
  const a = release(nodeApp);
  const b = release(nodeApp);
  try {
    const idOf = (lines) => /--mount=type=cache,id=([^,]+),/.exec(lines.find((l) => l.includes('npm ci --omit=dev')))[1];
    const ida = idOf(generate(a, { buildkit: true, slug: 'app-a' }));
    const idb = idOf(generate(b, { buildkit: true, slug: 'app-b' }));
    assert.equal(ida, 'npm-app-a');
    assert.notEqual(ida, idb);
  } finally { rmSync(a, { recursive: true, force: true }); rmSync(b, { recursive: true, force: true }); }

  const evil = npmCacheId('x,target=/root,id=npm-victim sharing=shared');
  assert.match(evil, /^npm-[a-z0-9-]+$/);
  assert.notEqual(npmCacheId('a_b'), npmCacheId('a-b'), 'sanitising must not merge two slugs into one cache');
  assert.equal(npmCacheId(null), null);

  const c = release(nodeApp);
  try {
    const install = generate(c, { buildkit: true, slug: 'x,target=/root id=npm-victim' }).find((l) => l.includes('npm ci --omit=dev'));
    const mount = install.split(' ')[1];
    assert.equal(mount.split(',').filter((o) => o.startsWith('id=')).length, 1);
    assert.equal(mount.split(',').filter((o) => o.startsWith('target=')).length, 1);
    const none = release(nodeApp);
    try {
      assert.ok(!generate(none, { buildkit: true, slug: null }).some((l) => l.includes('--mount')), 'no slug, no shared cache');
    } finally { rmSync(none, { recursive: true, force: true }); }
  } finally { rmSync(c, { recursive: true, force: true }); }
});
