import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// A catalogue entry's `build` recipe tells the generated Node build how to
// build a project with no Dockerfile and no deployhub.json (SignuDoc: a Next.js
// build needs its devDependencies, and migrations run before the server). The
// repo's own deployhub.json still wins field by field.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-recipe-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { ensureDockerfile } = await import('../server/services/dockerfileGen.js');
const { validateRecipe, catalogRecipeFor, applyRecipeHealth } = await import('../server/services/catalogBuildRecipe.js');
const { resolveHealthProbe } = await import('../server/services/healthProbeTarget.js');
const CATALOG = JSON.parse(readFileSync(new URL('../server/services/appCatalog.json', import.meta.url), 'utf8'));
const signudoc = CATALOG.find((e) => e.slug === 'signudoc');

function release(pkg = { name: 'x', version: '1.0.0', scripts: { build: 'next build', start: 'next start' }, engines: { node: '24.x' } }) {
  const dir = mkdtempSync(join(tmpdir(), 'crane-recipe-rel-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify(pkg));
  writeFileSync(join(dir, 'package-lock.json'), '{}');
  return dir;
}
const gen = (dir, manifest, recipe) => {
  ensureDockerfile({ releaseDir: dir, manifest, appBasePath: '/x/', craneUrl: 'http://crane.example.com', craneInternalUrl: 'http://host.docker.internal:5001', slug: 'x', recipe });
  return readFileSync(join(dir, 'Dockerfile'), 'utf8');
};

test('every catalogue recipe is one the generator accepts', () => {
  for (const e of CATALOG) if (e.build !== undefined) assert.doesNotThrow(() => validateRecipe(e.build), e.slug);
});

test('the recipe replaces install, build and start and adds its ENV defaults', () => {
  const df = gen(release(), {}, signudoc.build);
  assert.match(df, /^FROM node:24-alpine/m);
  assert.match(df, /^RUN npm ci$/m, 'devDependencies are installed for next build');
  assert.doesNotMatch(df, /--omit=dev; fi/);
  assert.match(df, /^RUN .* npm run build$/m);
  assert.match(df, /^ENV STORAGE_LOCAL_DIR="\/data\/storage"$/m);
  assert.match(df, /^CMD \["sh", "-c", "node db\/migrate\.mjs && exec npm start"\]$/m, 'migrations run before the server on every start');
});

test('without a recipe the generated build is what it always was', () => {
  const df = gen(release(), {}, null);
  assert.match(df, /npm ci --omit=dev; else npm install --omit=dev; fi$/m);
  assert.match(df, /^CMD \["npm","start"\]$/m);
  assert.doesNotMatch(df, /STORAGE_LOCAL_DIR/);
});

test('the repo\'s own deployhub.json wins over the recipe field by field', () => {
  const df = gen(release(), { be: { entry: 'node server.js' }, build: { frontend: 'npm run build:prod' } }, signudoc.build);
  assert.match(df, /^CMD \["node","server\.js"\]$/m);
  assert.match(df, /npm run build:prod$/m);
  assert.match(df, /^RUN npm ci$/m, 'install still comes from the recipe: the manifest did not set be.install');
});

test('a recipe the generator could not use safely is refused', () => {
  for (const bad of [null, [], { run: 'x' }, { start: '' }, { start: 'a\nb' }, { env: { 'A-B': 'x' } }, { env: { A: 'x"; rm -rf /' } }, { env: { A: '$HOME' } }, { env: [] }]) {
    assert.throws(() => validateRecipe(bad), undefined, JSON.stringify(bad));
  }
});

test('the recipe applies to a catalogue app built from source, never to an image deploy or a custom app', () => {
  assert.deepEqual(catalogRecipeFor({ catalog_slug: 'signudoc' }, false).recipe, signudoc.build);
  assert.equal(catalogRecipeFor({ catalog_slug: 'signudoc' }, true), null);
  assert.equal(catalogRecipeFor({ catalog_slug: null }, false), null);
  assert.equal(catalogRecipeFor({ catalog_slug: 'bookstack' }, false), null, 'an entry without a recipe');
});

test('the entry health becomes be.health unless the repo names one, and is held to "answers 200"', () => {
  const m = {};
  assert.equal(applyRecipeHealth(m, signudoc), true);
  assert.equal(m.be.health, signudoc.health);
  const own = { be: { health: '/healthz' } };
  assert.equal(applyRecipeHealth(own, signudoc), false);
  assert.equal(own.be.health, '/healthz');
  const app = { source_type: 'github' };
  assert.equal(resolveHealthProbe({ manifest: m, app, runtime: 'node', catalogBuild: true }).strict, false);
  assert.equal(resolveHealthProbe({ manifest: m, app, runtime: 'node' }).strict, true, 'an app of our own convention stays strict');
});
