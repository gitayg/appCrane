import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// A project leaving Heroku, adopted through the real /api/adopt routes: the
// analysis shows the imported plan, only the analyst (with platform.create_app)
// can read and adopt it, and after adoption the committed deployhub.json holds
// the mapped health path, cron job and database while no manifest value was
// stored. Manifests: the Heroku documentation examples
// (https://devcenter.heroku.com/articles/procfile,
//  https://devcenter.heroku.com/articles/app-json-schema), with a Render cron
// service in the shape of https://render.com/docs/blueprint-spec.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-adopt-platforms-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;
delete process.env.CRANE_DOMAIN;

const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { hashApiKey, decrypt } = await import('../server/services/encryption.js');
const lg = await import('../server/services/localGit.js');
const { default: adoptRouter } = await import('../server/routes/adopt.js');
const { makeZip } = await import('./fixtures/adopt/makeZip.js');

const FIX = fileURLToPath(new URL('./fixtures/platforms/', import.meta.url));
const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const git = (slug, args) => execFileSync('git', [`--git-dir=${lg.repoPath(slug)}`, ...args], { env: CLEAN_ENV }).toString('utf8');

const mkUser = (name, role) => {
  const key = `adoptp-${name}-key-0001`;
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@x.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id: Number(id), key };
};
const owner = mkUser('maker', 'user');
const bystander = mkUser('bystander', 'user');
const setUserCreate = (granted) => db.prepare(`INSERT INTO role_permissions (permission, role, granted) VALUES ('platform.create_app', 'user', ?)
  ON CONFLICT(permission, role) DO UPDATE SET granted = excluded.granted`).run(granted ? 1 : 0);

const web = express();
web.use(express.json({ limit: '10mb' }));
web.use('/api/adopt', adoptRouter);
const server = await new Promise((r) => { const s = web.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.close();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

async function api(key, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method, headers: { 'x-api-key': key, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
async function uploadZip(key, buf) {
  const form = new FormData();
  form.append('file', new Blob([buf]), 'heroku-shop.zip');
  const res = await fetch(`${BASE}/api/adopt/analyze`, { method: 'POST', headers: { 'x-api-key': key }, body: form });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
async function settle(appId) {
  const deadline = Date.now() + 60000;
  while (db.prepare("SELECT COUNT(*) n FROM deployments WHERE app_id = ? AND status IN ('pending','building','deploying')").get(appId).n) {
    if (Date.now() > deadline) throw new Error('deploys did not settle');
    await new Promise((r) => setTimeout(r, 100));
  }
}

const LITERAL = 'sk_live_MANIFEST_VALUE_0123456789';
const appJson = JSON.parse(readFileSync(join(FIX, 'app.json'), 'utf8'));
appJson.env.STRIPE_SECRET = { description: 'Stripe key', value: LITERAL };
const zip = () => makeZip([
  { name: 'shop/package.json', data: JSON.stringify({ name: 'shop', version: '2.0.0', scripts: { start: 'node server.js' }, dependencies: { express: '^5.0.0' } }) },
  { name: 'shop/package-lock.json', data: '{}' },
  { name: 'shop/server.js', data: "const app = require('express')();\napp.get('/api/health', (_q, s) => s.json({ status: 'ok', version: '2.0.0' }));\napp.listen(process.env.PORT);\n" },
  { name: 'shop/Procfile', data: 'web: node server.js\nrelease: ./release-tasks.sh\nworker: env QUEUE=* bundle exec rake resque:work\n' },
  { name: 'shop/app.json', data: JSON.stringify(appJson) },
  { name: 'shop/render.yaml', data: "services:\n  - type: cron\n    name: digest\n    runtime: node\n    schedule: '0 * * * *'\n    startCommand: node digest.js\n" },
]);

test('analysis: create_app is required, and the analysis is readable and adoptable only by its analyst', async () => {
  setUserCreate(false);
  const denied = await uploadZip(owner.key, zip());
  assert.equal(denied.status, 403, JSON.stringify(denied.body));
  setUserCreate(true);

  const a = await uploadZip(owner.key, zip());
  assert.equal(a.status, 201, JSON.stringify(a.body));
  const peek = await api(bystander.key, 'GET', `/api/adopt/${a.body.id}`);
  assert.equal(peek.status, 404, 'another user cannot read the analysis');
  const steal = await api(bystander.key, 'POST', `/api/adopt/${a.body.id}/adopt`, { name: 'Stolen', slug: 'stolen-shop', stage: 'sandbox' });
  assert.equal(steal.status, 404, JSON.stringify(steal.body));
  assert.equal(db.prepare("SELECT COUNT(*) n FROM apps WHERE slug = 'stolen-shop'").get().n, 0);
  setUserCreate(false);
  try {
    assert.equal((await api(owner.key, 'GET', `/api/adopt/${a.body.id}`)).status, 403, 'losing create_app closes the analysis too');
  } finally { setUserCreate(true); }
});

test('the analysis previews the mapping and what could not be mapped; adopting commits it and stores no manifest value', async () => {
  const a = await uploadZip(owner.key, zip());
  assert.equal(a.status, 201, JSON.stringify(a.body));
  const r = a.body.report;
  assert.deepEqual(r.platform.sources.map((s) => s.file), ['render.yaml', 'Procfile', 'app.json']);
  assert.equal(r.project.start, 'node server.js');
  assert.equal(r.project.start_source, 'Procfile web');
  assert.deepEqual(r.platform.crons.map((c) => c.name), ['render:digest']);
  assert.deepEqual(r.platform.database, { engine: 'postgres', injects: ['DATABASE_URL'], origin: 'addons: heroku-postgresql' });
  const unmapped = r.platform.unmapped.map((u) => u.field);
  for (const f of ['worker', 'scripts.postdeploy', 'buildpacks', 'addons: openredis', 'addons: mongolab:shared-single-small', '(Heroku Scheduler)']) {
    assert.ok(unmapped.includes(f), `${f} missing from unmapped: ${unmapped.join(' ; ')}`);
  }
  assert.ok(r.changes.some((c) => c.id === 'platform-release:0' && c.request));
  const envValues = r.changes.find((c) => c.id === 'platform-env-values');
  assert.match(envValues.detail, /STRIPE_SECRET/);
  assert.match(envValues.detail, /SECRET_TOKEN/);
  const env = Object.fromEntries(r.env.map((v) => [v.key, v]));
  assert.equal(env.STRIPE_SECRET.manifest.value, 'literal');
  assert.equal(env.STRIPE_SECRET.value_in_upload, false);
  assert.ok(!JSON.stringify(a.body).includes(LITERAL), 'the manifest value was echoed in the analysis');

  const out = await api(owner.key, 'POST', `/api/adopt/${a.body.id}/adopt`, { name: 'Shop', slug: 'heroku-shop', stage: 'sandbox', env_vars: { SECRET_TOKEN: 'typed-by-the-user-0123' } });
  assert.equal(out.status, 201, JSON.stringify(out.body));
  const app = db.prepare("SELECT * FROM apps WHERE slug = 'heroku-shop'").get();
  const manifest = JSON.parse(git('heroku-shop', ['cat-file', 'blob', 'main:deployhub.json']));
  assert.deepEqual(manifest, {
    name: 'Shop', version: '2.0.0', be: { health: '/api/health' },
    cron: [{ name: 'render:digest', schedule: '0 * * * *', command: 'node digest.js' }],
    database: { engine: 'postgres' },
  });
  assert.match(git('heroku-shop', ['cat-file', 'blob', 'main:Dockerfile']), /CMD \["sh", "-c", "node server\.js"\]/);

  const rows = db.prepare('SELECT env, key, value_encrypted FROM env_vars WHERE app_id = ?').all(app.id);
  assert.deepEqual(rows.map((x) => [x.env, x.key]), [['sandbox', 'SECRET_TOKEN']], 'only the value the user typed is stored');
  assert.equal(decrypt(rows[0].value_encrypted), 'typed-by-the-user-0123');
  const stored = JSON.stringify(db.prepare('SELECT detail FROM audit_log').all()) + JSON.stringify(rows.map((x) => decrypt(x.value_encrypted)));
  assert.ok(!stored.includes(LITERAL), 'a manifest value was stored');

  await settle(app.id);
  const crons = db.prepare("SELECT name, schedule, command, origin FROM app_cron_jobs WHERE app_id = ? AND env = 'sandbox'").all(app.id).map((x) => ({ ...x }));
  assert.deepEqual(crons, [{ name: 'render:digest', schedule: '0 * * * *', command: 'node digest.js', origin: 'manifest' }], 'the sandbox deploy synced the imported cron job');
});

test('prototype-pollution manifests uploaded through /api/adopt/analyze are reported unreadable and leave Object.prototype alone', async () => {
  const before = Object.getOwnPropertyNames(Object.prototype).sort();
  const payloads = [
    ['railway.toml', '[__proto__]\nroute_polluted_a = 1\n'],
    ['railway.toml', '__proto__.route_polluted_b = "y"\n'],
    ['render.yaml', '__proto__:\n  route_polluted_c: y\n'],
    ['heroku.yml', 'run:\n  web: {"__proto__": {route_polluted_d: 1}}\n'],
    ['app.json', '{"env":{"__proto__":{"route_polluted_e":"y"}}}'],
    ['railway.json', '{"deploy":{"__proto__":{"route_polluted_f":1}}}'],
  ];
  for (const [file, text] of payloads) {
    const res = await uploadZip(owner.key, makeZip([
      { name: 'p/package.json', data: JSON.stringify({ name: 'p', version: '1.0.0', scripts: { start: 'node s.js' }, dependencies: { express: '^5.0.0' } }) },
      { name: 'p/s.js', data: "require('express')().listen(process.env.PORT);\n" },
      { name: `p/${file}`, data: text },
    ]));
    assert.equal(res.status, 201, JSON.stringify(res.body));
    const u = res.body.report.platform.unmapped.find((x) => x.source === file);
    assert.equal(u?.kind, 'unreadable', `${file} was not refused: ${JSON.stringify(res.body.report.platform)}`);
    assert.match(u.detail, /is not allowed/);
  }
  assert.deepEqual(Object.getOwnPropertyNames(Object.prototype).sort(), before);
  for (const k of 'abcdef') assert.equal(({})[`route_polluted_${k}`], undefined, `route_polluted_${k} reached Object.prototype`);
});
