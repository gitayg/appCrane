import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// Adopt an app end to end: the /api/adopt routes and services/adopt/flow.js
// against a real database, real local git and real deploys that stop at a
// docker shim (which always fails), so no container can start. Proves who may
// adopt, that production is refused, that secrets land encrypted for the
// sandbox only, that the first deploy is a sandbox deploy, and that the intake
// hook is called.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-adopt-'));
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
const flow = await import('../server/services/adopt/flow.js');
const { adoptAppTool } = await import('../server/services/adopt/mcpTool.js');
const { default: adoptRouter } = await import('../server/routes/adopt.js');
const { makeZip, dirEntries, fakeJwt } = await import('./fixtures/adopt/makeZip.js');

const FIX = fileURLToPath(new URL('./fixtures/adopt/', import.meta.url));
const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const git = (slug, args) => execFileSync('git', [`--git-dir=${lg.repoPath(slug)}`, ...args], { env: CLEAN_ENV }).toString('utf8');
const repoFiles = (slug) => git(slug, ['ls-tree', '-r', '--name-only', 'main']).trim().split('\n').sort();
const repoFile = (slug, path) => git(slug, ['cat-file', 'blob', `main:${path}`]);

const mkUser = (name, role) => {
  const key = `adopt-${name}-key-0001`;
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@x.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id: Number(id), key, user: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
};
const admin = mkUser('pa', 'platform_admin');
const plain = mkUser('plain', 'user');
const other = mkUser('other', 'platform_admin');
const setUserCreate = (granted) => db.prepare(`
  INSERT INTO role_permissions (permission, role, granted) VALUES ('platform.create_app', 'user', ?)
  ON CONFLICT(permission, role) DO UPDATE SET granted = excluded.granted
`).run(granted ? 1 : 0);
setUserCreate(false);

const web = express();
web.use(express.json({ limit: '50mb' }));
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
async function uploadZip(key, buf, filename = 'project.zip') {
  const form = new FormData();
  form.append('file', new Blob([buf]), filename);
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

const SERVICE_ROLE = fakeJwt({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role: 'service_role', iat: 1700000000, exp: 2000000000 });
const SUPA_URL = 'https://abcdefghijklmnopqrst.supabase.co';
const SECRET_VALUE = 'sb_publishable_test_value_0123456789';
const lovableZip = () => makeZip(dirEntries(join(FIX, 'lovable-vite-supabase'), 'team-todos-main/'));

test('only callers allowed to create apps may analyse or adopt', async () => {
  const zip = lovableZip();
  const denied = await uploadZip(plain.key, zip);
  assert.equal(denied.status, 403, JSON.stringify(denied.body));
  assert.equal(denied.body.error.code, 'FORBIDDEN');
  const deniedGh = await api(plain.key, 'POST', '/api/adopt/analyze', { github_url: 'https://github.com/a/b' });
  assert.equal(deniedGh.status, 403);
  assert.equal((await api(plain.key, 'GET', '/api/adopt/sources')).status, 403);
  await assert.rejects(adoptAppTool.handler(plain.user, { action: 'analyze', github_url: 'https://github.com/a/b' }), /permission to create apps/);
  assert.equal(adoptAppTool.requiredRole, 'create_app');

  setUserCreate(true);
  try {
    const ok = await uploadZip(plain.key, zip);
    assert.equal(ok.status, 201, JSON.stringify(ok.body));
    assert.equal(ok.body.report.project.origin.tool, 'lovable');
  } finally { setUserCreate(false); }
});

test('an analysis belongs to the person who ran it', async () => {
  const a = await uploadZip(admin.key, lovableZip());
  assert.equal(a.status, 201);
  assert.match(a.body.id, /^[A-Za-z0-9_-]{22}$/);
  const peek = await api(other.key, 'GET', `/api/adopt/${a.body.id}`);
  assert.equal(peek.status, 200, 'a platform admin can read it');
  const steal = await api(other.key, 'POST', `/api/adopt/${a.body.id}/adopt`, { name: 'Stolen', slug: 'stolen-app', stage: 'sandbox' });
  assert.equal(steal.status, 403, JSON.stringify(steal.body));
  setUserCreate(true);
  try {
    const plainPeek = await api(plain.key, 'GET', `/api/adopt/${a.body.id}`);
    assert.equal(plainPeek.status, 404);
  } finally { setUserCreate(false); }
  assert.equal(db.prepare("SELECT COUNT(*) n FROM apps WHERE slug = 'stolen-app'").get().n, 0);
});

test('production is refused before anything is created', async () => {
  const a = await uploadZip(admin.key, lovableZip());
  const r = await api(admin.key, 'POST', `/api/adopt/${a.body.id}/adopt`, { name: 'Prod try', slug: 'prod-try', stage: 'production' });
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, 'PRODUCTION_REFUSED');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM apps WHERE slug = 'prod-try'").get().n, 0);
  assert.equal(db.prepare('SELECT status FROM app_adoptions WHERE id = ?').get(a.body.id).status, 'analyzed');
  await assert.rejects(adoptAppTool.handler(admin.user, { action: 'adopt', adoption_id: a.body.id, name: 'P', slug: 'prod-try', stage: 'production' }), /sandbox only/);
  await assert.rejects(adoptAppTool.handler(admin.user, { action: 'adopt', adoption_id: a.body.id, name: 'P', slug: 'prod-try', env: 'production' }), /sandbox only/);
});

test('adopt over HTTP: Crane-hosted app, code + scaffold committed, sandbox-only encrypted env, sandbox deploy, intake called, requests opened', async () => {
  const a = await uploadZip(admin.key, lovableZip(), 'team-todos-main.zip');
  assert.equal(a.status, 201, JSON.stringify(a.body));
  assert.deepEqual(a.body.suggested, { name: 'team-todos-main', slug: 'team-todos-main' });
  const r = await api(admin.key, 'POST', `/api/adopt/${a.body.id}/adopt`, {
    name: 'Team todos', slug: 'team-todos', stage: 'sandbox', open_requests: true,
    env_vars: { VITE_SUPABASE_URL: SUPA_URL, VITE_SUPABASE_PUBLISHABLE_KEY: SECRET_VALUE },
    intake: { purpose: 'Team todo list', data_classification: 'internal', intake_answers: { personal_data: false, access: 'team' } },
  });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.ok(!JSON.stringify(r.body).includes(SECRET_VALUE), 'a secret value was echoed back');

  const app = db.prepare("SELECT * FROM apps WHERE slug = 'team-todos'").get();
  assert.equal(app.source_type, 'managed');
  assert.equal(app.repo_backend, 'local');
  assert.equal(db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, admin.id).app_role, 'owner');

  const files = repoFiles('team-todos');
  for (const f of ['Dockerfile', 'appcrane-serve.mjs', 'deployhub.json', '.dockerignore', 'src/App.tsx', 'supabase/migrations/20260101000000_init.sql', 'package.json']) {
    assert.ok(files.includes(f), `${f} missing from the repo: ${files.join(', ')}`);
  }
  assert.ok(!files.some((f) => f.split('/').pop().startsWith('.env')), 'an env file was committed');
  assert.match(repoFile('team-todos', 'Dockerfile'), /EXPOSE 3000/);
  assert.equal(JSON.parse(repoFile('team-todos', 'deployhub.json')).be.health, '/api/health');

  const envRows = db.prepare('SELECT env, key, value_encrypted FROM env_vars WHERE app_id = ? ORDER BY key').all(app.id);
  assert.deepEqual(envRows.map((e) => [e.env, e.key]), [['sandbox', 'VITE_SUPABASE_PUBLISHABLE_KEY'], ['sandbox', 'VITE_SUPABASE_URL']]);
  for (const e of envRows) assert.ok(!e.value_encrypted.includes(SECRET_VALUE) && !e.value_encrypted.includes('supabase.co'));
  assert.equal(decrypt(envRows[0].value_encrypted), SECRET_VALUE);
  const envFile = db.prepare('SELECT env, rel_path FROM app_env_files WHERE app_id = ?').all(app.id);
  assert.deepEqual(envFile.map((f) => ({ ...f })), [{ env: 'sandbox', rel_path: '.env' }], 'client env vars must reach the build');

  const audit = db.prepare('SELECT detail FROM audit_log').all().map((x) => x.detail).join('\n');
  assert.ok(!audit.includes(SECRET_VALUE), 'a secret value reached the audit log');
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE app_id = ? AND action = 'app-adopt'").get(app.id));

  assert.deepEqual({ ...db.prepare('SELECT auto_deploy_prod, auto_deploy_sandbox FROM webhook_configs WHERE app_id = ?').get(app.id) }, { auto_deploy_prod: 0, auto_deploy_sandbox: 1 });
  assert.equal(r.body.deployments.length, 1);
  assert.equal(r.body.deployments[0].env, 'sandbox');
  await settle(app.id);
  const deps = db.prepare('SELECT env FROM deployments WHERE app_id = ?').all(app.id);
  assert.deepEqual(deps.map((d) => d.env), ['sandbox']);

  assert.ok(r.body.intake.submitted === true || /not implemented/.test(r.body.intake.reason), JSON.stringify(r.body.intake));

  const reqs = db.prepare("SELECT message, user_name, status FROM enhancement_requests WHERE app_slug = 'team-todos'").all();
  assert.equal(reqs.length, r.body.requests.length);
  assert.ok(reqs.length >= 2, JSON.stringify(reqs));
  assert.ok(reqs.some((q) => /Supabase Auth/.test(q.message)));
  assert.ok(reqs.every((q) => q.user_name === flow.ADOPT_REQUESTER && q.status === 'new'));

  const row = db.prepare('SELECT status, app_id FROM app_adoptions WHERE id = ?').get(a.body.id);
  assert.deepEqual({ ...row }, { status: 'adopted', app_id: app.id });
  assert.equal(existsSync(join(ROOT, 'adopt', `${a.body.id}.zip`)), false, 'staged archive left behind');
  const again = await api(admin.key, 'POST', `/api/adopt/${a.body.id}/adopt`, { name: 'x', slug: 'team-todos-2', stage: 'sandbox' });
  assert.equal(again.status, 409);
});

test('adopt calls submitIntake with the app and the intake answers', async () => {
  const a = await flow.analyzeSource(admin.user, { kind: 'zip', buffer: makeZip(dirEntries(join(FIX, 'v0-next'))), filename: 'pricing.zip' });
  const calls = [];
  const out = await flow.adoptAnalyzed(admin.user, {
    id: a.id, name: 'Pricing', slug: 'pricing-v0', stage: 'sandbox',
    intake: { purpose: 'Quote helper', data_classification: 'confidential', owner: admin.id, intake_answers: { personal_data: true, external_integrations: 'OpenAI', access: 'sales' } },
  }, { submitIntake: (app, intake) => { calls.push({ app, intake }); return { app_id: app.id, status: 'pending', data_classification: intake.data_classification, approval_required: true }; } });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].app.slug, 'pricing-v0');
  assert.deepEqual(calls[0].intake, {
    purpose: 'Quote helper', data_classification: 'confidential', owner: admin.id,
    intake_answers: { personal_data: true, external_integrations: 'OpenAI', access: 'sales' }, submitted_by: admin.id,
  });
  assert.equal(out.intake.submitted, true);
  assert.equal(out.intake.result.status, 'pending');
  assert.ok(repoFiles('pricing-v0').includes('app/api/health/route.js'));
  await settle(out.app.id);
});

test('critical risks must be acknowledged; the MCP tool adopts with [{ key, value }] env', async () => {
  const entries = dirEntries(join(FIX, 'bolt-vite'));
  entries.push({ name: 'src/lib/admin.ts', data: `export const k = '${SERVICE_ROLE}';\n` });
  entries.push({ name: '.env', data: `VITE_SUPABASE_URL=${SUPA_URL}\nVITE_SUPABASE_ANON_KEY=from-upload-0123456789\n` });
  const a = await adoptAppTool.handler(admin.user, { action: 'analyze', github_url: 'https://lovable.dev/projects/x' }).catch((e) => e);
  assert.match(a.message, /Connect to GitHub/);

  const an = await flow.analyzeSource(admin.user, { kind: 'zip', buffer: makeZip(entries), filename: 'bolt.zip' });
  assert.equal(an.report.risk_counts.critical, 1);
  await assert.rejects(adoptAppTool.handler(admin.user, { action: 'adopt', adoption_id: an.id, name: 'Bookings', slug: 'bookings', stage: 'sandbox' }), /critical risk/);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM apps WHERE slug = 'bookings'").get().n, 0);
  await assert.rejects(adoptAppTool.handler(admin.user, { action: 'adopt', adoption_id: an.id, name: 'B', slug: 'bookings', env_vars: [{ key: 'A', value: '1' }, { key: 'A', value: '2' }], acknowledge_risks: true }), /listed twice/);

  const out = await adoptAppTool.handler(admin.user, {
    action: 'adopt', adoption_id: an.id, name: 'Bookings', slug: 'bookings', stage: 'sandbox', acknowledge_risks: true,
    env_vars: [{ key: 'VITE_SUPABASE_ANON_KEY', value: 'typed-by-user-0123456789' }],
  });
  assert.equal(out.app.slug, 'bookings');
  assert.match(out.next, /appcrane_wait_deploy/);
  const app = db.prepare("SELECT id FROM apps WHERE slug = 'bookings'").get();
  const env = Object.fromEntries(db.prepare('SELECT key, value_encrypted FROM env_vars WHERE app_id = ?').all(app.id).map((r) => [r.key, decrypt(r.value_encrypted)]));
  assert.deepEqual(env, { VITE_SUPABASE_ANON_KEY: 'typed-by-user-0123456789', VITE_SUPABASE_URL: SUPA_URL }, 'typed value wins, the upload fills the rest');
  assert.ok(out.env_files_left_out.includes('.env'));
  await settle(app.id);
  assert.deepEqual(db.prepare('SELECT DISTINCT env FROM deployments WHERE app_id = ?').all(app.id).map((d) => d.env), ['sandbox']);
});

test('oversized and unsafe uploads are refused over HTTP', async () => {
  process.env.APPCRANE_ADOPT_MAX_ARCHIVE_BYTES = '2000';
  try {
    const big = await uploadZip(admin.key, makeZip([{ name: 'index.html', data: 'x'.repeat(5000) }]));
    assert.equal(big.status, 413, JSON.stringify(big.body));
    assert.equal(big.body.error.code, 'ARCHIVE_TOO_LARGE');
  } finally { delete process.env.APPCRANE_ADOPT_MAX_ARCHIVE_BYTES; }
  const slip = await uploadZip(admin.key, makeZip([{ name: 'index.html', data: 'x' }, { name: '../../outside.txt', data: 'x' }]));
  assert.equal(slip.status, 400);
  assert.equal(slip.body.error.code, 'ARCHIVE_UNSAFE_PATH');
  assert.equal(existsSync(join(ROOT, '..', 'outside.txt')), false);
  const notZip = await uploadZip(admin.key, Buffer.from('hello'), 'project.tar.gz');
  assert.equal(notZip.status, 400);
});
