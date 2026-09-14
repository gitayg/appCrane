import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// /api/apps/:slug/env-files — an app owner replaces or deletes a Crane-hosted
// app's stored .env file (routes/envFiles.js over envFileStore.js).
//
// Real HTTP on 127.0.0.1, real encryption, real deploy up to `docker build`,
// where a shim copies the build context and fails the build: "the next deploy
// writes the replaced content" is read from that copy, not assumed.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-envroutes-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'debug';

const SHIM = join(ROOT, 'bin');
const CAPTURE = join(ROOT, 'build-capture');
mkdirSync(SHIM, { recursive: true });
mkdirSync(CAPTURE, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
case "$1" in
  version) echo 27.0.0; exit 0 ;;
  image) exit 1 ;;
  build)
    for a in "$@"; do ctx="$a"; done
    n=$(cat "$ENVROUTES_CAPTURE/count" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$ENVROUTES_CAPTURE/count"
    mkdir -p "$ENVROUTES_CAPTURE/$n" && cp -Rp "$ctx"/. "$ENVROUTES_CAPTURE/$n/"
    echo "shim: build context captured, failing the build" >&2; exit 1 ;;
  *) exit 0 ;;
esac
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;
process.env.ENVROUTES_CAPTURE = CAPTURE;

const logLines = [];
const origLog = console.log;
const origErr = console.error;
console.log = (...a) => { logLines.push(a.join(' ')); };
console.error = (...a) => { logLines.push(a.join(' ')); };

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey, decrypt, encrypt } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { getNextSlot, getPortsForSlot } = await import('../server/services/portAllocator.js');
const lg = await import('../server/services/localGit.js');
const store = await import('../server/services/envFileStore.js');
const { deployApp } = await import('../server/services/deployer.js');
const routes = (await import('../server/routes/envFiles.js')).default;

const api = express();
api.use(express.json({ limit: '50mb' }));
api.use('/api/apps', routes);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  console.log = origLog;
  console.error = origErr;
  server.closeAllConnections?.();
  server.close();
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

const appRow = (slug) => db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
async function craneApp(slug) {
  await lg.createAppRepo(slug);
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES (?, ?, ?, 'managed', 'local', 'main')").run(slug, slug, getNextSlot(db));
  return appRow(slug);
}
const APP = await craneApp('ef-app');
const OTHER = await craneApp('ef-other');
db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url, branch) VALUES ('gh', 'ef-gh', ?, 'managed', 'https://github.com/svc-owner/AMC_ef-gh', 'main')").run(getNextSlot(db));
db.prepare("INSERT INTO apps (name, slug, slot, source_type, branch) VALUES ('up', 'ef-upload', ?, 'upload', 'main')").run(getNextSlot(db));
const GH = appRow('ef-gh');
const UPLOAD = appRow('ef-upload');

let seq = 0;
function user(role, grants = []) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)').run(`ef${n}`, `ef${n}@example.com`, role, hashApiKey(key), 'human').lastInsertRowid;
  for (const [app, appRole] of grants) {
    db.prepare('INSERT INTO app_users (app_id, user_id) VALUES (?, ?)').run(app.id, id);
    if (appRole) db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(app.id, id, appRole);
  }
  return { id, key };
}
const OWNER = user('user', [[APP, 'owner'], [GH, 'owner'], [UPLOAD, 'owner']]);
const APP_ADMIN = user('user', [[APP, 'admin']]);
const PLAIN = user('user', [[APP, null]]);
const OTHER_OWNER = user('user', [[OTHER, 'owner']]);
const PLATFORM_ASSIGNED = user('platform_admin', [[APP, null]]);
const PLATFORM_UNASSIGNED = user('platform_admin');

async function call(who, method, path, body) {
  const headers = { 'X-API-Key': who.key };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(`${BASE}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) {}
  return { status: r.status, text, json };
}
const qs = (env, path) => `env=${encodeURIComponent(env)}&path=${encodeURIComponent(path)}`;
const MARK = 'VALUEMARK-ef-5e2b';
const auditRows = () => db.prepare('SELECT action, detail FROM audit_log').all();
const rowOf = (app, env, path) => db.prepare('SELECT * FROM app_env_files WHERE app_id = ? AND env = ? AND rel_path = ?').get(app.id, env, path);

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

test('owner, assigned platform admin: allowed on every route', async () => {
  for (const who of [OWNER, PLATFORM_ASSIGNED]) {
    const put = await call(who, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path: '.env.authz', content: 'A=1\n' });
    assert.ok([200, 201].includes(put.status), put.text);
    assert.equal((await call(who, 'GET', '/api/apps/ef-app/env-files')).status, 200);
    assert.equal((await call(who, 'GET', `/api/apps/ef-app/env-files/content?${qs('sandbox', '.env.authz')}`)).status, 200);
    assert.equal((await call(who, 'DELETE', `/api/apps/ef-app/env-files?${qs('sandbox', '.env.authz')}`)).status, 200);
  }
});

test('app admin, plain user, another app\'s owner, unassigned platform admin: 403 on every route, nothing changes', async () => {
  store.putStoredEnvFile(db, APP.id, 'sandbox', '.env.keep', `KEEP=${MARK}\n`);
  const before = rowOf(APP, 'sandbox', '.env.keep');
  for (const who of [APP_ADMIN, PLAIN, OTHER_OWNER, PLATFORM_UNASSIGNED]) {
    const rs = [
      await call(who, 'GET', '/api/apps/ef-app/env-files'),
      await call(who, 'GET', `/api/apps/ef-app/env-files/content?${qs('sandbox', '.env.keep')}`),
      await call(who, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path: '.env.keep', content: 'KEEP=changed\n' }),
      await call(who, 'DELETE', `/api/apps/ef-app/env-files?${qs('sandbox', '.env.keep')}`),
    ];
    for (const r of rs) {
      assert.equal(r.status, 403, `user ${who.id}: ${r.text}`);
      assert.equal(r.text.includes(MARK), false);
    }
  }
  assert.deepEqual(rowOf(APP, 'sandbox', '.env.keep'), before);
  store.deleteStoredEnvFile(db, APP.id, 'sandbox', '.env.keep');
});

test('not Crane-hosted (GitHub-backed managed, upload): 409 for the owner', async () => {
  for (const slug of ['ef-gh', 'ef-upload']) {
    assert.equal((await call(OWNER, 'GET', `/api/apps/${slug}/env-files`)).status, 409);
    assert.equal((await call(OWNER, 'PUT', `/api/apps/${slug}/env-files`, { env: 'sandbox', path: '.env', content: 'A=1' })).status, 409);
  }
  assert.equal(db.prepare('SELECT COUNT(*) n FROM app_env_files WHERE app_id IN (?, ?)').get(GH.id, UPLOAD.id).n, 0);
  assert.equal((await call(OWNER, 'GET', '/api/apps/no-such-app/env-files')).status, 404);
});

// ---------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------

test('create: 201, mode 0600, stored encrypted; list has metadata and no content; says next deploy', async () => {
  const logStart = logLines.length;
  const content = `API_KEY=${MARK}\nURL="https://api.example.com"\n`;
  const put = await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env: 'production', path: 'web/.env', content });
  assert.equal(put.status, 201, put.text);
  assert.equal(put.json.created, true);
  assert.equal(put.json.mode, '0600');
  assert.match(put.json.message, /next deploy/);
  assert.equal(put.text.includes(MARK), false);

  const row = rowOf(APP, 'production', 'web/.env');
  assert.equal(row.mode, 0o600);
  assert.equal(row.source, 'owner');
  assert.equal(row.content_encrypted.includes(MARK), false);
  assert.equal(row.content_encrypted.includes(Buffer.from(content).toString('base64').slice(0, 12)), false, 'stored as plain base64');
  assert.equal(Buffer.from(decrypt(row.content_encrypted), 'base64').toString('utf8'), content);

  const list = await call(OWNER, 'GET', '/api/apps/ef-app/env-files');
  assert.equal(list.status, 200);
  assert.equal(list.text.includes(MARK), false);
  const f = list.json.files.find((x) => x.path === 'web/.env');
  assert.deepEqual(Object.keys(f).sort(), ['bytes', 'env', 'mode', 'path', 'source', 'updated_at']);
  assert.equal(f.bytes, Buffer.byteLength(content));

  const audit = auditRows().filter((r) => r.action === 'env_file.replace');
  assert.equal(audit.length >= 1, true);
  assert.deepEqual(JSON.parse(audit.at(-1).detail), { env: 'production', path: 'web/.env', created: true });
  assert.equal(auditRows().some((r) => r.detail?.includes(MARK)), false, 'content in the audit log');
  assert.equal(logLines.slice(logStart).join('\n').includes(MARK), false, 'content in the server log');
});

test('replace: 200, keeps the stored mode, new content', async () => {
  store.storeEnvFiles(db, APP.id, 'sandbox', store.encryptEnvFiles([{ rel_path: '.env', mode: 0o640, bytes: 4, content: Buffer.from('A=1\n') }]));
  const put = await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path: '.env', content: 'A=2\n' });
  assert.equal(put.status, 200, put.text);
  assert.equal(put.json.created, false);
  assert.equal(put.json.mode, '0640');
  assert.equal(rowOf(APP, 'sandbox', '.env').mode, 0o640);
  assert.equal(store.readStoredEnvFile(db, APP.id, 'sandbox', '.env').content.toString(), 'A=2\n');
});

test('base64 upload round-trips exact bytes', async () => {
  const bytes = Buffer.from('# comment\r\nX="multi\nline"\n');
  const put = await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path: '.env.b64', content: bytes.toString('base64'), encoding: 'base64' });
  assert.equal(put.status, 201, put.text);
  assert.ok(store.readStoredEnvFile(db, APP.id, 'sandbox', '.env.b64').content.equals(bytes));
});

test('reveal: content returned, audited with path only, throttled with the env-var reveal budget', async () => {
  store.putStoredEnvFile(db, APP.id, 'sandbox', '.env.reveal', `R=${MARK}\n`);
  const u = user('user', [[APP, 'owner']]);
  const logStart = logLines.length;
  const r = await call(u, 'GET', `/api/apps/ef-app/env-files/content?${qs('sandbox', '.env.reveal')}`);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.content, `R=${MARK}\n`);
  const ev = db.prepare("SELECT detail FROM audit_log WHERE user_id = ? AND action = 'env_file.reveal'").all(u.id);
  assert.equal(ev.length, 1);
  assert.deepEqual(JSON.parse(ev[0].detail), { env: 'sandbox', path: '.env.reveal' });
  assert.equal(logLines.slice(logStart).join('\n').includes(MARK), false, 'content in the server log');
  assert.ok(logLines.slice(logStart).some((l) => /SECRET REVEAL ef-app\/sandbox stored \.env file/.test(l)));

  // 29 more env-var reveals by the same user fill the shared 30/10min budget.
  const ins = db.prepare("INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (?, ?, 'env-reveal', '{}')");
  for (let i = 0; i < 29; i++) ins.run(u.id, APP.id);
  const t = await call(u, 'GET', `/api/apps/ef-app/env-files/content?${qs('sandbox', '.env.reveal')}`);
  assert.equal(t.status, 429, t.text);
  assert.equal(t.text.includes(MARK), false);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE user_id = ? AND action = 'env_file.reveal'").get(u.id).n, 1);

  assert.equal((await call(OWNER, 'GET', `/api/apps/ef-app/env-files/content?${qs('sandbox', '.env.nope')}`)).status, 404);
});

test('env-var reveal route counts .env file reveals against the same budget', async () => {
  const envVars = (await import('../server/routes/envVars.js')).default;
  const a2 = express();
  a2.use(express.json());
  a2.use('/api/apps', envVars);
  a2.use(errorHandler);
  const s2 = await new Promise((r) => { const s = a2.listen(0, '127.0.0.1', () => r(s)); });
  try {
    const u = user('user', [[APP, 'owner']]);
    db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'sandbox', 'EF_K', ?) ON CONFLICT DO NOTHING").run(APP.id, encrypt('v'));
    const ins = db.prepare("INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (?, ?, 'env_file.reveal', '{}')");
    for (let i = 0; i < 30; i++) ins.run(u.id, APP.id);
    const r = await fetch(`http://127.0.0.1:${s2.address().port}/api/apps/ef-app/env/sandbox?reveal=true`, { headers: { 'X-API-Key': u.key } });
    assert.equal(r.status, 429, await r.text());
  } finally {
    s2.closeAllConnections?.();
    s2.close();
  }
});

test('path rules: escape, absolute, empty segment, .git, not a .env name, too long -> 400, nothing stored', async () => {
  const before = db.prepare('SELECT COUNT(*) n FROM app_env_files').get().n;
  for (const path of ['../.env', 'a/../.env', '/etc/.env', 'a//.env', './.env', '.git/.env', 'sub/.GIT/.env', 'config.txt', 'env', 'a\\.env', `${'a/'.repeat(520)}.env`, '', null]) {
    const r = await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path, content: 'A=1\n' });
    assert.equal(r.status, 400, `${JSON.stringify(path)}: ${r.text}`);
    const d = await call(OWNER, 'DELETE', `/api/apps/ef-app/env-files?${qs('sandbox', path ?? '')}`);
    assert.equal(d.status, 400, `${JSON.stringify(path)} delete: ${d.text}`);
    const g = await call(OWNER, 'GET', `/api/apps/ef-app/env-files/content?${qs('sandbox', path ?? '')}`);
    assert.equal(g.status, 400, `${JSON.stringify(path)} reveal: ${g.text}`);
  }
  for (const env of ['staging', '', 'PRODUCTION']) {
    assert.equal((await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env, path: '.env', content: 'A=1\n' })).status, 400);
  }
  assert.equal(db.prepare('SELECT COUNT(*) n FROM app_env_files').get().n, before);
});

test('content rules: 1 MiB cap (413), invalid UTF-8, parse error with line number and no echo', async () => {
  const big = `A=${'x'.repeat(1024 * 1024)}\n`;
  const r1 = await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path: '.env.big', content: big });
  assert.equal(r1.status, 413, r1.text.slice(0, 200));
  const exact = `A=${'x'.repeat(1024 * 1024 - 3)}\n`;
  assert.equal(Buffer.byteLength(exact), 1024 * 1024);
  assert.equal((await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path: '.env.big', content: exact })).status, 201);
  store.deleteStoredEnvFile(db, APP.id, 'sandbox', '.env.big');

  const r2 = await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path: '.env.bad', content: Buffer.from([0x41, 0x3d, 0xff, 0x0a]).toString('base64'), encoding: 'base64' });
  assert.equal(r2.status, 400, r2.text);
  assert.match(r2.json.error.message, /UTF-8/);
  const r2b = await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path: '.env.bad', content: 'A=\ud800\n' });
  assert.equal(r2b.status, 400, r2b.text);

  const r3 = await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path: '.env.bad', content: `GOOD=1\n\nSECRET_${MARK.replace(/-/g, '_')} ${MARK}\n` });
  assert.equal(r3.status, 400, r3.text);
  assert.match(r3.json.error.message, /line 3: not a KEY=VALUE line/);
  assert.equal(r3.text.includes(MARK), false);
  assert.equal(r3.text.includes('VALUEMARK'), false);
  const r4 = await call(OWNER, 'PUT', '/api/apps/ef-app/env-files', { env: 'sandbox', path: '.env.bad', content: `X="${MARK}\n` });
  assert.equal(r4.status, 400);
  assert.match(r4.json.error.message, /line 1: unterminated quoted value/);
  assert.equal(r4.text.includes('X'), false, 'key name echoed');

  assert.equal(rowOf(APP, 'sandbox', '.env.bad'), undefined);
});

test('delete: 200 then 404; audited with path only', async () => {
  store.putStoredEnvFile(db, APP.id, 'sandbox', 'api/.env.local', 'Z=1\n');
  const d = await call(OWNER, 'DELETE', `/api/apps/ef-app/env-files?${qs('sandbox', 'api/.env.local')}`);
  assert.equal(d.status, 200, d.text);
  assert.match(d.json.message, /next deploy/);
  assert.equal(rowOf(APP, 'sandbox', 'api/.env.local'), undefined);
  assert.equal((await call(OWNER, 'DELETE', `/api/apps/ef-app/env-files?${qs('sandbox', 'api/.env.local')}`)).status, 404);
  const ev = auditRows().filter((r) => r.action === 'env_file.delete');
  assert.deepEqual(JSON.parse(ev.at(-1).detail), { env: 'sandbox', path: 'api/.env.local' });
});

// ---------------------------------------------------------------------------
// Effect on deploy
// ---------------------------------------------------------------------------

async function deploySandbox(app) {
  const count = () => Number(existsSync(join(CAPTURE, 'count')) ? readFileSync(join(CAPTURE, 'count'), 'utf8') : 0);
  const before = count();
  const depId = db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'sandbox', 'pending')").run(app.id).lastInsertRowid;
  await deployApp(depId, appRow(app.slug), 'sandbox', getPortsForSlot(appRow(app.slug).slot)).catch(() => {});
  const log = db.prepare('SELECT log FROM deployments WHERE id = ?').get(depId).log || '';
  return { log, ctx: count() > before ? join(CAPTURE, String(count())) : null };
}

test('the next deploy writes the replaced content; after delete it is no longer written', async () => {
  const app = await craneApp('ef-deploy');
  const owner = user('user', [[app, 'owner']]);
  const pushed = await lg.pushFilesToManagedRepo('ef-deploy', [
    { path: 'package.json', content: JSON.stringify({ name: 'ef-deploy', version: '1.0.0', scripts: { start: 'node server.js' } }) },
    { path: 'package-lock.json', content: JSON.stringify({ name: 'ef-deploy', lockfileVersion: 3, packages: {} }) },
    { path: 'server.js', content: 'console.log(1)\n' },
  ], { branch: 'main' });
  db.prepare('UPDATE apps SET last_managed_push_sha = ? WHERE id = ?').run(pushed.commit.sha, app.id);

  store.putStoredEnvFile(db, app.id, 'sandbox', 'web/.env', 'OLD=1\n');
  const put = await call(owner, 'PUT', '/api/apps/ef-deploy/env-files', { env: 'sandbox', path: 'web/.env', content: `NEW=${MARK}\n` });
  assert.equal(put.status, 200, put.text);

  const d1 = await deploySandbox(app);
  assert.ok(d1.ctx, `no build context captured:\n${d1.log}`);
  assert.equal(readFileSync(join(d1.ctx, 'web/.env'), 'utf8'), `NEW=${MARK}\n`);
  assert.equal((statSync(join(d1.ctx, 'web/.env')).mode & 0o777), 0o600);
  assert.equal(d1.log.includes(MARK), false, 'content in the deploy log');

  const del = await call(owner, 'DELETE', `/api/apps/ef-deploy/env-files?${qs('sandbox', 'web/.env')}`);
  assert.equal(del.status, 200, del.text);
  const d2 = await deploySandbox(app);
  assert.ok(d2.ctx, `no build context captured:\n${d2.log}`);
  assert.equal(existsSync(join(d2.ctx, 'web/.env')), false, 'deleted stored file still written');
});
