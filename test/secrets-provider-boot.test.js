import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'child_process';
import { createServer } from 'net';
import { writeFileSync, readFileSync, existsSync, rmSync, readdirSync } from 'fs';
import { join } from 'path';
import Database from 'better-sqlite3';
import { createHash } from 'crypto';
import { fakeSecretsManager, sandboxTree, SANDBOX_NODE_FLAGS, cleanEnv, K_A, K_B } from './secrets-provider-fake.mjs';

// The real server/index.js, from a sandbox directory with its own .env, so
// what is proven is a boot from the .env an operator would have. Plus backup,
// snapshot, restore and drill run the same way, because configBackup finds
// .env next to its own code.

const sm = fakeSecretsManager();
const trees = [];
const children = [];
const ANTHROPIC = 'sk-ant-sensitive-boot-value';
const ADMIN_KEY = 'dhk_test_admin_key_for_secrets_boot';

const tree = (envText) => {
  const dir = sandboxTree();
  trees.push(dir);
  if (envText != null) writeFileSync(join(dir, '.env'), envText);
  return dir;
};
const provider = (id = 'plat') => `APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=${id}\n`;

before(async () => { await sm.start(); });
beforeEach(() => {
  sm.secrets.clear();
  sm.calls.length = 0;
  for (const k of Object.keys(sm.faults)) delete sm.faults[k];
});
after(() => {
  for (const c of children) { try { c.kill('SIGKILL'); } catch (_) {} }
  sm.stop();
  for (const d of trees) rmSync(d, { recursive: true, force: true });
});

const freePort = () => new Promise((res) => {
  const s = createServer();
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); });
});

function startServer(dir, { env = {}, nodeFlags = [] } = {}) {
  return freePort().then((port) => {
    const c = spawn(process.execPath, [...SANDBOX_NODE_FLAGS, ...nodeFlags, 'server/index.js'], {
      cwd: dir,
      env: cleanEnv({ ...sm.awsEnv(), DATA_DIR: join(dir, 'data'), PORT: String(port), HOST: '127.0.0.1', CRANE_DOMAIN: 'crane.example.com', ...env }),
    });
    children.push(c);
    const out = { all: '', code: undefined, port, child: c, base: `http://127.0.0.1:${port}` };
    c.stdout.on('data', (d) => { out.all += d; });
    c.stderr.on('data', (d) => { out.all += d; });
    out.exited = new Promise((res) => c.on('exit', (code) => { out.code = code; res(code); }));
    return out;
  });
}

async function waitUp(s) {
  for (let i = 0; i < 240; i++) {
    if (s.code !== undefined) throw new Error(`server exited ${s.code}: ${s.all.slice(-2000)}`);
    try { const r = await fetch(`${s.base}/api/info`); if (r.ok) return; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`server did not come up: ${s.all.slice(-2000)}`);
}

async function stop(s) {
  s.child.kill('SIGTERM');
  const t = setTimeout(() => s.child.kill('SIGKILL'), 8000);
  await s.exited;
  clearTimeout(t);
}

async function refusesToBoot(dir, opts) {
  const s = await startServer(dir, opts);
  const code = await Promise.race([s.exited, new Promise((r) => setTimeout(() => r('timeout'), 60000))]);
  assert.equal(code, 1, s.all.slice(-1500));
  assert.match(s.all, /AppCrane cannot start: the platform secret could not be loaded/);
  assert.ok(!existsSync(join(dir, 'data', 'deployhub.db')), 'stopped before the database was opened');
  assert.ok(!s.all.includes(K_A) && !s.all.includes(K_B) && !s.all.includes(ANTHROPIC), 'no value in the output');
  return s;
}

// ── boot ───────────────────────────────────────────────────────────────────

test('fetch failure: exit 1, even with a working key in .env', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  sm.faults.GetSecretValue = () => sm.err('AccessDeniedException', 'not authorized');
  const s = await refusesToBoot(tree(`${provider()}ENCRYPTION_KEY=${K_A}\n`));
  assert.match(s.all, /AccessDeniedException/);
});

test('endpoint unreachable: exit 1, not a hang', async () => {
  await refusesToBoot(tree(provider()), { env: { AWS_ENDPOINT_URL_SECRETS_MANAGER: 'http://127.0.0.1:1' } });
});

test('endpoint accepts and never answers: exit 1, not a hang', async () => {
  const blackhole = createServer(() => {});
  await new Promise((r) => blackhole.listen(0, '127.0.0.1', r));
  try {
    const s = await refusesToBoot(tree(provider()), { env: { AWS_ENDPOINT_URL_SECRETS_MANAGER: `http://127.0.0.1:${blackhole.address().port}` } });
    assert.match(s.all, /Timeout|timed out|exceeded/i);
  } finally {
    blackhole.close();
  }
});

test('denied key name in the secret: exit 1', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A, NODE_OPTIONS: '--require=/tmp/x' }));
  const s = await refusesToBoot(tree(provider()));
  assert.match(s.all, /NODE_OPTIONS/);
  assert.doesNotMatch(s.all, /--require=\/tmp\/x/);
});

test('a different key in .env: exit 1', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const s = await refusesToBoot(tree(`${provider()}ENCRYPTION_KEY=${K_B}\n`));
  assert.match(s.all, /ENCRYPTION_KEY differ/);
});

const SDK_SPY = (file) => `data:text/javascript,${encodeURIComponent(`
import { registerHooks } from 'node:module';
import { appendFileSync } from 'node:fs';
registerHooks({ resolve(s, c, n) { if (s.includes('@aws-sdk')) appendFileSync(${JSON.stringify(file)}, s + '\\n'); return n(s, c); } });
`)}`;

test('feature off: a real boot from .env, the SDK never resolved', async () => {
  const dir = tree(`ENCRYPTION_KEY=${K_A}\n`);
  const spy = join(dir, 'sdk-resolves.txt');
  const s = await startServer(dir, { nodeFlags: ['--import', SDK_SPY(spy)] });
  await waitUp(s);
  await stop(s);
  assert.equal(existsSync(spy), false, 'the SDK was resolved with the feature off');
  assert.equal(sm.calls.length, 0);
  assert.ok(!s.all.includes(K_A));
});

function addAdmin(dir) {
  const db = new Database(join(dir, 'data', 'deployhub.db'));
  db.prepare("INSERT INTO users (name, email, role, api_key_hash) VALUES ('adm', 'adm@t.test', 'platform_admin', ?)").run(createHash('sha256').update(ADMIN_KEY).digest('hex'));
  db.close();
}

const api = (s, method, path, body) => fetch(`${s.base}${path}`, {
  method, headers: { 'X-API-Key': ADMIN_KEY, 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}),
});

test('migrate, then boot from the secret: old data still decrypts; the status route uses the provider; the Anthropic key goes to the database', async () => {
  // A host on .env: first boot creates the database, a value is stored under the key.
  const dir = tree(`ENCRYPTION_KEY=${K_A}\nANTHROPIC_API_KEY=${ANTHROPIC}\n`);
  const first = await startServer(dir);
  await waitUp(first);
  await stop(first);
  addAdmin(dir);
  const { encrypt } = await import('../server/services/encryption.js');
  const db = new Database(join(dir, 'data', 'deployhub.db'));
  const appId = Number(db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('m', 'mig-app', 77)").run().lastInsertRowid);
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'sandbox', 'K', ?)").run(appId, encrypt('stored-plain', K_A));
  const adminId = db.prepare('SELECT id FROM users WHERE api_key_hash = ?').get(createHash('sha256').update(ADMIN_KEY).digest('hex')).id;
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'admin')").run(appId, adminId);
  db.close();

  // The real CLI, in the sandbox. PATH without docker: IMDS is not measured.
  const port = await freePort();
  // Not execFileSync: the fake lives in this process and would never answer.
  const cli = spawn(process.execPath, [...SANDBOX_NODE_FLAGS, 'cli/index.js', 'secrets', 'migrate', '--secret-id', 'plat', '--region', 'us-east-1', '--port', String(port)], {
    cwd: dir, env: cleanEnv({ ...sm.awsEnv(), DATA_DIR: join(dir, 'data'), PATH: '/nonexistent' }),
  });
  let cliOut = '';
  cli.stdout.on('data', (d) => { cliOut += d; });
  cli.stderr.on('data', (d) => { cliOut += d; });
  assert.equal(await new Promise((r) => cli.on('exit', r)), 0, cliOut);
  assert.ok(!cliOut.includes(K_A) && !cliOut.includes(ANTHROPIC));
  assert.ok(!readFileSync(join(dir, '.env'), 'utf8').includes(K_A));
  assert.ok(!readFileSync(join(dir, '.env'), 'utf8').includes(ANTHROPIC), 'the first boot already moved ANTHROPIC_API_KEY into the database');

  const s = await startServer(dir);
  await waitUp(s);
  try {
    const rv = await api(s, 'POST', '/api/apps/mig-app/env/sandbox/K/reveal');
    assert.equal(rv.status, 200, await rv.clone().text());
    assert.ok(JSON.stringify(await rv.json()).includes('stored-plain'), 'old data decrypts with the key from the secret');

    const st = await api(s, 'GET', '/api/settings/secrets-provider');
    assert.equal(st.status, 200, 'the status route is mounted');
    const stBody = await st.json();
    assert.equal(stBody.active, true);
    assert.equal(stBody.platform_secret_configured, true);
    assert.equal((await fetch(`${s.base}/api/settings/secrets-provider`)).status, 401, 'and needs auth');

    // The boot moved the .env key into the database and dropped the line.
    const g1 = await (await api(s, 'GET', '/api/appstudio/anthropic-key')).json();
    assert.deepEqual([g1.configured, g1.source, g1.suffix], [true, 'database', ANTHROPIC.slice(-4)]);
    const envAfter = readFileSync(join(dir, '.env'), 'utf8');
    assert.ok(!envAfter.includes(ANTHROPIC) && !envAfter.includes(K_A));

    // A new key goes to the database: the platform secret and .env stay as they are.
    const beforeSecret = sm.current('plat');
    const good = await api(s, 'PUT', '/api/appstudio/anthropic-key', { key: 'sk-new-value-2' });
    assert.equal(good.status, 200);
    assert.equal(sm.current('plat'), beforeSecret, 'the platform secret is not written');
    assert.deepEqual(JSON.parse(sm.current('plat')), { ENCRYPTION_KEY: K_A });
    assert.equal(readFileSync(join(dir, '.env'), 'utf8'), envAfter, '.env is not written');
    const g3 = await (await api(s, 'GET', '/api/appstudio/anthropic-key')).json();
    assert.deepEqual([g3.source, g3.suffix], ['database', 'ue-2']);
  } finally {
    await stop(s);
  }
  assert.ok(!s.all.includes(K_A) && !s.all.includes(ANTHROPIC) && !s.all.includes('sk-new-value'), 'no value in the server log');
});

test('without a provider the Anthropic route stores the key in the database, never in .env', async () => {
  const dir = tree(`ENCRYPTION_KEY=${K_A}\n`);
  const first = await startServer(dir);
  await waitUp(first);
  await stop(first);
  addAdmin(dir);
  const s = await startServer(dir);
  await waitUp(s);
  try {
    assert.equal((await api(s, 'PUT', '/api/appstudio/anthropic-key', { key: 'sk-env-value' })).status, 200);
    assert.doesNotMatch(readFileSync(join(dir, '.env'), 'utf8'), /ANTHROPIC_API_KEY/);
    assert.equal((await (await api(s, 'GET', '/api/appstudio/anthropic-key')).json()).source, 'database');
  } finally {
    await stop(s);
  }
  assert.equal(sm.calls.length, 0);
});

// ── backup, snapshot, restore, drill ───────────────────────────────────────

// Runs in the sandbox: the same load as boot, then `steps`. Prints JSON.
function inTree(dir, steps, env = {}) {
  const code = `
import { readFileSync, existsSync } from 'fs';
for (const line of (existsSync('.env') ? readFileSync('.env', 'utf8') : '').split('\\n')) {
  const t = line.trim(); if (!t || t.startsWith('#') || !t.includes('=')) continue;
  const k = t.slice(0, t.indexOf('=')).trim(); if (!process.env[k]) process.env[k] = t.slice(t.indexOf('=') + 1).trim();
}
const { loadPlatformSecrets } = await import('./server/services/secretsProvider/index.js');
await loadPlatformSecrets({ log: { warn() {} } });
const { initDb } = await import('./server/db.js');
const db = initDb(process.env.DATA_DIR);
const { encrypt, decrypt } = await import('./server/services/encryption.js');
const backup = await import('./server/services/configBackup.js');
const snapshot = await import('./server/services/updateSnapshot.js');
const drill = await import('./server/services/restoreDrillChecks.js');
const out = await (async () => { ${steps} })();
console.log('RESULT ' + JSON.stringify(out));
process.exit(0);
`;
  // A file, not -e: the backup's worker thread inherits execArgv, and --input-type would break its eval.
  writeFileSync(join(dir, 'runner.mjs'), code);
  return new Promise((res) => {
    const c = spawn(process.execPath, [...SANDBOX_NODE_FLAGS, 'runner.mjs'], {
      cwd: dir, env: cleanEnv({ ...sm.awsEnv(), DATA_DIR: join(dir, 'data'), LOG_LEVEL: 'error', APPCRANE_NO_RESTART_AFTER_IMPORT: '1', ...env }),
    });
    let all = '';
    c.stdout.on('data', (d) => { all += d; });
    c.stderr.on('data', (d) => { all += d; });
    c.on('close', (code2) => {
      const m = /^RESULT (.*)$/m.exec(all);
      res({ code: code2, all, result: m ? JSON.parse(m[1]) : null });
    });
  });
}

const SEED = `
  const a = db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('b', 'bak-app', 88)").run().lastInsertRowid;
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'sandbox', 'K', ?)").run(a, encrypt('stored-plain'));
`;
const EXPORT = `const ex = await backup.exportDataArchive({ contents: 'platform' });`;

test('migrated host: the archive has no key, its manifest says so; a drill passes; a restore over the same host boots', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A, ANTHROPIC_API_KEY: ANTHROPIC }));
  const dir = tree(`PORT=1\n${provider()}`);
  const r = await inTree(dir, `${SEED}${EXPORT}
    const { mkdirSync } = await import('fs');
    const { execFileSync } = await import('child_process');
    mkdirSync('scratch');
    execFileSync('tar', ['-xzf', ex.path, '-C', 'scratch']);
    const v = await drill.verifyDataTree('scratch', { liveDb: db, tolerancePct: 10, pgRestoreList: async () => ({ available: false }) });
    const imp = await backup.importDataArchive(ex.path);
    return { path: ex.path, manifest: ex.manifest, checks: v.checks, imported: { envRestored: imp.envRestored, secrets: imp.secrets } };
  `);
  assert.equal(r.code, 0, r.all);
  const { manifest, checks, imported, path } = r.result;
  assert.equal(manifest.secrets.provider, 'aws-secrets-manager');
  assert.equal(manifest.secrets.secret_id, 'plat');
  assert.equal(manifest.secrets.encryption_key_in_provider, true);
  assert.equal(manifest.secrets.restorable_from_this_copy_alone, false);
  assert.ok(manifest.secrets.version_id);
  assert.deepEqual(manifest.secrets.keys_in_provider, ['ANTHROPIC_API_KEY', 'ENCRYPTION_KEY']);
  assert.match(manifest.secrets.note, /alone cannot restore/);

  const envInArchive = execFileSync('tar', ['-xzOf', path, '.env']).toString();
  assert.ok(!envInArchive.includes(K_A) && !envInArchive.includes(ANTHROPIC));
  const manifestText = execFileSync('tar', ['-xzOf', path, 'appcrane-backup.json']).toString();
  assert.ok(!manifestText.includes(K_A) && !manifestText.includes(ANTHROPIC));

  const byId = Object.fromEntries(checks.map((c) => [c.id, c]));
  assert.equal(byId.encryption_key.status, 'pass', JSON.stringify(byId.encryption_key));
  assert.match(byId.encryption_key.detail, /Secrets Manager/);
  assert.equal(byId.secrets_decrypt.status, 'pass', JSON.stringify(byId.secrets_decrypt));

  assert.equal(imported.envRestored, true);
  assert.equal(imported.secrets.secret_id, 'plat');
  assert.ok(!readFileSync(join(dir, '.env'), 'utf8').includes(K_A));
  const s = await startServer(dir);
  await waitUp(s);
  await stop(s);
});

test('a drill on a host with another secret warns rather than passes the key check', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const r = await inTree(tree(provider()), `${SEED}${EXPORT}
    const { mkdirSync } = await import('fs');
    const { execFileSync } = await import('child_process');
    mkdirSync('scratch');
    execFileSync('tar', ['-xzf', ex.path, '-C', 'scratch']);
    process.env.APPCRANE_SECRETS_ID = 'another';
    const v = await drill.verifyDataTree('scratch', { liveDb: db, tolerancePct: 10, pgRestoreList: async () => ({ available: false }) });
    return v.checks.find((c) => c.id === 'encryption_key');
  `);
  assert.equal(r.code, 0, r.all);
  assert.equal(r.result.status, 'warn');
});

test('no provider: the manifest has no secrets entry and the archive .env holds the key, as before', async () => {
  const r = await inTree(tree(`ENCRYPTION_KEY=${K_A}\n`), `${SEED}${EXPORT}
    const { mkdirSync } = await import('fs');
    const { execFileSync } = await import('child_process');
    mkdirSync('scratch');
    execFileSync('tar', ['-xzf', ex.path, '-C', 'scratch']);
    const v = await drill.verifyDataTree('scratch', { liveDb: db, tolerancePct: 10, pgRestoreList: async () => ({ available: false }) });
    const snap = snapshot.createPreUpdateSnapshot(process.cwd(), {}, db);
    const { readFileSync } = await import('fs');
    return { path: ex.path, hasSecrets: 'secrets' in ex.manifest, key: v.checks.find((c) => c.id === 'encryption_key'), snapHasSecrets: 'secrets' in JSON.parse(readFileSync(snap.dir + '/manifest.json', 'utf8')) };
  `);
  assert.equal(r.code, 0, r.all);
  assert.equal(r.result.hasSecrets, false);
  assert.equal(r.result.snapHasSecrets, false);
  assert.equal(r.result.key.status, 'pass');
  assert.equal(r.result.key.detail, 'matches the live key');
  assert.ok(execFileSync('tar', ['-xzOf', r.result.path, '.env']).toString().includes(K_A));
});

test('update snapshot on a migrated host: env.backup holds no key, the manifest records where it lives', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const dir = tree(`PORT=1\n${provider()}`);
  const r = await inTree(dir, 'return snapshot.createPreUpdateSnapshot(process.cwd(), { from: "1", to: "2" }, db);');
  assert.equal(r.code, 0, r.all);
  assert.equal(r.result.ok, true, r.all);
  const env = readFileSync(join(r.result.dir, 'env.backup'), 'utf8');
  assert.ok(!env.includes(K_A));
  const manifest = JSON.parse(readFileSync(join(r.result.dir, 'manifest.json'), 'utf8'));
  assert.equal(manifest.secrets.encryption_key_in_provider, true);
  assert.equal(manifest.secrets.secret_id, 'plat');
  assert.ok(!JSON.stringify(manifest).includes(K_A));
});

// Makes an archive on a plain .env host holding `key`.
async function preMigrationArchive(key) {
  const dir = tree(`ENCRYPTION_KEY=${key}\nANTHROPIC_API_KEY=sk-old-in-archive\nFROM_ARCHIVE=1\n`);
  const r = await inTree(dir, `${SEED}${EXPORT} return { path: ex.path };`);
  assert.equal(r.code, 0, r.all);
  return r.result.path;
}

test('pre-migration archive, same key, over a migrated host: restored, still migrated, and it boots', async () => {
  const archive = await preMigrationArchive(K_A);
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A, ANTHROPIC_API_KEY: ANTHROPIC }));
  const dir = tree(`PORT=1\n${provider()}`);
  const r = await inTree(dir, `const imp = await backup.importDataArchive(${JSON.stringify(archive)}); return { envRestored: imp.envRestored, secrets: imp.secrets };`);
  assert.equal(r.code, 0, r.all);
  assert.equal(r.result.envRestored, true);
  assert.deepEqual(r.result.secrets.env_lines_dropped, ['ENCRYPTION_KEY', 'ANTHROPIC_API_KEY']);
  const env = readFileSync(join(dir, '.env'), 'utf8');
  assert.ok(!env.includes(K_A) && !env.includes('sk-old-in-archive'), 'no key came back');
  assert.match(env, /^FROM_ARCHIVE=1$/m);
  assert.match(env, /^APPCRANE_SECRETS_ID=plat$/m);
  const s = await startServer(dir);
  await waitUp(s);
  await stop(s);
});

test('pre-migration archive under another key, over a migrated host: refused, nothing changed', async () => {
  const archive = await preMigrationArchive(K_B);
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const dir = tree(provider());
  const r = await inTree(dir, `
    const { createHash } = await import('crypto');
    const { readFileSync } = await import('fs');
    db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('keep', 'keep-app', 99)").run();
    const err = await backup.importDataArchive(${JSON.stringify(archive)}).then(() => null, (e) => e.message);
    return { err, apps: db.prepare("SELECT slug FROM apps").all() };
  `);
  assert.equal(r.code, 0, r.all);
  assert.match(r.result.err, /different ENCRYPTION_KEY/);
  assert.ok(!r.result.err.includes(K_A) && !r.result.err.includes(K_B));
  assert.equal(readFileSync(join(dir, '.env'), 'utf8'), provider());
  assert.ok(!readdirSync(join(dir, 'data')).some((n) => n.startsWith('pre-import-')), 'stopped before the point of no return');
  const db = new Database(join(dir, 'data', 'deployhub.db'), { readonly: true });
  assert.ok(db.prepare("SELECT 1 FROM apps WHERE slug = 'keep-app'").get(), 'the live database was not replaced');
  db.close();
});

test('archive from a migrated host over a plain host: the .env comes across, and the boot needs the secret', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const src = tree(provider());
  const a = await inTree(src, `${SEED}${EXPORT} return { path: ex.path };`);
  assert.equal(a.code, 0, a.all);
  const dir = tree(`ENCRYPTION_KEY=${K_B}\n`);
  const r = await inTree(dir, `const imp = await backup.importDataArchive(${JSON.stringify(a.result.path)}); return { envRestored: imp.envRestored, secrets: imp.secrets };`);
  assert.equal(r.code, 0, r.all);
  assert.equal(r.result.envRestored, true);
  assert.match(r.result.secrets.note, /alone cannot restore/);
  assert.equal(readFileSync(join(dir, '.env'), 'utf8'), provider());
  sm.faults.GetSecretValue = () => sm.err('AccessDeniedException', 'this host has no access');
  const s = await startServer(dir);
  assert.equal(await s.exited, 1, 'the archive alone does not get it running');
  assert.match(s.all, /AccessDeniedException/);
});
