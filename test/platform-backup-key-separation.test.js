import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'child_process';
import { writeFileSync, readFileSync, existsSync, rmSync, readdirSync, mkdtempSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { createHash, randomBytes } from 'crypto';
import Database from 'better-sqlite3';
import { sandboxTree, SANDBOX_NODE_FLAGS, cleanEnv } from './secrets-provider-fake.mjs';

// Key separation for platform backups (v2.145.0), with real tar archives
// written and restored by the real code in a sandbox checkout that has its own
// .env (configBackup finds .env next to its own code). Each "host" is a
// separate sandbox; a restart is a fresh process that loads the restored .env.

const K_A = randomBytes(32).toString('hex');
const K_B = randomBytes(32).toString('hex');
const K_C = randomBytes(32).toString('hex');
const K_OLD = randomBytes(32).toString('hex');
const fp = (k) => createHash('sha256').update(`sha256-appcrane-encryption-key-v1:${k}`).digest('hex');

const trees = [];
const scratch = [];
after(() => { for (const d of [...trees, ...scratch]) rmSync(d, { recursive: true, force: true }); });

const host = (envText) => {
  const dir = sandboxTree();
  trees.push(dir);
  writeFileSync(join(dir, '.env'), envText);
  return dir;
};

function run(dir, steps) {
  const code = `
import { readFileSync, existsSync } from 'fs';
for (const line of (existsSync('.env') ? readFileSync('.env', 'utf8') : '').split('\\n')) {
  const t = line.trim(); if (!t || t.startsWith('#') || !t.includes('=')) continue;
  const k = t.slice(0, t.indexOf('=')).trim(); if (!process.env[k]) process.env[k] = t.slice(t.indexOf('=') + 1).trim();
}
const { initDb } = await import('./server/db.js');
const db = initDb(process.env.DATA_DIR);
const { encrypt, decrypt } = await import('./server/services/encryption.js');
const backup = await import('./server/services/configBackup.js');
const local = await import('./server/services/localBackup.js');
const drill = await import('./server/services/restoreDrillChecks.js');
const out = await (async () => { ${steps} })();
console.log('RESULT ' + JSON.stringify(out));
process.exit(0);
`;
  writeFileSync(join(dir, 'runner.mjs'), code);
  return new Promise((res) => {
    const c = spawn(process.execPath, [...SANDBOX_NODE_FLAGS, 'runner.mjs'], {
      cwd: dir, env: cleanEnv({ DATA_DIR: join(dir, 'data'), LOG_LEVEL: 'error', APPCRANE_NO_RESTART_AFTER_IMPORT: '1', CRANE_DOMAIN: 'crane.t.test' }),
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
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'production', 'K', ?)").run(a, encrypt('stored-plain'));
`;
const READ_BACK = `
  const row = db.prepare("SELECT e.value_encrypted v FROM env_vars e JOIN apps a ON a.id = e.app_id WHERE a.slug = 'bak-app'").get();
  let plain = null; try { plain = row ? decrypt(row.v) : null; } catch (e) { plain = 'DECRYPT FAILED: ' + e.message; }
  return { plain, later: !!db.prepare("SELECT 1 FROM apps WHERE slug = 'later-app'").get() };
`;

/** Every byte of every file in the archive, searched for each key in hex (both cases) and raw. */
function keyBytesIn(archive, keys) {
  const dir = mkdtempSync(join(tmpdir(), 'crane-keyscan-'));
  scratch.push(dir);
  execFileSync('tar', ['-xzf', archive, '-C', dir]);
  const hits = [];
  const walk = (d) => {
    for (const n of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, n.name);
      if (n.isDirectory()) { walk(p); continue; }
      const buf = readFileSync(p);
      for (const k of keys) {
        for (const needle of [Buffer.from(k), Buffer.from(k.toUpperCase()), Buffer.from(k, 'hex')]) {
          if (buf.includes(needle)) hits.push(`${p.slice(dir.length + 1)}: ${k.slice(0, 6)}`);
        }
      }
    }
  };
  walk(dir);
  return { hits, dir };
}

async function nightlyArchive(dir) {
  const r = await run(dir, `${SEED} const b = await local.runLocalBackup(); return { path: b.path };`);
  assert.equal(r.code, 0, r.all);
  return r.result.path;
}

test('the nightly platform archive holds no key bytes, keeps the rest of .env, and names the key by fingerprint', async () => {
  const dir = host(`ENCRYPTION_KEY=${K_A}\nOTHER_SETTING=1\nOLD_ENCRYPTION_KEY=${K_OLD}\nCOPY_OF_KEY="${K_A.toUpperCase()}"\n`);
  const archive = await nightlyArchive(dir);
  assert.match(archive, /appcrane-platform-.*\.tar\.gz$/);
  const { hits, dir: ex } = keyBytesIn(archive, [K_A, K_OLD]);
  assert.deepEqual(hits, [], 'no file in the archive may hold a key');
  const env = readFileSync(join(ex, '.env'), 'utf8');
  assert.match(env, /^OTHER_SETTING=1$/m, 'the rest of .env is kept');
  const manifest = JSON.parse(readFileSync(join(ex, 'appcrane-backup.json'), 'utf8'));
  assert.equal(manifest.encryption_key.in_archive, false);
  assert.equal(manifest.encryption_key.fingerprint, fp(K_A));
  assert.deepEqual(manifest.encryption_key.removed_from_env.sort(), ['COPY_OF_KEY', 'ENCRYPTION_KEY', 'OLD_ENCRYPTION_KEY']);
  assert.ok(existsSync(join(ex, 'deployhub.db')));

  // A restore drill of a key-separated archive passes on the host that holds its key.
  const d = await run(dir, `
    const v = await drill.verifyDataTree(${JSON.stringify(ex)}, { liveDb: db, tolerancePct: 50, pgRestoreList: async () => ({ available: false }) });
    return v.checks;`);
  assert.equal(d.code, 0, d.all);
  const byId = Object.fromEntries(d.result.map((c) => [c.id, c]));
  assert.equal(byId.encryption_key.status, 'pass', JSON.stringify(byId.encryption_key));
  assert.equal(byId.secrets_decrypt.status, 'pass', JSON.stringify(byId.secrets_decrypt));
});

test('restore on the same host takes its key: the .env keeps the key line and env vars decrypt after a restart', async () => {
  const dir = host(`ENCRYPTION_KEY=${K_A}\nOTHER_SETTING=1\n`);
  const archive = await nightlyArchive(dir);
  const r = await run(dir, `
    db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('l', 'later-app', 77)").run();
    const imp = await backup.importDataArchive(${JSON.stringify(archive)});
    return imp.encryptionKey;`);
  assert.equal(r.code, 0, r.all);
  assert.deepEqual(r.result, { in_archive: false, source: 'host', fingerprint: fp(K_A).slice(0, 16), written_to_env: true });
  const env = readFileSync(join(dir, '.env'), 'utf8');
  assert.match(env, new RegExp(`^ENCRYPTION_KEY=${K_A}$`, 'm'));
  assert.match(env, /^OTHER_SETTING=1$/m);
  const after = await run(dir, READ_BACK);
  assert.equal(after.code, 0, after.all);
  assert.deepEqual(after.result, { plain: 'stored-plain', later: false });
});

test('restore on a new host with the recovery key: accepted, written to .env, env vars decrypt after a restart', async () => {
  const archive = await nightlyArchive(host(`ENCRYPTION_KEY=${K_A}\n`));
  const dir = host(`ENCRYPTION_KEY=${K_B}\nNEW_HOST=1\n`);
  const r = await run(dir, `
    const imp = await backup.importDataArchive(${JSON.stringify(archive)}, { encryptionKey: ${JSON.stringify(`ENCRYPTION_KEY=${K_A.toUpperCase()}`)} });
    return imp.encryptionKey;`);
  assert.equal(r.code, 0, r.all);
  assert.equal(r.result.source, 'supplied');
  assert.ok(!r.all.includes(K_A) && !r.all.includes(K_A.toUpperCase()), 'the key is not in any output');
  const env = readFileSync(join(dir, '.env'), 'utf8');
  assert.match(env, new RegExp(`^ENCRYPTION_KEY=${K_A}$`, 'm'));
  assert.ok(!env.includes(K_B), 'one key, not two');
  const after = await run(dir, READ_BACK);
  assert.equal(after.code, 0, after.all);
  assert.equal(after.result.plain, 'stored-plain');
});

function liveState(dir) {
  const d = new Database(join(dir, 'data', 'deployhub.db'), { readonly: true });
  try {
    return {
      env: readFileSync(join(dir, '.env'), 'utf8'),
      keep: !!d.prepare("SELECT 1 FROM apps WHERE slug = 'keep-app'").get(),
      preImport: readdirSync(join(dir, 'data')).filter((n) => n.startsWith('pre-import-')),
    };
  } finally { d.close(); }
}

test('the wrong key is refused before any write: this host\'s key, or a wrong recovery key', async () => {
  const archive = await nightlyArchive(host(`ENCRYPTION_KEY=${K_A}\n`));
  const dir = host(`ENCRYPTION_KEY=${K_B}\n`);
  const seed = await run(dir, `db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('k', 'keep-app', 99)").run(); return true;`);
  assert.equal(seed.code, 0, seed.all);
  const before = liveState(dir);
  assert.equal(before.keep, true);

  for (const [label, supplied] of [['host key', null], ['wrong recovery key', K_C], ['malformed', 'not-a-key']]) {
    const r = await run(dir, `
      const err = await backup.importDataArchive(${JSON.stringify(archive)}, { encryptionKey: ${JSON.stringify(supplied)} }).then(() => null, (e) => ({ message: e.message, status: e.status }));
      return err;`);
    assert.equal(r.code, 0, r.all);
    assert.ok(r.result, `${label}: must be refused`);
    assert.equal(r.result.status, 400, label);
    assert.match(r.result.message, /Nothing was changed/, label);
    if (label !== 'malformed') {
      assert.ok(r.result.message.includes(fp(K_A).slice(0, 16)), `${label}: names the fingerprint the backup needs`);
    }
    for (const k of [K_A, K_B, K_C]) assert.ok(!r.all.includes(k), `${label}: no key value in the output`);
    assert.deepEqual(liveState(dir), before, `${label}: nothing on the host changed`);
  }
});

test('an archive from before v2.145.0, with its key inside, still restores on another host', async () => {
  const src = host(`ENCRYPTION_KEY=${K_A}\n`);
  const made = await run(src, `${SEED} const ex = await backup.exportDataArchive({ contents: 'platform' }); return { path: ex.path, hasEntry: 'encryption_key' in ex.manifest };`);
  assert.equal(made.code, 0, made.all);
  assert.equal(made.result.hasEntry, false, 'precondition: the old format, no key entry');
  assert.ok(execFileSync('tar', ['-xzOf', made.result.path, '.env']).toString().includes(K_A), 'precondition: the old archive carries its key');

  const dir = host(`ENCRYPTION_KEY=${K_B}\n`);
  const r = await run(dir, `const imp = await backup.importDataArchive(${JSON.stringify(made.result.path)}); return { env: imp.envRestored, key: imp.encryptionKey };`);
  assert.equal(r.code, 0, r.all);
  assert.deepEqual(r.result, { env: true, key: { in_archive: null } });
  assert.match(readFileSync(join(dir, '.env'), 'utf8'), new RegExp(`^ENCRYPTION_KEY=${K_A}$`, 'm'));
  const after = await run(dir, READ_BACK);
  assert.equal(after.result.plain, 'stored-plain');
});

test('POST /api/settings/config/import takes the recovery key as encryption_key, and refuses without it', async () => {
  const archive = await nightlyArchive(host(`ENCRYPTION_KEY=${K_A}\n`));
  const dir = host(`ENCRYPTION_KEY=${K_B}\n`);
  const r = await run(dir, `
    const { mkdirSync, copyFileSync } = await import('fs');
    const { join } = await import('path');
    mkdirSync(join(process.env.DATA_DIR, 'backups'), { recursive: true });
    copyFileSync(${JSON.stringify(archive)}, join(process.env.DATA_DIR, 'backups', 'night.tar.gz'));
    const { generateApiKey, hashApiKey } = await import('./server/services/encryption.js');
    const key = generateApiKey('dhk_t');
    const uid = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('pa','pa@t.test','platform_admin',?,1,'human')").run(hashApiKey(key)).lastInsertRowid;
    const sess = generateApiKey('sess');
    db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(uid, hashApiKey(sess));
    const express = (await import('express')).default;
    const api = express();
    api.use(express.json());
    api.use('/api/settings', (await import('./server/routes/settings.js')).default);
    api.use((await import('./server/utils/errors.js')).errorHandler);
    const srv = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
    const post = async (body) => {
      const x = await fetch('http://127.0.0.1:' + srv.address().port + '/api/settings/config/import', { method: 'POST', headers: { Authorization: 'Bearer ' + sess, 'Content-Type': 'application/json' }, body: JSON.stringify({ confirm: 'crane.t.test', ...body }) });
      return { status: x.status, body: await x.json() };
    };
    const without = await post({ path: 'night.tar.gz' });
    const withKey = await post({ path: 'night.tar.gz', encryption_key: ${JSON.stringify(K_A)} });
    srv.close();
    const audit = db.prepare("SELECT detail FROM audit_log WHERE action = 'config-import'").all().map((a) => JSON.parse(a.detail));
    return { without: { status: without.status, message: without.body.error?.message }, withKey: { status: withKey.status, key: withKey.body.encryptionKey }, audit };
  `);
  assert.equal(r.code, 0, r.all);
  assert.equal(r.result.without.status, 400);
  assert.match(r.result.without.message, /needs the ENCRYPTION_KEY with fingerprint/);
  assert.equal(r.result.withKey.status, 200, JSON.stringify(r.result.withKey));
  assert.equal(r.result.withKey.key.source, 'supplied');
  assert.equal(r.result.audit.length, 1, 'the import was not audited');
  assert.equal(r.result.audit[0].encryption_key_replaced, true, 'the audit row does not say ENCRYPTION_KEY was replaced');
  assert.notEqual(r.result.audit[0].encryption_key_before, r.result.audit[0].encryption_key_after);
  assert.equal(r.result.audit[0].recovery_key_supplied, true);
  assert.match(readFileSync(join(dir, '.env'), 'utf8'), new RegExp(`^ENCRYPTION_KEY=${K_A}$`, 'm'));
  const after = await run(dir, READ_BACK);
  assert.equal(after.result.plain, 'stored-plain');
});

test('the off-site set: its data archive holds no key, its manifest names it, it restores, and Job Health turns ok', async () => {
  const fakeS3 = new URL('./fake-s3.mjs', import.meta.url).href;
  const dir = host(`ENCRYPTION_KEY=${K_A}\nOTHER_SETTING=1\n`);
  const r = await run(dir, `${SEED}
    const { startFakeS3 } = await import(${JSON.stringify(fakeS3)});
    const { writeFileSync } = await import('fs');
    const fake = await startFakeS3();
    const sched = await import('./server/services/backupScheduler.js');
    const health = await import('./server/services/platformBackupHealth.js');
    sched.setBackupConfig({ bucket: fake.bucket, region: fake.region, endpoint: fake.endpoint, prefix: 'n/', access_key_id: fake.accessKeyId, secret_access_key: fake.secretAccessKey, encrypt: false, include_repos: false, enabled: true }, null);
    const before = health.checkPlatformBackupOffsite();
    const up = await sched.runS3Backup();
    const after = health.checkPlatformBackupOffsite();
    const dataKey = [...fake.objects.keys()].find((k) => k.endsWith('data.tar.gz'));
    writeFileSync('offsite-data.tar.gz', fake.objects.get(dataKey).body);
    const manifest = JSON.parse(fake.objects.get([...fake.objects.keys()].find((k) => k.endsWith('manifest.json'))).body.toString());
    db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('l', 'later-app', 77)").run();
    const restored = await sched.restoreS3Backup(up.set);
    await fake.close();
    return { before: before.reason, after: after.ok, manifestKey: manifest.encryption_key, restoredKey: restored.data.encryptionKey };
  `);
  assert.equal(r.code, 0, r.all);
  assert.equal(r.result.before, 'never-uploaded');
  assert.equal(r.result.after, true, 'a real upload makes the check pass');
  assert.equal(r.result.manifestKey.in_archive, false);
  assert.equal(r.result.manifestKey.fingerprint, fp(K_A));
  assert.equal(r.result.restoredKey.source, 'host');
  const { hits } = keyBytesIn(join(dir, 'offsite-data.tar.gz'), [K_A]);
  assert.deepEqual(hits, [], 'the uploaded data archive holds no key');
  const back = await run(dir, READ_BACK);
  assert.deepEqual(back.result, { plain: 'stored-plain', later: false });
});
