import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, existsSync, statSync, readdirSync, rmSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash, randomBytes } from 'crypto';
import { spawn, spawnSync } from 'child_process';
import http from 'http';
import Database from 'better-sqlite3';

// crane rotate-key (server/services/keyRotation/*, cli/rotateKey.js). One
// database is seeded under K1 through the real write paths (encrypt() and the
// services that call it), then copied into a fresh DATA_DIR per case.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const K1 = randomBytes(32).toString('hex');
const SCRATCH = mkdtempSync(join(tmpdir(), 'crane-rotate-'));
const GOLDEN = join(SCRATCH, 'golden');
mkdirSync(GOLDEN);

process.env.DATA_DIR = GOLDEN;
process.env.ENCRYPTION_KEY = K1;
process.env.LOG_LEVEL = 'error';

const { initDb } = await import('../server/db.js');
const { encrypt, decrypt, deriveSecret, hashApiKey } = await import('../server/services/encryption.js');
const registry = await import('../server/services/keyRotation/registry.js');
const { rotateKey, RefusedError, RotationError } = await import('../server/services/keyRotation/index.js');
const chain = await import('../server/services/auditChain.js');
const mfa = await import('../server/services/mfa.js');
const totp = await import('../server/services/totp.js');

after(() => rmSync(SCRATCH, { recursive: true, force: true }));

// ── seed ───────────────────────────────────────────────────────────────────

const PLAIN = new Map(); // "table.column" -> plaintext written
const db = initDb(GOLDEN);
const put = (label, plain) => { PLAIN.set(label, plain); return encrypt(plain); };

const userId = Number(db.prepare("INSERT INTO users (name, email, role, api_key_hash, api_key_encrypted, password_hash) VALUES ('u', 'u@t.test', 'platform_admin', ?, ?, NULL)")
  .run(hashApiKey('k'), put('users.api_key_encrypted', 'legacy-api-key')).lastInsertRowid);
const appId = Number(db.prepare(`INSERT INTO apps (name, slug, slot, github_token_encrypted, claude_credentials_encrypted, service_token_encrypted)
  VALUES ('a', 'rot-a', 1, ?, ?, ?)`).run(put('apps.github_token_encrypted', 'ghp_x'), put('apps.claude_credentials_encrypted', '{"c":1}'),
  put('apps.service_token_encrypted', 'svc-token')).lastInsertRowid);
db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'production', 'DB_URL', ?)").run(appId, put('env_vars.value_encrypted', 'postgres://p'));
db.prepare("INSERT INTO app_env_files (app_id, env, rel_path, mode, bytes, content_encrypted) VALUES (?, 'production', '.env', 384, 3, ?)")
  .run(appId, put('app_env_files.content_encrypted', Buffer.from('A=1').toString('base64')));
db.prepare('INSERT INTO user_claude_tokens (user_id, token_encrypted) VALUES (?, ?)').run(userId, put('user_claude_tokens.token_encrypted', 'claude-tok'));
db.prepare("INSERT INTO llm_gateway_tokens (app_id, env, token_hash, token_encrypted) VALUES (?, 'production', 'h1', ?)").run(appId, put('llm_gateway_tokens.token_encrypted', 'aclg_x'));
db.prepare("INSERT INTO app_identity_secrets (app_id, env, secret_encrypted) VALUES (?, 'production', ?)").run(appId, put('app_identity_secrets.secret_encrypted', 'idsecret'));
db.prepare("INSERT INTO github_app_config (id, github_app_id, slug, client_secret_enc, webhook_secret_enc, private_key_enc) VALUES (1, 7, 'g', ?, ?, ?)")
  .run(put('github_app_config.client_secret_enc', 'cs'), put('github_app_config.webhook_secret_enc', 'whs'), put('github_app_config.private_key_enc', 'PEM'));
db.prepare("INSERT INTO siem_sinks (name, type, secrets_enc) VALUES ('s', 'https', ?)").run(put('siem_sinks.secrets_enc', '{"token":"t"}'));
db.prepare("INSERT INTO managed_databases (app_id, engine, db_name, db_user, password_enc, app_password_enc) VALUES (?, 'postgres', 'd', 'u', ?, ?)")
  .run(appId, put('managed_databases.password_enc', 'pw1'), put('managed_databases.app_password_enc', 'pw2'));
db.prepare("INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc) VALUES ('postgres', 'c', 'i', 5432, ?)")
  .run(put('managed_db_servers.admin_password_enc', 'adminpw'));
db.prepare("INSERT INTO managed_db_certs (name, cert_pem, key_enc, not_after) VALUES ('ca', 'CERT', ?, '2030-01-01')").run(put('managed_db_certs.key_enc', 'KEYPEM'));
const agentId = Number(db.prepare("INSERT INTO crew_agents (name, owner_user_id, kind) VALUES ('ag', ?, 'mcp')").run(userId).lastInsertRowid);
const tokId = Number(db.prepare("INSERT INTO crew_agent_tokens (agent_id, token_hash, hint) VALUES (?, 'th', 'h')").run(agentId).lastInsertRowid);
db.prepare("INSERT INTO crew_tasks (id, from_agent_id, to_agent_id, title, state) VALUES ('t1', ?, ?, 'x', 'submitted')").run(agentId, agentId);
db.prepare("INSERT INTO crew_push_configs (id, task_id, agent_id, token_id, url, token_enc, auth_credentials_enc) VALUES ('p1', 't1', ?, ?, 'https://x.test', ?, ?)")
  .run(agentId, tokId, put('crew_push_configs.token_enc', 'pushtok'), put('crew_push_configs.auth_credentials_enc', 'creds'));
// settings: a whole-value blob, the MariaDB key row (never loaded) and the llm gateway JSON.
db.prepare("INSERT INTO settings (key, value) VALUES ('oidc_client_secret_enc', ?)").run(put('settings.oidc_client_secret_enc', 'oidc-secret'));
(await import('../server/services/managedDbEncryption.js')).ensureKey(db);
PLAIN.set('settings.managed_db_mariadb_encryption_key_enc', decrypt(db.prepare("SELECT value FROM settings WHERE key = 'managed_db_mariadb_encryption_key_enc'").get().value));
(await import('../server/services/llmGateway/config.js')).updateConfig({ providers: { anthropic: { enabled: true, api_key: 'sk-ant-x' } } }, userId, db);
PLAIN.set('settings.llm_gateway:providers.anthropic.key_encrypted', 'sk-ant-x');
// MFA through the real enrollment: user_mfa.totp_secret_enc plus recovery codes;
// a second user left pending covers pending_secret_enc.
const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
const enr = mfa.startEnrollment(db, user);
const act = mfa.activateEnrollment(db, user, totp.totp(totp.base32Decode(enr.secret), Date.now(), { algorithm: 'SHA1' }));
assert.equal(act.ok, true);
PLAIN.set('user_mfa.totp_secret_enc', enr.secret);
const RECOVERY = act.recovery_codes;
const u2 = Number(db.prepare("INSERT INTO users (name, email, role, api_key_hash) VALUES ('v', 'v@t.test', 'user', ?)").run(hashApiKey('k2')).lastInsertRowid);
const enr2 = mfa.startEnrollment(db, db.prepare('SELECT * FROM users WHERE id = ?').get(u2));
PLAIN.set('user_mfa.pending_secret_enc', enr2.secret);
// The audit chain: seal and sign real checkpoints.
await chain.sealNew({ db });
chain.checkpointNow({ db });
db.prepare("INSERT INTO audit_log (action, detail) VALUES ('later', 'x')").run();
await chain.sealNew({ db });
chain.checkpointNow({ db, now: Date.now() + 1000 });
const CHECKPOINTS = db.prepare('SELECT COUNT(*) AS n FROM audit_chain_checkpoints').get().n;
assert.ok(CHECKPOINTS >= 2);
db.pragma('wal_checkpoint(TRUNCATE)');
db.close();

// ── helpers ────────────────────────────────────────────────────────────────

let caseN = 0;
function fixture({ envMode = 0o644, mutate = null } = {}) {
  const dir = join(SCRATCH, `case-${++caseN}`);
  const dataDir = join(dir, 'data');
  mkdirSync(dataDir, { recursive: true });
  copyFileSync(join(GOLDEN, 'deployhub.db'), join(dataDir, 'deployhub.db'));
  const envPath = join(dir, '.env');
  writeFileSync(envPath, `# test\nPORT=1\nENCRYPTION_KEY=${K1}\nOTHER=1\n`);
  chmodSync(envPath, envMode);
  if (mutate) { const d = new Database(join(dataDir, 'deployhub.db')); mutate(d); d.close(); }
  return { dir, dataDir, envPath, dbPath: join(dataDir, 'deployhub.db') };
}

const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const tryDec = (b, k) => { try { return decrypt(b, k); } catch { return null; } };
const freePort = async () => { const s = http.createServer(); await new Promise((r) => s.listen(0, '127.0.0.1', r)); const p = s.address().port; await new Promise((r) => s.close(r)); return p; };

/** Every PLAIN entry read back from a database file: label -> blob. */
function blobs(dbPath) {
  const d = new Database(dbPath, { readonly: true });
  const out = new Map();
  for (const label of PLAIN.keys()) {
    if (label.startsWith('settings.')) {
      const [key, path] = label.slice('settings.'.length).split(':');
      const v = d.prepare('SELECT value FROM settings WHERE key = ?').get(key).value;
      out.set(label, path ? path.split('.').reduce((o, k) => o[k], JSON.parse(v)) : v);
    } else {
      const [t, c] = label.split('.');
      out.set(label, d.prepare(`SELECT "${c}" AS v FROM "${t}" WHERE "${c}" IS NOT NULL LIMIT 1`).get().v);
    }
  }
  d.close();
  return out;
}

async function run(f, opts = {}) {
  return rotateKey({ dataDir: f.dataDir, envPath: f.envPath, port: opts.port ?? await freePort(), ...opts });
}

// ── tests ──────────────────────────────────────────────────────────────────

test('the seed covers every registry column (so the round-trip test below is not vacuous)', () => {
  for (const [t, cols] of registry.COLUMNS) for (const c of cols) assert.ok(PLAIN.has(`${t}.${c}`), `not seeded: ${t}.${c}`);
});

test('drift guard: every *_enc / *_encrypted column the migrations create is covered by rotate-key', () => {
  const dir = mkdtempSync(join(SCRATCH, 'schema-'));
  const out = spawnSync(process.execPath, ['--input-type=module', '-e', `
    process.env.LOG_LEVEL = 'error';
    const { initDb } = await import(${JSON.stringify(join(ROOT, 'server/db.js'))});
    const db = initDb(${JSON.stringify(dir)});
    const cols = [];
    for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all())
      for (const c of db.prepare('PRAGMA table_info("' + name + '")').all()) if (/(_enc|_encrypted)$/.test(c.name)) cols.push(name + '.' + c.name);
    console.log(JSON.stringify(cols));`], { encoding: 'utf8', env: { ...process.env, DATA_DIR: dir } });
  assert.equal(out.status, 0, out.stderr);
  const cols = JSON.parse(out.stdout.trim().split('\n').pop());
  assert.ok(cols.length >= 20, `only ${cols.length} columns found`);
  const missing = cols.filter((tc) => { const [t, c] = tc.split('.'); return !registry.coveredColumn(t, c); });
  assert.deepEqual(missing, [], `add these to server/services/keyRotation/registry.js COLUMNS: ${missing.join(', ')}`);
});

test('dry run changes nothing and reports a count for every covered column', async () => {
  const f = fixture();
  const before = { db: sha(f.dbPath), env: sha(f.envPath) };
  const res = await run(f, { dryRun: true });
  assert.equal(res.report.dry_run, true);
  assert.equal(res.backupDir, null);
  for (const [t, cols] of registry.COLUMNS) for (const c of cols) assert.ok(res.report.counts[`${t}.${c}`] >= 1, `${t}.${c}`);
  assert.equal(res.report.values, PLAIN.size);
  assert.deepEqual(res.report.blockers, []);
  assert.equal(sha(f.dbPath), before.db);
  assert.equal(sha(f.envPath), before.env);
  assert.equal(existsSync(join(f.dataDir, 'backups')), false);
});

test('rotation: every encrypted value round-trips under the new key, the old key no longer decrypts, backup first, .env replaced atomically 0600', async () => {
  const f = fixture({ envMode: 0o644 });
  const inodeBefore = statSync(f.envPath).ino;
  const res = await run(f);
  const newKey = readFileSync(f.envPath, 'utf8').match(/ENCRYPTION_KEY=([0-9a-f]+)/)[1];
  assert.notEqual(newKey, K1);
  assert.equal(res.report.post_check.ok, true);
  for (const [label, blob] of blobs(f.dbPath)) {
    assert.equal(tryDec(blob, newKey), PLAIN.get(label), `${label} under the new key`);
    assert.equal(tryDec(blob, K1), null, `${label} still decrypts with the old key`);
  }
  // .env: only the key line changed, old key gone, 0600, replaced by rename (new inode).
  const env = readFileSync(f.envPath, 'utf8');
  assert.equal(env, `# test\nPORT=1\nENCRYPTION_KEY=${newKey}\nOTHER=1\n`);
  assert.equal(env.includes(K1), false);
  assert.equal(statSync(f.envPath).mode & 0o777, 0o600);
  assert.notEqual(statSync(f.envPath).ino, inodeBefore);
  assert.deepEqual(readdirSync(f.dir).filter((n) => n.includes('.tmp')), []);
  // Backup: taken before any change (its copy still decrypts under K1), 0700/0600, old key only there.
  assert.ok(res.backupDir.startsWith(join(f.dataDir, 'backups', 'key-rotation-')));
  assert.equal(statSync(res.backupDir).mode & 0o777, 0o700);
  assert.equal(statSync(join(res.backupDir, 'deployhub.db')).mode & 0o777, 0o600);
  assert.equal(statSync(join(res.backupDir, 'env.backup')).mode & 0o777, 0o600);
  assert.match(readFileSync(join(res.backupDir, 'env.backup'), 'utf8'), new RegExp(`ENCRYPTION_KEY=${K1}`));
  for (const [label, blob] of blobs(join(res.backupDir, 'deployhub.db'))) assert.equal(tryDec(blob, K1), PLAIN.get(label), `backup ${label}`);
  // Audit trail, no key material.
  const d = new Database(f.dbPath, { readonly: true });
  const row = d.prepare("SELECT detail FROM audit_log WHERE action = 'security.key_rotated'").get();
  const ev = d.prepare("SELECT data FROM events WHERE kind = 'security.key_rotated'").get();
  d.close();
  assert.ok(row && ev);
  for (const s of [row.detail, ev.data]) { assert.equal(s.includes(K1), false); assert.equal(s.includes(newKey), false); }
});

test('audit chain: checkpoints are re-signed under the new key and still verify; a forged one stays forged', async () => {
  let forgedId;
  const f = fixture({ mutate: (d) => {
    forgedId = Number(d.prepare("INSERT INTO audit_chain_checkpoints (kind, src, upto_row_id, chain_hash, created_at, prev_signature, signature) VALUES ('seal', 'events', 1, 'x', '2020-01-01 00:00:00', NULL, ?)")
      .run('ab'.repeat(32)).lastInsertRowid);
  } });
  const res = await run(f);
  assert.equal(res.report.audit_checkpoints_resigned, CHECKPOINTS);
  assert.equal(res.report.audit_checkpoints_invalid_left, 1);
  const newKey = readFileSync(f.envPath, 'utf8').match(/ENCRYPTION_KEY=([0-9a-f]+)/)[1];
  const d = new Database(f.dbPath);
  const newK = deriveSecret(chain.KEY_LABEL, newKey);
  const rows = d.prepare('SELECT * FROM audit_chain_checkpoints ORDER BY id').all();
  assert.equal(rows.length, CHECKPOINTS + 1);
  for (const c of rows) assert.equal(chain.checkpointValid(c, newK), c.id !== forgedId, `checkpoint ${c.id}`);
  chain._resetAuditChainForTests({ key: newK });
  const v = await chain.verifyChain({ db: d });
  chain._resetAuditChainForTests();
  d.close();
  assert.deepEqual(v.problems.map((p) => [p.type, p.checkpoint_id]), [['forged_checkpoint', forgedId]]);
});

test('MFA recovery codes issued before the rotation still work after it (and only once)', async () => {
  const f = fixture();
  await run(f);
  const newKey = readFileSync(f.envPath, 'utf8').match(/ENCRYPTION_KEY=([0-9a-f]+)/)[1];
  const out = spawnSync(process.execPath, ['--input-type=module', '-e', `
    process.env.LOG_LEVEL = 'error';
    const { initDb } = await import(${JSON.stringify(join(ROOT, 'server/db.js'))});
    const mfa = await import(${JSON.stringify(join(ROOT, 'server/services/mfa.js'))});
    const db = initDb(${JSON.stringify(f.dataDir)});
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(${userId});
    const a = mfa.verifyCode(db, user, ${JSON.stringify(RECOVERY[0])});
    const b = mfa.verifyCode(db, user, ${JSON.stringify(RECOVERY[0])});
    console.log(JSON.stringify([a.ok, a.method, b.ok]));`], { encoding: 'utf8', env: { ...process.env, DATA_DIR: f.dataDir, ENCRYPTION_KEY: newKey } });
  assert.equal(out.status, 0, out.stderr);
  assert.deepEqual(JSON.parse(out.stdout.trim().split('\n').pop()), [true, 'recovery_code', false]);
});

test('a value that does not decrypt aborts: nothing changed, .env untouched, backup already taken', async () => {
  const f = fixture({ mutate: (d) => d.prepare("UPDATE env_vars SET value_encrypted = ? WHERE key = 'DB_URL'").run(encrypt('x', 'ab'.repeat(32))) });
  const envBefore = sha(f.envPath);
  const rowsBefore = blobs(f.dbPath);
  await assert.rejects(run(f), (e) => {
    assert.ok(e instanceof RotationError, e.message);
    assert.match(e.report.failures[0], /^env_vars\.value_encrypted rowid \d+$/);
    assert.ok(e.backupDir && existsSync(join(e.backupDir, 'deployhub.db')));
    return true;
  });
  assert.equal(sha(f.envPath), envBefore);
  assert.deepEqual(blobs(f.dbPath), rowsBefore);
});

test('a failure at the last step (staging .env) rolls the database back and leaves .env untouched', async () => {
  const f = fixture();
  writeFileSync(`${f.envPath}.rotate-${process.pid}.tmp`, 'in the way');
  const envBefore = sha(f.envPath);
  const rowsBefore = blobs(f.dbPath);
  await assert.rejects(run(f), /EEXIST/);
  assert.equal(sha(f.envPath), envBefore);
  assert.deepEqual(blobs(f.dbPath), rowsBefore);
  const d = new Database(f.dbPath, { readonly: true });
  assert.equal(d.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'security.key_rotated'").get().n, 0);
  d.close();
});

test('refuses while the database is open in another process (AppCrane running)', async () => {
  const f = fixture();
  const holder = spawn(process.execPath, ['--input-type=module', '-e', `
    const Database = (await import(${JSON.stringify(join(ROOT, 'node_modules/better-sqlite3/lib/index.js'))})).default;
    const d = new Database(${JSON.stringify(f.dbPath)}); d.pragma('journal_mode = WAL'); d.prepare('SELECT 1').get();
    console.log('ready'); setInterval(() => {}, 1000);`], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((r) => holder.stdout.once('data', r));
  const before = sha(f.dbPath);
  try {
    await assert.rejects(run(f), (e) => e instanceof RefusedError && /appears to be running/.test(e.message));
  } finally {
    holder.kill();
  }
  assert.equal(sha(f.dbPath), before);
  assert.equal(existsSync(join(f.dataDir, 'backups')), false);
});

test('refuses while something answers on the AppCrane port', async () => {
  const f = fixture();
  const srv = http.createServer((q, r) => r.end('{}'));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(run(f, { port: srv.address().port }), (e) => e instanceof RefusedError && /appears to be running/.test(e.message));
  } finally {
    srv.close();
  }
});

test('refuses while MariaDB encryption at rest is in use; dry run lists it', async () => {
  const f = fixture({ mutate: (d) => d.prepare("INSERT INTO settings (key, value) VALUES ('managed_db_mariadb_encryption_key_loaded', '1')").run() });
  const dry = await run(f, { dryRun: true });
  assert.match(dry.report.blockers[0], /MariaDB encryption at rest/);
  const before = sha(f.dbPath);
  await assert.rejects(run(f), (e) => e instanceof RefusedError && /MariaDB encryption at rest/.test(e.message));
  assert.equal(sha(f.dbPath), before);
});

test('refuses when ciphertext sits somewhere rotate-key does not cover; a copy in an audit row is left as is', async () => {
  const stray = encrypt('stray');
  const f = fixture({ mutate: (d) => d.prepare("UPDATE apps SET description = ? WHERE slug = 'rot-a'").run(`note ${stray}`) });
  await assert.rejects(run(f), (e) => e instanceof RotationError && /^apps\.description rowid \d+$/.test(e.report.uncovered[0]));
  const g = fixture({ mutate: (d) => d.prepare("INSERT INTO audit_log (action, detail) VALUES ('x', ?)").run(stray) });
  const res = await run(g);
  assert.equal(res.report.inert_left_as_is.length, 1);
});

test('CLI: dry run then rotate with --new-key-file, DATA_DIR taken from .env; no key material on stdout or stderr', async () => {
  const f = fixture();
  writeFileSync(f.envPath, readFileSync(f.envPath, 'utf8') + `DATA_DIR=${f.dataDir}\n`);
  const keyFile = join(f.dir, 'newkey');
  const K2 = randomBytes(32).toString('hex');
  writeFileSync(keyFile, `${K2}\n`, { mode: 0o600 });
  const env = { ...process.env, LOG_LEVEL: 'error' };
  delete env.ENCRYPTION_KEY;
  delete env.DATA_DIR;
  const port = String(await freePort());
  const cli = (args) => spawnSync(process.execPath, [join(ROOT, 'bin/deployhub.js'), 'rotate-key', '--env-file', f.envPath, '--port', port, ...args], { encoding: 'utf8', env });
  const dry = cli(['--dry-run', '--json']);
  assert.equal(dry.status, 0, dry.stderr);
  assert.equal(JSON.parse(dry.stdout).values, PLAIN.size);
  const real = cli(['--new-key-file', keyFile]);
  assert.equal(real.status, 0, real.stderr + real.stdout);
  assert.match(real.stdout, /ENCRYPTION_KEY rotated/);
  for (const s of [dry.stdout, dry.stderr, real.stdout, real.stderr]) {
    assert.equal(s.includes(K1), false);
    assert.equal(s.includes(K2), false);
  }
  assert.match(readFileSync(f.envPath, 'utf8'), new RegExp(`ENCRYPTION_KEY=${K2}`));
  const again = cli(['--new-key-file', keyFile]);
  assert.equal(again.status, 1);
  assert.match(again.stderr, /same as the current one/);
});
