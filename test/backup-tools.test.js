import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Off-site backup, reachable from an agent (v2.48.0).
//
// The capability has existed since v2.21.9 and there was no way to ASK whether
// it was switched on. An August 2026 incident review recorded "no SQLite backup
// exists" as an open risk when the truth was "it exists and nobody enabled it" —
// a five-minute settings task filed as a missing feature. These tools make the
// question answerable, so the properties worth testing are the ones that make
// the answer trustworthy:
//
//   1. The secret NEVER comes back out. The destination bucket receives a copy
//      of every secret AppCrane holds, so the credential to that bucket is the
//      most sensitive value in the system.
//   2. Only a platform admin can read or change it. A global 'admin' is not
//      enough — pointing the destination at another bucket is an exfiltration
//      path, not a misconfiguration.
//   3. Enabling a backup that cannot run is REFUSED. An enabled-but-broken
//      backup reports itself enabled while uploading nothing, which is worse
//      than being plainly off: it is the reassuring-but-false state the whole
//      feature exists to eliminate.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-backup-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { callTool, getToolCatalog } = await import('../server/services/mcpTools.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

function mkUser(role, email) {
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(role, email, role, hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}
const platformAdmin = mkUser('platform_admin', 'pa@x.io');
const plainAdmin    = mkUser('admin', 'admin@x.io');
const owner         = mkUser('user', 'user@x.io');

const call = (u, name, args = {}) => callTool(u, name, args);
const unwrap = (r) => (typeof r === 'string' ? JSON.parse(r) : (r?.content ? JSON.parse(r.content[0].text) : r));
const status = async (u = platformAdmin) => unwrap(await call(u, 'appcrane_get_backup_status'));

const SECRET = 'wJalrXUtnFEMI-K7MDENG-EXAMPLEKEY';

// ---------------------------------------------------------------------------
// The secret never comes back
// ---------------------------------------------------------------------------

test('the secret is never returned by any surface, in any field', async () => {
  await call(platformAdmin, 'appcrane_set_backup_config', {
    bucket: 'crane-backups', access_key_id: 'AKIAEXAMPLE', secret_access_key: SECRET,
  });

  const s = await status();
  assert.equal(s.has_secret, true, 'the secret was not stored at all');
  // Serialised in full: a leak into any nested field counts, not just a
  // top-level `secret_access_key` key.
  assert.doesNotMatch(JSON.stringify(s), new RegExp(SECRET),
    'the backup status payload contains the secret access key in plaintext');
});

test('the setter does not echo the secret back either', async () => {
  const r = unwrap(await call(platformAdmin, 'appcrane_set_backup_config', { secret_access_key: SECRET }));
  assert.doesNotMatch(JSON.stringify(r), new RegExp(SECRET),
    'the write response echoed the secret — a write-only field that is echoed is not write-only');
  assert.equal(r.has_secret, true);
});

test('the audit entry records that the secret changed, never its value', async () => {
  await call(platformAdmin, 'appcrane_set_backup_config', { secret_access_key: SECRET, bucket: 'other-bucket' });
  const rows = db.prepare("SELECT detail FROM audit_log WHERE action = 'backup-config-change' ORDER BY id DESC").all();
  assert.ok(rows.length > 0, 'no dedicated audit entry was written for a backup destination change');
  const joined = rows.map(r => r.detail).join('\n');
  assert.doesNotMatch(joined, new RegExp(SECRET), 'the audit log stored the secret in plaintext');
  assert.match(joined, /secret_access_key/, 'the audit entry does not record that the secret was replaced at all');
  assert.match(joined, /other-bucket/, 'the destination change is not recorded — that is the exfiltration-relevant field');
});

// ---------------------------------------------------------------------------
// Platform admin only
// ---------------------------------------------------------------------------

test('a plain admin cannot read the backup configuration', async () => {
  await assert.rejects(() => call(plainAdmin, 'appcrane_get_backup_status'), /platform admin/i,
    'a global admin could read the destination every platform secret is copied to');
});

test('a plain admin cannot change it, and cannot run it', async () => {
  await assert.rejects(() => call(plainAdmin, 'appcrane_set_backup_config', { bucket: 'attacker' }), /platform admin/i);
  await assert.rejects(() => call(plainAdmin, 'appcrane_run_backup_now'), /platform admin/i);
  assert.notEqual((await status()).bucket, 'attacker', 'the refused write took effect anyway');
});

test('an ordinary user is refused by the dispatcher before the handler runs', async () => {
  await assert.rejects(() => call(owner, 'appcrane_get_backup_status'), /Forbidden/i);
});

test('the platform-admin check is the FIRST statement in every backup handler', () => {
  // Anything above it runs for a global admin. Asserted against the source the
  // same way the ingress setter is, because ordering here is a security
  // property that no functional test can see once it is correct.
  const src = readFileSync('server/services/mcpTools.js', 'utf8');
  for (const name of ['appcrane_get_backup_status', 'appcrane_set_backup_config', 'appcrane_run_backup_now']) {
    const from = src.indexOf(`name: '${name}'`);
    assert.notEqual(from, -1, `${name} is no longer registered`);
    const block = src.slice(from, from + 9000);
    assert.match(block, /handler: async \(user(?:, args)?\) => \{\s*if \(user\.role !== 'platform_admin'\)/,
      `${name}: the platform_admin check is no longer the first thing the handler does`);
  }
});

// ---------------------------------------------------------------------------
// Refusing to enable a backup that cannot run
// ---------------------------------------------------------------------------

test('enabling is refused while the config is incomplete, and names what is missing', async () => {
  // Fresh, empty config.
  db.prepare("DELETE FROM settings WHERE key LIKE 'backup_s3_%'").run();

  await assert.rejects(
    () => call(platformAdmin, 'appcrane_set_backup_config', { enabled: true }),
    (e) => /bucket/.test(e.message) && /access_key_id/.test(e.message) && /secret_access_key/.test(e.message),
    'an unconfigured backup was enabled — it would fail nightly while reporting itself enabled');

  assert.equal((await status()).enabled, false, 'the refused enable was persisted anyway');
});

test('enabling succeeds when the same call supplies what was missing', async () => {
  const r = unwrap(await call(platformAdmin, 'appcrane_set_backup_config', {
    enabled: true, bucket: 'b', access_key_id: 'k', secret_access_key: SECRET,
  }));
  assert.equal(r.enabled, true, 'a complete configuration was still refused');
});

// ---------------------------------------------------------------------------
// The verdict — the thing the incident review got wrong
// ---------------------------------------------------------------------------

test('an unconfigured platform reports NOT CONFIGURED and what is missing', async () => {
  db.prepare("DELETE FROM settings WHERE key LIKE 'backup_s3_%'").run();
  const s = await status();
  assert.equal(s.configured, false);
  assert.equal(s.healthy, false);
  assert.deepEqual(s.missing, ['bucket', 'access_key_id', 'secret_access_key']);
  assert.match(s.summary, /NOT CONFIGURED/);
});

test('configured-but-disabled is called out as its own state, not as healthy', async () => {
  await call(platformAdmin, 'appcrane_set_backup_config', {
    bucket: 'b', access_key_id: 'k', secret_access_key: SECRET,
  });
  const s = await status();
  assert.equal(s.configured, true, 'a fully populated config did not read as configured');
  assert.equal(s.healthy, false,
    'stored credentials were reported as healthy while nothing is being uploaded');
  assert.match(s.summary, /CONFIGURED BUT DISABLED/);
});

test('enabled but never run is distinguished from enabled and working', async () => {
  await call(platformAdmin, 'appcrane_set_backup_config', {
    enabled: true, bucket: 'b', access_key_id: 'k', secret_access_key: SECRET,
  });
  const s = await status();
  assert.equal(s.healthy, false, 'a backup that has never completed once was reported healthy');
  assert.equal(s.hours_since_last_run, null);
  assert.match(s.summary, /NEVER RUN/);
});

test('a stale successful run is reported as overdue, not healthy', async () => {
  const old = new Date(Date.now() - 72 * 3600 * 1000).toISOString();
  db.prepare("INSERT INTO settings (key,value) VALUES ('backup_s3_last_run',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(old);
  db.prepare("DELETE FROM settings WHERE key = 'backup_s3_last_error'").run();

  const s = await status();
  assert.equal(s.healthy, false,
    'a nightly job that last succeeded three days ago was reported healthy — that is the failure mode ' +
    'an operator most needs told about, and it looks identical to working if only the config is read');
  assert.equal(s.hours_since_last_run, 72);
  assert.match(s.summary, /OVERDUE/);
});

test('a recent successful run reads healthy', async () => {
  const recent = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
  db.prepare("INSERT INTO settings (key,value) VALUES ('backup_s3_last_run',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(recent);
  const s = await status();
  assert.equal(s.healthy, true, 'a working backup was not reported healthy — the check is useless if it never says yes');
  assert.match(s.summary, /Healthy/);
});

test('a recorded last_error keeps it unhealthy even with a recent run', async () => {
  db.prepare("INSERT INTO settings (key,value) VALUES ('backup_s3_last_error','AccessDenied') ON CONFLICT(key) DO UPDATE SET value=excluded.value").run();
  const s = await status();
  assert.equal(s.healthy, false);
  assert.match(s.summary, /FAILING/);
  assert.match(s.summary, /AccessDenied/, 'the operator is told it failed but not why');
});

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

test('the status tool is read-only and the two acting tools are not', () => {
  const byName = new Map(getToolCatalog().map(t => [t.name, t]));
  assert.equal(byName.get('appcrane_get_backup_status').readOnly, true);
  assert.ok(!byName.get('appcrane_set_backup_config').readOnly,
    'a tool that writes credentials is marked read-only, so a read-only key could use it');
  assert.ok(!byName.get('appcrane_run_backup_now').readOnly,
    'running a backup writes a copy of every platform secret off-box; it is not a read');
});
