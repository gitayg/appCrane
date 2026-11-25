import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Job Health 'platform-backup-offsite' (v2.145.0): failing while no off-site
// destination is configured or the last successful upload is older than 26 h,
// ok otherwise; one e-mail per platform admin per day while failing; and the
// same verdict on Settings > Backup's API.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-offsite-health-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { setBackupConfig } = await import('../server/services/backupScheduler.js');
const { checkPlatformBackupOffsite, JOB_ID } = await import('../server/services/platformBackupHealth.js');
const { getJobHealth, jobStarted, enableJobHealthAlerts, _resetJobHealthForTests } = await import('../server/services/jobHealth.js');
const { issueRecoveryKey } = await import('../server/services/recoveryKey.js');
const { keyFingerprint, shortFingerprint } = await import('../server/services/backupCrypto.js');
const { planBackupKey } = await import('../server/services/backupKeySeparation.js');

const ADMIN_KEY = generateApiKey('dhk_admin');
const ADMIN_ID = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('PA','pa@t.test','platform_admin',?,1,'human')").run(hashApiKey(ADMIN_KEY)).lastInsertRowid;
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('PB','pb@t.test','platform_admin',?,1,'human')").run(hashApiKey(generateApiKey('dhk_admin')));
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','u@t.test','user',?,1,'human')").run(hashApiKey(generateApiKey('dhk_user')));

const settingsRoutes = (await import('../server/routes/settings.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/settings', settingsRoutes);
api.use(errorHandler);
const server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
after(() => { server.closeAllConnections?.(); server.close(); rmSync(ROOT, { recursive: true, force: true }); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const row = () => getJobHealth().find((j) => j.id === JOB_ID);
const mails = () => db.prepare("SELECT to_email, subject, body_text FROM email_queue WHERE source = 'job-health' ORDER BY id").all();
const setLastRun = (iso) => db.prepare("INSERT INTO settings (key, value) VALUES ('backup_s3_last_run', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(iso);
const configure = () => setBackupConfig({ bucket: 'crane-backups', access_key_id: 'AKIAEXAMPLE', secret_access_key: 'not-a-real-secret', enabled: true }, null);
const flush = () => new Promise((r) => setTimeout(r, 50));

test('no destination: failing, the message names what is missing, and each admin gets one e-mail that day', async () => {
  _resetJobHealthForTests();
  jobStarted(JOB_ID, { cadenceMs: 3_600_000 });
  const h = checkPlatformBackupOffsite();
  assert.equal(h.ok, false);
  assert.equal(row().status, 'failing');
  assert.match(row().last_error, /No off-site destination is configured \(missing: bucket, access_key_id, secret_access_key\)/);
  await flush();
  checkPlatformBackupOffsite();
  checkPlatformBackupOffsite();
  await flush();
  const m = mails();
  assert.deepEqual(m.map((x) => x.to_email).sort(), ['pa@t.test', 'pb@t.test'], 'one per platform admin, not per check, never a plain user');
  assert.match(m[0].subject, /Platform backup off-site copy/);
  assert.match(m[0].body_text, /missing: bucket/);
  for (const must of [
    /Settings > Backup > Scheduled off-site backup \(S3\)/,
    /Fill in Bucket, Access key and Secret key/,
    /Endpoint is needed only for an S3-compatible store/,
    /s3:PutObject, s3:GetObject, s3:ListBucket, s3:DeleteObject and s3:AbortMultipartUpload/,
    /Tick "Enable nightly S3 backup", click "Save S3 settings", then "Test connection"/,
    /"Back up to S3 now"/,
    /PUT \/api\/settings\/backup\/s3 with bucket, region, endpoint, prefix, access_key_id, secret_access_key and enabled: true/,
    /appcrane_set_backup_config, then appcrane_run_backup_now/,
    /recovery key for the current ENCRYPTION_KEY has not been downloaded/,
  ]) assert.match(m[0].body_text, must);

  const body = await (await fetch(`${BASE}/api/settings/backup/s3`, { headers: { 'X-API-Key': ADMIN_KEY } })).json();
  assert.equal(body.off_site.health.ok, false);
  assert.equal(body.off_site.health.reason, 'not-configured');
});

test('configured but never uploaded: still failing', () => {
  configure();
  const h = checkPlatformBackupOffsite();
  assert.equal(h.ok, false);
  assert.equal(h.reason, 'never-uploaded');
  assert.equal(row().status, 'failing');
});

test('an upload 2 h ago with the recovery key never downloaded: a WARNING on Job Health and Settings, ok once it is downloaded', async () => {
  setLastRun(new Date(Date.now() - 2 * 3_600_000).toISOString());
  const h = checkPlatformBackupOffsite();
  assert.equal(h.ok, true, 'the off-site copy itself is fine');
  assert.equal(h.severity, 'warning');
  assert.equal(row().status, 'warning', 'Job Health reads warning, not ok');
  assert.match(row().detail.message, /recovery key for the current ENCRYPTION_KEY has not been downloaded/);
  let body = await (await fetch(`${BASE}/api/settings/backup/s3`, { headers: { 'X-API-Key': ADMIN_KEY } })).json();
  assert.equal(body.off_site.health.severity, 'warning');
  assert.equal(body.off_site.health.recovery_key.downloaded_for_current_key, false);
  assert.match(body.off_site.health.warnings[0], /has not been downloaded/);

  issueRecoveryKey(ADMIN_ID);
  const h2 = checkPlatformBackupOffsite();
  assert.equal(h2.severity, 'ok');
  assert.deepEqual(h2.warnings, []);
  assert.equal(row().status, 'ok');
  body = await (await fetch(`${BASE}/api/settings/backup/s3`, { headers: { 'X-API-Key': ADMIN_KEY } })).json();
  assert.equal(body.off_site.health.severity, 'ok');
});

test('an upload 2 h ago: ok; 30 h ago: failing with "older than 26 h"; back to ok after a fresh upload', async () => {
  setLastRun(new Date(Date.now() - 2 * 3_600_000).toISOString());
  assert.equal(checkPlatformBackupOffsite().ok, true);
  assert.equal(row().status, 'ok');

  setLastRun(new Date(Date.now() - 30 * 3_600_000).toISOString());
  const stale = checkPlatformBackupOffsite();
  assert.equal(stale.ok, false);
  assert.equal(stale.reason, 'stale');
  assert.equal(row().status, 'failing');
  assert.match(row().last_error, /older than 26 h/);
  const body = await (await fetch(`${BASE}/api/settings/backup/s3`, { headers: { 'X-API-Key': ADMIN_KEY } })).json();
  assert.equal(body.off_site.has_off_site_copy, true, 'a copy exists');
  assert.equal(body.off_site.health.ok, false, 'but it is not fresh, and the API says so');

  setLastRun(new Date(Date.now() - 25 * 3_600_000).toISOString());
  assert.equal(checkPlatformBackupOffsite().ok, true, '25 h is inside the limit');
  assert.equal(row().status, 'ok');
});

test('with Job Health alerts on, the failing transition still sends ONE e-mail per admin, and it is the one that says what to configure', async () => {
  db.prepare('DELETE FROM email_queue').run();
  db.prepare("DELETE FROM settings WHERE key LIKE 'backup_s3_%'").run();
  _resetJobHealthForTests();
  enableJobHealthAlerts();
  jobStarted(JOB_ID, { cadenceMs: 3_600_000 });
  checkPlatformBackupOffsite();
  await flush();
  checkPlatformBackupOffsite();
  await flush();
  _resetJobHealthForTests();
  const m = mails();
  assert.equal(m.length, 2, JSON.stringify(m.map((x) => x.subject)));
  for (const x of m) {
    assert.match(x.subject, /no S3 destination configured/);
    assert.match(x.body_text, /Fill in Bucket, Access key and Secret key/);
  }
});

test('a configured but never-uploaded destination: the e-mail says to run the upload, not to configure a bucket', async () => {
  db.prepare('DELETE FROM email_queue').run();
  configure();
  _resetJobHealthForTests();
  jobStarted(JOB_ID, { cadenceMs: 3_600_000 });
  checkPlatformBackupOffsite();
  await flush();
  const body = mails()[0].body_text;
  assert.match(body, /"Back up to S3 now"/);
  assert.doesNotMatch(body, /Fill in Bucket/);
});

test('after a key change the warning returns, the previous fingerprint is on record, and a restore that needs it says so', async () => {
  setLastRun(new Date(Date.now() - 1 * 3_600_000).toISOString());
  const oldKey = process.env.ENCRYPTION_KEY;
  const oldFp = keyFingerprint(oldKey);
  issueRecoveryKey(ADMIN_ID);
  assert.equal(checkPlatformBackupOffsite().severity, 'ok');
  process.env.ENCRYPTION_KEY = 'd'.repeat(64);
  try {
    const h = checkPlatformBackupOffsite();
    assert.equal(h.severity, 'warning', 'the new key has not been downloaded');
    const st = await (await fetch(`${BASE}/api/settings/backup/recovery-key`, { headers: { 'X-API-Key': ADMIN_KEY } })).json();
    assert.equal(st.previous_keys.length, 1);
    assert.equal(st.previous_keys[0].fingerprint, shortFingerprint(oldFp));
    assert.ok(st.previous_keys[0].replaced_at, 'the time the new key was first seen');
    assert.ok(st.previous_keys[0].downloaded_at, 'its recovery key had been downloaded');
    assert.ok(!JSON.stringify(st).includes(oldKey) && !JSON.stringify(st).includes('d'.repeat(64)), 'fingerprints only, never a key');
    assert.throws(() => planBackupKey({ encryption_key: { in_archive: false, fingerprint: oldFp } }, {}),
      (e) => /That key was this host's key from .* until .*; its recovery key was downloaded at /.test(e.message) && /Nothing was changed/.test(e.message));
  } finally {
    process.env.ENCRYPTION_KEY = oldKey;
  }
});
