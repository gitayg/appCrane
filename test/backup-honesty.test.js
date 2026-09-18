import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync } from 'fs';
import { execFileSync } from 'child_process';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// Backup honesty (v2.79.0).
//
// MEASURED ON A PRODUCTION INSTANCE running 62 apps: the backup status read
// `configured: false`, `last_run: null`. No copy of the database existed — not
// off this host, and not on it either, because the only scheduled backup
// AppCrane had was the off-site one and it is a no-op until someone enters a
// bucket and credentials. The platform's own words are "everything AppCrane
// knows lives in one SQLite file on this host", and nothing said that out loud
// anywhere an operator would trip over it.
//
// Two properties are under test, and they pull in opposite directions on
// purpose:
//
//   1. A FRESH INSTANCE TAKES A LOCAL BACKUP WITHOUT BEING ASKED. Not because
//      a local copy is good enough — it is on the same disk as the thing it
//      protects — but because it needs no destination, no credentials and no
//      decision, and it covers the failure that needs none of those either: the
//      single SQLite file corrupted, deleted, or replaced by a bad restore.
//      Default-off would reproduce exactly the state above: a capability that
//      ships switched off and is discovered during the incident.
//
//   2. IT IS NEVER ALLOWED TO READ AS "we are backed up". Every surface that
//      reports backup — the settings API, the MCP status tool, and the
//      dashboard through the API's own words — says NO_OFFSITE_NOTICE verbatim
//      until an upload has actually completed. Not when a bucket is merely
//      stored, not when the schedule is merely enabled: only when bytes have
//      demonstrably left the host.
//
// The archive contents are asserted from the tar itself, not from the manifest
// it declares: a scheduled job that quietly swept every hosted app's /data onto
// the same disk, seven copies deep, is how a backup takes a host down.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-backup-honesty-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { callTool } = await import('../server/services/mcpTools.js');
const {
  NO_OFFSITE_NOTICE, offSiteState, getBackupConfig, setBackupConfig,
} = await import('../server/services/backupScheduler.js');
const {
  getLocalBackupConfig, setLocalBackupConfig, runLocalBackup, listLocalBackups,
  localBackupsDir, KEEP_DEFAULT, HOUR_DEFAULT,
} = await import('../server/services/localBackup.js');

const ADMIN_KEY = generateApiKey('dhk_admin');
const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('PA','pa@example.com','platform_admin',?,1,'human')"
).run(hashApiKey(ADMIN_KEY)).lastInsertRowid;
const platformAdmin = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);

const settingsRoutes = (await import('../server/routes/settings.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/settings', settingsRoutes);
api.use(errorHandler);
const server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;
const getJson = async (p) => (await fetch(`${BASE}${p}`, { headers: { 'X-API-Key': ADMIN_KEY } })).json();

const unwrap = (r) => (typeof r === 'string' ? JSON.parse(r) : (r?.content ? JSON.parse(r.content[0].text) : r));
const status = async () => unwrap(await callTool(platformAdmin, 'appcrane_get_backup_status', {}));

const clearBackupSettings = () => db.prepare(
  "DELETE FROM settings WHERE key LIKE 'backup_s3_%' OR key LIKE 'backup_local_%'"
).run();

// ---------------------------------------------------------------------------
// 1. The default on a fresh instance
// ---------------------------------------------------------------------------

test('a fresh instance has the local backup ON, with no setting written at all', () => {
  clearBackupSettings();
  const rows = db.prepare("SELECT key FROM settings WHERE key LIKE 'backup_local_%'").all();
  assert.deepEqual(rows, [], 'precondition: no local-backup setting exists yet');

  const cfg = getLocalBackupConfig();
  assert.equal(cfg.enabled, true,
    'a fresh instance must keep a local copy without being asked — default-off is the measured failure this fixes');
  assert.equal(cfg.keep, KEEP_DEFAULT);
  assert.equal(cfg.hour, HOUR_DEFAULT);
  assert.equal(cfg.directory, join(ROOT, 'backups', 'local'));
  assert.deepEqual(cfg.contents, ['deployhub.db', '.env']);
  assert.equal(cfg.last_run, null);
});

test('a fresh instance has the OFF-SITE backup off, and says so rather than implying a copy exists', () => {
  clearBackupSettings();
  const off = offSiteState();
  assert.equal(off.configured, false);
  assert.equal(off.has_off_site_copy, false);
  assert.deepEqual(off.missing, ['bucket', 'access_key_id', 'secret_access_key']);
  assert.equal(off.notice,
    `${NO_OFFSITE_NOTICE} No off-site destination is configured (missing: bucket, access_key_id, secret_access_key).`);
});

test('an operator can still turn the local schedule off — the default is a default, not a lock', () => {
  clearBackupSettings();
  assert.equal(setLocalBackupConfig({ enabled: false }, adminId).enabled, false);
  assert.equal(getLocalBackupConfig().enabled, false);
  setLocalBackupConfig({ enabled: true }, adminId);
  assert.equal(getLocalBackupConfig().enabled, true);
  clearBackupSettings();
});

test('keep and hour are clamped, so a typo cannot fill the disk or disable the schedule by arithmetic', () => {
  clearBackupSettings();
  assert.equal(setLocalBackupConfig({ keep: 0 }, adminId).keep, 1);
  assert.equal(setLocalBackupConfig({ keep: 9999 }, adminId).keep, 60);
  assert.equal(setLocalBackupConfig({ hour: -3 }, adminId).hour, 0);
  assert.equal(setLocalBackupConfig({ hour: 47 }, adminId).hour, 23);
  clearBackupSettings();
});

// ---------------------------------------------------------------------------
// 2. "No off-site copy" on every surface
// ---------------------------------------------------------------------------

test('the settings API states the no-off-site notice, it is not left to be inferred from an empty bucket', async () => {
  clearBackupSettings();
  const body = await getJson('/api/settings/backup/s3');
  assert.equal(body.off_site.has_off_site_copy, false);
  assert.ok(body.off_site.notice.startsWith(NO_OFFSITE_NOTICE),
    `the API's off-site notice must lead with "${NO_OFFSITE_NOTICE}"; got: ${body.off_site.notice}`);
  // The flat fields the Settings form binds to are untouched.
  assert.equal(body.bucket, '');
  assert.equal(body.last_run, null);
});

test('the local-backup API carries the same notice, so the tab cannot show one without the other', async () => {
  clearBackupSettings();
  const body = await getJson('/api/settings/backup/local');
  assert.equal(body.enabled, true);
  assert.ok(body.off_site.notice.startsWith(NO_OFFSITE_NOTICE));
  assert.deepEqual(body.archives, []);
});

test('the MCP status tool leads its summary with the notice, verbatim', async () => {
  clearBackupSettings();
  const s = await status();
  assert.equal(s.off_site.has_off_site_copy, false);
  assert.ok(s.summary.startsWith(NO_OFFSITE_NOTICE),
    `the MCP summary must open with "${NO_OFFSITE_NOTICE}"; got: ${s.summary.slice(0, 120)}`);
  assert.match(s.summary, /NOT CONFIGURED/, 'the existing verdict is kept, not replaced');
  assert.match(s.summary, /Local nightly archive: ON/);
  assert.match(s.summary, /never the loss of the host/,
    'the local archive must never be offered as a substitute for an off-site copy');
  assert.deepEqual(s.local_covers, ['deployhub.db (apps, users, settings, encrypted env vars)', '.env']);
});

test('the dashboard renders the notice the server sends instead of composing its own wording', () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(join(here, '..', 'studio-web', 'src', 'pages', 'Settings.tsx'), 'utf8');
  // Anchored on the `{` so a guard slipped in front of it — `{false && …`, a
  // feature flag, an isPlatformAdmin that is already true one level up — does
  // not leave this assertion passing over a banner that no longer renders. A
  // loose substring match let exactly that mutation survive.
  assert.match(src, /\n\s*\{s3\.off_site\?\.notice && \(\n/,
    'the Backup tab must render the API\'s off_site.notice, gated on nothing but the notice itself');
  assert.match(src, /\{s3\.off_site\.notice\}/);
  assert.match(src, /Scheduled local backup \(on by default\)/);

  // The SPA that ships is the built bundle, not this source file: an edit that
  // is never rebuilt is invisible to every user of the dashboard.
  const bundleDir = join(here, '..', 'docs', 'admin-app', 'assets');
  const bundles = readdirSync(bundleDir).filter((f) => f.endsWith('.js'));
  const built = bundles.map((f) => readFileSync(join(bundleDir, f), 'utf8')).join('\n');
  assert.match(built, /off_site/, 'the committed admin bundle predates the off-site notice — rebuild it');
  assert.match(built, /Scheduled local backup \(on by default\)/,
    'the committed admin bundle has no local-backup section — rebuild it');
});

test('a stored bucket with the schedule off is still NO off-site copy', () => {
  clearBackupSettings();
  setBackupConfig({ bucket: 'crane-backups', access_key_id: 'AKIAEXAMPLE', secret_access_key: 'not-a-real-secret' }, adminId);
  const off = offSiteState();
  assert.equal(off.configured, true, 'precondition: every field is present');
  assert.equal(off.enabled, false);
  assert.equal(off.has_off_site_copy, false,
    'credentials on file are not a copy — nothing has been uploaded');
  assert.ok(off.notice.startsWith(NO_OFFSITE_NOTICE));
  assert.match(off.notice, /switched off and has never run/);
  clearBackupSettings();
});

test('an enabled schedule that has never completed is still NO off-site copy', () => {
  clearBackupSettings();
  setBackupConfig({ bucket: 'crane-backups', access_key_id: 'AKIAEXAMPLE', secret_access_key: 'not-a-real-secret', enabled: true }, adminId);
  const off = offSiteState();
  assert.equal(off.has_off_site_copy, false);
  assert.match(off.notice, /switched on but has never completed/);
  clearBackupSettings();
});

// ---------------------------------------------------------------------------
// 3. An instance that already has off-site backup is unchanged
// ---------------------------------------------------------------------------

test('an instance with a completed off-site upload gets no notice and keeps its existing verdict', async () => {
  clearBackupSettings();
  setBackupConfig({
    bucket: 'crane-backups', region: 'us-east-1', prefix: 'appcrane/',
    access_key_id: 'AKIAEXAMPLE', secret_access_key: 'not-a-real-secret', enabled: true, hour: 3,
  }, adminId);
  db.prepare("INSERT INTO settings (key, value) VALUES ('backup_s3_last_run', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .run(new Date(Date.now() - 2 * 3600_000).toISOString());

  const off = offSiteState();
  assert.equal(off.has_off_site_copy, true);
  assert.equal(off.notice, null, 'a host with a real off-site copy must not be told it has none');

  const s = await status();
  assert.ok(s.summary.startsWith('Healthy —'),
    `the pre-existing healthy verdict must be untouched; got: ${s.summary.slice(0, 80)}`);
  assert.doesNotMatch(s.summary, new RegExp(NO_OFFSITE_NOTICE.replace(/[.*+?^${}()|[\]\\—]/g, '\\$&')));
  assert.equal(s.healthy, true);

  // The config the Settings form reads is byte-for-byte what it was before the
  // off_site block existed.
  const body = await getJson('/api/settings/backup/s3');
  const { off_site, ...flat } = body;
  assert.deepEqual(flat, getBackupConfig(),
    'the off-site config payload gained a field and changed nothing else');
  assert.equal(off_site.notice, null);
  clearBackupSettings();
});

// ---------------------------------------------------------------------------
// 4. What the local backup actually writes
// ---------------------------------------------------------------------------

const tarList = (p) => execFileSync('tar', ['-tzf', p], { encoding: 'utf8' })
  .split('\n').map((s) => s.trim()).filter(Boolean);

test('a local backup holds the database and nothing from any hosted app', async () => {
  clearBackupSettings();
  // An app with real state on disk: it must NOT be swept into the nightly
  // archive, whose whole cost argument depends on being bounded.
  const appData = join(ROOT, 'apps', 'demo', 'production', 'shared', 'data');
  mkdirSync(appData, { recursive: true });
  writeFileSync(join(appData, 'big.bin'), 'x'.repeat(4096));

  const r = await runLocalBackup();
  assert.ok(existsSync(r.path), 'the archive was not written');
  assert.equal(dirname(r.path), localBackupsDir());
  assert.match(r.file, /^appcrane-platform-.*\.tar\.gz$/);

  const members = tarList(r.path);
  assert.ok(members.includes('appcrane-backup.json'), 'the manifest must be present');
  assert.ok(members.includes('deployhub.db'), 'the database is the point of the whole job');
  assert.deepEqual(members.filter((m) => m.startsWith('apps/')), [],
    'the nightly local archive must not copy hosted-app data onto the same disk it protects');

  const cfg = getLocalBackupConfig();
  assert.equal(cfg.last_file, r.file);
  assert.equal(cfg.last_error, null);
  assert.equal(cfg.last_bytes, r.bytes);
});

test('the archive declares its own partial scope, so a restore cannot mistake it for a full backup', async () => {
  clearBackupSettings();
  const r = await runLocalBackup();
  const work = mkdtempSync(join(tmpdir(), 'crane-manifest-'));
  execFileSync('tar', ['-xzf', r.path, '-C', work, 'appcrane-backup.json']);
  const manifest = JSON.parse(readFileSync(join(work, 'appcrane-backup.json'), 'utf8'));
  assert.equal(manifest.contents, 'platform');
  assert.ok(!manifest.includes.includes('appdata'), 'includes must not claim appdata');
  assert.ok(!manifest.includes.includes('appvolumes'));
  assert.ok(manifest.includes.includes('deployhub.db'));
});

test('retention keeps the newest N and deletes nothing else', async () => {
  clearBackupSettings();
  setLocalBackupConfig({ keep: 2 }, adminId);
  // A manual export sitting in the backups directory must survive: retention
  // only ever removes files this job named.
  const manual = join(ROOT, 'backups', 'appcrane-backup-manual.tar.gz');
  mkdirSync(join(ROOT, 'backups'), { recursive: true });
  writeFileSync(manual, 'manual');

  const written = [];
  for (let i = 0; i < 3; i++) written.push((await runLocalBackup()).file);

  const kept = (await listLocalBackups()).map((f) => f.file);
  assert.equal(kept.length, 2, `keep=2 must leave two archives, got ${kept.length}`);
  assert.deepEqual(kept, written.slice(-2).reverse(), 'the two newest are the ones kept');
  assert.ok(existsSync(manual), 'retention deleted an operator\'s own manual export');
  clearBackupSettings();
});
