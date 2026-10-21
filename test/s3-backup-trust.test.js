import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, existsSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, createHmac } from 'crypto';
import { startFakeS3 } from './fake-s3.mjs';

// Off-site backup sets are trusted on a signature, not on their names
// (security review 2026-10, F-003). Someone with write access to the bucket can
// plant objects with any name; this drives the review's proof scenario (10
// genuine nightly sets, 7 forged future-dated ones) through the real retention,
// listing, download and restore code against the in-process fake S3.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-s3trust-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test';
process.env.APPCRANE_NO_RESTART_AFTER_IMPORT = '1';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const sets = await import('../server/services/backupS3Sets.js');
const crypt = await import('../server/services/backupCrypto.js');
const sched = await import('../server/services/backupScheduler.js');

const fake = await startFakeS3();
after(async () => {
  await fake.close();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const HOST = 'crane.test';
const PREFIX = 'nightly/';
const POLICY = { daily: 7, weekly: 4, monthly: 6 };
const sha = (b) => createHash('sha256').update(b).digest('hex');
const DATA = Buffer.from([0x1f, 0x8b, 0x08, 0x00]);

const configure = (extra = {}) => {
  db.prepare("DELETE FROM settings WHERE key LIKE 'backup_s3_%'").run();
  sched.setBackupConfig({
    bucket: fake.bucket, region: fake.region, endpoint: fake.endpoint, prefix: PREFIX,
    access_key_id: fake.accessKeyId, secret_access_key: fake.secretAccessKey, ...extra,
  }, null);
};
const reset = () => { fake.objects.clear(); fake.uploads.clear(); fake.log.length = 0; fake.state.failOn = null; fake.state.pageSize = 1000; };
const put = (key, body) => fake.objects.set(key, { body: Buffer.isBuffer(body) ? body : Buffer.from(body), last_modified: new Date().toISOString() });

function manifestFor(at, host = HOST) {
  return {
    kind: sets.MANIFEST_KIND, format: 1, set: sets.setIdFor(at, host), host, created_at: at.toISOString(),
    artifacts: [{ kind: 'data', name: 'data.tar.gz', bytes: DATA.length, sha256: sha(DATA), encrypted: false }],
  };
}

/** A set as AppCrane writes it (signed with this host's key) or as an attacker plants it. */
function plant(at, { sign = true, manifest = null, host = HOST } = {}) {
  const m = manifest || manifestFor(at, host);
  const id = sets.setIdFor(at, host);
  put(`${PREFIX}${id}/data.tar.gz`, DATA);
  put(`${PREFIX}${id}/manifest.json`, JSON.stringify(sign ? crypt.signManifest(m) : m));
  return id;
}

function seedGenuine() {
  const ids = [];
  for (let d = 11; d <= 20; d++) ids.push(plant(new Date(`2026-10-${d}T03:00:00.000Z`)));
  return ids;
}

const forgeries = {
  'empty manifest': (at) => { const id = sets.setIdFor(at, HOST); put(`${PREFIX}${id}/manifest.json`, '{}'); return id; },
  'well-formed but unsigned': (at) => plant(at, { sign: false }),
  'signed with another key': (at) => {
    const m = manifestFor(at);
    const { signature: _s, ...body } = crypt.signManifest(m);
    const mac = createHmac('sha256', Buffer.alloc(32, 7)).update(crypt.canonicalJson(body)).digest('hex');
    const id = sets.setIdFor(at, HOST);
    put(`${PREFIX}${id}/data.tar.gz`, DATA);
    put(`${PREFIX}${id}/manifest.json`, JSON.stringify({ ...body, signature: { alg: 'hmac-sha256', mac } }));
    return id;
  },
  'a genuine signed manifest copied under a future name': (at, genuineId) => {
    const id = sets.setIdFor(at, HOST);
    put(`${PREFIX}${id}/manifest.json`, fake.objects.get(`${PREFIX}${genuineId}/manifest.json`).body);
    put(`${PREFIX}${id}/data.tar.gz`, DATA);
    return id;
  },
};

test('F-003 proof scenario: 10 genuine + 7 forged future-dated sets; retention deletes nothing it would not have, the forgeries are not latest and not restorable', async () => {
  reset();
  const genuine = seedGenuine();
  const baseline = await sets.applyRetention(fake.conn, PREFIX, POLICY, { host: HOST, justUploaded: genuine.at(-1) });
  const baselineRemoved = [...baseline.removed_sets].sort();
  console.log(`# baseline (genuine only): kept ${baseline.kept.length}, removed ${baseline.removed_sets.length}`);

  for (const [label, forge] of Object.entries(forgeries)) {
    reset();
    const ids = seedGenuine();
    const forged = [];
    for (let d = 1; d <= 7; d++) forged.push(forge(new Date(`2099-01-0${d}T00:00:00.000Z`), ids.at(-1)));
    const before = fake.objects.size;
    const r = await sets.applyRetention(fake.conn, PREFIX, POLICY, { host: HOST, justUploaded: ids.at(-1) });
    const genuineRemoved = ids.filter((id) => r.removed_sets.includes(id));
    console.log(`# ${label}: applied=${r.applied} genuine removed ${genuineRemoved.length} of ${ids.length} (baseline ${baselineRemoved.length}), forged ignored ${r.unverified_ignored}, forged deleted ${forged.filter((id) => r.removed_sets.includes(id)).length}`);
    assert.equal(r.applied, true, label);
    assert.deepEqual([...genuineRemoved].sort(), baselineRemoved, `${label}: forged sets changed which genuine sets are deleted`);
    assert.equal(r.unverified_ignored, 7, label);
    assert.ok(!r.kept.some((k) => forged.includes(k.id)), `${label}: a forged set took a retention slot`);
    assert.ok(forged.every((id) => [...fake.objects.keys()].some((k) => k.startsWith(`${PREFIX}${id}/`))), `${label}: retention deleted a forged set (it must never act on unverified objects)`);
    assert.equal(fake.objects.size, before - r.deleted_objects);
  }

  configure({ encrypt: false });
  const list = await sched.listS3Backups();
  console.log(`# listing: first=${list.backups[0].id} verified=${list.backups[0].verified} latest_verified=${list.latest_verified} unverified=${list.unverified}`);
  assert.equal(list.latest_verified, 'appcrane-backup-crane.test-2026-10-20T03-00-00-000Z');
  assert.equal(list.backups[0].id, list.latest_verified, 'a forged future-dated set is listed first');
  const forgedRows = list.backups.filter((b) => b.id.includes('2099-'));
  assert.equal(forgedRows.length, 7);
  assert.ok(forgedRows.every((b) => !b.verified && !b.restorable && !b.downloadable), JSON.stringify(forgedRows[0]));

  const forgedId = forgedRows[0].id;
  await assert.rejects(sched.restoreS3Backup(forgedId), (e) => e.status === 409 && e.code === 'BACKUP_UNVERIFIED');
  const out = join(ROOT, 'dl-forged');
  await assert.rejects(sched.fetchS3Backup(forgedId, out), (e) => e.status === 409);
  assert.deepEqual(existsSync(out) ? readdirSync(out) : [], [], 'nothing of a forged set is downloaded');
  assert.ok(!fake.log.some((l) => l.op === 'GET' && l.key === `${PREFIX}${forgedId}/data.tar.gz`), 'the forged data archive was fetched before the manifest was authenticated');
});

test('F-003 a tampered manifest is rejected; a genuine signed set verifies', async () => {
  reset();
  configure({ encrypt: false });
  const at = new Date('2026-10-20T03:00:00.000Z');
  const id = plant(at);
  const m = await sets.readManifest(fake.conn, PREFIX, id);
  assert.equal(m.set, id, 'baseline: the signed set verifies');
  assert.equal((await sched.getS3BackupManifest(id)).verified, true);

  const signed = JSON.parse(fake.objects.get(`${PREFIX}${id}/manifest.json`).body);
  const edits = {
    'artifact hash swapped': (x) => { x.artifacts[0].sha256 = sha(Buffer.from('attacker data')); },
    'created_at moved': (x) => { x.created_at = '2099-01-01T00:00:00.000Z'; },
    'repo artifact added': (x) => { x.artifacts.push({ kind: 'repo', slug: 'shop', name: 'repos/appcrane-repo-shop-aaaaaaaaaaaa-2026-10-20.tar', bytes: 1, sha256: sha(DATA), encrypted: false }); },
    'signature removed': (x) => { delete x.signature; },
  };
  for (const [label, edit] of Object.entries(edits)) {
    const copy = structuredClone(signed);
    edit(copy);
    put(`${PREFIX}${id}/manifest.json`, JSON.stringify(copy));
    await assert.rejects(sets.readManifest(fake.conn, PREFIX, id), (e) => e.status === 409 && /no valid signature/.test(e.message), label);
  }
  put(`${PREFIX}${id}/manifest.json`, JSON.stringify(signed));
  assert.equal((await sets.readManifest(fake.conn, PREFIX, id)).set, id);
});

test('F-003 manifest fields are validated strictly, even when signed', async () => {
  reset();
  const at = new Date('2026-10-20T03:00:00.000Z');
  const bad = {
    'unknown artifact kind': (m) => { m.artifacts.push({ kind: 'env', name: 'repos/appcrane-repo-shop-aaaaaaaaaaaa-2026-10-20.tar', bytes: 1, sha256: sha(DATA), encrypted: false }); },
    'repo slug that is a path': (m) => { m.artifacts.push({ kind: 'repo', slug: '../etc', name: 'repos/appcrane-repo-shop-aaaaaaaaaaaa-2026-10-20.tar', bytes: 1, sha256: sha(DATA), encrypted: false }); },
    'repo artifact for another slug': (m) => { m.artifacts.push({ kind: 'repo', slug: 'blog', name: 'repos/appcrane-repo-shop-aaaaaaaaaaaa-2026-10-20.tar', bytes: 1, sha256: sha(DATA), encrypted: false }); },
    'two data archives': (m) => { m.artifacts.push({ ...m.artifacts[0], name: 'data.tar.gz.enc', encrypted: true, plain_sha256: sha(DATA) }); },
    'created_at not the set name': (m) => { m.created_at = '2026-10-19T03:00:00.000Z'; },
    'host not the set name': (m) => { m.host = 'other.test'; },
  };
  for (const [label, edit] of Object.entries(bad)) {
    const m = manifestFor(at);
    edit(m);
    const id = plant(at, { manifest: m });
    await assert.rejects(sets.readManifest(fake.conn, PREFIX, id), (e) => e.status === 409 && !/no valid signature/.test(e.message), label);
  }
  const id = plant(at);
  assert.equal((await sets.readManifest(fake.conn, PREFIX, id)).set, id, 'baseline: the unedited signed manifest passes');
});

test('F-003 a real run writes a signed manifest that verifies; legacy sets are download-only', async () => {
  reset();
  configure({ encrypt: false });
  const r = await sched.runS3Backup({ at: new Date('2026-10-21T03:00:00.000Z') });
  const stored = JSON.parse(fake.objects.get(`${PREFIX}${r.set}/manifest.json`).body);
  assert.equal(stored.signature.alg, 'hmac-sha256');
  assert.ok(crypt.manifestSignatureValid(stored));
  assert.equal(r.retention.applied, true, 'retention accepts the set it just wrote');

  put(`${PREFIX}appcrane-backup-crane.test-2025-12-01T03-00-00-000Z.tar.gz`, DATA);
  const list = await sched.listS3Backups();
  const legacy = list.backups.find((b) => b.legacy);
  assert.deepEqual([legacy.verified, legacy.restorable, legacy.downloadable], [false, false, true]);
  assert.equal(list.backups.find((b) => b.id === r.set).verified, true);
  await assert.rejects(sched.restoreS3Backup(legacy.id), (e) => e.status === 409);
  const f = await sched.fetchS3Backup(legacy.id, join(ROOT, 'legacy-dl'));
  assert.equal(f.files[0].verified, false);
});

test('F-003 client-side encryption is on by default for a new config; an existing config keeps its setting', async () => {
  configure();
  assert.equal(sched.getBackupConfig().encrypt, true, 'a new config must encrypt by default');
  configure({ encrypt: false });
  assert.equal(sched.getBackupConfig().encrypt, false, 'an explicit choice is kept');
  db.prepare("DELETE FROM settings WHERE key = 'backup_s3_encrypt'").run();
  assert.equal(sched.getBackupConfig().encrypt, false, 'a config saved before the default (bucket, no encrypt row) stays as it was: off');
  sched.setBackupConfig({ region: 'eu-west-1' }, null);
  assert.equal(sched.getBackupConfig().encrypt, false, 'editing an existing config does not flip it');
});
