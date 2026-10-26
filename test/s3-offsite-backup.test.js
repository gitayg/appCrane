import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync, createReadStream, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import { createHash, randomBytes } from 'crypto';
import express from 'express';
import { startFakeS3 } from './fake-s3.mjs';

// Off-site (S3) backup against an in-process fake S3 that verifies every
// request's SigV4 signature with its own implementation. No real AWS, no
// Docker: managed-database dumps come from a `docker` shim on PATH, repos are
// real git repos made by localGit.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-s3bk-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test';
process.env.APPCRANE_NO_RESTART_AFTER_IMPORT = '1';

const SHIM_DIR = join(ROOT, 'bin');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
const argv = process.argv.slice(2);
if (argv.includes('pg_dump') || argv.includes('mariadb-dump')) process.stdout.write('FAKE-DUMP ' + argv[argv.length - 1]);
`, { mode: 0o755 });
const REAL_PATH = process.env.PATH;
process.env.PATH = `${SHIM_DIR}:${REAL_PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const s3 = await import('../server/services/s3.js');
const sets = await import('../server/services/backupS3Sets.js');
const crypt = await import('../server/services/backupCrypto.js');
const sched = await import('../server/services/backupScheduler.js');
const mdb = await import('../server/services/managedDb.js');
const { getJobHealth, _resetJobHealthForTests } = await import('../server/services/jobHealth.js');
const { createAppRepo, pushFilesToManagedRepo } = await import('../server/services/localGit.js');
const { encrypt, generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

const fake = await startFakeS3();
after(async () => {
  await fake.close();
  process.env.PATH = REAL_PATH;
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

let slot = 0;
const appId = (slug) => Number(db.prepare("INSERT INTO apps (name, slug, slot, source_type, branch) VALUES (?, ?, ?, 'managed', 'main')").run(slug, slug, ++slot).lastInsertRowid);
const A = appId('s3-a');
for (const engine of ['postgres', 'mariadb']) {
  const { database, username } = mdb.namesForScope({ appId: A });
  db.prepare('INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc) VALUES (?, ?, ?, ?, ?, ?)')
    .run(A, '', engine, database, username, encrypt('pw-' + 'z'.repeat(30)));
}
mkdirSync(join(ROOT, 'apps', 's3-a', 'production', 'shared', 'data'), { recursive: true });
writeFileSync(join(ROOT, 'apps', 's3-a', 'production', 'shared', 'data', 'blob.bin'), randomBytes(300 * 1024));
await createAppRepo('shop', { description: 'shop' });
await pushFilesToManagedRepo('shop', [{ path: 'index.js', content: 'console.log(1)\n' }], { message: 'one' });
await createAppRepo('blog');

const sha = (b) => createHash('sha256').update(b).digest('hex');
const ops = () => ({ ...mdb.backupAccess, ensureServer: async () => {}, runAdminSql: async () => '', containerFor: (e) => `x-${e}` });
const configure = (extra = {}) => {
  db.prepare("DELETE FROM settings WHERE key LIKE 'backup_s3_%'").run();
  sched.setBackupConfig({
    bucket: fake.bucket, region: fake.region, endpoint: fake.endpoint, prefix: 'nightly/',
    access_key_id: fake.accessKeyId, secret_access_key: fake.secretAccessKey, ...extra,
  }, null);
};
const resetBucket = () => { fake.objects.clear(); fake.uploads.clear(); fake.log.length = 0; fake.state.failOn = null; fake.state.pageSize = 1000; };

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

test('the fake verifies signatures: right secret round-trips, wrong secret is refused', async () => {
  resetBucket();
  await s3.s3PutObject({ ...fake.conn, key: 'a/b c(1).txt', body: 'hello' });
  assert.equal((await s3.s3GetObject(fake.conn, 'a/b c(1).txt')).toString(), 'hello');
  await assert.rejects(s3.s3PutObject({ ...fake.conn, secretAccessKey: 'wrong', key: 'x', body: 'y' }),
    (e) => /SignatureDoesNotMatch/.test(e.message) && !e.message.includes('wrong'));
  assert.equal(fake.objects.has('x'), false);
});

test('multipart: a file larger than the part size uploads part by part with correct ETags and content', async () => {
  resetBucket();
  const file = join(ROOT, 'big.bin');
  const data = randomBytes(3.5 * 1024 * 1024);
  writeFileSync(file, data);
  const r = await s3.s3UploadStream(fake.conn, 'big/obj.bin', createReadStream(file), { partSize: 1024 * 1024 });
  console.log(`# multipart result: ${JSON.stringify({ parts: r.parts, multipart: r.multipart, etag: r.etag, bytes: r.bytes })}`);
  assert.equal(r.multipart, true);
  assert.equal(r.parts, 4);
  assert.match(r.etag, /-4"$/);
  assert.equal(r.bytes, data.length);
  assert.equal(r.sha256, sha(data));
  assert.ok(fake.objects.get('big/obj.bin').body.equals(data), 'stored object must be byte-identical');
  assert.deepEqual(fake.log.map((l) => l.op), ['CREATE-MULTIPART', 'UPLOAD-PART', 'UPLOAD-PART', 'UPLOAD-PART', 'UPLOAD-PART', 'COMPLETE-MULTIPART']);
  assert.deepEqual(fake.log.filter((l) => l.op === 'UPLOAD-PART').map((l) => l.bytes), [1048576, 1048576, 1048576, 524288]);
  assert.equal(fake.uploads.size, 0);
});

test('a stream smaller than one part is a single PUT', async () => {
  resetBucket();
  const r = await s3.s3UploadStream(fake.conn, 'small.bin', createReadStream(join(ROOT, 'big.bin'), { end: 999 }), { partSize: 1024 * 1024 });
  assert.equal(r.multipart, false);
  assert.deepEqual(fake.log.map((l) => l.op), ['PUT']);
  assert.equal(fake.objects.get('small.bin').body.length, 1000);
});

test('a failure mid-way aborts the multipart upload: no object, no orphaned parts', async () => {
  resetBucket();
  fake.state.failOn = (e) => e.op === 'UPLOAD-PART' && e.partNumber === '3';
  await assert.rejects(
    s3.s3UploadStream(fake.conn, 'big/fail.bin', createReadStream(join(ROOT, 'big.bin')), { partSize: 1024 * 1024 }),
    /UPLOAD-PART 3 failed \(500\): InternalError/,
  );
  console.log(`# ops on failure: ${fake.log.map((l) => l.op + (l.partNumber ? ` ${l.partNumber}` : '')).join(', ')}`);
  assert.equal(fake.log.at(-1).op, 'ABORT-MULTIPART');
  assert.equal(fake.uploads.size, 0, 'the upload must be aborted, not left with billed parts');
  assert.equal(fake.objects.has('big/fail.bin'), false);
});

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

// A set as a real run writes it: data object + a manifest signed under this ENCRYPTION_KEY.
function signedManifestFor(d, host) {
  const id = sets.setIdFor(d, host);
  return crypt.signManifest({
    kind: sets.MANIFEST_KIND, format: 1, set: id, host, created_at: d.toISOString(),
    artifacts: [{ kind: 'data', name: 'data.tar.gz', bytes: 1, sha256: sha(Buffer.from('x')), encrypted: false }],
  });
}

function seedDailySets({ host = 'crane.test', from = '2026-01-01', to = '2026-10-21', prefix = 'nightly/' } = {}) {
  for (let d = new Date(`${from}T03:00:00.000Z`); d <= new Date(`${to}T03:00:00.000Z`); d = new Date(d.getTime() + 86400000)) {
    const id = sets.setIdFor(d, host);
    fake.objects.set(`${prefix}${id}/data.tar.gz`, { body: Buffer.from('x'), last_modified: d.toISOString() });
    fake.objects.set(`${prefix}${id}/manifest.json`, { body: Buffer.from(JSON.stringify(signedManifestFor(d, host))), last_modified: d.toISOString() });
  }
}

test('retention keeps exactly 7 daily / 4 weekly / 6 monthly and deletes only this host\'s AppCrane objects', async () => {
  resetBucket();
  seedDailySets();
  seedDailySets({ host: 'other-host.test', from: '2026-01-01', to: '2026-01-10' });
  fake.objects.set('nightly/notes.txt', { body: Buffer.from('mine'), last_modified: '2026-01-01T00:00:00.000Z' });
  fake.objects.set('nightly/appcrane-backup-crane.test-garbage/x', { body: Buffer.from('?'), last_modified: '2026-01-01T00:00:00.000Z' });
  fake.objects.set('elsewhere/appcrane-backup-crane.test-2026-01-01T03-00-00-000Z/manifest.json', { body: Buffer.from('{}'), last_modified: '2026-01-01T00:00:00.000Z' });
  // An incomplete set and a legacy single-object backup carry no signature, so
  // retention neither counts nor deletes them (v2.114: names are not trusted).
  fake.objects.set('nightly/appcrane-backup-crane.test-2026-10-20T05-00-00-000Z/data.tar.gz', { body: Buffer.from('partial'), last_modified: '2026-10-20T05:00:00.000Z' });
  fake.objects.set('nightly/appcrane-backup-crane.test-2025-12-01T03-00-00-000Z.tar.gz', { body: Buffer.from('legacy'), last_modified: '2025-12-01T03:00:00.000Z' });
  const before = fake.objects.size;

  const r = await sets.applyRetention(fake.conn, 'nightly/', { daily: 7, weekly: 4, monthly: 6 }, { host: 'crane.test', justUploaded: 'appcrane-backup-crane.test-2026-10-21T03-00-00-000Z' });
  const kept = r.kept.map((k) => k.id.slice('appcrane-backup-crane.test-'.length, 'appcrane-backup-crane.test-'.length + 10));
  console.log(`# kept: ${kept.join(' ')}`);
  assert.equal(r.applied, true);
  assert.deepEqual(kept, ['2026-10-21', '2026-10-20', '2026-10-19', '2026-10-18', '2026-10-17', '2026-10-16', '2026-10-15', '2026-10-11', '2026-10-04', '2026-09-30', '2026-08-31', '2026-07-31', '2026-06-30', '2026-05-31']);
  const count = (reason) => r.kept.filter((k) => k.reasons.includes(reason)).length;
  assert.equal(count('daily'), 7);
  assert.equal(count('weekly'), 4);
  assert.equal(count('monthly'), 6);

  assert.equal(r.removed_sets.length, 294 - 14);
  assert.equal(r.deleted_objects, (294 - 14) * 2);
  assert.equal(r.unverified_ignored, 2, 'the incomplete and the legacy set are left alone');
  assert.ok(fake.objects.has('nightly/appcrane-backup-crane.test-2026-10-20T05-00-00-000Z/data.tar.gz'));
  assert.ok(fake.objects.has('nightly/appcrane-backup-crane.test-2025-12-01T03-00-00-000Z.tar.gz'));
  assert.equal(fake.objects.size, before - r.deleted_objects);
  for (const k of ['nightly/notes.txt', 'nightly/appcrane-backup-crane.test-garbage/x', 'elsewhere/appcrane-backup-crane.test-2026-01-01T03-00-00-000Z/manifest.json']) {
    assert.ok(fake.objects.has(k), `${k} is not AppCrane's set and must survive`);
  }
  assert.equal([...fake.objects.keys()].filter((k) => k.includes('other-host.test')).length, 20, 'another host\'s sets are never deleted');
});

test('retention refuses to delete when the listing cannot be trusted', async () => {
  resetBucket();
  fake.objects.set('nightly/someone-elses.bin', { body: Buffer.from('x'), last_modified: '2026-01-01T00:00:00.000Z' });
  let r = await sets.applyRetention(fake.conn, 'nightly/', { daily: 1, weekly: 0, monthly: 0 });
  assert.equal(r.applied, false);
  assert.match(r.refused, /no AppCrane backups for this host .* 1 other object/);

  seedDailySets({ from: '2026-08-01', to: '2026-10-21' });
  r = await sets.applyRetention(fake.conn, 'nightly/', { daily: 1, weekly: 0, monthly: 0 }, { justUploaded: 'appcrane-backup-crane.test-2026-10-22T03-00-00-000Z' });
  assert.match(r.refused, /does not show the backup that was just uploaded/);

  fake.state.pageSize = 1;
  const n = fake.objects.size;
  r = await sets.applyRetention(fake.conn, 'nightly/', { daily: 1, weekly: 0, monthly: 0 });
  assert.match(r.refused, /truncated/);
  assert.equal(fake.objects.size, n, 'nothing deleted on any refusal');
  assert.equal(fake.log.filter((l) => l.op === 'DELETE-OBJECTS').length, 0);
});

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

test('encryption round-trips, and a wrong key or a flipped byte fails authentication', async () => {
  const { pipeline } = await import('stream/promises');
  const { createWriteStream } = await import('fs');
  const src = join(ROOT, 'big.bin');
  const encFile = join(ROOT, 'big.enc');
  const key = crypt.archiveKey();
  await pipeline(createReadStream(src), crypt.encryptStream(key), createWriteStream(encFile));
  const out = join(ROOT, 'big.dec');
  const r = await crypt.decryptFile(encFile, out, key);
  assert.equal(r.sha256, sha(readFileSync(src)));
  assert.ok(!readFileSync(encFile).subarray(20, 60).equals(readFileSync(src).subarray(0, 40)), 'ciphertext is not plaintext');
  await assert.rejects(crypt.decryptFile(encFile, join(ROOT, 'x.dec'), Buffer.alloc(32, 1)), /failed authentication/);
  assert.equal(existsSync(join(ROOT, 'x.dec')), false);
  const buf = readFileSync(encFile); buf[1000] ^= 1; writeFileSync(encFile, buf);
  await assert.rejects(crypt.decryptFile(encFile, join(ROOT, 'y.dec'), key), /failed authentication/);
  assert.equal(existsSync(join(ROOT, 'y.dec')), false);
});

// ---------------------------------------------------------------------------
// Whole run: coverage, manifest, Job Health, fetch/verify, restore
// ---------------------------------------------------------------------------

const objectsOf = (setId) => [...fake.objects.keys()].filter((k) => k.startsWith(`nightly/${setId}/`)).map((k) => k.slice(`nightly/${setId}/`.length)).sort();

test('a run uploads data archive + managed DB dumps + every repo bundle + a manifest whose hashes match', async () => {
  resetBucket();
  _resetJobHealthForTests();
  configure({ encrypt: false });
  const r = await sched.runS3Backup({ partSize: 64 * 1024, managedDbOps: ops(), at: new Date('2026-10-21T03:00:00.000Z') });
  console.log(`# objects: ${objectsOf(r.set).join(', ')}`);
  assert.deepEqual(objectsOf(r.set).map((k) => k.replace(/-[0-9a-f]{12}-\d{4}-\d{2}-\d{2}\.tar$/, '-<fp>.tar')),
    ['data.tar.gz', 'manifest.json', 'repos/appcrane-repo-blog-<fp>.tar', 'repos/appcrane-repo-shop-<fp>.tar']);
  const manifest = JSON.parse(fake.objects.get(`nightly/${r.set}/manifest.json`).body);
  for (const a of manifest.artifacts) {
    const body = fake.objects.get(`nightly/${r.set}/${a.name}`).body;
    assert.equal(a.sha256, sha(body), `${a.name} hash in manifest`);
    assert.equal(a.bytes, body.length);
  }
  assert.deepEqual(manifest.artifacts.filter((a) => a.kind === 'repo').map((a) => a.slug).sort(), ['blog', 'shop']);
  assert.equal(manifest.data.managed_db.databases, 2);
  assert.ok(manifest.covers.includes('managed-app git repositories'));
  const dataFile = join(ROOT, 'dl.tar.gz');
  writeFileSync(dataFile, fake.objects.get(`nightly/${r.set}/data.tar.gz`).body);
  const members = execFileSync('tar', ['-tzf', dataFile]).toString().split('\n');
  assert.ok(members.includes('deployhub.db'));
  assert.ok(members.includes('apps/s3-a/production/shared/data/blob.bin'), 'per-app /data is in the off-site set');
  assert.deepEqual(members.filter((m) => /^managed-db\/.+\.dump$/.test(m)).sort(),
    db.prepare('SELECT engine, db_name FROM managed_databases').all().map((x) => `managed-db/${x.engine}/${x.db_name}.dump`).sort());
  assert.ok(fake.log.some((l) => l.op === 'COMPLETE-MULTIPART'), 'the data archive is bigger than the 64 KB part size and went multipart');

  const job = getJobHealth().find((j) => j.id === 'offsite-backup');
  assert.equal(job.last_run.ok, true);
  assert.equal(job.detail.last_success_bytes, r.size);
  assert.equal(job.detail.artifacts, 3, "data archive + two repo archives");
  const cfg = sched.getBackupConfig();
  assert.equal(cfg.last_bytes, r.size);
  assert.equal(cfg.last_set, r.set);
  assert.ok(cfg.last_duration_ms >= 0);
  assert.equal(r.retention.applied, true);
  assert.equal([...readdirSync(join(ROOT, 'backups'))].filter((n) => n.startsWith('appcrane-repo-')).length, 0, 'repo archives for the upload are not left in DATA_DIR/backups');
});

test('Job Health records a failed run, without the secret in the error', async () => {
  resetBucket();
  _resetJobHealthForTests();
  configure({ secret_access_key: 'definitely-wrong-secret' });
  await assert.rejects(sched.runS3Backup({ managedDbOps: ops() }), /SignatureDoesNotMatch/);
  const job = getJobHealth().find((j) => j.id === 'offsite-backup');
  assert.equal(job.last_run.ok, false);
  assert.match(job.last_error, /SignatureDoesNotMatch/);
  assert.ok(!JSON.stringify(job).includes('definitely-wrong-secret'));
  assert.equal([...fake.objects.keys()].length, 0, 'nothing left in the bucket');
});

test('a run that fails part-way removes what it uploaded and aborts the multipart upload', async () => {
  resetBucket();
  configure({ encrypt: false });
  fake.state.failOn = (e) => e.op === 'PUT' && /\/repos\//.test(e.key || '');
  await assert.rejects(sched.runS3Backup({ partSize: 64 * 1024, managedDbOps: ops() }), /S3 PUT failed \(500\)/);
  assert.ok(fake.log.some((l) => l.op === 'COMPLETE-MULTIPART'), 'precondition: the data archive was uploaded first');
  assert.deepEqual([...fake.objects.keys()], [], 'the partial set is deleted, so no unverifiable half-backup is left');
  assert.equal(fake.uploads.size, 0);
  assert.match(sched.getBackupConfig().last_error, /S3 PUT failed \(500\)/);
});

test('encrypted run: objects are ciphertext; fetch verifies hash + tag and restores plaintext; tampering is caught', async () => {
  resetBucket();
  configure({ encrypt: true, sse: 'AES256' });
  const r = await sched.runS3Backup({ partSize: 64 * 1024, managedDbOps: ops() });
  const names = objectsOf(r.set);
  assert.ok(names.filter((n) => n !== 'manifest.json').every((n) => n.endsWith('.enc')), names.join(','));
  const stored = fake.objects.get(`nightly/${r.set}/data.tar.gz.enc`).body;
  assert.notDeepEqual([...stored.subarray(0, 2)], [0x1f, 0x8b], 'not a plain gzip');
  assert.ok(fake.log.filter((l) => l.op === 'PUT' || l.op === 'CREATE-MULTIPART').every((l) => l.sse === 'AES256'), 'SSE header on every object');

  const out = join(ROOT, 'fetched');
  const f = await sched.fetchS3Backup(r.set, out);
  const manifest = JSON.parse(fake.objects.get(`nightly/${r.set}/manifest.json`).body);
  for (const file of f.files) {
    const a = manifest.artifacts.find((x) => x.name === file.name);
    assert.equal(sha(readFileSync(file.path)), a.plain_sha256);
    assert.equal(file.verified, true);
  }
  assert.deepEqual([...readFileSync(f.files.find((x) => x.kind === 'data').path).subarray(0, 2)], [0x1f, 0x8b]);

  const k = `nightly/${r.set}/data.tar.gz.enc`;
  const bad = Buffer.from(fake.objects.get(k).body); bad[bad.length >> 1] ^= 0xff;
  fake.objects.get(k).body = bad;
  const out2 = join(ROOT, 'fetched2');
  await assert.rejects(sched.fetchS3Backup(r.set, out2), /data\.tar\.gz\.enc failed verification: expected/);
  assert.deepEqual(existsSync(out2) ? readdirSync(out2) : [], [], 'nothing lands when verification fails');
});

test('test connection: PUT + GET + DELETE a probe; a bad secret fails at put with a clear error', async () => {
  resetBucket();
  configure();
  const ok = await sched.testS3Connection();
  assert.deepEqual(ok.steps.map((s) => [s.step, s.ok]), [['put', true], ['get', true], ['delete', true]]);
  assert.equal(fake.objects.size, 0, 'probe deleted');
  const bad = await sched.testS3Connection({ secret_access_key: 'nope-secret' });
  assert.equal(bad.ok, false);
  assert.match(bad.steps[0].error, /S3 PUT failed \(403\): SignatureDoesNotMatch/);
  assert.ok(!JSON.stringify(bad).includes('nope-secret'));
  const none = await sched.testS3Connection({ bucket: '', access_key_id: '' });
  assert.equal(none.ok, true, 'blank overrides fall back to the saved config');
});

test('routes: platform admin lists, downloads (verified) and restores; a typed confirmation is required; others are refused', async () => {
  resetBucket();
  configure({ encrypt: false });
  const r = await sched.runS3Backup({ managedDbOps: ops() });
  const PA = generateApiKey('dhk_admin');
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('PA','pa@example.com','platform_admin',?,1,'human')").run(hashApiKey(PA));
  const U = generateApiKey('dhk_user');
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','u@example.com','user',?,1,'human')").run(hashApiKey(U));
  const settingsRoutes = (await import('../server/routes/settings.js')).default;
  const api = express();
  api.use(express.json());
  api.use('/api/settings', settingsRoutes);
  api.use((await import('../server/utils/errors.js')).errorHandler);
  const server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  const BASE = `http://127.0.0.1:${server.address().port}`;
  const call = (method, p, key, body) => fetch(`${BASE}${p}`, { method, headers: { 'X-API-Key': key, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  try {
    assert.equal((await call('GET', '/api/settings/backup/s3/backups', U)).status, 403);
    const list = await (await call('GET', '/api/settings/backup/s3/backups', PA)).json();
    assert.deepEqual(list.backups.map((b) => [b.id, b.own, b.complete]), [[r.set, true, true]]);

    const dl = await call('GET', `/api/settings/backup/s3/backups/${r.set}/download`, PA);
    assert.equal(dl.status, 200);
    assert.equal(dl.headers.get('x-appcrane-verified'), 'sha256');
    const manifest = JSON.parse(fake.objects.get(`nightly/${r.set}/manifest.json`).body);
    assert.equal(sha(Buffer.from(await dl.arrayBuffer())), manifest.artifacts.find((a) => a.kind === 'data').sha256);

    const k = `nightly/${r.set}/data.tar.gz`;
    const orig = fake.objects.get(k).body;
    const bad = Buffer.from(orig); bad[10] ^= 1; fake.objects.get(k).body = bad;
    const dlBad = await call('GET', `/api/settings/backup/s3/backups/${r.set}/download`, PA);
    assert.equal(dlBad.status, 502);
    assert.match((await dlBad.json()).error.message, /failed verification/);
    fake.objects.get(k).body = orig;

    assert.equal((await call('POST', `/api/settings/backup/s3/backups/${r.set}/restore`, PA, {})).status, 400);
    assert.equal((await call('POST', `/api/settings/backup/s3/backups/${r.set}/restore`, U, { confirm: r.set })).status, 403);
    const restored = await call('POST', `/api/settings/backup/s3/backups/${r.set}/restore`, PA, { confirm: r.set });
    const body = await restored.json();
    assert.equal(restored.status, 200, JSON.stringify(body).slice(0, 400));
    assert.deepEqual(body.repos.restored.sort(), ['blog', 'shop']);
    assert.equal(body.repo_verification.matched, true);
  } finally {
    server.closeAllConnections?.();
    await new Promise((res) => server.close(res));
  }
});
