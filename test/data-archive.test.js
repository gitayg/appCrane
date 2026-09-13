import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import {
  mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync, mkdirSync, readdirSync, symlinkSync, lstatSync,
} from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { createHash } from 'crypto';
import { gzipSync } from 'zlib';
import http from 'http';
import AdmZip from 'adm-zip';
import express from 'express';
import Database from 'better-sqlite3';

// The DATA archive (v2.74.0): DB + .env + icons + /data + declared volumes,
// written by a spawned tar to a file and restored from a file. Properties:
//   - round trip proven by SHA of every byte restored, and by the DB's rows;
//   - the restored DB is the one that opens after restart, even over a live
//     WAL (measured: without removing -wal the restore silently reverts);
//   - symlinks are archived as links, never dereferenced into host files;
//   - traversal and write-through-symlink are refused, with archives built BY
//     HAND so the hostile names reach the guards (adm-zip's writer would
//     normalise them away);
//   - routes: upload streamed to disk, path import confined, download piped.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-dataarch-'));
const OUTSIDE = mkdtempSync(join(tmpdir(), 'crane-outside-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPCRANE_NO_RESTART_AFTER_IMPORT = '1';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { exportDataArchive, importDataArchive, snapshotDatabase } = await import('../server/services/configBackup.js');

after(() => {
  for (const d of [ROOT, OUTSIDE]) { try { rmSync(d, { recursive: true, force: true }); } catch (_) {} }
});

const BACKUPS = join(ROOT, 'backups');
const sha256 = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const liveDb = () => join(ROOT, 'deployhub.db');
const shared = (slug, env, ...p) => join(ROOT, 'apps', slug, env, 'shared', ...p);

function writeTree(files) {
  for (const [p, content] of Object.entries(files)) {
    mkdirSync(join(p, '..'), { recursive: true });
    writeFileSync(p, content);
  }
}

/** Rows of every table in a DB file, opened independently of the live connection. */
function dump(file, tables = ['settings']) {
  const d = new Database(file, { readonly: true });
  try { return Object.fromEntries(tables.map((t) => [t, d.prepare(`SELECT * FROM ${t} ORDER BY rowid`).all()])); }
  finally { d.close(); }
}

// Writes go to the DB FILE through a fresh connection, the way a restarted
// server opens it. After an import this process's `db` still holds the
// replaced inode (production exits at that point), and the export snapshots
// the file, so fixtures written through `db` would silently miss the archive.
function setSettingOn(conn, k, v) {
  conn.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(k, v);
}
function setSetting(k, v) {
  const c = new Database(liveDb());
  try { setSettingOn(c, k, v); } finally { c.close(); }
}

// --- a hand-built tar, so names are exactly what we write -------------------
function tarHeader(name, { size = 0, type = '0', linkname = '', mode = 0o644 } = {}) {
  const h = Buffer.alloc(512, 0);
  h.write(name, 0, 100, 'utf8');
  h.write(`${mode.toString(8).padStart(7, '0')}\0`, 100, 8);
  h.write('0000000\0', 108, 8);
  h.write('0000000\0', 116, 8);
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 12);
  h.write(`${Math.floor(Date.now() / 1000).toString(8).padStart(11, '0')}\0`, 136, 12);
  h.write('        ', 148, 8);
  h.write(type, 156, 1);
  h.write(linkname, 157, 100, 'utf8');
  h.write('ustar\0', 257, 6);
  h.write('00', 263, 2);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8);
  return h;
}
function rawTarGz(entries) {
  const parts = [];
  for (const e of entries) {
    const data = e.data ? Buffer.from(e.data) : Buffer.alloc(0);
    parts.push(tarHeader(e.name, { size: data.length, type: e.type || '0', linkname: e.linkname || '', mode: e.type === '5' ? 0o755 : 0o644 }));
    if (data.length) parts.push(data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}
async function hostileArchive(name, extra) {
  const tmpDb = join(ROOT, `hostile-src-${name}.db`);
  await snapshotDatabase(tmpDb);
  const dbBytes = readFileSync(tmpDb);
  rmSync(tmpDb);
  mkdirSync(BACKUPS, { recursive: true });
  const dest = join(BACKUPS, `hostile-${name}.tar.gz`);
  writeFileSync(dest, rawTarGz([
    { name: 'appcrane-backup.json', data: JSON.stringify({ kind: 'appcrane-config-backup', format: 2, exported_at: new Date().toISOString(), bytes: { total: dbBytes.length } }) },
    { name: 'deployhub.db', data: dbBytes },
    ...extra,
  ]));
  return dest;
}

// ---------------------------------------------------------------------------

test('the restored DB survives a live WAL: a restart must not replay pre-import writes over it', async () => {
  // Measured before this change: a restored file renamed over a WAL-mode DB
  // whose -wal still holds frames reopens as the PRE-import data.
  // FIRST in this file: after an import the live connection writes to an
  // unlinked -wal (the server exits at that point in production), so only the
  // first import here can have a real WAL beside it.
  const out = await exportDataArchive({ version: '2.74.0' });
  db.pragma('wal_autocheckpoint = 0');
  try {
    for (let i = 0; i < 300; i++) setSettingOn(db, `wal_row_${i}`, 'written after export, before import');
    assert.ok(readFileSync(`${liveDb()}-wal`).length > 0, 'fixture: the WAL holds frames');
    await importDataArchive(out.path, { restoreEnv: false });
  } finally {
    db.pragma('wal_autocheckpoint = 1000');
  }
  const reopened = dump(liveDb());
  assert.equal(reopened.settings.filter((s) => s.key.startsWith('wal_row_')).length, 0,
    'the pre-import WAL was replayed over the restored database');
});

test('data round trip: DB rows, .env-less host, icons, /data and volumes come back byte-identical', async () => {
  const files = {
    [join(ROOT, 'apps', 'shop', 'icon.png')]: Buffer.from([137, 80, 78, 71, 1, 2, 3]),
    [shared('shop', 'production', 'data', 'db', 'store.sqlite')]: Buffer.from(Array.from({ length: 70000 }, (_, i) => (i * 7) & 255)),
    [shared('shop', 'production', 'data', 'uploads', 'a b.txt')]: 'spaces in a name',
    [shared('shop', 'sandbox', 'data', 'x.json')]: '{"sandbox":true}',
    [shared('shop', 'production', 'volumes', 'var', 'lib', 'pg', 'base')]: 'PG-STATE',
  };
  writeTree(files);
  mkdirSync(shared('shop', 'production', 'data', 'empty-dir'), { recursive: true });
  setSetting('roundtrip_marker', 'BACKED-UP');
  const before = Object.fromEntries(Object.keys(files).map((p) => [p, sha256(p)]));
  const rowsBefore = dump(liveDb());

  const out = await exportDataArchive({ version: '2.74.0' });
  assert.match(out.file, /^appcrane-backup-appcrane-[0-9a-f]{12}-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z\.tar\.gz$/);
  assert.equal(lstatSync(out.path).mode & 0o777, 0o600, 'a key-bearing archive must not be world-readable');
  const members = execFileSync('tar', ['-tzf', out.path]).toString().trim().split('\n');
  assert.equal(members[0], 'appcrane-backup.json', 'the manifest must be the first member');

  // Wipe: change the DB, destroy every tree.
  setSetting('roundtrip_marker', 'CHANGED-AFTER-EXPORT');
  setSetting('only_after_export', 'x');
  rmSync(join(ROOT, 'apps'), { recursive: true, force: true });

  const r = await importDataArchive(out.path, { restoreEnv: false });
  const after = Object.fromEntries(Object.keys(files).map((p) => [p, existsSync(p) ? sha256(p) : null]));
  console.log(`# data SHA round trip:\n${Object.keys(files).map((p) => `#  ${p.slice(ROOT.length)}  before=${before[p].slice(0, 16)} after=${after[p]?.slice(0, 16)}`).join('\n')}`);
  assert.deepEqual(after, before, 'every restored file must be byte-identical');
  assert.equal(existsSync(shared('shop', 'production', 'data', 'empty-dir')), true, 'empty directories come back too');
  assert.equal(r.icons, 1);
  assert.equal(r.dataFiles, 3);
  assert.equal(r.volumeFiles, 1);

  const rowsAfter = dump(liveDb());
  console.log(`# DB round trip: marker after import = ${JSON.stringify(rowsAfter.settings.find((s) => s.key === 'roundtrip_marker')?.value)}, rows before=${rowsBefore.settings.length} after=${rowsAfter.settings.length}`);
  assert.deepEqual(rowsAfter, rowsBefore, 'the restored DB must hold exactly the exported rows');
  assert.ok(existsSync(join(r.preImportDir, 'deployhub.db')), 'the replaced DB must be kept');
  assert.equal(dump(join(r.preImportDir, 'deployhub.db')).settings.find((s) => s.key === 'roundtrip_marker').value, 'CHANGED-AFTER-EXPORT');
  assert.deepEqual(readdirSync(BACKUPS).filter((n) => n.startsWith('.')), [], 'no work dir left behind');
});

test('a symlink in /data is archived as a link, never as the host file it points at', async () => {
  writeFileSync(join(OUTSIDE, 'host-secret.txt'), 'HOST-SECRET');
  const link = shared('leaky', 'production', 'data', 'innocent.txt');
  mkdirSync(join(link, '..'), { recursive: true });
  symlinkSync(join(OUTSIDE, 'host-secret.txt'), link);

  const out = await exportDataArchive({ version: '2.74.0' });
  const listing = execFileSync('tar', ['-tvzf', out.path]).toString();
  const row = listing.split('\n').find((l) => l.includes('leaky/production/shared/data/innocent.txt'));
  assert.ok(row, 'the link must be in the archive');
  assert.match(row, /^l/, `archived as something other than a symlink: ${row}`);
  const x = mkdtempSync(join(tmpdir(), 'crane-x-'));
  try {
    execFileSync('tar', ['-xzf', out.path, '-C', x]);
    assert.equal(execFileSync('grep', ['-rl', 'HOST-SECRET', x], { encoding: 'utf8' }).toString().trim(), '',
      'the host file\'s content is inside the backup');
  } catch (e) {
    if (e.status !== 1) throw e;                                // grep: 1 = no match
  } finally {
    rmSync(x, { recursive: true, force: true });
  }
});

test('traversal names in a hand-built tar are refused and write nothing outside', async () => {
  const dbBefore = (() => { db.pragma('wal_checkpoint(TRUNCATE)'); return sha256(liveDb()); })();
  const escape = (n) => `../../../../../../../../${OUTSIDE.replace(/^\//, '')}/${n}`;
  for (const [name, entries] of Object.entries({
    leading: [{ name: escape('lead.txt'), data: 'X' }],
    embedded: [{ name: `apps/shop/production/shared/data/${escape('emb.txt')}`, data: 'X' }],
    absolute: [{ name: join(OUTSIDE, 'abs.txt'), data: 'X' }],
    unknownTop: [{ name: 'etc/cron.d/x', data: 'X' }],
    device: [{ name: 'apps/shop/production/shared/data/fifo', type: '6' }],
  })) {
    const p = await hostileArchive(name, entries);
    await assert.rejects(importDataArchive(p, { restoreEnv: false }), /unexpected entry|corrupt/, name);
  }
  assert.deepEqual(readdirSync(OUTSIDE).filter((n) => n !== 'host-secret.txt'), [], 'a traversal entry wrote outside DATA_DIR');
  assert.equal(sha256(liveDb()), dbBefore, 'a refused import replaced the DB');
});

test('an archive cannot write through a symlink: neither one it carries nor one already on the host', async () => {
  // (a) the archive carries data/evil -> OUTSIDE and then data/evil/pwned.txt
  const carried = await hostileArchive('carried', [
    { name: 'apps/shop/production/shared/data/evil', type: '2', linkname: OUTSIDE },
    { name: 'apps/shop/production/shared/data/evil/pwned.txt', data: 'PWNED' },
  ]);
  try { await importDataArchive(carried, { restoreEnv: false }); } catch (_) { /* refusal is acceptable */ }
  assert.equal(existsSync(join(OUTSIDE, 'pwned.txt')), false, 'wrote through a symlink the archive carried');

  // (b) the HOST already has data/linkdir -> OUTSIDE; a benign archive writes data/linkdir/x.txt
  const hostLink = shared('shop', 'production', 'data', 'linkdir');
  rmSync(hostLink, { recursive: true, force: true });
  symlinkSync(OUTSIDE, hostLink);
  const benign = await hostileArchive('benign', [
    { name: 'apps/shop/production/shared/data/linkdir/', type: '5' },
    { name: 'apps/shop/production/shared/data/linkdir/x.txt', data: 'THROUGH-HOST-LINK' },
  ]);
  const r = await importDataArchive(benign, { restoreEnv: false });
  assert.equal(existsSync(join(OUTSIDE, 'x.txt')), false, 'wrote through a symlink already on the host');
  assert.ok(r.refused >= 1, `the refusal must be counted, got ${r.refused}`);
  rmSync(hostLink);
});

test('traversal names inside a legacy zip are ignored and write nothing outside', async () => {
  // adm-zip's writer collapses '..', so write same-length placeholders and patch
  // the raw bytes of both headers afterwards. CRCs cover data, not names.
  const z = new AdmZip();
  const tmpDb = join(ROOT, 'zip-src.db');
  await snapshotDatabase(tmpDb);
  z.addLocalFile(tmpDb, '', 'deployhub.db');
  rmSync(tmpDb);
  z.addFile('appcrane-backup.json', Buffer.from(JSON.stringify({ kind: 'appcrane-config-backup', version: '2.72.1', exported_at: new Date().toISOString() })));
  z.addFile('appdata/shop/production/QQ/QQ/QQ/QQ/QQ/QQ/QQ/QQ/QQ/QQ/zipescape.txt', Buffer.from('ESCAPED'));
  z.addFile('appvolumes/shop/production/QQ/QQ/QQ/QQ/QQ/QQ/QQ/QQ/QQ/QQ/zipescape2.txt', Buffer.from('ESCAPED'));
  let raw = z.toBuffer();
  raw = Buffer.from(raw.toString('latin1').replaceAll('QQ/', '../'), 'latin1');
  mkdirSync(BACKUPS, { recursive: true });
  const p = join(BACKUPS, 'traversal.zip');
  writeFileSync(p, raw);
  assert.ok(raw.includes(Buffer.from('appdata/shop/production/../../')), 'fixture: the raw name must carry ..');

  const r = await importDataArchive(p, { restoreEnv: false });
  assert.equal(r.dataFiles + r.volumeFiles, 0);
  // Where each name lands if joined naively onto the apps tree or the staging tree.
  const up = Array(10).fill('..');
  const candidates = [
    resolve(shared('shop', 'production', 'data'), ...up, 'zipescape.txt'),
    resolve(shared('shop', 'production', 'volumes'), ...up, 'zipescape2.txt'),
    resolve(BACKUPS, '.data-import-x', 'tree', 'apps', 'shop', 'production', 'shared', 'data', ...up, 'zipescape.txt'),
    resolve(BACKUPS, '.data-import-x', 'tree', 'apps', 'shop', 'production', 'shared', 'volumes', ...up, 'zipescape2.txt'),
  ];
  assert.deepEqual(candidates.filter((c) => existsSync(c)), [], 'a traversal zip entry was written');
  const inRoot = execFileSync('find', [ROOT, OUTSIDE, '-name', 'zipescape*'], { encoding: 'utf8' }).trim();
  assert.equal(inRoot, '', `a traversal zip entry was written: ${inRoot}`);
});

test('a v2.72 zip restores DB, icons, /data and volumes with the streaming reader', async () => {
  const z = new AdmZip();
  const tmpDb = join(ROOT, 'v272.db');
  setSetting('legacy_marker', 'FROM-V2.72');
  await snapshotDatabase(tmpDb);
  z.addLocalFile(tmpDb, '', 'deployhub.db');
  rmSync(tmpDb);
  const big = Buffer.from(Array.from({ length: 300000 }, (_, i) => (i * 13) % 251));
  z.addFile('icons/old/icon.svg', Buffer.from('<svg/>'));
  z.addFile('appdata/old/production/big.bin', big);
  z.addFile('appvolumes/old/sandbox/var/lib/x/state', Buffer.from('VOL'));
  z.addFile('appcrane-backup.json', Buffer.from(JSON.stringify({ kind: 'appcrane-config-backup', version: '2.72.1', exported_at: new Date().toISOString(), includes: ['deployhub.db', 'icons', 'appdata', 'appvolumes'] })));
  const p = join(BACKUPS, 'v272.zip');
  z.writeZip(p);
  setSetting('legacy_marker', 'CHANGED');

  const r = await importDataArchive(p, { restoreEnv: false });
  assert.equal(r.format, 'legacy-zip');
  assert.equal(sha256(shared('old', 'production', 'data', 'big.bin')), createHash('sha256').update(big).digest('hex'));
  assert.equal(readFileSync(shared('old', 'sandbox', 'volumes', 'var', 'lib', 'x', 'state'), 'utf8'), 'VOL');
  assert.equal(readFileSync(join(ROOT, 'apps', 'old', 'icon.svg'), 'utf8'), '<svg/>');
  assert.equal(dump(liveDb()).settings.find((s) => s.key === 'legacy_marker').value, 'FROM-V2.72');
  assert.match(r.repoSet.note, /predates/);
});

test('a legacy zip whose entry fails its CRC is refused before anything is replaced', async () => {
  const z = new AdmZip();
  const tmpDb = join(ROOT, 'crc.db');
  await snapshotDatabase(tmpDb);
  z.addLocalFile(tmpDb, '', 'deployhub.db');
  rmSync(tmpDb);
  z.addFile('appdata/crc/production/f.bin', Buffer.alloc(50000, 0x41));
  z.addFile('appcrane-backup.json', Buffer.from(JSON.stringify({ kind: 'appcrane-config-backup', version: '2.72.1', exported_at: new Date().toISOString() })));
  const raw = z.toBuffer();
  const at = raw.indexOf(Buffer.from('appdata/crc/production/f.bin'));
  raw[at + 'appdata/crc/production/f.bin'.length + 4] ^= 0x01;       // damage the entry's first data byte(s)
  const p = join(BACKUPS, 'crc.zip');
  writeFileSync(p, raw);
  db.pragma('wal_checkpoint(TRUNCATE)');
  const dbBefore = sha256(liveDb());
  await assert.rejects(importDataArchive(p, { restoreEnv: false }), /corrupt/);
  assert.equal(sha256(liveDb()), dbBefore);
  assert.equal(existsSync(shared('crc', 'production', 'data', 'f.bin')), false);
});

test('not-a-backup inputs are refused with a reason', async () => {
  const p = join(BACKUPS, 'junk.bin');
  writeFileSync(p, 'hello');
  await assert.rejects(importDataArchive(p), /Not an AppCrane backup/);
  const noManifest = join(BACKUPS, 'nomanifest.tar.gz');
  writeFileSync(noManifest, rawTarGz([{ name: 'deployhub.db', data: 'x' }]));
  await assert.rejects(importDataArchive(noManifest), /manifest missing/);
  const notSqlite = await hostileArchive('notsqlite', []);
  const x = mkdtempSync(join(tmpdir(), 'crane-ns-'));
  execFileSync('tar', ['-xzf', notSqlite, '-C', x]);
  writeFileSync(join(x, 'deployhub.db'), 'definitely not sqlite');
  execFileSync('tar', ['-czf', notSqlite, '-C', x, 'appcrane-backup.json', 'deployhub.db']);
  rmSync(x, { recursive: true, force: true });
  await assert.rejects(importDataArchive(notSqlite), /not a valid SQLite file/);
});

// ---------------------------------------------------------------------------
// Routes, over a real socket with a real API key
// ---------------------------------------------------------------------------

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')").run(name, `${name}@t.test`, role, hashApiKey(key));
  return { key };
}
const admin = mkUser('bkadmin', 'platform_admin');
const plain = mkUser('bkuser', 'user');
const settingsRoutes = (await import('../server/routes/settings.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/settings', settingsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

test('routes: download is a streamed tar.gz that imports; upload is streamed to disk and removed; non-admins refused', async () => {
  setSetting('route_marker', 'IN-DOWNLOAD');
  const refused = await fetch(`${BASE}/api/settings/config/export`, { headers: { 'X-API-Key': plain.key } });
  assert.equal(refused.status, 403);

  const dl = await fetch(`${BASE}/api/settings/config/export`, { headers: { 'X-API-Key': admin.key } });
  assert.equal(dl.status, 200);
  assert.equal(dl.headers.get('content-type'), 'application/gzip');
  assert.match(dl.headers.get('content-disposition'), /filename="appcrane-backup-.*\.tar\.gz"/);
  const body = Buffer.from(await dl.arrayBuffer());
  assert.equal(body.length, Number(dl.headers.get('content-length')));
  await new Promise((r) => setTimeout(r, 100));
  assert.deepEqual(readdirSync(BACKUPS).filter((n) => n.startsWith('.')), [], 'the download left its temp file behind');

  setSetting('route_marker', 'CHANGED');
  const fd = new FormData();
  fd.append('file', new Blob([body]), 'backup.tar.gz');
  const up = await fetch(`${BASE}/api/settings/config/import?restore_env=0`, { method: 'POST', headers: { 'X-API-Key': admin.key }, body: fd });
  const upBody = await up.json();
  assert.equal(up.status, 200, JSON.stringify(upBody));
  assert.equal(upBody.format, 'tar.gz');
  assert.equal(dump(liveDb()).settings.find((s) => s.key === 'route_marker').value, 'IN-DOWNLOAD');
  assert.deepEqual(readdirSync(BACKUPS).filter((n) => n.startsWith('.upload-')), [], 'the uploaded file must be removed');
});

test('routes: path import is confined to DATA_DIR/backups; an upload larger than free disk is refused before it is read', async () => {
  const outside = join(OUTSIDE, 'elsewhere.tar.gz');
  writeFileSync(outside, 'x');
  const r1 = await fetch(`${BASE}/api/settings/config/import`, {
    method: 'POST', headers: { 'X-API-Key': admin.key, 'Content-Type': 'application/json' }, body: JSON.stringify({ path: outside }),
  });
  assert.equal(r1.status, 400);
  assert.match((await r1.json()).error.message, /must be inside/);

  const r2 = await fetch(`${BASE}/api/settings/repos/import`, {
    method: 'POST', headers: { 'X-API-Key': admin.key, 'Content-Type': 'application/json' }, body: JSON.stringify({ path: 'x.tar', slug: '../etc' }),
  });
  assert.equal(r2.status, 400);

  const status = await new Promise((resolve, reject) => {
    const req = http.request(`${BASE}/api/settings/config/import`, {
      method: 'POST',
      headers: { 'X-API-Key': admin.key, 'Content-Type': 'multipart/form-data; boundary=zzz', 'Content-Length': String(2 ** 50) },
    }, (res) => { res.resume(); resolve(res.statusCode); req.destroy(); });
    // Without the up-front check the upload is accepted and waits for a body
    // that never comes; fail with that, not with a whole-file timeout.
    req.setTimeout(5000, () => { reject(new Error('no answer in 5 s: an upload larger than free disk was accepted instead of refused')); req.destroy(); });
    req.on('error', (e) => (e.code === 'ECONNRESET' ? null : reject(e)));
    req.write('--zzz\r\n');
  });
  assert.equal(status, 507);
});
