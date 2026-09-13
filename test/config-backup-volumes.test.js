import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Config backup must carry DECLARED VOLUMES, not just /data.
//
// v2.70.0 let an app declare the paths it persists, mounted from
// <slug>/<env>/shared/volumes/<mirrored container path>. configBackup.js copied
// only shared/data, so from that release until this one an app's real state was
// outside every config backup — and the failure was silent in the worst way:
// export succeeded, reported a file count, and restore produced an app with an
// empty directory where its database or uploads had been. Nothing failed, so
// nothing prompted anyone to look.
//
// The round trip is asserted end to end (export -> wipe -> import -> read the
// bytes back) rather than by inspecting the zip's entry names, because the
// export and import sides use SEPARATE hardcoded path lists. A test that only
// checked the archive would have passed with an import that dropped every entry
// on the floor, which is exactly half the bug.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-cfgbackup-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb } = await import('../server/db.js');
initDb();
const { exportDataArchive, importDataArchive } = await import('../server/services/configBackup.js');

const SLUG = 'odoo';
const ENV = 'production';
const sharedDir = join(ROOT, 'apps', SLUG, ENV, 'shared');

// The two trees a running app writes to: /data, and a declared '/var/lib/odoo'
// whose host layout mirrors the container path.
const dataFile = join(sharedDir, 'data', 'keep.txt');
const volFile = join(sharedDir, 'volumes', 'var', 'lib', 'odoo', 'filestore.bin');
const nestedVolFile = join(sharedDir, 'volumes', 'config', 'app.conf');

before(() => {
  mkdirSync(join(sharedDir, 'data'), { recursive: true });
  mkdirSync(join(sharedDir, 'volumes', 'var', 'lib', 'odoo'), { recursive: true });
  mkdirSync(join(sharedDir, 'volumes', 'config'), { recursive: true });
  writeFileSync(dataFile, 'DATA-PAYLOAD');
  writeFileSync(volFile, 'VOLUME-PAYLOAD');
  writeFileSync(nestedVolFile, 'CONFIG-PAYLOAD');
});

after(() => { try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

test('a declared volume survives an export/import round trip', async () => {
  const { path: zip, bytes, manifest } = await exportDataArchive({ version: '2.70.2' });
  assert.ok(bytes > 0, 'export produced no archive');
  assert.ok(manifest.includes.includes('appvolumes'),
    'the manifest must declare the volume prefix, or a reader cannot tell an old ' +
    'bundle (no volumes captured) from a new one');

  // Destroy the live trees, the way a fresh host has nothing.
  rmSync(join(sharedDir, 'data'), { recursive: true, force: true });
  rmSync(join(sharedDir, 'volumes'), { recursive: true, force: true });
  assert.equal(existsSync(volFile), false, 'precondition: the volume tree is gone');

  const result = await importDataArchive(zip, { restoreEnv: false });

  assert.equal(existsSync(dataFile), true, '/data did not come back');
  assert.equal(readFileSync(dataFile, 'utf8'), 'DATA-PAYLOAD');

  assert.equal(existsSync(volFile), true,
    'the declared volume was not restored — an app that keeps its state in a declared ' +
    'mount would come back empty, from a backup that reported success');
  assert.equal(readFileSync(volFile, 'utf8'), 'VOLUME-PAYLOAD');

  assert.equal(readFileSync(nestedVolFile, 'utf8'), 'CONFIG-PAYLOAD',
    'a second declared mount must round-trip too');

  assert.ok(result.volumeFiles >= 2,
    `the result must report what it restored so a silent zero is visible; got ${result.volumeFiles}`);
});

test('the container path is reconstructed exactly, not flattened', () => {
  // The host layout mirrors the container path so two different container paths
  // can never collide on one host directory. If the restore flattened
  // 'var/lib/odoo' to 'odoo', the app would mount an empty dir and the data
  // would sit unreachable one directory away.
  assert.equal(existsSync(join(sharedDir, 'volumes', 'var', 'lib', 'odoo', 'filestore.bin')), true);
  assert.equal(existsSync(join(sharedDir, 'volumes', 'filestore.bin')), false,
    'the volume tree was flattened on restore');
});

test('an app with no declared volumes is unaffected', async () => {
  const plain = join(ROOT, 'apps', 'plainapp', 'sandbox', 'shared', 'data');
  mkdirSync(plain, { recursive: true });
  writeFileSync(join(plain, 'only.txt'), 'ONLY-DATA');

  const { path: zip } = await exportDataArchive({ version: '2.70.2' });
  rmSync(join(ROOT, 'apps', 'plainapp'), { recursive: true, force: true });
  await importDataArchive(zip, { restoreEnv: false });

  assert.equal(readFileSync(join(plain, 'only.txt'), 'utf8'), 'ONLY-DATA',
    'adding volume support must not disturb the pre-existing /data path');
});

// PATH TRAVERSAL is proven in test/data-archive.test.js, against archives
// assembled byte by byte (tar headers, and zip names patched after adm-zip
// wrote them) so the hostile names actually reach the import guards. adm-zip
// normalises '..' out of names in its writer, so no archive built with it here
// could exercise them.
