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
const { exportConfig, importConfig } = await import('../server/services/configBackup.js');

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

test('a declared volume survives an export/import round trip', () => {
  const { buffer: zip, manifest } = exportConfig('2.70.2');
  assert.ok(Buffer.isBuffer(zip) && zip.length > 0, 'export produced no bundle');
  assert.ok(manifest.includes.includes('appvolumes'),
    'the manifest must declare the volume prefix, or a reader cannot tell an old ' +
    'bundle (no volumes captured) from a new one');

  // Destroy the live trees, the way a fresh host has nothing.
  rmSync(join(sharedDir, 'data'), { recursive: true, force: true });
  rmSync(join(sharedDir, 'volumes'), { recursive: true, force: true });
  assert.equal(existsSync(volFile), false, 'precondition: the volume tree is gone');

  const result = importConfig(zip, { restoreEnv: false });

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

test('an app with no declared volumes is unaffected', () => {
  const plain = join(ROOT, 'apps', 'plainapp', 'sandbox', 'shared', 'data');
  mkdirSync(plain, { recursive: true });
  writeFileSync(join(plain, 'only.txt'), 'ONLY-DATA');

  const { buffer: zip } = exportConfig('2.70.2');
  rmSync(join(ROOT, 'apps', 'plainapp'), { recursive: true, force: true });
  importConfig(zip, { restoreEnv: false });

  assert.equal(readFileSync(join(plain, 'only.txt'), 'utf8'), 'ONLY-DATA',
    'adding volume support must not disturb the pre-existing /data path');
});

// PATH TRAVERSAL: NOT PROVEN HERE, and the reason is worth recording.
//
// The import path has two independent guards — `name.includes('..')` skips the
// entry, and writeUnderApps() resolves the destination and range-checks it
// against the apps root. Removing EITHER one, or BOTH together, leaves this
// file green and writes nothing outside the tree. That is not defence in depth
// working; it is the test never reaching the code.
//
// Measured cause: adm-zip normalises traversal names in its WRITER.
//
//   z.addFile('appvolumes/../../../../../../tmp/crane-escaped.txt', ...)
//   -> stored entry name: "tmp/crane-escaped.txt"
//
// The '..' segments are collapsed before the bytes hit the archive, so the
// entry no longer carries the 'appvolumes/' prefix and the import loop ignores
// it. A hostile bundle built with adm-zip therefore CANNOT express this attack,
// and no test written with adm-zip can exercise either guard.
//
// Proving them needs a hand-assembled archive with a raw filename in the local
// file header — worth doing, not done here. Until then both guards are
// unexercised by any test, for the `appdata/` prefix as much as the new
// `appvolumes/` one.
