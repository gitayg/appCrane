import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, statSync, chownSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Supply Hub sandbox, 2026-10-24: a file uploaded with appcrane_cp into a
// folder that did not exist yet left that folder owned by root. The app runs
// as `node`, so every later save into /data/order-status failed with EACCES.
// docker cp creates a missing parent as root unless the archive carries an
// entry for it, and the archive AppCrane built (as root) said uid 0 for the
// file. Measured live on Linux with GNU tar: before 0:0 and EACCES, after
// 1000:1000 and the app writes.
//
// What AppCrane creates in /data now belongs to whoever owns /data, and an
// existing folder is not in the archive at all, because Docker would rewrite
// its owner and mode (measured: 0700 became 0755).

const TMP = mkdtempSync(join(tmpdir(), 'crane-data-owner-'));
const SHIM = join(TMP, 'bin');
const RUNNING = join(TMP, 'running');
const TAR = join(TMP, 'last.tar');
mkdirSync(SHIM);
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === 'inspect') {
  if (!fs.existsSync(${JSON.stringify(RUNNING)})) { process.stderr.write('Error: No such object: x\\n'); process.exit(1); }
  process.stdout.write('true\\n'); process.exit(0);
}
if (args[0] === 'cp') fs.writeFileSync(${JSON.stringify(TAR)}, fs.readFileSync(0));
process.exit(0);
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { writeAppData } = await import('../server/services/appDataWrite.js');

// ustar header: name at 0 (100 bytes), uid at 108 and gid at 116 (octal),
// type at 156. macOS bsdtar adds pax headers (x/g) and AppleDouble ._ files;
// GNU tar on a server writes neither, so they are skipped.
function tarEntries(buf) {
  const out = [];
  for (let off = 0; off + 512 <= buf.length; ) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    const field = (a, n) => h.subarray(a, a + n).toString('latin1').replace(/\0.*$/s, '').trim();
    const size = parseInt(field(124, 12) || '0', 8);
    const name = field(0, 100).replace(/\/$/, '');
    if (!'xg'.includes(field(156, 1) || '-') && !name.split('/').pop().startsWith('._')) {
      out.push({ name, uid: parseInt(field(108, 8), 8), gid: parseInt(field(116, 8), 8) });
    }
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

function fixture(slug) {
  const dataDir = join(TMP, slug);
  const root = join(dataDir, 'apps', slug, 'sandbox', 'shared', 'data');
  mkdirSync(root, { recursive: true });
  // As root (the server, or the Linux check of this fix) /data is given an
  // owner that is neither root nor AppCrane, so following it is what is tested.
  if (process.getuid() === 0) chownSync(root, 4321, 4321);
  const st = statSync(root);
  return { dataDir, root, owner: { uid: st.uid, gid: st.gid } };
}

test('running container: missing folders and the file are archived as owned by /data\'s owner', async () => {
  writeFileSync(RUNNING, '1');
  const f = fixture('own-a');
  await writeAppData({ dataDir: f.dataDir, slug: 'own-a', env: 'sandbox', rel: 'order-status/views/saved.json', buf: Buffer.from('{}') });
  const entries = tarEntries(readFileSync(TAR));
  assert.deepEqual(entries.map((e) => e.name), ['order-status', 'order-status/views', 'order-status/views/saved.json']);
  for (const e of entries) assert.deepEqual({ uid: e.uid, gid: e.gid }, f.owner, `${e.name} is not owned by /data's owner`);
});

test('running container: an existing folder gets no entry, so Docker leaves its owner and mode alone', async () => {
  writeFileSync(RUNNING, '1');
  const f = fixture('own-b');
  mkdirSync(join(f.root, 'order-status'), { mode: 0o700 });
  await writeAppData({ dataDir: f.dataDir, slug: 'own-b', env: 'sandbox', rel: 'order-status/new/map.json', buf: Buffer.from('{}') });
  assert.deepEqual(tarEntries(readFileSync(TAR)).map((e) => e.name), ['order-status/new', 'order-status/new/map.json']);
});

test('running container: a link on the way ends the walk; Docker resolves the rest inside the container', async () => {
  writeFileSync(RUNNING, '1');
  const f = fixture('own-c');
  symlinkSync('/tmp', join(f.root, 'lnk'));
  await writeAppData({ dataDir: f.dataDir, slug: 'own-c', env: 'sandbox', rel: 'lnk/sub/x.json', buf: Buffer.from('{}') });
  assert.deepEqual(tarEntries(readFileSync(TAR)).map((e) => e.name), ['lnk/sub/x.json']);
});

test('no container: folders and the file created on the host belong to /data\'s owner', async () => {
  rmSync(RUNNING, { force: true });
  const f = fixture('own-d');
  const r = await writeAppData({ dataDir: f.dataDir, slug: 'own-d', env: 'sandbox', rel: 'order-status/stage-map.json', buf: Buffer.from('{}') });
  assert.equal(r.via, 'host');
  for (const p of ['order-status', 'order-status/stage-map.json']) {
    assert.ok(existsSync(join(f.root, p)));
    const st = statSync(join(f.root, p));
    assert.deepEqual({ uid: st.uid, gid: st.gid }, f.owner, `${p} is not owned by /data's owner`);
  }
});
