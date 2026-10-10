import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// pruneOldImages only ran after a deploy passed its health check, for apps that
// still exist. So two kinds of image stayed on disk forever: those of a DELETED
// app, and the one a FAILED deploy built (which, as the newest, also outranked
// the last good image in the next keep-N-newest prune). Measured on a host that
// was back to 30.6 GB reclaimable minutes after a manual prune.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-imgclean-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
const SHIM = join(process.env.DATA_DIR, 'bin');
const LOG = join(process.env.DATA_DIR, 'docker.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(LOG)}, JSON.stringify(args) + '\\n');
if (args[0] === 'images' && args.includes('label=slug=gone')) {
  process.stdout.write('sha256:aaa 2026-10-01 10:00:00 +0000 UTC\\nsha256:bbb 2026-09-01 10:00:00 +0000 UTC\\n');
}
if (args[0] === 'image' && args[1] === 'inspect') {
  // Docker's own normalisation: the docker.io/library/ spelling is the same image.
  const ref = args[2].replace('docker.io/library/', '');
  if (ref.startsWith('odoo@')) { process.stdout.write('sha256:id-' + ref.slice(5) + '\\n'); process.exit(0); }
  process.stderr.write('Error: No such image\\n'); process.exit(1);
}
if (args[0] === 'rmi' && args[1] === 'in-use:tag') { process.stderr.write('conflict: image is being used by container\\n'); process.exit(1); }
process.exit(0);
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;
const calls = () => existsSync(LOG) ? readFileSync(LOG, 'utf8').trim().split('\n').map(JSON.parse) : [];

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const key = generateApiKey('dhk_user');
db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('p','p@t.test','platform_admin',1,?)").run(hashApiKey(key));
const goneId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('G','gone',1,'managed','main')").run().lastInsertRowid;
// Two image apps on one repository. Deleting 'pulled' must remove only the
// digest it alone deployed, never 'neighbour''s (its rollback image).
const pulledId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,image_ref) VALUES ('P','pulled',2,'image','odoo:19')").run().lastInsertRowid;
const neighbourId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,image_ref) VALUES ('N','neighbour',3,'image','odoo:19')").run().lastInsertRowid;
const dep = (appId, ref) => db.prepare("INSERT INTO deployments (app_id, env, status, image_ref) VALUES (?, 'production', 'live', ?)").run(appId, ref);
dep(pulledId, 'odoo@sha256:mine');
dep(pulledId, 'odoo@sha256:shared');
dep(neighbourId, 'odoo@sha256:shared');
dep(neighbourId, 'odoo@sha256:neighbours-rollback');
// The same image as neighbour's rollback, spelt the way Docker also accepts.
dep(pulledId, 'docker.io/library/odoo@sha256:neighbours-rollback');

const apps = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const a = express(); a.use(express.json()); a.use('/api/apps', apps); a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });

test('deleting an app removes its images, both environments', async () => {
  const r = await fetch(`http://127.0.0.1:${server.address().port}/api/apps/gone?confirm=true`, { method: 'DELETE', headers: { 'x-api-key': key } });
  assert.equal(r.status, 200);
  const listings = calls().filter(a => a[0] === 'images' && a.includes('label=slug=gone'));
  assert.deepEqual(listings.map(a => a[a.indexOf('label=env=production') >= 0 ? a.indexOf('label=env=production') : a.indexOf('label=env=sandbox')]).sort(),
    ['label=env=production', 'label=env=sandbox'], 'both environments\' images were not listed');
  for (const l of listings) {
    assert.ok(l.some(x => /^reference=appcrane-gone-(production|sandbox)$/.test(x)), `listed by label alone, which any pulled image can carry: ${l.join(' ')}`);
  }
  const removed = calls().filter(a => a[0] === 'rmi').map(a => a.at(-1));
  assert.deepEqual([...new Set(removed)].sort(), ['sha256:aaa', 'sha256:bbb']);
});

test('deleting an image app removes only the digests it alone deployed, never a shared repository\'s images', async () => {
  const before = calls().length;
  const r = await fetch(`http://127.0.0.1:${server.address().port}/api/apps/pulled?confirm=true`, { method: 'DELETE', headers: { 'x-api-key': key } });
  assert.equal(r.status, 200);
  const mine = calls().slice(before);
  assert.ok(!mine.some(a => a[0] === 'images' && a.includes('odoo')), 'the repository-wide pass ran, which deletes other apps\' images');
  const removed = mine.filter(a => a[0] === 'rmi');
  assert.deepEqual(removed, [['rmi', 'odoo@sha256:mine']], 'removed something another app deployed, or forced it');
});

test('a failed deploy\'s image is removed without -f, so an in-use image is refused', async () => {
  const { discardImage } = await import('../server/services/docker.js');
  assert.equal(await discardImage('crane-x-sandbox:abc'), true);
  assert.deepEqual(calls().at(-1), ['rmi', 'crane-x-sandbox:abc']);
  assert.equal(await discardImage('in-use:tag'), false);
});

test('the deploy failure path discards only an image this attempt built', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server/services/deployer.js'), 'utf8');
  assert.match(src, /if \(!wasCached\) attemptImage = image;/, 'a reused (cached) image, e.g. a rollback target, would be discarded');
  const failure = src.slice(src.indexOf('} catch (error) {', src.indexOf('let attemptImage')));
  assert.match(failure, /discardImage\(attemptImage\)/, 'the failure handler does not remove the image it built');
});
