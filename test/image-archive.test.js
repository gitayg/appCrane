import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, execFile } from 'child_process';
import { promisify } from 'util';
import { mkdtempSync, existsSync, statSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const execFileAsync = promisify(execFile);

// Restoring an app's IMAGE, not just its configuration and data.
//
// The failure this exists to prevent is not hypothetical and cannot be repaired
// after the fact: a restore that re-pulls `name@sha256:...` fails outright once
// the publisher removes the image. Every `bitnami/*` image 404s since their
// registry change; medusajs/medusa, vendureio/vendure and crater/crater 404
// today. The bytes are gone from the internet, so they have to be in the
// backup.
//
// THE ASSERTIONS THAT MATTER are the two at the bottom, and they are properties
// rather than strings:
//
//   - with the registry STOPPED and every local copy of the image removed, a
//     container starts from the archive. Preceded by a control that shows the
//     same command FAILING before the archive is loaded — otherwise "it ran"
//     could just as well mean a copy was still lying around.
//   - saving by DIGEST (the obvious thing to do with deployments.image_ref)
//     produces an archive that loads an image no name can reach. That is the
//     design decision this file defends; without it the export would look
//     correct and restore nothing.
//
// Measured while writing this, because the answer decides the design and
// differs by image store:
//   Docker 29.6.1, containerd snapshotter: save-by-tag -> load restores
//     RepoDigests, so the digest reference still runs.
//   Docker 27.5.1, Linux, classic overlay2: save-by-tag -> load leaves
//     RepoDigests EMPTY. The digest reference is "No such image" and Docker
//     falls through to a pull, which is exactly what is unavailable.
// So nothing here may assert on the digest reference resolving. The archive tag
// is the handle that holds on both.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-imgarchive-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const {
  restoreTagFor, imageSetFingerprint, liveDeploymentImages, planImageArchive,
  exportImageArchive, importImageArchive, verifyImageSet, archiveFileName,
  RESTORE_TAG_PREFIX,
} = await import('../server/services/imageArchive.js');
const { exportConfig } = await import('../server/services/configBackup.js');

// A daemon that RESPONDS, not a binary that exists — `docker` is installed on
// the GitHub runner, so testing for the CLI would run the round trip everywhere
// and fail wherever the daemon is absent.
let DOCKER = null;
try {
  DOCKER = execFileSync('/usr/bin/env', ['sh', '-c', 'command -v docker'], { encoding: 'utf8' }).trim() || null;
  if (DOCKER) execFileSync(DOCKER, ['version', '--format', '{{.Server.Version}}'], { timeout: 15000, stdio: 'pipe' });
} catch (_) { DOCKER = null; }
const noDocker = DOCKER ? false : 'no reachable Docker daemon on this host';

const dk = (args, timeout = 300000) => execFileAsync(DOCKER, args, { timeout }).then((r) => r.stdout.trim());
const dkOk = async (args) => { try { await dk(args); return true; } catch (_) { return false; } };

let slot = 900;
const imageApp = (slug, imageRef) => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,image_ref) VALUES (?,?,?,'image',?)",
).run(slug, slug, slot++, imageRef).lastInsertRowid;
const sourceApp = (slug) => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'managed')",
).run(slug, slug, slot++).lastInsertRowid;
const deployment = (appId, env, status, { imageRef = null, commit = null } = {}) => db.prepare(
  'INSERT INTO deployments (app_id,env,version,status,commit_hash,image_ref) VALUES (?,?,?,?,?,?)',
).run(appId, env, '1', status, commit, imageRef).lastInsertRowid;

after(() => { try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {} });

// ---------------------------------------------------------------------------
// Naming and identity — no daemon needed
// ---------------------------------------------------------------------------

test('the archive tag keeps the original repository, because that is what makes the image reachable again', () => {
  assert.equal(
    restoreTagFor('odoo@sha256:' + 'a'.repeat(64)),
    `odoo:${RESTORE_TAG_PREFIX}${'a'.repeat(64)}`,
  );
  // A registry-qualified reference keeps its registry: `zammad:appcrane-restore-x`
  // would be a DIFFERENT repository, and an image saved under it comes back
  // under a name no deployment refers to.
  const ghcr = restoreTagFor('ghcr.io/zammad/zammad@sha256:' + 'b'.repeat(64));
  assert.equal(ghcr, `ghcr.io/zammad/zammad:${RESTORE_TAG_PREFIX}${'b'.repeat(64)}`);
  assert.ok(ghcr.startsWith('ghcr.io/zammad/zammad:'), 'the registry and path must survive');
  // Docker's tag limit is 128 characters. If the tag ever stopped fitting,
  // `docker tag` would fail at export time on every image at once.
  assert.ok(ghcr.split(':').pop().length <= 128, 'the archive tag must be a legal Docker tag');
  // Two digests of one repository that differ ONLY in their last hex must not
  // collide onto one tag — a truncated tag would archive one image where the
  // fleet runs two, and nothing in the export would say so.
  assert.notEqual(
    restoreTagFor('odoo@sha256:' + 'a'.repeat(64)),
    restoreTagFor('odoo@sha256:' + 'a'.repeat(63) + 'b'),
  );
  assert.equal(restoreTagFor('odoo:19'), null, 'a reference with no digest has no digest-derived tag');
});

test('the image-set fingerprint identifies a SET, not an ordering', () => {
  const a = imageSetFingerprint(['x:1', 'y:2', 'z:3']);
  assert.equal(a, imageSetFingerprint(['z:3', 'x:1', 'y:2']), 'order must not change the identity');
  assert.equal(a, imageSetFingerprint(['x:1', 'y:2', 'z:3', 'x:1']), 'a duplicate must not change it either');
  assert.notEqual(a, imageSetFingerprint(['x:1', 'y:2']), 'a different set must be a different identity');
});

test('only the newest LIVE deployment per app+env is archived — a later failed deploy is not what is running', () => {
  const app = imageApp('sel-image', 'odoo:19');
  const stale = deployment(app, 'production', 'live', { imageRef: 'odoo@sha256:' + '1'.repeat(64) });
  const current = deployment(app, 'production', 'live', { imageRef: 'odoo@sha256:' + '3'.repeat(64) });
  // The ordinary case that makes the status filter load-bearing: a deploy was
  // attempted and failed, so it is the NEWEST row while the previous image is
  // still the one serving traffic. Archiving the failed row's image would back
  // up bytes that never ran and miss the ones that did.
  const failedAfter = deployment(app, 'production', 'failed', { imageRef: 'odoo@sha256:' + '2'.repeat(64) });
  assert.ok(failedAfter > current, 'the failed row must be newer, or this proves nothing');

  const rows = liveDeploymentImages('live').filter((r) => r.slug === 'sel-image');
  assert.equal(rows.length, 1, 'one row per app+env, not one per deployment');
  assert.equal(rows[0].deployment_id, current, 'the newest LIVE row is what is running');
  assert.notEqual(rows[0].deployment_id, stale);
  assert.notEqual(rows[0].deployment_id, failedAfter);
  assert.equal(rows[0].ref, 'odoo@sha256:' + '3'.repeat(64));
});

test('a source-built app is archived under the same tag buildImageIfNeeded looks for', async () => {
  const { imageTagFor } = await import('../server/services/docker.js');
  const app = sourceApp('sel-source');
  deployment(app, 'sandbox', 'live', { commit: 'abc123def456' });

  const row = liveDeploymentImages('live').find((r) => r.slug === 'sel-source');
  assert.equal(row.ref, imageTagFor('sel-source', 'sandbox', 'abc123def456'),
    'if these ever drift, a restored image is invisible to the build cache and the app rebuilds from GitHub');
  assert.equal(row.archive_tag, row.ref, 'a built image is already addressed by a tag; it needs no second one');

  // scope 'image-apps' is the narrow-it-down option, and must actually narrow.
  assert.equal(liveDeploymentImages('image-apps').find((r) => r.slug === 'sel-source'), undefined);
  assert.ok(liveDeploymentImages('image-apps').some((r) => r.slug === 'sel-image'));
});

test('a deployment with nothing to archive says why instead of guessing', () => {
  const app = imageApp('sel-noref', 'odoo:19');
  deployment(app, 'production', 'live', { imageRef: null });
  const row = liveDeploymentImages('live').find((r) => r.slug === 'sel-noref');
  assert.equal(row.ref, null);
  assert.equal(row.archive_tag, null);
  assert.ok(row.skip_reason, 'silently falling back to apps.image_ref would archive bytes nobody ran');
});

test('the config zip names the image archive it belongs with, and stops naming it when the fleet changes', () => {
  const before = exportConfig('2.72.0').manifest;
  assert.ok(before.image_set, 'a zip that names no image set cannot be paired with one');
  assert.equal(
    before.image_set.fingerprint,
    imageSetFingerprint(liveDeploymentImages('live').filter((e) => e.archive_tag).map((e) => e.archive_tag)),
  );

  // A deploy happens. A zip taken now must NOT claim the earlier archive.
  const app = imageApp('sel-pair', 'redis:8');
  deployment(app, 'production', 'live', { imageRef: 'redis@sha256:' + '7'.repeat(64) });
  const afterManifest = exportConfig('2.72.0').manifest;
  assert.notEqual(afterManifest.image_set.fingerprint, before.image_set.fingerprint,
    'a mismatched pair must be detectable, or a restore half-applies');

  db.prepare('DELETE FROM apps WHERE slug = ?').run('sel-pair');
});

test('an image that is not on this host is reported, never silently dropped', async (t) => {
  if (noDocker) return t.skip(noDocker);
  const plan = await planImageArchive('live');
  const row = plan.images.find((r) => r.slug === 'sel-image');
  assert.equal(row.present, false, 'odoo@sha256:333... is not a real local image');
  assert.ok(plan.missing.some((m) => m.slug === 'sel-image'), 'it must appear in missing[]');
  assert.ok(row.reason, 'and say why');
  assert.equal(typeof plan.estimated_bytes, 'number');
  assert.ok(plan.required_bytes > plan.estimated_bytes, 'the reservation must exceed the estimate, or the space check is decorative');
  assert.ok(plan.dest_dir.startsWith(process.env.DATA_DIR), 'the archive belongs under DATA_DIR');
});

// ---------------------------------------------------------------------------
// The round trip, against a registry that is then taken away
// ---------------------------------------------------------------------------

const BASE = 'busybox:latest';
const REG_NAME = `appcrane-archive-reg-${process.pid}`;
let regPort = null;
let fixtureRepo = null;    // localhost:<port>/appcrane-archive-fixture
let fixtureDigestRef = null;
let archivePath = null;
let e2eSkip = noDocker;

before(async () => {
  if (noDocker) return;
  try {
    // At most one pull each, and only when the image is not already here.
    if (!await dkOk(['image', 'inspect', BASE])) await dk(['pull', BASE], 300000);
    if (!await dkOk(['image', 'inspect', 'registry:2'])) await dk(['pull', 'registry:2'], 300000);

    // An EXPLICIT published port, not an ephemeral one. Measured on Docker
    // Desktop 29.6.1: with `-p 127.0.0.1::5000` the daemon (which lives in a
    // VM) cannot reach the mapped port and every push answers 'Unavailable'
    // forever, while an explicit `-p 127.0.0.1:<port>:5000` is forwarded and
    // works. The port has to be free in the DAEMON's namespace, which is why
    // this is a plain high port rather than one this process bound first.
    regPort = 30000 + (process.pid % 20000);
    await dk(['run', '-d', '-p', `127.0.0.1:${regPort}:5000`, '--name', REG_NAME, 'registry:2']);

    fixtureRepo = `localhost:${regPort}/appcrane-archive-fixture`;
    await dk(['tag', BASE, `${fixtureRepo}:1`]);
    // The push IS the readiness check, because the DAEMON performs it. A TCP
    // connect from this process would instead prove something about whichever
    // network namespace the test runs in — and when those differ the symptom is
    // not a failure, it is this whole section quietly SKIPPING, which is the
    // one outcome a proof may not have.
    //
    // The per-attempt timeout is short on purpose: `docker push` to a registry
    // that is up but not serving retries internally and does not return, so a
    // loop built on the default timeout takes hours to report a failure.
    let pushed = null;
    for (let i = 0; i < 20; i++) {
      try { await dk(['push', `${fixtureRepo}:1`], 20000); pushed = true; break; }
      catch (e) { pushed = e.message; await new Promise((r) => setTimeout(r, 1000)); }
    }
    if (pushed !== true) throw new Error(`local registry never accepted a push: ${pushed}`);
    // Remove and re-pull, so RepoDigests is populated the way a deployed image's
    // is — that is what deployApp records as deployments.image_ref.
    await dk(['rmi', `${fixtureRepo}:1`]);
    await dk(['pull', `${fixtureRepo}:1`]);
    const digest = await dk(['image', 'inspect', `${fixtureRepo}:1`, '--format', '{{index .RepoDigests 0}}']);
    fixtureDigestRef = digest;
    assert.ok(/@sha256:[a-f0-9]{64}$/.test(fixtureDigestRef), `unusable fixture digest: ${fixtureDigestRef}`);

    const app = imageApp('archive-e2e', `${fixtureRepo}:1`);
    deployment(app, 'production', 'live', { imageRef: fixtureDigestRef });
  } catch (e) {
    e2eSkip = `could not build the registry fixture: ${e.message}`;
  }
});

after(async () => {
  if (noDocker) return;
  await dk(['rm', '-f', REG_NAME]).catch(() => {});
  if (fixtureRepo) {
    for (const ref of [`${fixtureRepo}:1`, restoreTagFor(fixtureDigestRef || `x@sha256:${'0'.repeat(64)}`)]) {
      if (ref) await dk(['rmi', '-f', ref]).catch(() => {});
    }
  }
});

test('an export with nothing archivable refuses instead of writing an archive that restores nothing', async (t) => {
  if (e2eSkip) return t.skip(e2eSkip);
  // Take the one app whose image is really here out of the live set, leaving
  // only deployments whose images are absent. An export that "succeeded" here
  // would hand an operator a file, a byte count and a green result for a
  // backup containing none of their images — the failure mode that is worst
  // because nothing prompts anyone to look.
  const row = db.prepare("SELECT d.id FROM deployments d JOIN apps a ON a.id = d.app_id WHERE a.slug = 'archive-e2e' AND d.status = 'live'").get();
  db.prepare("UPDATE deployments SET status = 'rolled_back' WHERE id = ?").run(row.id);
  try {
    await assert.rejects(
      () => exportImageArchive({ scope: 'image-apps' }),
      /Nothing to archive/i,
    );
  } finally {
    db.prepare("UPDATE deployments SET status = 'live' WHERE id = ?").run(row.id);
  }
});

test('export writes a file on disk, sized like an image and not like a JSON blob', async (t) => {
  if (e2eSkip) return t.skip(e2eSkip);
  const result = await exportImageArchive({ scope: 'image-apps' });
  archivePath = result.path;

  assert.ok(existsSync(archivePath), 'the archive must be a file on disk, never an HTTP response body');
  const bytes = statSync(archivePath).size;
  assert.equal(bytes, result.bytes);
  assert.ok(bytes > 100 * 1024, `an image archive of ${bytes} bytes is not an image archive`);
  // The free-space check is only worth having if `required_bytes` really does
  // cover the archive. `estimated_bytes` on its own does not — measured, a
  // 1916245-byte unpacked fixture wrote a 1929216-byte archive, because a tar
  // pads and carries its own manifest, config and index blobs.
  assert.ok(bytes <= result.required_bytes,
    `the free-space check would have under-reserved: wrote ${bytes}, reserved ${result.required_bytes}`);
  assert.ok(result.estimated_bytes > 0, 'a plan that estimates nothing cannot gate on disk space');
  assert.equal(result.file, archiveFileName(result.fingerprint), 'the pair is identified by the filename too');
  assert.ok(result.images.some((i) => i.slug === 'archive-e2e'));
});

test('with the registry gone and every local copy removed, the archive still starts a container', async (t) => {
  if (e2eSkip || !archivePath) return t.skip(e2eSkip || 'no archive was produced');
  const archiveTag = restoreTagFor(fixtureDigestRef);

  // Take away everything: the tag, the archive tag, the digest, and the registry.
  await dk(['rmi', '-f', `${fixtureRepo}:1`]).catch(() => {});
  await dk(['rmi', '-f', archiveTag]).catch(() => {});
  await dk(['rmi', '-f', fixtureDigestRef]).catch(() => {});
  await dk(['rm', '-f', REG_NAME]);

  // THE CONTROL. Without it, a pass below could just mean a copy survived the
  // removals — which is precisely how a sweep returns a clean result that is
  // not clean.
  const ranBefore = await dkOk(['run', '--rm', archiveTag, 'true']);
  assert.equal(ranBefore, false,
    'the image is supposed to be gone and the registry unreachable; if it runs here the test proves nothing');

  const loaded = await importImageArchive(archivePath);
  assert.ok(loaded.loaded.includes(archiveTag), `docker load did not restore ${archiveTag}: ${loaded.loaded.join(', ')}`);
  assert.equal(loaded.unnamed.length, 0, 'an image loaded by id alone cannot be started by any reference');

  const ranAfter = await dkOk(['run', '--rm', archiveTag, 'true']);
  assert.equal(ranAfter, true, 'THE REQUIREMENT: a container must start from the archive with no registry');

  const verification = await verifyImageSet('live');
  const row = verification.rows.find((r) => r.slug === 'archive-e2e');
  // Recorded, not asserted. This is the number that differs between image
  // stores, and printing it is how a future reader finds out which store the
  // run was on without re-deriving it.
  const store = await dk(['info', '--format', '{{.Driver}}']).catch(() => 'unknown');
  t.diagnostic(`store=${store} digest_ref_resolves=${row.digest_ref_resolves} archive_tag_present=${row.archive_tag_present}`);
  assert.equal(row.archive_tag_present, true, 'the archive tag is the handle that holds on every image store');
  assert.equal(row.restorable, true);
  // Deliberately NOT asserted: row.digest_ref_resolves. Measured true on a
  // containerd-snapshotter store and false on a classic overlay2 store, so an
  // assertion either way would be a lie on half the hosts this runs on.
});

test('saving by digest — the obvious reading of deployments.image_ref — produces an archive that restores nothing', async (t) => {
  if (e2eSkip || !fixtureDigestRef) return t.skip(e2eSkip || 'no fixture');
  const archiveTag = restoreTagFor(fixtureDigestRef);
  if (!await dkOk(['image', 'inspect', archiveTag])) return t.skip('fixture image is not present');

  // Reconstruct the digest reference locally so `docker save` can be given it.
  const byDigest = join(process.env.DATA_DIR, 'by-digest.tar');
  const id = await dk(['image', 'inspect', archiveTag, '--format', '{{.Id}}']);
  await dk(['save', id, '-o', byDigest]);
  await dk(['rmi', '-f', archiveTag]).catch(() => {});

  const { loadImagesFrom } = await import('../server/services/docker.js');
  const r = await loadImagesFrom(byDigest);
  assert.equal(r.loaded.length, 0, 'an archive saved without a repository name carries no reference to start');
  assert.ok(r.unnamed.length > 0,
    'this is why the export tags first: the image comes back reachable only by id, ' +
    'so no configured image_ref — digest or tag — can start it');
});

// ---------------------------------------------------------------------------
// The HTTP surface. The archive contains every app's image and the routes sit
// next to the config export that ships the ENCRYPTION_KEY, so the gate matters
// as much as the mechanism.
// ---------------------------------------------------------------------------

const express = (await import('express')).default;
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const settingsRoutes = (await import('../server/routes/settings.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key));
  return { key };
}
const ADMIN = mkUser('imgadmin', 'platform_admin');
const PLAIN = mkUser('imgplain', 'user');

const api = express();
api.use(express.json());
api.use('/api/settings', settingsRoutes);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE_URL = `http://127.0.0.1:${server.address().port}`;
after(() => server.close());

const call = async (as, method, path, body) => {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': as.key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
};

test('the image-archive routes are platform-admin only', async (t) => {
  if (noDocker) return t.skip(noDocker);
  for (const [method, path] of [['GET', '/api/settings/images/plan'], ['GET', '/api/settings/images/verify'], ['POST', '/api/settings/images/import']]) {
    const denied = await call(PLAIN, method, path, method === 'POST' ? { path: 'x.tar' } : undefined);
    assert.equal(denied.status, 403, `${method} ${path} must refuse a non-admin (got ${denied.status})`);
  }
  const allowed = await call(ADMIN, 'GET', '/api/settings/images/plan');
  assert.equal(allowed.status, 200);
  assert.equal(typeof allowed.body.estimated_bytes, 'number');
  assert.ok(Array.isArray(allowed.body.images));
});

test('import refuses a path outside the backups directory', async (t) => {
  if (noDocker) return t.skip(noDocker);
  const { archiveDir } = await import('../server/services/imageArchive.js');
  for (const bad of ['/etc/passwd', `${archiveDir()}/../../../etc/passwd`]) {
    const res = await call(ADMIN, 'POST', '/api/settings/images/import', { path: bad });
    assert.equal(res.status, 400, `must refuse ${bad}`);
    // The refusal has to come from the confinement check, not from the file
    // merely being absent — a guard that only works because the path happens
    // not to exist is not a guard.
    assert.match(res.body.error.message, /must be inside/i);
  }
});
