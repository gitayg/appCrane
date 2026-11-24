import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import express from 'express';

// Turning enforce on safely, end to end with real Docker and the real routers.
// An app runs an image built before signing existed (the production case: warn
// mode logs UNSIGNED on every auto-restart). The census lists it, PUT enforce is
// refused while it is unsigned, an acknowledged override is audited, a refused
// restart under enforce leaves the container running and is audited, mailed and
// shown on the app, and after "sign current" enforce turns on and the restart
// passes. On-disk release images are signed by the backfill only when a
// deployment row names them. A PATH shim forwards to the real CLI and answers
// only the pinned SBOM tool.

function realDocker() {
  const r = spawnSync('sh', ['-c', 'command -v docker'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}
const DOCKER = realDocker();
const LIVE = !!DOCKER
  && spawnSync(DOCKER, ['version', '--format', '{{.Server.Version}}']).status === 0
  && spawnSync(DOCKER, ['image', 'inspect', 'alpine:3']).status === 0;

const ROOT = mkdtempSync(join(tmpdir(), 'crane-trust-ready-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test.local';

const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(ROOT, 'sbom.json'), readFileSync(new URL('./fixtures/image-trust-sbom.cdx.json', import.meta.url), 'utf8'));
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const { readFileSync } = require('fs');
const { spawnSync } = require('child_process');
const argv = process.argv.slice(2);
if (argv.some((a) => String(a).startsWith('aquasec/trivy'))) {
  if (argv[0] === 'image') { process.stdout.write('sha256:' + 'a'.repeat(64)); process.exit(0); }
  const sbom = JSON.parse(readFileSync(${JSON.stringify(join(ROOT, 'sbom.json'))}, 'utf8'));
  sbom.metadata.component.properties = [{ name: 'aquasecurity:trivy:ImageID', value: argv[argv.length - 1] }];
  process.stdout.write(JSON.stringify(sbom));
  process.exit(0);
}
const r = spawnSync(${JSON.stringify(DOCKER)}, argv, { stdio: 'inherit' });
process.exit(r.status ?? 1);
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
const warnings = [];
logger.warn = (m) => { warnings.push(String(m)); };
for (const lvl of ['info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const { setTrustPolicy, getTrustMode } = await import('../server/services/imageTrust/policy.js');
const docker = await import('../server/services/docker.js');

const SLUG = `itg-${randomBytes(4).toString('hex')}`;
const NAME = `appcrane-${SLUG}-sandbox`;
const TAG = `appcrane-${SLUG}-sandbox:c1`;
const OLD = `appcrane-${SLUG}-sandbox:c0`;
const STRAY = `appcrane-${SLUG}-sandbox:stray`;
const ROLLBACK = `appcrane-${SLUG}-production:r1`;

function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, email: `${name}@t.test` };
}
const admin = mkUser('itgadmin', 'platform_admin');
const owner = mkUser('itgowner', 'user');
const stranger = mkUser('itgstranger', 'user');
const appId = Number(db.prepare("INSERT INTO apps (name, slug, slot, source_type, branch) VALUES (?, ?, (SELECT COALESCE(MAX(slot), 0) + 1 FROM apps), 'managed', 'main')").run(SLUG, SLUG).lastInsertRowid);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, owner.id);

const routes = (await import('../server/routes/imageTrust.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api', routes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
async function req(as, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(as ? { 'X-API-Key': as.key } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, text, json };
}

after(() => {
  server.closeAllConnections?.();
  server.close();
  if (LIVE) {
    spawnSync(DOCKER, ['rm', '-f', NAME]);
    for (const t of [TAG, OLD, STRAY, ROLLBACK]) spawnSync(DOCKER, ['rmi', '-f', t]);
    spawnSync(DOCKER, ['image', 'prune', '-f', '--filter', `label=itg=${SLUG}`]);
  }
  rmSync(ROOT, { recursive: true, force: true });
});

function build(which, ref) {
  const dir = mkdtempSync(join(ROOT, 'ctx-'));
  writeFileSync(join(dir, 'Dockerfile'), `FROM alpine:3\nLABEL itg=${SLUG}\nCOPY . /app\nCMD ["sleep","3600"]\n`);
  writeFileSync(join(dir, 'which.txt'), which);
  execFileSync(DOCKER, ['build', '-q', '-t', ref, dir], { stdio: ['ignore', 'pipe', 'inherit'] });
  return execFileSync(DOCKER, ['image', 'inspect', ref, '--format', '{{.Id}}']).toString().trim();
}
const inspect = (fmt) => execFileSync(DOCKER, ['inspect', NAME, '--format', fmt]).toString().trim();
const audits = (action) => db.prepare('SELECT detail FROM audit_log WHERE action = ? ORDER BY id').all(action).map((r) => JSON.parse(r.detail));
const mails = () => db.prepare("SELECT to_email, subject FROM email_queue WHERE source = 'image-trust' ORDER BY id").all();
const start = () => docker.startApp({ slug: SLUG, env: 'sandbox', image: TAG, hostPort: 0, admission: false, memoryMb: 64, cpus: 0.1 });

const opts = { skip: !LIVE && 'docker or alpine:3 unavailable' };
let runningId;
let oldId;

test('LIVE: warn mode logs an unsigned restart once a day per image, counts every one, and the census lists it', opts, async () => {
  runningId = build('running', TAG);
  oldId = build('older release', OLD);
  build('stray', STRAY);
  db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash) VALUES (?, 'sandbox', 'rolled_back', 'c0')").run(appId);
  db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash) VALUES (?, 'sandbox', 'live', 'c1')").run(appId);
  assert.equal(getTrustMode(db), 'warn');

  await start();
  await docker.restartApp(SLUG, 'sandbox');
  await docker.restartApp(SLUG, 'sandbox');
  const lines = warnings.filter((w) => w.includes('Image trust (warn mode)') && w.includes(SLUG));
  assert.equal(lines.length, 1, `expected one warn line for three unsigned starts, got ${lines.length}:\n${lines.join('\n')}`);
  assert.match(lines[0], /UNSIGNED: no signature from this instance/);
  const ev = db.prepare("SELECT count, what FROM image_trust_events WHERE app_id = ? AND kind = 'warn' AND image_id = ?").get(appId, runningId);
  assert.equal(ev.count, 3);

  const c = await req(admin, 'GET', '/api/image-trust/census');
  assert.equal(c.status, 200, c.text);
  assert.equal(c.json.enforce_ready, false);
  assert.deepEqual(c.json.envs.find((e) => e.app === SLUG), { app: SLUG, env: 'sandbox', deployment_id: c.json.envs.find((e) => e.app === SLUG).deployment_id, image_id: runningId, state: 'unsigned' });
  const mine = c.json.on_disk.filter((i) => i.app === SLUG);
  assert.equal(mine.find((i) => i.image_ref === OLD)?.state, 'unsigned');
  assert.equal(mine.find((i) => i.image_ref === STRAY)?.state, 'unprovable');
  assert.ok(c.json.events.some((e) => e.app === SLUG && e.kind === 'warn' && e.count === 3));
  assert.equal((await req(owner, 'GET', '/api/image-trust/census')).status, 403);
});

test('LIVE: switching to enforce with an unsigned running image is refused with the list; an acknowledged switch is audited', opts, async () => {
  const r = await req(admin, 'PUT', '/api/image-trust/policy', { mode: 'enforce' });
  assert.equal(r.status, 409, r.text);
  assert.equal(r.json.error.code, 'IMAGE_TRUST_NOT_READY');
  assert.ok(r.json.error.running_unsigned.some((e) => e.app === SLUG && e.image_id === runningId));
  assert.ok(r.json.error.on_disk_unsigned.some((e) => e.image_ref === OLD));
  assert.equal(getTrustMode(db), 'warn', 'a refused switch changed the mode');
  assert.equal((await req(admin, 'PUT', '/api/image-trust/policy', { mode: 'enforce', acknowledge_unsigned: 'yes' })).status, 409, 'only true acknowledges');
  assert.equal((await req(owner, 'PUT', '/api/image-trust/policy', { mode: 'enforce', acknowledge_unsigned: true })).status, 403);

  const ok = await req(admin, 'PUT', '/api/image-trust/policy', { mode: 'enforce', acknowledge_unsigned: true });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(getTrustMode(db), 'enforce');
  const a = audits('image-trust-policy-set').at(-1);
  assert.equal(a.mode, 'enforce');
  assert.ok(a.acknowledged_unsigned.some((s) => s.startsWith(`${SLUG}/sandbox`)), JSON.stringify(a));
});

test('LIVE: a restart refused under enforce leaves the container running, and is audited, mailed once a day and shown on the app', opts, async () => {
  const startedAt = inspect('{{.State.StartedAt}}');
  await assert.rejects(docker.restartApp(SLUG, 'sandbox'), (e) => e.code === 'IMAGE_UNTRUSTED');
  await assert.rejects(docker.restartApp(SLUG, 'sandbox'), (e) => e.code === 'IMAGE_UNTRUSTED');
  assert.equal(inspect('{{.State.Status}}'), 'running', 'a refused restart stopped the container');
  assert.equal(inspect('{{.State.StartedAt}}'), startedAt, 'the container was restarted although refused');

  const refused = audits('image-trust-refused');
  assert.equal(refused.length, 2, 'every refusal is audited');
  assert.equal(refused[1].count, 2);
  assert.equal(refused[0].what, 'restart');
  assert.equal(refused[0].image_id, runningId);
  const m = mails();
  assert.deepEqual(m.map((x) => x.to_email).sort(), [admin.email, owner.email], 'one mail each to the owner and the platform admin, not one per refusal');
  assert.match(m[0].subject, new RegExp(`IMAGE REFUSED - ${SLUG} sandbox restart`));

  const app = await req(owner, 'GET', `/api/apps/${SLUG}/attestations`);
  assert.equal(app.status, 200, app.text);
  const ev = app.json.trust_events.find((e) => e.kind === 'refused');
  assert.equal(ev.count, 2);
  assert.match(ev.reason, /UNSIGNED/);
  assert.equal((await req(stranger, 'GET', `/api/apps/${SLUG}/attestations`)).status, 403);
});


test('LIVE: waking a sleeping env with an unsigned image under enforce is refused and leaves it asleep', opts, async () => {
  const { wakeEnv, _setWakeDepsForTests } = await import('../server/services/envWake.js');
  const { setSleepState } = await import('../server/services/envSleepState.js');
  execFileSync(DOCKER, ['stop', '-t', '1', NAME]);
  setSleepState(db, appId, 'sandbox', { state: 'sleeping' });
  const before = audits('image-trust-refused').length;
  _setWakeDepsForTests({ admit: async () => {}, recoverSoon: async () => {}, invalidate: () => {} });
  try {
    const r = await wakeEnv({ id: appId, slug: SLUG }, 'sandbox');
    assert.equal(r.ok, false, 'an unsigned image was woken under enforce');
    assert.equal(r.code, 'IMAGE_UNTRUSTED');
  } finally { _setWakeDepsForTests(null); }
  assert.equal(inspect('{{.State.Status}}'), 'exited', 'the refused wake started the container');
  assert.equal(audits('image-trust-refused').length, before + 1);
  assert.equal(audits('image-trust-refused').at(-1).what, 'wake');
  execFileSync(DOCKER, ['start', NAME]);
  setSleepState(db, appId, 'sandbox', { state: 'awake' });
});
test('LIVE: after signing the running image enforce turns on without an override and the restart passes', opts, async () => {
  setTrustPolicy(db, { mode: 'warn' }, null);
  const s = await req(admin, 'POST', '/api/image-trust/sign-current');
  assert.equal(s.status, 200, s.text);
  assert.equal(s.json.envs.find((e) => e.app === SLUG).state, 'backfilled', s.text);
  const c = await req(admin, 'GET', '/api/image-trust/census');
  assert.equal(c.json.enforce_ready, true);
  assert.ok(!c.json.events.some((e) => e.app === SLUG), 'a signed image still shows as a trust event');
  const ok = await req(admin, 'PUT', '/api/image-trust/policy', { mode: 'enforce' });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(audits('image-trust-policy-set').at(-1).acknowledged_unsigned, undefined);
  await docker.restartApp(SLUG, 'sandbox');
  assert.equal(inspect('{{.State.Status}}'), 'running');
  assert.equal((await req(owner, 'GET', `/api/apps/${SLUG}/attestations`)).json.trust_events.length, 0);
});

test('LIVE: the disk backfill signs a release image a deployment names, as trust on first use, and lists a stray tag unsigned', opts, async () => {
  assert.equal((await req(owner, 'POST', '/api/image-trust/backfill-disk')).status, 403);
  const r = await req(admin, 'POST', '/api/image-trust/backfill-disk');
  assert.equal(r.status, 200, r.text);
  const mine = r.json.images.filter((i) => i.app === SLUG);
  const old = mine.find((i) => i.image_ref === OLD);
  assert.equal(old.state, 'backfilled', JSON.stringify(old));
  assert.equal(mine.find((i) => i.image_ref === STRAY).state, 'unprovable');
  assert.equal(mine.find((i) => i.image_ref === TAG).state, 'signed');
  const row = db.prepare("SELECT origin, status, deployment_id FROM deploy_attestations WHERE app_id = ? AND image_id = ? ORDER BY id DESC").get(appId, oldId);
  assert.equal(row.origin, 'backfill');
  assert.equal(row.status, 'signed');
  assert.equal(row.deployment_id, old.deployment_id);
  assert.equal(db.prepare("SELECT commit_hash FROM deployments WHERE id = ?").get(row.deployment_id).commit_hash, 'c0');
  assert.ok(audits('image-trust-backfill-disk').at(-1).backfilled.some((s) => s.includes(OLD)));

  const { verifyImageForRun } = await import('../server/services/imageTrust/verify.js');
  const v = await verifyImageForRun({ db, slug: SLUG, env: 'sandbox', image: OLD });
  assert.equal(v.ok, true, v.reason);
  const stray = await verifyImageForRun({ db, slug: SLUG, env: 'sandbox', image: STRAY });
  assert.equal(stray.ok, false);
  setTrustPolicy(db, { mode: 'warn' }, null);
});

test('the warn log line and the refusal mail come back after a day, not before', async () => {
  const { enforceImageTrust } = await import('../server/services/imageTrust/verify.js');
  const id = `sha256:${'7'.repeat(64)}`;
  const q = { db, slug: SLUG, env: 'production', image: `appcrane-${SLUG}-production:x`, imageId: id, what: 'restart' };
  const lines = () => warnings.filter((w) => w.includes('Image trust (warn mode)') && w.includes(`${SLUG}/production`)).length;
  setTrustPolicy(db, { mode: 'warn' }, null);
  await enforceImageTrust(q);
  await enforceImageTrust(q);
  assert.equal(lines(), 1);
  db.prepare("UPDATE image_trust_events SET last_logged_at = datetime('now', '-25 hours') WHERE image_id = ? AND kind = 'warn'").run(id);
  await enforceImageTrust(q);
  assert.equal(lines(), 2, 'a day later the image is logged again');

  setTrustPolicy(db, { mode: 'enforce' }, null);
  const before = mails().length;
  await assert.rejects(enforceImageTrust(q), (e) => e.code === 'IMAGE_UNTRUSTED');
  await assert.rejects(enforceImageTrust(q), (e) => e.code === 'IMAGE_UNTRUSTED');
  assert.equal(mails().length, before + 2, 'first refusal mails owner and admin once');
  db.prepare("UPDATE image_trust_events SET last_notified_at = datetime('now', '-25 hours') WHERE image_id = ? AND kind = 'refused'").run(id);
  db.prepare("DELETE FROM email_queue WHERE source = 'image-trust' AND subject LIKE ?").run(`%${SLUG} production%`);
  await assert.rejects(enforceImageTrust(q), (e) => e.code === 'IMAGE_UNTRUSTED');
  assert.equal(mails().length, before + 2, 'a day later the refusal is mailed again');
  setTrustPolicy(db, { mode: 'warn' }, null);
});

test('LIVE: under enforce, the deploy pipeline a rollback runs signs a cached unsigned release image (trust on first use) and starts it', opts, async () => {
  const id = build('rollback target', ROLLBACK);
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
  const dep = Number(db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash) VALUES (?, 'production', 'deploying', 'r1')").run(appId).lastInsertRowid);
  setTrustPolicy(db, { mode: 'enforce' }, null);
  try {
    const { attestDeployImage } = await import('../server/services/imageTrust/attest.js');
    const { enforceImageTrust } = await import('../server/services/imageTrust/verify.js');
    const r = await attestDeployImage({ db, app, env: 'production', deploymentId: dep, image: ROLLBACK, fresh: false, allowPull: false });
    assert.equal(r.status, 'signed', r.error);
    assert.equal(db.prepare('SELECT origin FROM deploy_attestations WHERE id = ?').get(r.id).origin, 'backfill');
    const v = await enforceImageTrust({ db, slug: SLUG, env: 'production', image: ROLLBACK, what: 'deploy' });
    assert.equal(v.ok, true);
    assert.equal(v.imageId, id);
  } finally {
    setTrustPolicy(db, { mode: 'warn' }, null);
  }
});
