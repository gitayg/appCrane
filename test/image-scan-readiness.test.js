import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import express from 'express';

// The production case: a deploy ran while the pinned scanner was missing, so
// its image was signed WITHOUT an SBOM attestation, and every restart logged
// "Image trust (warn mode): ... INVALID: no SBOM attestation (container image
// scanner unavailable ...)". Enforce would refuse that restart, so the
// enforce-readiness census must count it, and once the scanner is here,
// "sign current" and the next cached deploy must add the SBOM. A row whose
// documents do not verify for any other reason is reported, never re-signed.
// A docker shim on PATH: the scanner is present only after a pull that is
// allowed to succeed; containers map to image ids from a file.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-scan-ready-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.t.test';

const SHIM = join(ROOT, 'bin');
const PRESENT = join(ROOT, 'scanner-present');
const PULL_FAIL = join(ROOT, 'pull-fail');
const CONTAINERS = join(ROOT, 'containers.json');
mkdirSync(SHIM, { recursive: true });
writeFileSync(CONTAINERS, '{}');
writeFileSync(join(ROOT, 'sbom.json'), readFileSync(new URL('./fixtures/image-trust-sbom.cdx.json', import.meta.url), 'utf8'));
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const { readFileSync, writeFileSync, existsSync } = require('fs');
const argv = process.argv.slice(2);
const trivy = argv.some((a) => String(a).startsWith('aquasec/trivy'));
const idOf = (ref) => 'sha256:' + require('crypto').createHash('sha256').update(String(ref)).digest('hex');
const fail = (m) => { process.stderr.write(m + '\\n'); process.exit(1); };
if (argv[0] === 'image' && argv[1] === 'inspect') {
  const ref = argv[2];
  if (trivy) { if (!existsSync(${JSON.stringify(PRESENT)})) fail('Error response from daemon: No such image: ' + ref); process.stdout.write('sha256:' + 'f'.repeat(64)); process.exit(0); }
  const id = /^sha256:[a-f0-9]{64}$/.test(ref) ? ref : idOf(ref);
  const fmt = argv[argv.indexOf('--format') + 1] || '';
  process.stdout.write(fmt.includes('RepoDigests') ? id + '|[]' : id);
  process.exit(0);
}
if (argv[0] === 'pull' && trivy) {
  if (existsSync(${JSON.stringify(PULL_FAIL)})) fail('Error response from daemon: Get "https://registry.t.test/v2/": dial tcp: i/o timeout');
  writeFileSync(${JSON.stringify(PRESENT)}, '1');
  process.exit(0);
}
if (argv[0] === 'inspect') {
  const c = JSON.parse(readFileSync(${JSON.stringify(CONTAINERS)}, 'utf8'))[argv[1]];
  if (!c) fail('Error: No such object: ' + argv[1]);
  process.stdout.write(c.id + '|' + c.ref + '|' + c.ref);
  process.exit(0);
}
if (argv[0] === 'run' && trivy) {
  const sbom = JSON.parse(readFileSync(${JSON.stringify(join(ROOT, 'sbom.json'))}, 'utf8'));
  sbom.metadata.component.properties = [{ name: 'aquasecurity:trivy:ImageID', value: argv[argv.length - 1] }];
  process.stdout.write(JSON.stringify(sbom));
  process.exit(0);
}
if (argv[0] === 'images') process.exit(0);
fail('shim: unexpected docker ' + argv.join(' '));
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { attestImage, attestDeployImage } = await import('../server/services/imageTrust/attest.js');
const { verifyImageForRun } = await import('../server/services/imageTrust/verify.js');
const { enforceReadiness } = await import('../server/services/imageTrust/readiness.js');
const { signCurrentImages } = await import('../server/services/imageTrust/backfill.js');
const { setTrustPolicy } = await import('../server/services/imageTrust/policy.js');
const { readDoc } = await import('../server/services/imageTrust/store.js');
const { _setScannerDockerForTests } = await import('../server/services/imageScan.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { getTrustMode } = await import('../server/services/imageTrust/policy.js');
const adminKey = generateApiKey('dhk_user');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('rdadmin','rdadmin@t.test','platform_admin',?,1,'human')").run(hashApiKey(adminKey));
const api = express();
api.use(express.json());
api.use('/api', (await import('../server/routes/imageTrust.js')).default);
api.use((await import('../server/utils/errors.js')).errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
async function call(method, path, body) {
  const res = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
    method, headers: { 'Content-Type': 'application/json', 'X-API-Key': adminKey },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, json: await res.json() };
}

after(() => { server.closeAllConnections?.(); server.close(); rmSync(ROOT, { recursive: true, force: true }); });

let slot = 800;
function mkApp(slug) {
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')").run(slug, slug, slot++).lastInsertRowid);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
function liveDeploy(app, env) {
  return Number(db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash) VALUES (?, ?, 'live', 'c1')").run(app.id, env).lastInsertRowid);
}
function run(app, env, image, id) {
  const c = JSON.parse(readFileSync(CONTAINERS, 'utf8'));
  c[`appcrane-${app.slug}-${env}`] = { id, ref: image };
  writeFileSync(CONTAINERS, JSON.stringify(c));
}

setTrustPolicy(db, { mode: 'warn' }, null);
writeFileSync(PULL_FAIL, '1');
const voip = mkApp('rd-voip');
const VOIP_IMG = 'appcrane-rd-voip-production:c1';
const site = mkApp('rd-site');
const SITE_IMG = 'appcrane-rd-site-production:c1';
let voipId;

test('a deploy with no obtainable scanner signs without an SBOM, and verify-before-run reports it', async () => {
  const lines = [];
  const r = await attestImage({ db, app: voip, env: 'production', deploymentId: liveDeploy(voip, 'production'), image: VOIP_IMG, appendLog: (l) => lines.push(l) });
  assert.equal(r.status, 'signed', r.error);
  assert.equal(r.sbomStatus, 'missing');
  voipId = r.imageId;
  run(voip, 'production', VOIP_IMG, voipId);
  const row = db.prepare('SELECT sbom_error FROM deploy_attestations WHERE id = ?').get(r.id);
  assert.match(row.sbom_error, /container image scanner unavailable: .* could not be pulled .*i\/o timeout/);
  const v = await verifyImageForRun({ db, slug: voip.slug, env: 'production', image: VOIP_IMG, imageId: voipId });
  assert.equal(v.ok, false);
  assert.match(v.reason, /^INVALID: no SBOM attestation \(container image scanner unavailable/);
});

test('enforce readiness counts the SBOM-less running image as one enforce would refuse', async () => {
  const r = await enforceReadiness(db);
  assert.equal(r.ready, false, JSON.stringify(r));
  const e = r.running_unsigned.find((x) => x.app === voip.slug);
  assert.ok(e, JSON.stringify(r.running_unsigned));
  assert.equal(e.state, 'sbom-missing');
  assert.equal(e.scanner_missing, true);
  assert.deepEqual(r.would_refuse, { total: 1, unsigned: 0, sbom_missing: 1, scanner_missing: 1, invalid: 0 });
});

test('the census and the enforce switch (real router) treat an SBOM-less running image as one enforce refuses', async () => {
  const c = await call('GET', '/api/image-trust/census');
  assert.equal(c.status, 200, JSON.stringify(c.json));
  assert.equal(c.json.envs.find((e) => e.app === voip.slug).state, 'sbom-missing');
  assert.equal(c.json.enforce_ready, false);
  const r = await call('PUT', '/api/image-trust/policy', { mode: 'enforce' });
  assert.equal(r.status, 409, JSON.stringify(r.json));
  assert.equal(r.json.error.code, 'IMAGE_TRUST_NOT_READY');
  assert.match(r.json.error.message, /^1 running image\(s\) are not signed by this instance, signed without an SBOM, or whose signature does not verify \(0 unsigned, 1 without an SBOM, 0 not verifying\)/);
  assert.deepEqual(r.json.error.would_refuse, { total: 1, unsigned: 0, sbom_missing: 1, scanner_missing: 1, invalid: 0 });
  assert.ok(r.json.error.running_unsigned.some((e) => e.app === voip.slug && e.state === 'sbom-missing'));
  assert.equal(getTrustMode(db), 'warn');
});

test('once the scanner can be pulled, sign-current adds the SBOM and readiness clears', async () => {
  rmSync(PULL_FAIL);
  const envs = await signCurrentImages({ db });
  const e = envs.find((x) => x.app === voip.slug);
  assert.equal(e.state, 'backfilled', JSON.stringify(envs));
  assert.ok(existsSync(PRESENT), 'the scanner was pulled');
  const v = await verifyImageForRun({ db, slug: voip.slug, env: 'production', image: VOIP_IMG, imageId: voipId });
  assert.equal(v.ok, true, v.reason);
  const r = await enforceReadiness(db);
  assert.equal(r.ready, true, JSON.stringify(r));
  assert.equal(r.would_refuse.total, 0);
  assert.equal((await call('GET', '/api/image-trust/census')).json.enforce_ready, true);
});

test('a cached deploy whose earlier signature has no SBOM is signed again with one', async () => {
  rmSync(PRESENT);
  writeFileSync(PULL_FAIL, '1');
  const first = await attestImage({ db, app: site, env: 'production', deploymentId: liveDeploy(site, 'production'), image: SITE_IMG });
  assert.equal(first.sbomStatus, 'missing');
  rmSync(PULL_FAIL);
  // A deploy does not retry a failed pull for 15 minutes; this is later than that.
  _setScannerDockerForTests(null);
  const lines = [];
  const again = await attestDeployImage({ db, app: site, env: 'production', deploymentId: liveDeploy(site, 'production'), image: SITE_IMG, fresh: false, appendLog: (l) => lines.push(l) });
  assert.equal(again.status, 'signed', again.error);
  assert.equal(again.sbomStatus, 'ok', lines.join('\n'));
  assert.ok(!again.reused, 'the SBOM-less signature is not reused');
  const origins = db.prepare('SELECT id, origin FROM deploy_attestations WHERE id IN (?, ?)').all(first.id, again.id);
  assert.deepEqual(origins.map((o) => o.origin), ['deploy', 'deploy'], 'a deploy-built image keeps its deploy provenance when re-signed');
  const v = await verifyImageForRun({ db, slug: site.slug, env: 'production', image: SITE_IMG, imageId: first.imageId });
  assert.equal(v.ok, true, v.reason);
});

test('a signed row whose signature no longer verifies is reported invalid and never re-signed over', async () => {
  run(site, 'production', SITE_IMG, (await verifyImageForRun({ db, slug: site.slug, env: 'production', image: SITE_IMG })).imageId);
  const row = db.prepare("SELECT * FROM deploy_attestations WHERE app_id = ? AND status = 'signed' ORDER BY id DESC LIMIT 1").get(site.id);
  writeFileSync(join(row.dir, 'image.sig'), Buffer.from('tampered').toString('base64'));
  assert.ok(readDoc(row, 'signature'));
  const before = db.prepare('SELECT COUNT(*) AS n FROM deploy_attestations WHERE app_id = ?').get(site.id).n;
  const envs = await signCurrentImages({ db });
  const e = envs.find((x) => x.app === site.slug);
  assert.equal(e.state, 'invalid', JSON.stringify(e));
  assert.match(e.detail, /signature does not verify/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM deploy_attestations WHERE app_id = ?').get(site.id).n, before, 'nothing was signed');
  const r = await enforceReadiness(db);
  assert.equal(r.ready, false);
  assert.equal(r.would_refuse.invalid, 1);
});
