import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Image trust (services/imageTrust): SBOM, SLSA provenance, signature and
// verify-before-run. The LIVE tests use the real Docker daemon and the real
// pinned Trivy image: a tiny image is built, attested and verified, then a
// different image is moved under its tag and the start paths must refuse it.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-image-trust-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { getSigningKey, getPublicKey, PRIVATE_KEY_SETTING, _resetSigningKeyCache } = await import('../server/services/imageTrust/signingKey.js');
const { signStatement, verifyEnvelope } = await import('../server/services/imageTrust/envelope.js');
const { enrichSbom, sbomCoverage } = await import('../server/services/imageTrust/sbom.js');
const { licensePolicyCheck } = await import('../server/services/imageTrust/licensePolicy.js');
const { setTrustPolicy, getTrustMode } = await import('../server/services/imageTrust/policy.js');
const { attestDeployImage } = await import('../server/services/imageTrust/attest.js');
const { verifyImageForRun, enforceImageTrust } = await import('../server/services/imageTrust/verify.js');
const { SCANNER_IMAGE } = await import('../server/services/imageScan.js');
const { readDoc } = await import('../server/services/imageTrust/store.js');

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/image-trust-sbom.cdx.json', import.meta.url), 'utf8'));

function dockerOk() {
  return spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' }).status === 0;
}
function imagePresent(ref) {
  return spawnSync('docker', ['image', 'inspect', ref], { encoding: 'utf8' }).status === 0;
}
const LIVE = dockerOk() && imagePresent(SCANNER_IMAGE) && imagePresent('alpine:3');
const COSIGN = 'ghcr.io/sigstore/cosign/cosign:v2.5.3';
const tag = randomBytes(4).toString('hex');
const SLUG = `itr-${tag}`;
const OTHER = `itr-${tag}-legacy`;
const created = { tags: [], containers: [] };

after(() => {
  for (const c of created.containers) spawnSync('docker', ['rm', '-f', c]);
  for (const t of created.tags) spawnSync('docker', ['rmi', '-f', t]);
  rmSync(ROOT, { recursive: true, force: true });
});

function mkApp(slug) {
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type, branch) VALUES (?, ?, (SELECT COALESCE(MAX(slot), 0) + 1 FROM apps), 'managed', 'main')").run(slug, slug).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
function mkDeploy(app, extra = {}) {
  return Number(db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, commit_sha, lockfile_name, lockfile_sha256, base_image, base_digest)
    VALUES (?, 'sandbox', 'deploying', ?, ?, 'package-lock.json', ?, 'alpine:3', NULL)`)
    .run(app.id, extra.sha || 'a'.repeat(40), extra.sha || 'a'.repeat(40), 'b'.repeat(64)).lastInsertRowid);
}
function build(ctxFiles, ref) {
  const dir = mkdtempSync(join(ROOT, 'ctx-'));
  for (const [p, c] of Object.entries(ctxFiles)) {
    mkdirSync(join(dir, p, '..'), { recursive: true });
    writeFileSync(join(dir, p), c);
  }
  execFileSync('docker', ['build', '-q', '-t', ref, dir], { stdio: ['ignore', 'pipe', 'inherit'] });
  created.tags.push(ref);
  return execFileSync('docker', ['image', 'inspect', ref, '--format', '{{.Id}}']).toString().trim();
}

const CTX = {
  Dockerfile: 'FROM alpine:3\nWORKDIR /app\nCOPY . .\nCMD ["sleep","3600"]\n',
  'package.json': '{"name":"itr","version":"1.0.0","dependencies":{"left-pad":"1.3.0","agpl-thing":"2.0.0"}}',
  'node_modules/left-pad/package.json': '{"name":"left-pad","version":"1.3.0","license":"WTFPL"}',
  'node_modules/agpl-thing/package.json': '{"name":"agpl-thing","version":"2.0.0","license":"AGPL-3.0-only"}',
};

test('the signing key is created once, stored encrypted, and only the public half is exported', () => {
  const k1 = getSigningKey(db);
  _resetSigningKeyCache();
  const k2 = getSigningKey(db);
  assert.equal(k1.keyId, k2.keyId);
  const stored = db.prepare('SELECT value FROM settings WHERE key = ?').get(PRIVATE_KEY_SETTING).value;
  assert.doesNotMatch(stored, /PRIVATE KEY/);
  assert.match(stored, /^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
  const pub = getPublicKey(db);
  assert.match(pub.publicKeyPem, /BEGIN PUBLIC KEY/);
  assert.doesNotMatch(JSON.stringify(pub), /PRIVATE/);
  assert.equal(pub.keyId, k1.keyId);
});

test('a DSSE envelope verifies with the instance key and fails once its payload changes', () => {
  const key = getSigningKey(db);
  const env = signStatement({ _type: 'https://in-toto.io/Statement/v1', subject: [{ name: 'x', digest: { sha256: 'c'.repeat(64) } }], predicateType: 'p', predicate: {} }, key);
  assert.equal(verifyEnvelope(env, key.publicKey).ok, true);
  const forged = { ...env, payload: Buffer.from(Buffer.from(env.payload, 'base64').toString().replace('x', 'y')).toString('base64') };
  assert.equal(verifyEnvelope(forged, key.publicKey).ok, false);
});

test('the enriched SBOM carries the CISA 2026 fields and marks what is unknown', () => {
  const out = enrichSbom(FIXTURE, {
    author: 'AppCrane (crane.test.local)', appcraneVersion: '9.9.9', app: { slug: 'fx' }, env: 'sandbox', deploymentId: 7,
    imageRef: 'appcrane-fx-sandbox:abc', imageId: `sha256:${'d'.repeat(64)}`, commitSha: 'e'.repeat(40),
    lockfile: { name: 'package-lock.json', sha256: 'f'.repeat(64) },
  });
  assert.equal(out.bomFormat, 'CycloneDX');
  assert.equal(out.specVersion, '1.6');
  assert.ok(out.serialNumber && out.version === 1, 'SBOM version / serial');
  assert.ok(out.metadata.timestamp, 'timestamp');
  assert.deepEqual(out.metadata.lifecycles, [{ phase: 'post-build' }], 'generation context');
  assert.deepEqual(out.metadata.authors, [{ name: 'AppCrane (crane.test.local)' }], 'SBOM author');
  const tools = out.metadata.tools.components.map((t) => `${t.name}@${t.version}`);
  assert.ok(tools.includes('trivy@0.74.0') && tools.includes('AppCrane@9.9.9'), `tool name/version: ${tools}`);
  assert.deepEqual(out.metadata.component.hashes.find((h) => h.alg === 'SHA-256'), { alg: 'SHA-256', content: 'd'.repeat(64) });
  const props = Object.fromEntries(out.metadata.properties.map((p) => [p.name, p.value]));
  assert.equal(props['appcrane:commit_sha'], 'e'.repeat(40));
  assert.equal(props['appcrane:lockfile_sha256'], 'f'.repeat(64));
  assert.equal(props['appcrane:image_id'], `sha256:${'d'.repeat(64)}`);
  const nolic = out.components.find((c) => c.name === 'no-license');
  assert.equal(nolic.properties.find((p) => p.name === 'cisa:unknown').value, 'license,hash,producer');
  const cov = sbomCoverage(out);
  assert.deepEqual([cov.components, cov.withHash, cov.withLicense, cov.withSha256], [4, 3, 3, 0]);
  assert.equal(FIXTURE.specVersion, '1.7', 'the fixture itself is not mutated');
});

test('license policy: a denied license fails, AGPL and unknown are flagged, a clean SBOM passes', () => {
  const app = { slug: 'fx' };
  const deny = licensePolicyCheck(app, FIXTURE, { denied: ['WTFPL'], flagged: ['AGPL-3.0-only', 'unknown'] });
  assert.equal(deny.status, 'fail');
  assert.equal(deny.id, 'licenses');
  assert.ok(Array.isArray(deny.reasons) && deny.reasons.some((r) => r === 'left-pad@1.3.0: WTFPL'), deny.reasons.join('|'));
  const flag = licensePolicyCheck(app, FIXTURE, { denied: [], flagged: ['AGPL-3.0-only', 'unknown'] });
  assert.equal(flag.status, 'warn');
  assert.equal(flag.flagged, 2);
  assert.ok(flag.reasons.includes('agpl-thing@2.0.0: AGPL-3.0-only') && flag.reasons.includes('no-license@0.1.0: unknown'));
  const ok = licensePolicyCheck(app, { components: [FIXTURE.components[1]] }, { denied: ['AGPL-3.0-only'], flagged: ['unknown'] });
  assert.equal(ok.status, 'pass');
  assert.equal(licensePolicyCheck(app, null, { denied: [], flagged: [] }).status, 'warn');
  assert.equal(licensePolicyCheck(app, { components: [{ name: 'e', licenses: [{ expression: 'MIT OR AGPL-3.0-only' }] }] }, { denied: ['AGPL-3.0-only'], flagged: [] }).status, 'fail');
});

test('the default mode is warn, and the policy refuses an unknown mode', () => {
  assert.equal(getTrustMode(db), 'warn');
  assert.throws(() => setTrustPolicy(db, { mode: 'audit' }, null), /mode must be one of off, warn, enforce/);
});

test('LIVE: a built image gets an SBOM, signed provenance and a signature that verify; a moved tag is refused', { skip: !LIVE && 'docker, alpine:3 or the pinned Trivy image unavailable' }, async () => {
  setTrustPolicy(db, { mode: 'warn' }, null);
  const app = mkApp(SLUG);
  const ref = `appcrane-${SLUG}-sandbox:c1`;
  const imageId = build(CTX, ref);
  const deployId = mkDeploy(app);
  const lines = [];
  const r = await attestDeployImage({ db, app, env: 'sandbox', deploymentId: deployId, image: ref, fresh: true, appendLog: (l) => lines.push(l), allowPull: false });
  assert.equal(r.status, 'signed', lines.join('\n'));
  assert.equal(r.imageId, imageId);
  const row = db.prepare('SELECT * FROM deploy_attestations WHERE id = ?').get(r.id);
  assert.equal(row.sbom_status, 'ok', row.sbom_error);
  assert.ok(lines.some((l) => /CycloneDX 1\.6 SBOM, \d+ component\(s\); hash \d+\/\d+ \(SHA-1 \d+\), license \d+\/\d+/.test(l)), lines.join('\n'));

  const sbom = JSON.parse(readDoc(row, 'sbom'));
  assert.deepEqual(sbom.metadata.lifecycles, [{ phase: 'post-build' }]);
  assert.ok(sbom.metadata.tools.components.some((t) => t.name === 'trivy' && t.version));
  const names = new Set(sbom.components.map((c) => c.name));
  assert.ok(names.has('agpl-thing') && names.has('left-pad') && names.has('busybox'), [...names].join(','));
  assert.ok(sbom.components.filter((c) => c.type === 'library').every((c) => c.hashes?.length || c.properties?.some((p) => p.name === 'cisa:unknown')));
  const lic = JSON.parse(row.license_check_json);
  assert.equal(lic.status, 'warn', 'AGPL is flagged by default');
  assert.ok(lic.reasons.includes('agpl-thing@2.0.0: AGPL-3.0-only'));

  const key = getPublicKey(db);
  const prov = verifyEnvelope(JSON.parse(readDoc(row, 'provenance')), key.publicKey);
  assert.equal(prov.ok, true, prov.reason);
  assert.equal(prov.statement.predicateType, 'https://slsa.dev/provenance/v1');
  assert.equal(prov.statement.subject[0].digest.sha256, imageId.slice(7));
  assert.equal(prov.statement.predicate.runDetails.builder.id, 'https://crane.test.local/appcrane/builder');
  assert.deepEqual(prov.statement.predicate.buildDefinition.resolvedDependencies.find((d) => d.digest.gitCommit), { uri: `git+appcrane:managed:${SLUG}@refs/heads/main`, digest: { gitCommit: 'a'.repeat(40) } });
  assert.equal(prov.statement.predicate.runDetails.byproducts[0].digest.sha256, row.sbom_sha256);

  const ok = await verifyImageForRun({ db, slug: SLUG, env: 'sandbox', image: ref });
  assert.equal(ok.ok, true, ok.reason);

  if (imagePresent(COSIGN)) {
    const pub = join(row.dir, 'cosign.pub');
    writeFileSync(pub, key.publicKeyPem);
    const cfg = join(row.dir, 'config.json');
    writeFileSync(cfg, execFileSync('sh', ['-c', `docker save "$1" | tar -xOf - "blobs/sha256/$2"`, 'sh', ref, imageId.slice(7)]));
    const cosign = (...args) => spawnSync('docker', ['run', '--rm', '--network', 'none', '-v', `${row.dir}:/w:ro`, '-w', '/w', COSIGN, ...args], { encoding: 'utf8' });
    const blob = cosign('verify-blob', '--key', 'cosign.pub', '--insecure-ignore-tlog', '--signature', 'image.sig', 'image.sig.payload.json');
    assert.equal(blob.status, 0, blob.stderr);
    const att = cosign('verify-blob-attestation', '--key', 'cosign.pub', '--insecure-ignore-tlog', '--signature', 'provenance.intoto.json', '--type', 'https://slsa.dev/provenance/v1', 'config.json');
    assert.equal(att.status, 0, att.stderr);
    const sb = cosign('verify-blob-attestation', '--key', 'cosign.pub', '--insecure-ignore-tlog', '--signature', 'sbom.intoto.json', '--type', 'https://cyclonedx.org/bom', 'config.json');
    assert.equal(sb.status, 0, sb.stderr);
  }

  // Tamper: other bytes under the signed tag.
  const otherId = build({ ...CTX, 'extra.txt': 'not what was signed' }, `appcrane-${SLUG}-sandbox:other`);
  execFileSync('docker', ['tag', `appcrane-${SLUG}-sandbox:other`, ref]);
  const bad = await verifyImageForRun({ db, slug: SLUG, env: 'sandbox', image: ref });
  assert.equal(bad.ok, false);
  assert.match(bad.reason, new RegExp(`TAMPERED: ${ref.replace(/[.:]/g, '\\$&')} now points at ${otherId}, but this instance signed ${imageId}`));

  const warned = [];
  const w = await enforceImageTrust({ db, slug: SLUG, env: 'sandbox', image: ref, onLog: (l) => warned.push(l) });
  assert.equal(w.ok, false);
  assert.match(warned.join('\n'), /Image trust \(warn mode\): .*TAMPERED/);

  const cached = await attestDeployImage({ db, app, env: 'sandbox', deploymentId: mkDeploy(app), image: ref, fresh: false, allowPull: false });
  assert.equal(cached.status, 'error');
  assert.match(cached.error, /not signing it/);

  setTrustPolicy(db, { mode: 'enforce' }, null);
  try {
    const refused = [];
    await assert.rejects(enforceImageTrust({ db, slug: SLUG, env: 'sandbox', image: ref, onLog: (l) => refused.push(l) }), (e) => e.code === 'IMAGE_UNTRUSTED' && /TAMPERED/.test(e.message));
    assert.match(refused.join('\n'), /IMAGE_UNTRUSTED: refusing to start/);

    const docker = await import('../server/services/docker.js');
    const name = `appcrane-${SLUG}-sandbox`;
    await assert.rejects(docker.startApp({ slug: SLUG, env: 'sandbox', image: ref, hostPort: 1, admission: false }), /IMAGE_UNTRUSTED/);
    assert.equal(spawnSync('docker', ['inspect', name]).status, 1, 'startApp created a container from a tampered image');

    execFileSync('docker', ['create', '--name', name, ref, 'sleep', '3600'], { stdio: 'ignore' });
    created.containers.push(name);
    await assert.rejects(docker.restartApp(SLUG, 'sandbox'), /IMAGE_UNTRUSTED/);
    assert.equal(execFileSync('docker', ['inspect', name, '--format', '{{.State.Status}}']).toString().trim(), 'created', 'restartApp started a tampered image');

    execFileSync('docker', ['tag', imageId, ref]);
    const again = await enforceImageTrust({ db, slug: SLUG, env: 'sandbox', image: ref });
    assert.equal(again.ok, true, again.reason);
  } finally {
    setTrustPolicy(db, { mode: 'warn' }, null);
  }
});

test('LIVE: an unsigned legacy image is warned about under warn and refused under enforce', { skip: !LIVE && 'docker, alpine:3 or the pinned Trivy image unavailable' }, async () => {
  mkApp(OTHER);
  const ref = `appcrane-${OTHER}-sandbox:legacy`;
  build({ Dockerfile: 'FROM alpine:3\nCMD ["sleep","3600"]\n' }, ref);
  const lines = [];
  const r = await enforceImageTrust({ db, slug: OTHER, env: 'sandbox', image: ref, onLog: (l) => lines.push(l) });
  assert.equal(r.ok, false);
  assert.match(lines.join('\n'), /Image trust \(warn mode\): .*UNSIGNED: no signature from this instance/);
  setTrustPolicy(db, { mode: 'enforce' }, null);
  try {
    await assert.rejects(enforceImageTrust({ db, slug: OTHER, env: 'sandbox', image: ref }), /IMAGE_UNTRUSTED: .*UNSIGNED/);
  } finally {
    setTrustPolicy(db, { mode: 'off' }, null);
  }
  const off = await enforceImageTrust({ db, slug: OTHER, env: 'sandbox', image: ref });
  assert.equal(off.skipped, true);
  setTrustPolicy(db, { mode: 'warn' }, null);
});

test('LIVE: a tampered signature file fails verification', { skip: !LIVE && 'docker, alpine:3 or the pinned Trivy image unavailable' }, async () => {
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(SLUG);
  const ref = `appcrane-${SLUG}-sandbox:c1`;
  const r = await attestDeployImage({ db, app, env: 'sandbox', deploymentId: mkDeploy(app), image: ref, fresh: true, allowPull: false });
  assert.equal(r.status, 'signed');
  const row = db.prepare('SELECT * FROM deploy_attestations WHERE id = ?').get(r.id);
  const p = join(row.dir, 'image.sig.payload.json');
  const original = readFileSync(p);
  writeFileSync(p, original.toString().replace('"dev.appcrane.env":"sandbox"', '"dev.appcrane.env":"production"'));
  db.prepare("UPDATE deploy_attestations SET status = 'superseded' WHERE app_id = ? AND id != ?").run(app.id, r.id);
  const bad = await verifyImageForRun({ db, slug: SLUG, env: 'sandbox', image: ref });
  assert.match(bad.reason || '', /INVALID: the image signature does not verify/);
  writeFileSync(p, original);
  assert.equal((await verifyImageForRun({ db, slug: SLUG, env: 'sandbox', image: ref })).ok, true);
  assert.ok(existsSync(join(row.dir, 'sbom.cdx.json')));
  assert.equal(createHash('sha256').update(readFileSync(join(row.dir, 'sbom.cdx.json'))).digest('hex'), row.sbom_sha256);
});
