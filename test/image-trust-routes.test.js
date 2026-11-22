import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import express from 'express';

// The attestation routes over a real socket with real API keys: a document of
// one app is readable only by a user of that app (or a platform admin), a
// deployment id of another app is a 404, and nothing any route returns carries
// the private signing key or its ciphertext.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-image-trust-routes-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const { getSigningKey, PRIVATE_KEY_SETTING } = await import('../server/services/imageTrust/signingKey.js');
const { signStatement, simpleSigningPayload, signBytes } = await import('../server/services/imageTrust/envelope.js');
const { dirFor, writeDoc, FILES, insertPending, finishRow } = await import('../server/services/imageTrust/store.js');

function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
}
function mkApp(slug) {
  return db.prepare("INSERT INTO apps (name, slug, slot) VALUES (?, ?, (SELECT COALESCE(MAX(slot), 0) + 1 FROM apps))").run(slug, slug).lastInsertRowid;
}

const admin = mkUser('itradmin', 'platform_admin');
const owner = mkUser('itrowner', 'user');
const stranger = mkUser('itrstranger', 'user');
const appA = mkApp('itr-a');
const appB = mkApp('itr-b');
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appA, owner.id);
const depA = Number(db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'sandbox', 'live')").run(appA).lastInsertRowid);
const depB = Number(db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'sandbox', 'live')").run(appB).lastInsertRowid);

const key = getSigningKey(db);
const imageId = `sha256:${'1'.repeat(64)}`;
const SBOM = JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [] });
function attest(appId, slug, depId) {
  const id = insertPending(db, { deploymentId: depId, appId, env: 'sandbox', origin: 'deploy', imageRef: `appcrane-${slug}-sandbox:x` });
  const dir = dirFor(slug, 'sandbox', id);
  writeDoc(dir, FILES.sbom, SBOM);
  writeDoc(dir, FILES.provenance, JSON.stringify(signStatement({ _type: 'https://in-toto.io/Statement/v1', subject: [], predicateType: 'https://slsa.dev/provenance/v1', predicate: {} }, key)));
  const payload = simpleSigningPayload({ repository: `appcrane-${slug}-sandbox`, digest: imageId });
  writeDoc(dir, FILES.signaturePayload, payload);
  writeDoc(dir, FILES.signature, signBytes(payload, key.privateKey));
  finishRow(db, id, { status: 'signed', image_id: imageId, key_id: key.keyId, dir, sbom_status: 'ok', sbom_sha256: 'x' });
}
attest(appA, 'itr-a', depA);
attest(appB, 'itr-b', depB);

const imageTrustRoutes = (await import('../server/routes/imageTrust.js')).default;
const settingsRoutes = (await import('../server/routes/settings.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api', imageTrustRoutes);
api.use('/api/settings', settingsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.close(); rmSync(process.env.DATA_DIR, { recursive: true, force: true }); });

const bodies = [];
async function req(as, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(as ? { 'X-API-Key': as.key } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  bodies.push(text);
  return { status: res.status, text, headers: res.headers };
}

test('an app user downloads its own SBOM; a stranger gets 403 and nobody signed in gets 401', async () => {
  const own = await req(owner, 'GET', `/api/apps/itr-a/deployments/${depA}/attestation/sbom`);
  assert.equal(own.status, 200);
  assert.equal(own.text, SBOM);
  assert.match(own.headers.get('content-type'), /application\/vnd\.cyclonedx\+json/);
  assert.match(own.headers.get('content-disposition'), /itr-a-sandbox-\d+-sbom\.cdx\.json/);
  assert.equal((await req(stranger, 'GET', `/api/apps/itr-a/deployments/${depA}/attestation/sbom`)).status, 403);
  assert.equal((await req(stranger, 'GET', `/api/apps/itr-a/deployments/${depA}/attestation`)).status, 403);
  assert.equal((await req(stranger, 'GET', '/api/apps/itr-a/attestations')).status, 403);
  assert.equal((await req(null, 'GET', `/api/apps/itr-a/deployments/${depA}/attestation/sbom`)).status, 401);
});

test('another app\'s deployment id under my app is a 404, not a cross-app read', async () => {
  assert.equal((await req(owner, 'GET', `/api/apps/itr-a/deployments/${depB}/attestation/sbom`)).status, 404);
  assert.equal((await req(owner, 'GET', `/api/apps/itr-a/deployments/${depB}/attestation`)).status, 404);
  assert.equal((await req(owner, 'GET', `/api/apps/itr-b/deployments/${depB}/attestation`)).status, 403);
  assert.equal((await req(owner, 'GET', `/api/apps/itr-a/deployments/${depA}/attestation/private-key`)).status, 400);
});

test('the signature status of a deploy is reported, and verifies', async () => {
  const r = await req(owner, 'GET', `/api/apps/itr-a/deployments/${depA}/attestation`);
  assert.equal(r.status, 200);
  const a = JSON.parse(r.text).attestation;
  assert.equal(a.status, 'signed');
  assert.equal(a.key_id, key.keyId);
  assert.ok(a.documents.includes('sbom') && a.documents.includes('signature'));
  assert.ok(Array.isArray(a.problems));
  const { sbomForDeployment } = await import('../server/services/imageTrust/store.js');
  assert.deepEqual(sbomForDeployment(db, appA, depA), JSON.parse(SBOM), 'the release-check input is the stored SBOM');
  assert.equal(sbomForDeployment(db, appA, depB), null, 'another app\'s deployment yields no SBOM');
});

test('policy and backfill are platform-admin only; the generic settings routes cannot reach the key or the mode', async () => {
  assert.equal((await req(owner, 'GET', '/api/image-trust/policy')).status, 403);
  assert.equal((await req(owner, 'PUT', '/api/image-trust/policy', { mode: 'off' })).status, 403);
  assert.equal((await req(owner, 'POST', '/api/image-trust/sign-current')).status, 403);
  const put = await req(admin, 'PUT', '/api/image-trust/policy', { mode: 'enforce', denied: ['GPL-3.0-only'] });
  assert.equal(put.status, 200, put.text);
  assert.equal(JSON.parse(put.text).mode, 'enforce');
  assert.equal((await req(admin, 'PUT', '/api/image-trust/policy', { mode: 'audit' })).status, 400);
  assert.equal((await req(admin, 'PUT', '/api/image-trust/policy', { denied: ['not a license; rm'] })).status, 400);
  assert.equal((await req(admin, 'PUT', '/api/settings/image_trust_mode', { value: 'off' })).status, 403);
  assert.equal((await req(admin, 'PUT', `/api/settings/${PRIVATE_KEY_SETTING}`, { value: 'x' })).status, 403);
  assert.equal((await req(admin, 'GET', `/api/settings/${PRIVATE_KEY_SETTING}`)).status, 403);
  const all = await req(admin, 'GET', '/api/settings');
  assert.equal(all.status, 200);
  assert.ok(!(PRIVATE_KEY_SETTING in JSON.parse(all.text).settings), 'the bulk settings dump returned the encrypted signing key');
});

test('the public key is exported to any signed-in user; no response ever carries the private key', async () => {
  const r = await req(stranger, 'GET', '/api/image-trust/public-key');
  assert.equal(r.status, 200);
  assert.equal(r.text, key.publicKeyPem);
  assert.equal(r.headers.get('x-key-id'), key.keyId);
  const enc = db.prepare('SELECT value FROM settings WHERE key = ?').get(PRIVATE_KEY_SETTING).value;
  const pkcs8 = key.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const der = key.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  for (const b of bodies) {
    assert.ok(!b.includes('PRIVATE KEY') && !b.includes(enc) && !b.includes(pkcs8) && !b.includes(der), `a response carried key material: ${b.slice(0, 120)}`);
  }
});
