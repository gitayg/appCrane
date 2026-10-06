import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// Signed identity headers (v2.97.0).
//
// Stripping client-sent X-AppCrane-* headers at Caddy only protects traffic
// that goes through Caddy. Measured: on Docker Desktop a sibling container
// reaches another app's 127.0.0.1 publish through host.docker.internal, and a
// raw tcp/dual port never passes Caddy at all. So /api/identity/verify signs
// what it issues with a secret only that app holds (APPCRANE_IDENTITY_SECRET),
// and appcrane-tenant's verifyIdentity() rejects anything it did not sign.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-idsig-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkApp = (slug, slot) => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES (?,?,?,'managed','forward_auth','private')"
).run(slug, slug, slot).lastInsertRowid;
const ALPHA = mkApp('sig-alpha', 1);
const BETA = mkApp('sig-beta', 2);

const uid = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('Dana','dana@acme.test','user',1,?)")
  .run(hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?,?, datetime('now','+1 day'))")
  .run(uid, hashApiKey('sig-token'));
for (const a of [ALPHA, BETA]) db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(a, uid);

const identityRouter = (await import('../server/routes/identity.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { identitySecretFor } = await import('../server/services/identitySignature.js');
const { verifyIdentity } = await import('../packages/tenant/index.js');

const api = express();
api.use('/api/identity', identityRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

/** The headers Caddy would copy onto the upstream request, as a plain object. */
async function issued(slug) {
  const r = await fetch(`${BASE}/api/identity/verify?app=${slug}&prefix=/${slug}`, {
    headers: { Authorization: 'Bearer sig-token' }, redirect: 'manual',
  });
  assert.equal(r.status, 200);
  const h = {};
  for (const [k, v] of r.headers) if (k.startsWith('x-appcrane-')) h[k] = v;
  return h;
}

test('/verify signs what it issues, and the app\'s own secret verifies it', async () => {
  const h = await issued('sig-alpha');
  assert.ok(h['x-appcrane-identity-sig'], 'no signature issued');
  assert.ok(/^\d+$/.test(h['x-appcrane-identity-ts']), 'no timestamp issued');
  const id = verifyIdentity(h, { secret: identitySecretFor(db, ALPHA) });
  assert.equal(id.userId, String(uid));
  assert.equal(id.email, 'dana@acme.test');
});

test('forged headers with no signature are rejected', () => {
  const forged = { 'x-appcrane-user-id': '1', 'x-appcrane-user-email': 'admin@acme.test', 'x-appcrane-user-role': 'platform_admin' };
  assert.throws(() => verifyIdentity(forged, { secret: identitySecretFor(db, ALPHA) }), /signature/);
});

test('one header changed after signing is rejected', async () => {
  const h = await issued('sig-alpha');
  h['x-appcrane-user-role'] = 'platform_admin';
  assert.throws(() => verifyIdentity(h, { secret: identitySecretFor(db, ALPHA) }), /signature/);
});

test('a signature issued for another app does not verify here', async () => {
  // A compromised sibling sees its OWN signed headers; replaying them at another
  // app must fail, because each app has its own secret.
  const fromBeta = await issued('sig-beta');
  assert.throws(() => verifyIdentity(fromBeta, { secret: identitySecretFor(db, ALPHA) }), /signature/);
});

test('a signature older than the window is rejected', async () => {
  const h = await issued('sig-alpha');
  const later = (Number(h['x-appcrane-identity-ts']) + 301) * 1000;
  assert.throws(() => verifyIdentity(h, { secret: identitySecretFor(db, ALPHA), now: later }), /expired|stale/);
});

test('each app has its own secret, created once and then stable', () => {
  const a1 = identitySecretFor(db, ALPHA);
  assert.equal(identitySecretFor(db, ALPHA), a1);
  assert.notEqual(identitySecretFor(db, BETA), a1);
  assert.ok(a1.length >= 32);
});

test('Caddy strips client-sent signature headers and copies the issued ones', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server/services/caddy.js'), 'utf8');
  const list = src.slice(src.indexOf('const IDENTITY_HEADERS = ['), src.indexOf('];', src.indexOf('const IDENTITY_HEADERS = [')));
  for (const h of ['X-AppCrane-Identity-Ts', 'X-AppCrane-Identity-Sig']) {
    assert.ok(list.includes(`'${h}'`), `${h} is not in IDENTITY_HEADERS, so a client could send its own`);
  }
});

test('every deploy hands the app its secret', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server/services/deployer.js'), 'utf8');
  assert.match(src, /runtimeEnvVars\.APPCRANE_IDENTITY_SECRET\s*=\s*identitySecretFor\(getDb\(\), app\.id, env\)/,
    'the deploy must hand each environment its own secret');
});

test('sandbox and production of one app sign with different secrets', async () => {
  // Sandbox runs code still under review, deployable by app admins and the
  // coder; it must not be able to sign identity that production believes.
  assert.notEqual(identitySecretFor(db, ALPHA, 'sandbox'), identitySecretFor(db, ALPHA, 'production'));
  const r = await fetch(`${BASE}/api/identity/verify?app=sig-alpha&prefix=/sig-alpha-sandbox`, {
    headers: { Authorization: 'Bearer sig-token' }, redirect: 'manual',
  });
  const h = {};
  for (const [k, v] of r.headers) if (k.startsWith('x-appcrane-')) h[k] = v;
  assert.ok(verifyIdentity(h, { secret: identitySecretFor(db, ALPHA, 'sandbox') }));
  assert.throws(() => verifyIdentity(h, { secret: identitySecretFor(db, ALPHA, 'production') }), /signature/,
    'a sandbox-signed identity verifies in production');
});
