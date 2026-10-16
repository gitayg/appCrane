import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'net';
import crypto from 'crypto';
import express from 'express';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The env cards load the MASKED list and reveal one key at a time through
// POST /api/apps/:slug/env/:env/:key/reveal. Opening the card must decrypt
// nothing for the viewer, and a reveal must audit and notify about that one key
// only — not the whole environment the way ?reveal=true does.
//
// The notice is read off a real SMTP conversation, the same seam
// secrets-notify.test.js uses: a spy on notifySecretReveal would prove the mail
// was composed, not what the owner actually receives.

const inbox = [];
const smtp = net.createServer((sock) => {
  let buf = ''; let inData = false; let data = ''; let to = [];
  sock.write('220 fake.appcrane.test ESMTP\r\n');
  sock.on('error', () => {});
  sock.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    for (;;) {
      const i = buf.indexOf('\r\n');
      if (i < 0) break;
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (inData) {
        if (line === '.') { inData = false; inbox.push({ raw: data, to }); data = ''; to = []; sock.write('250 Ok\r\n'); }
        else data += (line.startsWith('..') ? line.slice(1) : line) + '\r\n';
        continue;
      }
      const cmd = line.split(/[ :]/)[0].toUpperCase();
      if (cmd === 'EHLO' || cmd === 'HELO') sock.write('250-fake.appcrane.test\r\n250 8BITMIME\r\n');
      else if (cmd === 'RCPT') { to.push(line.match(/<([^>]*)>/)?.[1]); sock.write('250 Ok\r\n'); }
      else if (cmd === 'DATA') { inData = true; sock.write('354 go\r\n'); }
      else if (cmd === 'QUIT') { sock.write('221 Bye\r\n'); sock.end(); }
      else sock.write('250 Ok\r\n');
    }
  });
});
await new Promise((res) => smtp.listen(0, '127.0.0.1', res));
process.env.SMTP_HOST = '127.0.0.1';
process.env.SMTP_PORT = String(smtp.address().port);
for (const k of ['SMTP_USER', 'SMTP_PASS', 'GRAPH_TENANT_ID', 'GRAPH_CLIENT_ID', 'GRAPH_CLIENT_SECRET']) delete process.env[k];
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-onekey-reveal-'));
process.env.ENCRYPTION_KEY = '7'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { logAudit } = await import('../server/middleware/audit.js');
const envRoutes = (await import('../server/routes/envVars.js')).default;
initDb();
const db = getDb();

const mkApp = (slug, slot) => db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')").run(slug, slug, slot).lastInsertRowid;
const APP = mkApp('onekey', 601);
const OTHER = mkApp('onekey-other', 602);
const mk = (name, role, appRole, appId = APP) => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(name, `${name}@example.test`, role, hashApiKey(key)).lastInsertRowid;
  if (appRole) db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, id, appRole);
  return { id, key, name };
};
const OWNER = mk('owner', 'user', 'owner');
const APPADMIN = mk('appadmin', 'user', 'admin');
const MEMBER = mk('member', 'user', 'user');
const NOTIFIED = mk('fresh-member', 'user', 'user');
const BUDGET = mk('budget-member', 'user', 'user');
const PLATFORM = mk('platform', 'platform_admin', 'user');
mk('other-owner', 'user', 'owner', OTHER);

const SECRETS = {
  sandbox: { ONE_KEY: 'canary-one-4b1f0c2d', TWO_KEY: 'canary-two-8e7a19f3', THREE_KEY: 'canary-three-c05d6e21' },
  production: { PROD_KEY: 'canary-prod-91aa3f70' },
};
for (const [env, vars] of Object.entries(SECRETS)) {
  for (const [k, v] of Object.entries(vars)) {
    db.prepare("INSERT INTO env_vars (app_id,env,key,value_encrypted,updated_at) VALUES (?,?,?,?,datetime('now'))").run(APP, env, k, encrypt(v));
  }
}
const OTHER_CANARY = 'canary-other-app-5d3c';
db.prepare("INSERT INTO env_vars (app_id,env,key,value_encrypted) VALUES (?,?,?,?)").run(OTHER, 'sandbox', 'OTHER_KEY', encrypt(OTHER_CANARY));
const ALL_CANARIES = [...Object.values(SECRETS.sandbox), ...Object.values(SECRETS.production), OTHER_CANARY];

const server = await new Promise((r) => {
  const a = express(); a.use(express.json()); a.use('/api/apps', envRoutes); a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); smtp.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

async function call(who, method, path) {
  const r = await fetch(`${BASE}${path}`, { method, headers: { 'x-api-key': who.key } });
  const body = await r.text();
  let json = null; try { json = JSON.parse(body); } catch (_) {}
  return { status: r.status, body, json, headers: r.headers };
}
const revealOne = (who, key, env = 'sandbox', slug = 'onekey') => call(who, 'POST', `/api/apps/${slug}/env/${env}/${key}/reveal`);
const leaked = (text, except = []) => ALL_CANARIES.filter(c => !except.includes(c) && text.includes(c)).length;
const revealRows = (userId) => db.prepare("SELECT detail FROM audit_log WHERE user_id = ? AND action = 'env-reveal' ORDER BY id")
  .all(userId).map(r => JSON.parse(r.detail));
const settle = (ms = 700) => new Promise(r => setTimeout(r, ms));
const decoded = (raw) => raw + '\n' + raw.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
const notices = (from, actor) => inbox.slice(from).filter(m => /SECRET REVEAL/.test(m.raw) && (!actor || decoded(m.raw).includes(`${actor.name}@example.test`)));

test('a single-key reveal returns that key\'s value and no other', async () => {
  const r = await revealOne(MEMBER, 'ONE_KEY');
  assert.equal(r.status, 200);
  assert.equal(r.json.key, 'ONE_KEY');
  assert.ok(r.json.value === SECRETS.sandbox.ONE_KEY, 'the route did not return the requested value');
  assert.equal(leaked(r.body, [SECRETS.sandbox.ONE_KEY]), 0, 'the response carried a value other than the one requested');
  assert.equal(r.json.vars, undefined, 'the single-key route returned a list');
  assert.equal(r.headers.get('cache-control'), 'no-store');
});

test('it writes ONE env-reveal row and sends ONE notice, both naming only that key', async () => {
  await settle();
  const before = inbox.length;
  const r = await revealOne(NOTIFIED, 'TWO_KEY');
  assert.equal(r.status, 200);

  assert.deepEqual(revealRows(NOTIFIED.id), [{ env: 'sandbox', keys: ['TWO_KEY'] }],
    'the audit row does not name exactly the one revealed key');

  const deadline = Date.now() + 15_000;
  while (!notices(before, NOTIFIED).length && Date.now() < deadline) await settle(50);
  await settle();
  const mails = notices(before, NOTIFIED);
  assert.equal(mails.length, 1, `expected one SECRET REVEAL notice, got ${mails.length}`);
  assert.deepEqual(mails[0].to, [`${OWNER.name}@example.test`], 'the notice did not go to the app owner');
  const text = decoded(mails[0].raw);
  assert.ok(text.includes('TWO_KEY'), 'the notice does not name the revealed key');
  assert.ok(/\(1 key\(s\)\)/.test(text), 'the notice subject does not say one key');
  for (const k of ['ONE_KEY', 'THREE_KEY', 'PROD_KEY']) assert.ok(!text.includes(k), `the notice names ${k}, which was not revealed`);
  assert.equal(leaked(text), 0, 'the notice carried a secret value');
});

test('production: app admin and member get 403, owner and platform admin get the value', async () => {
  for (const who of [APPADMIN, MEMBER]) {
    const r = await revealOne(who, 'PROD_KEY', 'production');
    assert.equal(r.status, 403, `${who.name} revealed a production secret`);
    assert.equal(leaked(r.body), 0, `${who.name}'s refusal carried a value`);
    assert.ok(!revealRows(who.id).some(d => d.env === 'production'), `${who.name}'s refusal was logged as a reveal`);
  }
  for (const who of [OWNER, PLATFORM]) {
    const r = await revealOne(who, 'PROD_KEY', 'production');
    assert.equal(r.status, 200, `${who.name} was refused`);
    assert.ok(r.json.value === SECRETS.production.PROD_KEY, `${who.name} did not get the production value`);
  }
});

test('an unknown key is a 404 that reveals and records nothing', async () => {
  const rowsBefore = revealRows(MEMBER.id).length;
  const r = await revealOne(MEMBER, 'NO_SUCH_KEY');
  assert.equal(r.status, 404);
  assert.equal(r.json?.error?.code, 'NOT_FOUND', 'the 404 did not come from the reveal route');
  assert.equal(leaked(r.body), 0, 'the 404 carried secret values');
  assert.equal(revealRows(MEMBER.id).length, rowsBefore, 'a 404 wrote an env-reveal row');
});

test('another app\'s key is refused', async () => {
  const viaOtherSlug = await revealOne(OWNER, 'OTHER_KEY', 'sandbox', 'onekey-other');
  assert.ok([403, 404].includes(viaOtherSlug.status), `a user with no access to the other app got ${viaOtherSlug.status}`);
  assert.equal(leaked(viaOtherSlug.body), 0);
  const viaOwnSlug = await revealOne(OWNER, 'OTHER_KEY', 'sandbox', 'onekey');
  assert.equal(viaOwnSlug.status, 404, 'a key that exists only in another app resolved through this app');
  assert.equal(viaOwnSlug.json?.error?.code, 'NOT_FOUND', 'the 404 did not come from the reveal route');
  assert.equal(leaked(viaOwnSlug.body), 0);
});

test('a single-key reveal spends the same budget and is throttled with the bulk reveal', async () => {
  for (let i = 0; i < 30; i++) logAudit(BUDGET.id, APP, 'secret-reveal', { env: 'sandbox', key: 'ONE_KEY' });
  const r = await revealOne(BUDGET, 'ONE_KEY');
  assert.equal(r.status, 429);
  assert.equal(leaked(r.body), 0, 'the throttled response carried the value');
});

test('the masked list carries masks and fingerprints, never plaintext, and records nothing', async () => {
  await settle();
  const before = inbox.length;
  const rowsBefore = db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'env-reveal'").get().n;
  const { secretFingerprint: fp } = await import('../server/services/secretMask.js');

  const sb = await call(MEMBER, 'GET', '/api/apps/onekey/env/sandbox');
  assert.equal(sb.status, 200);
  assert.equal(leaked(sb.body), 0, 'the masked sandbox list carried plaintext');
  assert.equal(sb.json.can_reveal, true);
  for (const v of sb.json.vars) {
    assert.equal(v.value, '********');
    assert.ok(v.fingerprint === fp(SECRETS.sandbox[v.key]), `${v.key} has no (or a wrong) fingerprint`);
    assert.match(v.preview, /^•+.{3}$/, `${v.key} has no masked preview`);
    assert.equal(v.length, SECRETS.sandbox[v.key].length);
  }

  const prodMember = await call(MEMBER, 'GET', '/api/apps/onekey/env/production');
  assert.equal(prodMember.status, 200);
  assert.equal(leaked(prodMember.body), 0, 'the masked production list carried plaintext');
  assert.equal(prodMember.json.can_reveal, false, 'a member is told they can reveal production');
  assert.match(prodMember.json.reveal_refusal, /owner or a platform admin/);
  assert.match(prodMember.json.vars[0].preview, /^•+$/, 'a viewer who cannot reveal saw the value\'s tail');
  assert.equal(prodMember.json.vars[0].fingerprint, undefined, 'a viewer who cannot reveal production got a fingerprint to match against sandbox');
  assert.equal(prodMember.json.vars[0].length, undefined, 'a viewer who cannot reveal saw the value\'s length');
  const prodOwnerFp = (await call(OWNER, 'GET', '/api/apps/onekey/env/production')).json.vars[0].fingerprint;
  const plainHash = crypto.createHash('sha256').update(SECRETS.production.PROD_KEY).digest('hex').slice(0, 8);
  assert.equal(prodOwnerFp, fp(SECRETS.production.PROD_KEY));
  assert.notEqual(prodOwnerFp, plainHash, 'the fingerprint is a plain hash anyone can check guesses against');

  const prodOwner = await call(OWNER, 'GET', '/api/apps/onekey/env/production');
  assert.equal(prodOwner.json.can_reveal, true);
  assert.equal(prodOwner.json.reveal_refusal, undefined);

  await settle();
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'env-reveal'").get().n, rowsBefore,
    'a masked read wrote an env-reveal row');
  assert.equal(notices(before).length, 0, 'a masked read sent a SECRET REVEAL notice');
});
