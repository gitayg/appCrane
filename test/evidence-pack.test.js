import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, statSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Compliance evidence pack: files per control, no secrets, signed manifest,
// tamper detection, platform-admin only, optional modules degrade.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-evidence-pack-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.PLANTED_SERVICE_TOKEN = 'planted-env-token-value-Q7Z';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
const { logAudit } = await import('../server/middleware/audit.js');
const { recordEvent } = await import('../server/services/eventStore.js');
const { extractTar, createTar } = await import('../server/services/backupFiles.js');
const ep = await import('../server/services/evidencePack/index.js');
const { CONTROLS } = await import('../server/services/evidencePack/controls.js');
const { _setOptionalModulesForTests } = await import('../server/services/evidencePack/optional.js');

const ADMIN_KEY = generateApiKey('dhk_admin');
const adminId = Number(db.prepare("INSERT INTO users (name,username,email,role,api_key_hash,active,kind) VALUES ('PA','pa','pa@example.com','platform_admin',?,1,'human')").run(hashApiKey(ADMIN_KEY)).lastInsertRowid);
const admin = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);
const USER_KEY = generateApiKey('dhk_user');
db.prepare("INSERT INTO users (name,username,email,role,api_key_hash,active,kind) VALUES ('U','u','u@example.com','user',?,1,'human')").run(hashApiKey(USER_KEY));
const appId = Number(db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('Demo','demo',1)").run().lastInsertRowid);

const PLAIN_ENV = 'planted-env-var-plaintext-R4X';
const ENC_ENV = encrypt(PLAIN_ENV);
db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'production', 'DB_PASSWORD', ?)").run(appId, ENC_ENV);
const PLAIN_OIDC = 'planted-oidc-client-secret-W2';
const ENC_OIDC = encrypt(PLAIN_OIDC);
const setSetting = (k, v) => db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(k, v);
setSetting('oidc_client_secret_enc', ENC_OIDC);
setSetting('oidc_enabled', '1');
setSetting('session_user_idle_minutes', '30');
logAudit(adminId, appId, 'env-set', { key: 'DB_PASSWORD', note: `pasted key ${USER_KEY} by mistake` });
db.prepare("INSERT INTO deployments (app_id, env, version, status, commit_hash, deployed_by) VALUES (?, 'production', 'v1', 'live', 'abc123', ?)").run(appId, adminId);
recordEvent({ kind: 'test.incident', severity: 'critical', summary: 'planted critical event', appId });
db.prepare("INSERT INTO restore_drills (run_id, source, trigger, status, rpo_seconds, rto_ms, checks_json, cleaned_up, started_at, finished_at) VALUES ('r1','local','schedule','passed',3600,1234,'[]',1,?,?)")
  .run(new Date().toISOString(), new Date().toISOString());

const PLANTED = [PLAIN_ENV, ENC_ENV, PLAIN_OIDC, ENC_OIDC, ADMIN_KEY, hashApiKey(ADMIN_KEY), USER_KEY, hashApiKey(USER_KEY), process.env.PLANTED_SERVICE_TOKEN, process.env.ENCRYPTION_KEY];

const today = new Date().toISOString().slice(0, 10);
const NONE = { accessReviews: null, auditChain: null, releaseCheck: null, siem: null };

function readAll(dir, rel = '') {
  const out = {};
  for (const n of readdirSync(join(dir, rel), { withFileTypes: true })) {
    const r = rel ? `${rel}/${n.name}` : n.name;
    if (n.isDirectory()) Object.assign(out, readAll(dir, r));
    else out[r] = readFileSync(join(dir, r));
  }
  return out;
}
async function unpack(path) {
  const dir = mkdtempSync(join(tmpdir(), 'crane-ep-x-'));
  await extractTar(path, dir, { gzip: true });
  return { dir, files: readAll(dir) };
}
async function build(opts = {}) {
  const { pack, done } = ep.startEvidencePack({ from: opts.from || today, to: today, user: admin });
  await done;
  return ep.getPack(pack.id);
}

after(() => { _setOptionalModulesForTests(null); ep._setExtraForbiddenForTests(null); });

test('the pack holds every control\'s evidence, the README disclaimer, and no planted secret', async () => {
  _setOptionalModulesForTests(NONE);
  const p = await build();
  assert.equal(p.status, 'ready', p.error);
  const { files } = await unpack(ep.packFilePath(p.id));
  for (const c of CONTROLS) for (const f of c.evidence) assert.ok(files[f], `${c.id}: ${f}`);
  for (const f of ['README.md', 'index.html', 'manifest.json', 'manifest.sig']) assert.ok(files[f], f);
  const readme = files['README.md'].toString();
  assert.match(readme, /not a SOC 2 report, an attestation or a certification/);
  assert.match(readme, /The key is rotated with crane rotate-key/);
  assert.doesNotMatch(readme, /No ENCRYPTION_KEY rotation mechanism exists/);
  assert.match(files['CC7/audit-log.csv'].toString(), /env-set/);
  assert.match(files['CC7/critical-events.csv'].toString(), /planted critical event/);
  assert.match(files['CC8/deployments.csv'].toString(), /abc123/);
  assert.match(files['A1/restore-drills.csv'].toString(), /r1,local,schedule,passed,,,3600,1234/);
  const auth = JSON.parse(files['CC6/authentication-settings.json']);
  assert.equal(auth.settings.oidc_client_secret_enc.value, '[not exported]');
  assert.equal(auth.settings.oidc_client_secret_enc.configured, true);
  assert.equal(auth.settings.session_user_idle_minutes.value, '30');
  const enc = JSON.parse(files['C1/encryption.json']);
  assert.equal(enc.key_rotation.supported, true);
  assert.equal(enc.key_rotation.last_rotated_at, null);
  assert.match(enc.key_rotation.method, /crane rotate-key/);
  for (const [path, buf] of Object.entries(files)) {
    const text = buf.toString('utf8');
    for (const s of PLANTED) assert.equal(text.includes(s), false, `${path} contains a planted secret (${s.slice(0, 6)}...)`);
  }
});

test('the secret scan refuses a pack that would carry a forbidden value', async () => {
  ep._setExtraForbiddenForTests(['u@example.com']);
  const p = await build();
  ep._setExtraForbiddenForTests(null);
  assert.equal(p.status, 'failed');
  assert.match(p.error, /secret scan found/);
  assert.match(p.error, /CC6\/users-and-roles\.csv/);
  assert.equal(p.file_name, null);
});

test('manifest hashes and HMAC verify; a tampered file, manifest or extra file fails', async () => {
  const p = await build();
  const path = ep.packFilePath(p.id);
  const good = await ep.verifyPackFile(path);
  assert.equal(good.ok, true, JSON.stringify(good.errors));
  assert.equal(good.signature_ok, true);
  assert.ok(good.files.length >= 18);

  const { dir } = await unpack(path);
  const top = readdirSync(dir);
  const csv = join(dir, 'CC7', 'audit-log.csv');
  writeFileSync(csv, readFileSync(csv, 'utf8') + '999,2026-01-01 00:00:00,1,x,human,,forged,\r\n');
  const t1 = join(ROOT, 't1.tar.gz');
  await createTar(t1, [{ cwd: dir, paths: top }], { gzip: true });
  const r1 = await ep.verifyPackFile(t1);
  assert.equal(r1.ok, false);
  assert.equal(r1.signature_ok, true);
  assert.deepEqual(r1.files.filter((f) => !f.ok).map((f) => f.path), ['CC7/audit-log.csv']);

  const { createHash } = await import('crypto');
  const mPath = join(dir, 'manifest.json');
  const m = JSON.parse(readFileSync(mPath, 'utf8'));
  const buf = readFileSync(csv);
  const entry = m.files.find((f) => f.path === 'CC7/audit-log.csv');
  entry.sha256 = createHash('sha256').update(buf).digest('hex');
  entry.bytes = buf.length;
  writeFileSync(mPath, JSON.stringify(m, null, 2) + '\n');
  const t2 = join(ROOT, 't2.tar.gz');
  await createTar(t2, [{ cwd: dir, paths: top }], { gzip: true });
  const r2 = await ep.verifyPackFile(t2);
  assert.equal(r2.ok, false);
  assert.equal(r2.signature_ok, false, 'a manifest re-hashed to match the forged file fails the HMAC');

  const { dir: d3 } = await unpack(path);
  mkdirSync(join(d3, 'extra'));
  writeFileSync(join(d3, 'extra', 'note.txt'), 'added');
  const t3 = join(ROOT, 't3.tar.gz');
  await createTar(t3, [{ cwd: d3, paths: readdirSync(d3) }], { gzip: true });
  const r3 = await ep.verifyPackFile(t3);
  assert.equal(r3.ok, false);
  assert.deepEqual(r3.unexpected, ['extra/note.txt']);

  const r4 = await ep.verifyUploadedPack(Buffer.from('not a pack'));
  assert.equal(r4.ok, false);
});

test('optional modules: absent ones degrade with a reason, present ones are used', async () => {
  _setOptionalModulesForTests(NONE);
  const p = await build();
  assert.equal(p.status, 'ready', p.error);
  const files = new Set(p.degraded.map((d) => d.file));
  for (const f of ['CC6/access-reviews.json', 'CC7/audit-chain-verification.json', 'CC8/release-checks.json', 'CC7/siem-sinks.json']) assert.ok(files.has(f), f);
  const { files: out } = await unpack(ep.packFilePath(p.id));
  assert.equal(JSON.parse(out['CC6/access-reviews.json']).available, false);
  assert.match(out['README.md'].toString(), /Gaps in this pack/);

  let calledWith = null;
  _setOptionalModulesForTests({
    ...NONE,
    accessReviews: { getAccessReviewEvidence: async (arg) => { calledWith = arg; return { campaigns: [{ id: 7, decisions: 3 }] }; } },
    auditChain: { verifyChain: async () => ({ ok: true, problems: [] }) },
  });
  const p2 = await build();
  assert.equal(p2.status, 'ready', p2.error);
  assert.deepEqual(calledWith, { from: today, to: today });
  const { files: out2 } = await unpack(ep.packFilePath(p2.id));
  const ar = JSON.parse(out2['CC6/access-reviews.json']);
  assert.equal(ar.available, true);
  assert.equal(ar.evidence.campaigns[0].id, 7);
  assert.equal(JSON.parse(out2['CC7/audit-chain-verification.json']).result.ok, true);
  assert.equal(p2.degraded.some((d) => d.file === 'CC6/access-reviews.json'), false);
  _setOptionalModulesForTests(null);
});

test('period validation', () => {
  assert.throws(() => ep.normalizePeriod({ from: '2026-13-01', to: today }), /YYYY-MM-DD/);
  assert.throws(() => ep.normalizePeriod({ from: today, to: '2999-01-01' }), /future/);
  assert.throws(() => ep.normalizePeriod({ from: '2020-01-01', to: today }), /at most 400 days/);
  assert.equal(ep.normalizePeriod({}).to, today);
});

test('routes: platform admin only; create, download and verify are audited', async () => {
  _setOptionalModulesForTests(NONE);
  const routes = (await import('../server/routes/evidencePack.js')).default;
  const { errorHandler } = await import('../server/utils/errors.js');
  const api = express();
  api.use(express.json());
  api.use('/api/evidence-packs', routes);
  api.use(errorHandler);
  const server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/evidence-packs`;
    const A = { 'X-API-Key': ADMIN_KEY, 'Content-Type': 'application/json' };
    assert.equal((await fetch(base)).status, 401);
    assert.equal((await fetch(base, { headers: { 'X-API-Key': USER_KEY } })).status, 403);
    assert.equal((await fetch(base, { method: 'POST', headers: { 'X-API-Key': USER_KEY, 'Content-Type': 'application/json' }, body: '{}' })).status, 403);
    assert.equal((await fetch(`${base}/verify`, { method: 'POST', headers: { 'X-API-Key': USER_KEY, 'Content-Type': 'application/gzip' }, body: 'x' })).status, 403);
    assert.equal((await fetch(base, { method: 'POST', headers: A, body: JSON.stringify({ from: 'bad' }) })).status, 400);

    const created = await fetch(base, { method: 'POST', headers: A, body: JSON.stringify({ from: today, to: today }) });
    assert.equal(created.status, 202);
    const { pack } = await created.json();
    let cur = pack;
    for (let i = 0; i < 200 && cur.status === 'running'; i++) {
      await new Promise((r) => setTimeout(r, 50));
      cur = (await (await fetch(`${base}/${pack.id}`, { headers: A })).json()).pack;
    }
    assert.equal(cur.status, 'ready', cur.error);
    assert.equal((await fetch(`${base}/${pack.id}/download`, { headers: { 'X-API-Key': USER_KEY } })).status, 403);
    const dl = await fetch(`${base}/${pack.id}/download`, { headers: A });
    assert.equal(dl.status, 200);
    const body = Buffer.from(await dl.arrayBuffer());
    assert.equal(body.length, cur.bytes);
    const v = await (await fetch(`${base}/verify`, { method: 'POST', headers: { 'X-API-Key': ADMIN_KEY, 'Content-Type': 'application/gzip' }, body })).json();
    assert.equal(v.ok, true, JSON.stringify(v.errors));
    assert.equal(v.pack_id, pack.id);
    const v2 = await (await fetch(`${base}/${pack.id}/verify`, { method: 'POST', headers: A })).json();
    assert.equal(v2.ok, true);
    const actions = db.prepare("SELECT action FROM audit_log WHERE action LIKE 'evidence-pack.%' ORDER BY id").all().map((r) => r.action);
    assert.deepEqual(actions, ['evidence-pack.create', 'evidence-pack.download', 'evidence-pack.verify', 'evidence-pack.verify']);
    assert.equal(statSync(ep.packFilePath(pack.id)).mode & 0o777, 0o600);
  } finally {
    server.closeAllConnections?.();
    server.close();
    _setOptionalModulesForTests(null);
  }
});
