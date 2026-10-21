import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Tamper-evident audit (services/auditChain.js, routes/auditChain.js,
// migration 146): the sealer chains audit_log and events rows, and the
// verifier names the first row that was modified, deleted, inserted out of
// order, or whose chain entry was edited.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-audit-chain-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { logAudit } = await import('../server/middleware/audit.js');
const chain = await import('../server/services/auditChain.js');
const retention = await import('../server/services/eventRetention.js');
const { JOBS } = await import('../server/services/jobHealth.js');
initDb();
const db = getDb();

function mkUser(name, role = 'user') {
  const key = generateApiKey(role === 'platform_admin' ? 'dhk_admin' : 'dhk_user');
  const id = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid);
  return { id, key };
}
const admin = mkUser('chainadmin', 'platform_admin');
const user = mkUser('chainuser');
const appId = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('C','chain-a',901,'managed')").run().lastInsertRowid);

const api = express();
api.use(express.json());
api.use('/api', (await import('../server/routes/auditChain.js')).default);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const DAY = 86_400_000;
const unlocked = (fn) => {
  db.exec('DROP TRIGGER IF EXISTS audit_chain_append_only; DROP TRIGGER IF EXISTS events_append_only;');
  try { return fn(); } finally {
    db.exec(`CREATE TRIGGER IF NOT EXISTS audit_chain_append_only BEFORE UPDATE ON audit_chain BEGIN SELECT RAISE(ABORT, 'audit_chain is append-only'); END;
             CREATE TRIGGER IF NOT EXISTS events_append_only BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;`);
  }
};
const types = (r) => [...new Set(r.problems.map(p => p.type))].sort();
const sealAndSign = async () => { await chain.sealNew(); chain.checkpointNow({ now: Date.now() }); };
const insOld = db.prepare("INSERT INTO events (ts, kind, severity, summary) VALUES (?, 'test.old', 'info', 'old event')");

let auditIds;

test('sealing produces a chain that verifies clean, and the job is registered in Job Health', async () => {
  chain._resetAuditChainForTests();
  for (let i = 0; i < 5; i++) insOld.run(retention.sqliteTime(Date.now() - 40 * DAY));
  for (let i = 0; i < 6; i++) logAudit(i % 2 ? user.id : admin.id, appId, `chain-test-${i}`, { n: i });
  const rows = db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n + db.prepare('SELECT COUNT(*) AS n FROM events').get().n;
  await sealAndSign();
  auditIds = db.prepare('SELECT id FROM audit_log ORDER BY id').all().map(r => r.id);
  const r = await chain.verifyChain();
  assert.deepEqual(r.problems, []);
  assert.equal(r.ok, true);
  assert.equal(r.checked, rows);
  assert.ok(db.prepare("SELECT COUNT(*) AS n FROM audit_chain_checkpoints WHERE kind = 'seal'").get().n >= 2);
  assert.ok(JOBS['audit-chain']);
});

test('modifying a sealed row is detected at that row; clearing a deleted user id is not tampering', async () => {
  const target = auditIds[2];
  const orig = db.prepare('SELECT detail FROM audit_log WHERE id = ?').get(target).detail;
  db.prepare("UPDATE audit_log SET detail = '{\"n\":999}' WHERE id = ?").run(target);
  const r = await chain.verifyChain();
  assert.deepEqual(types(r), ['modified']);
  assert.equal(r.first_broken.audit_log, target);
  db.prepare('UPDATE audit_log SET detail = ? WHERE id = ?').run(orig, target);
  assert.equal((await chain.verifyChain()).ok, true);

  db.prepare('UPDATE audit_log SET user_id = NULL WHERE id = ?').run(auditIds[1]);
  db.prepare('UPDATE audit_log SET user_id = NULL, app_id = NULL WHERE id = ?').run(auditIds[3]);
  const p = await chain.verifyChain();
  assert.equal(p.ok, true, JSON.stringify(p.problems));
  assert.equal(p.pseudonymised, 2);
  db.prepare('UPDATE audit_log SET user_id = ? WHERE id = ?').run(admin.id, auditIds[1]);
  const swap = await chain.verifyChain();
  assert.equal(swap.first_broken.audit_log, auditIds[1], 'changing the actor to someone else is an edit');
  db.prepare('UPDATE audit_log SET user_id = NULL WHERE id = ?').run(auditIds[1]);
});

test('deleting a sealed row is detected at that row', async () => {
  const target = auditIds[4];
  const row = db.prepare('SELECT * FROM audit_log WHERE id = ?').get(target);
  db.prepare('DELETE FROM audit_log WHERE id = ?').run(target);
  const r = await chain.verifyChain();
  assert.deepEqual(types(r), ['deleted']);
  assert.equal(r.first_broken.audit_log, target);
  db.prepare('INSERT INTO audit_log (id, user_id, app_id, action, detail, created_at, actor_kind) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(row.id, row.user_id, row.app_id, row.action, row.detail, row.created_at, row.actor_kind);
  assert.equal((await chain.verifyChain()).ok, true);
});

test('a row inserted out of order, below rows already sealed, is detected at its id', async () => {
  const max = db.prepare('SELECT MAX(id) AS m FROM audit_log').get().m;
  db.prepare("INSERT INTO audit_log (id, action, detail) VALUES (?, 'chain-later', '{}')").run(max + 3);
  await chain.sealNew();
  db.prepare("INSERT INTO audit_log (id, action, detail) VALUES (?, 'backdated', '{}')").run(max + 1);
  const r = await chain.verifyChain();
  assert.deepEqual(types(r), ['unsealed']);
  assert.equal(r.first_broken.audit_log, max + 1);
  db.prepare('DELETE FROM audit_log WHERE id = ?').run(max + 1);
  assert.equal((await chain.verifyChain()).ok, true);
});

test('editing a chain entry is detected at that entry; rebuilding the whole chain is caught by the signed checkpoint', async () => {
  await sealAndSign();
  const e = db.prepare("SELECT * FROM audit_chain WHERE src = 'audit_log' AND row_id = ?").get(auditIds[3]);
  unlocked(() => db.prepare('UPDATE audit_chain SET chain_hash = ? WHERE id = ?').run('f'.repeat(64), e.id));
  const r = await chain.verifyChain();
  assert.ok(types(r).includes('broken_link'));
  assert.equal(r.first_broken.audit_log, auditIds[3]);
  unlocked(() => db.prepare('UPDATE audit_chain SET chain_hash = ? WHERE id = ?').run(e.chain_hash, e.id));
  assert.equal((await chain.verifyChain()).ok, true);

  const target = auditIds[0];
  const orig = db.prepare('SELECT detail FROM audit_log WHERE id = ?').get(target).detail;
  db.prepare("UPDATE audit_log SET detail = '{\"n\":-1}' WHERE id = ?").run(target);
  const saved = db.prepare("SELECT * FROM audit_chain WHERE src = 'audit_log' ORDER BY row_id").all();
  db.prepare("DELETE FROM audit_chain WHERE src = 'audit_log'").run();
  await chain.sealNew();
  const rebuilt = await chain.verifyChain();
  assert.deepEqual(types(rebuilt), ['checkpoint_mismatch'], 'links and rows agree after a rebuild; only the signed checkpoint disagrees');
  db.prepare("DELETE FROM audit_chain WHERE src = 'audit_log'").run();
  const ins = db.prepare('INSERT INTO audit_chain (id, src, row_id, row_hash, alt_hash, meta, chain_hash, sealed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  for (const s of saved) ins.run(s.id, s.src, s.row_id, s.row_hash, s.alt_hash, s.meta, s.chain_hash, s.sealed_at);
  db.prepare('UPDATE audit_log SET detail = ? WHERE id = ?').run(orig, target);
  assert.equal((await chain.verifyChain()).ok, true);
});

test('pruning old events by retention verifies clean, compaction drops them below a signed checkpoint, and a recent deletion is still caught', async () => {
  await sealAndSign();
  const removed = await retention.pruneEvents();
  assert.equal(removed.info, 5);
  const r = await chain.verifyChain();
  assert.equal(r.ok, true, JSON.stringify(r.problems));
  assert.equal(r.pruned, 5);
  const n = await chain.compact({ min: 1 });
  assert.equal(n, 5);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_chain_checkpoints WHERE kind = 'compaction'").get().n, 1);
  const after = await chain.verifyChain();
  assert.equal(after.ok, true, JSON.stringify(after.problems));
  assert.equal(after.pruned, 0);
  const recent = db.prepare("SELECT MAX(row_id) AS id FROM audit_chain WHERE src = 'events'").get().id;
  const row = db.prepare('SELECT * FROM events WHERE id = ?').get(recent);
  db.prepare('DELETE FROM events WHERE id = ?').run(recent);
  const del = await chain.verifyChain();
  assert.deepEqual(types(del), ['deleted']);
  assert.equal(del.first_broken.events, recent);
  db.prepare('INSERT INTO events (id, ts, kind, severity, app_id, app_slug, user_id, subject_user_id, summary, ref_table, ref_id, data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(row.id, row.ts, row.kind, row.severity, row.app_id, row.app_slug, row.user_id, row.subject_user_id, row.summary, row.ref_table, row.ref_id, row.data);
  assert.equal((await chain.verifyChain()).ok, true);
});

test('a checkpoint forged without the key is detected', async () => {
  const head = db.prepare("SELECT row_id, chain_hash FROM audit_chain WHERE src = 'audit_log' ORDER BY row_id DESC LIMIT 1").get();
  const last = db.prepare('SELECT signature FROM audit_chain_checkpoints ORDER BY id DESC LIMIT 1').get().signature;
  const c = { kind: 'seal', src: 'audit_log', upto_row_id: head.row_id, chain_hash: 'a'.repeat(64), data: null, created_at: retention.sqliteTime(Date.now()), prev_signature: last };
  c.signature = chain.signCheckpoint(c, 'not-the-instance-key');
  const id = Number(db.prepare('INSERT INTO audit_chain_checkpoints (kind, src, upto_row_id, chain_hash, data, created_at, prev_signature, signature) VALUES (?,?,?,?,?,?,?,?)')
    .run(c.kind, c.src, c.upto_row_id, c.chain_hash, c.data, c.created_at, c.prev_signature, c.signature).lastInsertRowid);
  const r = await chain.verifyChain();
  assert.deepEqual(types(r), ['forged_checkpoint']);
  assert.equal(r.problems[0].checkpoint_id, id);
  db.prepare('DELETE FROM audit_chain_checkpoints WHERE id = ?').run(id);
  chain._resetAuditChainForTests();
  assert.equal((await chain.verifyChain()).ok, true);
});

test('a failure e-mails each platform admin once and records one critical event; the API reports it', async () => {
  const target = auditIds[5];
  const orig = db.prepare('SELECT detail FROM audit_log WHERE id = ?').get(target).detail;
  db.prepare("UPDATE audit_log SET detail = '{}' WHERE id = ?").run(target);
  await chain.verifyAndRecord();
  await chain.verifyAndRecord();
  const v = await fetch(`${BASE}/api/audit-chain/verify`, { method: 'POST', headers: { 'X-API-Key': admin.key } });
  assert.equal(v.status, 200);
  const body = await v.json();
  assert.equal(body.ok, false);
  assert.equal(body.first_broken.audit_log, target);
  const mail = db.prepare("SELECT * FROM email_queue WHERE source = 'audit-chain'").all();
  assert.equal(mail.length, 1);
  assert.equal(mail[0].to_email, 'chainadmin@t.test');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM events WHERE kind = 'audit.chain_broken'").get().n, 1);
  assert.equal((await fetch(`${BASE}/api/audit-chain/verify`, { method: 'POST', headers: { 'X-API-Key': user.key } })).status, 403);
  db.prepare('UPDATE audit_log SET detail = ? WHERE id = ?').run(orig, target);
  const st = await (await fetch(`${BASE}/api/audit-chain/status`, { headers: { 'X-API-Key': admin.key } })).json();
  assert.equal(st.last_verification.ok, false);
});

test('a key holder can rebuild and re-sign the chain undetected locally, but externally held checkpoints catch it', async () => {
  await sealAndSign();
  const held = (await (await fetch(`${BASE}/api/audit-chain/checkpoints`, { headers: { 'X-API-Key': admin.key } })).json()).checkpoints;
  const ok = await (await fetch(`${BASE}/api/audit-chain/checkpoints/check`, { method: 'POST', headers: { 'X-API-Key': admin.key, 'Content-Type': 'application/json' }, body: JSON.stringify({ checkpoints: held }) })).json();
  assert.equal(ok.ok, true, JSON.stringify(ok.results));
  db.prepare("UPDATE audit_log SET detail = '{\"rewritten\":1}' WHERE id = ?").run(auditIds[0]);
  db.prepare('DELETE FROM audit_chain').run();
  db.prepare('DELETE FROM audit_chain_checkpoints').run();
  db.prepare('DELETE FROM audit_chain_verifications').run();
  chain._resetAuditChainForTests();
  await sealAndSign();
  assert.equal((await chain.verifyChain()).ok, true, 'with the key, a full rebuild verifies locally (the documented limit)');
  const caught = await (await fetch(`${BASE}/api/audit-chain/checkpoints/check`, { method: 'POST', headers: { 'X-API-Key': admin.key, 'Content-Type': 'application/json' }, body: JSON.stringify({ checkpoints: held }) })).json();
  assert.equal(caught.ok, false);
  assert.ok(caught.results.some(r => r.src === 'audit_log' && r.result === 'mismatch'));
});
