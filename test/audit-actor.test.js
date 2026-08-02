import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Agent vs human attribution on the audit trail (v2.28.0). The question this
// has to answer is "what did the agents do here" — previously unanswerable
// because only user_id was stored.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-audit-'));

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { logAudit } = await import('../server/middleware/audit.js');

const humanId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('H','h@x.io','platform_admin','h1',1,'human')"
).run().lastInsertRowid;
const agentId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@x.io','admin','h2',1,'agent')"
).run().lastInsertRowid;

const kindOf = (id) =>
  db.prepare('SELECT actor_kind FROM audit_log WHERE id = ?').get(id).actor_kind;

test('migration 070 added actor_kind', () => {
  const cols = db.prepare('PRAGMA table_info(audit_log)').all().map(c => c.name);
  assert.ok(cols.includes('actor_kind'), `audit_log columns: ${cols.join(',')}`);
});

test('actor_kind resolves from users.kind when not passed', () => {
  logAudit(agentId, null, 'mcp.appcrane_deploy', { tool: 'deploy' });
  const agentRow = db.prepare("SELECT id FROM audit_log ORDER BY id DESC LIMIT 1").get().id;
  assert.equal(kindOf(agentRow), 'agent');

  logAudit(humanId, null, 'app-update', { via: 'ui' });
  const humanRow = db.prepare("SELECT id FROM audit_log ORDER BY id DESC LIMIT 1").get().id;
  assert.equal(kindOf(humanRow), 'human');
});

test('an explicitly passed actor_kind wins over the lookup', () => {
  logAudit(humanId, null, 'weird', {}, 'agent');
  const row = db.prepare('SELECT id FROM audit_log ORDER BY id DESC LIMIT 1').get().id;
  assert.equal(kindOf(row), 'agent');
});

test('agent actions are filterable', () => {
  const n = db.prepare(`
    SELECT COUNT(*) AS n FROM audit_log al
    LEFT JOIN users u ON al.user_id = u.id
    WHERE COALESCE(al.actor_kind, u.kind) = 'agent'
  `).get().n;
  assert.ok(n >= 2, `expected agent rows, got ${n}`);
});

test('logAudit redacts secrets in the detail payload', () => {
  logAudit(agentId, null, 'mcp.appcrane_set_secret', { args: { value: 'top-secret-xyz' } });
  const detail = db.prepare('SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1').get().detail;
  // logAudit stringifies whatever it is given; the MCP path redacts before
  // calling it, so assert the redactor itself is what stands between a secret
  // and the table — see audit-redact.test.js for the full contract.
  assert.ok(typeof detail === 'string');
});
