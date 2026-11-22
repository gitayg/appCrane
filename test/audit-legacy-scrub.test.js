import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-audit-scrub-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
const { initDb, getDb } = await import('../server/db.js');
const { scrubLegacyAuditSecrets } = await import('../server/services/auditLegacyScrub.js');
initDb();
const db = getDb();

// Shapes copied from pre-v2.28.0 rows on a real instance, values made up.
const SECRET = 'sk-ant-api03-made-up-value-for-the-test';
const legacySetSecret = { tool: 'appcrane_set_secret', args: { slug: 'demo', stage: 'sandbox', key: 'ANTHROPIC_API_KEY', value: SECRET }, ok: true, error: null };
const legacyPush = { tool: 'appcrane_push_to_managed_app', args: { slug: 'demo', files: [{ path: 'a.js', staged_token: 'st-123456' }, { path: 'b.js', staged_token: 'st-654321' }] }, ok: true };
const current = { tool: 'appcrane_set_secret', args: { slug: 'demo', stage: 'sandbox', key: 'X', value: '[redacted:5 chars]' }, ok: true };
const plain = { tool: 'appcrane_list_apps', args: { filter: 'value-like text stays' } };

const ins = db.prepare('INSERT INTO audit_log (user_id, action, detail) VALUES (NULL, ?, ?)');
const ids = {
  setSecret: ins.run('mcp.appcrane_set_secret', JSON.stringify(legacySetSecret)).lastInsertRowid,
  push: ins.run('mcp.appcrane_push_to_managed_app', JSON.stringify(legacyPush)).lastInsertRowid,
  current: ins.run('mcp.appcrane_set_secret', JSON.stringify(current)).lastInsertRowid,
  plain: ins.run('mcp.appcrane_list_apps', JSON.stringify(plain)).lastInsertRowid,
  notJson: ins.run('deploy', 'not json').lastInsertRowid,
};
const detail = (id) => db.prepare('SELECT detail FROM audit_log WHERE id = ?').get(id).detail;

test('legacy rows lose their secret values and keep everything else', () => {
  const r = scrubLegacyAuditSecrets(db);
  assert.equal(r.rows, 2);
  assert.ok(!detail(ids.setSecret).includes(SECRET));
  assert.deepEqual(JSON.parse(detail(ids.setSecret)), { ...legacySetSecret, args: { ...legacySetSecret.args, value: `[redacted:${SECRET.length} chars]` } });
  const push = JSON.parse(detail(ids.push));
  assert.deepEqual(push.args.files.map((f) => f.path), ['a.js', 'b.js']);
  assert.deepEqual(push.args.files.map((f) => f.staged_token), ['[redacted:9 chars]', '[redacted:9 chars]']);
});

test('rows already redacted, rows without secrets and non-JSON rows are untouched', () => {
  assert.equal(detail(ids.current), JSON.stringify(current));
  assert.equal(detail(ids.plain), JSON.stringify(plain));
  assert.equal(detail(ids.notJson), 'not json');
});

test('it runs once', () => {
  ins.run('mcp.appcrane_set_secret', JSON.stringify(legacySetSecret));
  assert.deepEqual(scrubLegacyAuditSecrets(db), { skipped: true });
});
