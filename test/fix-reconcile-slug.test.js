import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// A pulled image carries whatever labels its author baked in, containers inherit
// them, and reconcile used to take the slug from one. The container NAME is the
// platform's. Release files are the app author's too, so what they say about a
// repo gets the same checks a request would.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-fix-reconcile-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';
const BIN = join(ROOT, 'bin');
mkdirSync(BIN);
process.env.CRANE_TEST_PS = join(ROOT, 'ps.txt');
// Answers the query it is asked: the slug label's column only if the format names it.
writeFileSync(join(BIN, 'docker'), `#!/bin/bash
if [ "$1" = ps ]; then
  case "$*" in
    *'Label "slug"'*) cat "$CRANE_TEST_PS" ;;
    *) cut -d'|' -f1,3,4 "$CRANE_TEST_PS" ;;
  esac
fi
exit 0
`);
chmodSync(join(BIN, 'docker'), 0o755);
process.env.PATH = `${BIN}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const KEY = generateApiKey('dhk_admin');
const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Admin','admin@t.test','platform_admin',?,1,'human')").run(hashApiKey(KEY)).lastInsertRowid;

const { reconcileOrphanedApps, getOrphanedSlugs } = await import('../server/services/reconcile.js');
const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.unref();
  server.close();
  rmSync(ROOT, { recursive: true, force: true });
});

// name|slug label|env label|status, one per container.
function ps(lines) { writeFileSync(process.env.CRANE_TEST_PS, lines.map((l) => `${l}\n`).join('')); }
const slugs = () => db.prepare('SELECT slug FROM apps ORDER BY slug').all().map((r) => r.slug);
const post = (qs = '') => fetch(`${BASE}/api/apps/reconcile${qs}`, { method: 'POST', headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json' }, body: '{}' }).then((r) => r.json());
const audits = () => db.prepare("SELECT user_id, detail FROM audit_log WHERE action = 'apps-reconcile' ORDER BY id").all();

beforeEach(() => {
  db.prepare('DELETE FROM apps').run();
  db.prepare('DELETE FROM audit_log').run();
});

function release(slug, files) {
  const current = join(ROOT, 'apps', slug, 'production', 'current');
  mkdirSync(current, { recursive: true });
  for (const [f, body] of Object.entries(files)) writeFileSync(join(current, f), body);
  return current;
}

test('a container label cannot choose the slug', async () => {
  ps([
    'hungry_turing|../../evil|production|Up 5 seconds',
    'brave_raman|victim-label|production|Up 5 seconds',
    'appcrane-real-app-production|forged-label|production|Up 5 seconds',
  ]);
  const r = await reconcileOrphanedApps({});
  assert.deepEqual(r.registered.map((x) => x.slug), ['real-app']);
  assert.deepEqual(slugs(), ['real-app']);
  assert.deepEqual(getOrphanedSlugs(ROOT), []);
});

test('a name that decodes to a refused slug is not registered, and getOrphanedSlugs agrees', async () => {
  ps([
    'appcrane-Bad_Slug-production|x|production|Up',
    'appcrane-api-production|x|production|Up',
    'appcrane-fine-production|x|sandbox|Up',
  ]);
  assert.deepEqual(getOrphanedSlugs(ROOT), ['fine']);
  const r = await reconcileOrphanedApps({});
  assert.deepEqual(r.registered.map((x) => x.slug), ['fine']);
});

test('github_url and branch from a release are validated before they reach the row', async () => {
  release('meta-bad', { 'deployhub.json': JSON.stringify({ name: 'n', github_url: 'https://evil.test/owner/repo', branch: '--upload-pack=x' }) });
  release('meta-dash', { 'deployhub.json': JSON.stringify({ name: 'n', github_url: 'https://github.com/owner/repo', branch: '-x' }) });
  release('meta-good', { 'deployhub.json': JSON.stringify({ name: 'n', github_url: 'https://github.com/owner/repo', branch: 'dev' }) });
  ps(['appcrane-meta-bad-production|x|production|Up', 'appcrane-meta-dash-production|x|production|Up', 'appcrane-meta-good-production|x|production|Up']);
  await reconcileOrphanedApps({});
  const row = (s) => db.prepare('SELECT source_type, github_url, branch FROM apps WHERE slug = ?').get(s);
  assert.deepEqual(row('meta-bad'), { source_type: 'managed_legacy', github_url: null, branch: 'main' });
  assert.deepEqual(row('meta-dash'), { source_type: 'github', github_url: 'https://github.com/owner/repo', branch: 'main' });
  assert.deepEqual(row('meta-good'), { source_type: 'github', github_url: 'https://github.com/owner/repo', branch: 'dev' });
});

test('a committed link is not followed for a release\'s name', async () => {
  const outside = join(ROOT, 'outside.json');
  writeFileSync(outside, JSON.stringify({ name: 'LEAKED', description: 'LEAKED' }));
  const current = release('meta-link', {});
  symlinkSync(outside, join(current, 'deployhub.json'));
  ps(['appcrane-meta-link-production|x|production|Up']);
  await reconcileOrphanedApps({});
  const row = db.prepare('SELECT name, description FROM apps WHERE slug = ?').get('meta-link');
  assert.deepEqual(row, { name: 'meta-link', description: null });
});

test('POST /reconcile audits a run that registered something, and only that', async () => {
  ps([]);
  await post();
  assert.equal(audits().length, 0, 'nothing registered, nothing to audit');

  ps(['appcrane-dry-app-production|x|production|Up']);
  const dry = await post('?dry_run=1');
  assert.equal(dry.registered.length, 1);
  assert.equal(audits().length, 0, 'a dry run changed nothing');
  assert.deepEqual(slugs(), []);

  const real = await post();
  assert.equal(real.registered.length, 1);
  const rows = audits();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].user_id, adminId);
  assert.deepEqual(JSON.parse(rows[0].detail).registered, ['dry-app']);
});
