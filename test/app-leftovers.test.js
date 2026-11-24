import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Every per-app directory keyed by slug follows the app on rename and goes to
// the trash on delete: backups (rows re-pointed, a restore works after the
// rename), the coder's transcripts (coder_sessions re-pointed), attestations,
// the studio npm cache. Orphans of each are listed by the reconciler and moved
// to the trash in one click. Real routers on 127.0.0.1, a temp DATA_DIR, real
// files and a real `tar` backup.

const ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'crane-leftovers-')));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const rs = await import('../server/services/reconcileState.js');
const { createGrant } = await import('../server/services/stepUp.js');
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/api/state-reconcile', (await import('../server/routes/stateReconcile.js')).default);
api.use('/api/apps', (await import('../server/routes/apps.js')).default);
api.use('/api/apps', (await import('../server/routes/backups.js')).default);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

after(() => {
  server.closeAllConnections?.(); server.close();
  try { chmodSync(join(ROOT, 'backups'), 0o700); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

const RUN = crypto.randomBytes(3).toString('hex');
const key = generateApiKey('dhk_user');
const adminId = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
  .run('lo-admin', 'lo-admin@t.test', 'platform_admin', hashApiKey(key)).lastInsertRowid);
const admin = { id: adminId, key };

let slot = 3400 + Math.floor(Math.random() * 300);
function mkApp(slug) {
  const id = Number(db.prepare("INSERT INTO apps (name, slug, slot, source_type, branch) VALUES (?, ?, ?, 'github', 'main')").run(slug, slug, ++slot).lastInsertRowid);
  db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(id, adminId, 'owner');
  for (const env of ['production', 'sandbox']) mkdirSync(join(ROOT, 'apps', slug, env, 'shared', 'data'), { recursive: true });
  writeFileSync(join(ROOT, 'apps', slug, 'production', 'shared', 'data', 'notes.txt'), `data of ${slug}`);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

async function call(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': admin.key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, body: json };
}

// A real backup through the router, a database dump entry beside it (the
// shape managedDbBackup writes), a coder transcript and session, an
// attestation and an npm cache: one of each per-app directory.
async function withLeftovers(app) {
  const b = await call('POST', `/api/apps/${app.slug}/backup/production`);
  assert.equal(b.status, 200, JSON.stringify(b.body));
  const row = db.prepare('SELECT * FROM backups WHERE app_id = ?').get(app.id);
  const dump = join(ROOT, 'backups', app.slug, 'production-x.postgres.dump');
  writeFileSync(dump, 'dump');
  db.prepare('UPDATE backups SET databases = ? WHERE id = ?')
    .run(JSON.stringify([{ engine: 'postgres', tenant: '', db_name: `crane_${app.id}`, file: dump, size_bytes: 4 }]), row.id);
  const tx = join(ROOT, 'app-containers', app.slug, 'claude-projects', '-workspace');
  mkdirSync(tx, { recursive: true });
  writeFileSync(join(tx, 'sess-1.jsonl'), '{}\n');
  db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, workspace_dir, claude_session_id) VALUES (?, ?, ?, 'main', ?, 'sess-1')")
    .run(`cs-${app.slug}`, app.slug, adminId, join(ROOT, 'app-containers', app.slug, 'workspace'));
  const att = join(ROOT, 'attestations', app.slug, 'production', '1');
  mkdirSync(att, { recursive: true });
  writeFileSync(join(att, 'image.sig'), 'sig');
  db.prepare("INSERT INTO deploy_attestations (app_id, env, image_ref, status, dir) VALUES (?, 'production', 'x@sha256:1', 'signed', ?)").run(app.id, att);
  mkdirSync(join(ROOT, 'appstudio-npm-cache', app.slug, '_cacache'), { recursive: true });
  return row;
}

const quiet = { listContainers: async () => new Map(), rescheduleHealth: async () => {}, resumeHealth: async () => {} };
const finding = (kind, slug) => db.prepare('SELECT * FROM reconcile_findings WHERE kind = ? AND slug = ? ORDER BY id DESC LIMIT 1').get(kind, slug);

test('rename moves backups, coder transcripts, attestations and npm cache, re-points their rows, and a restore works afterwards', async () => {
  const app = mkApp(`lo-ren-${RUN}`);
  const newSlug = `lo-ren2-${RUN}`;
  const backup = await withLeftovers(app);

  const r = await call('POST', `/api/apps/${app.slug}/rename`, { new_slug: newSlug });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  for (const tree of ['backups', 'app-containers', 'attestations', 'appstudio-npm-cache']) {
    assert.equal(existsSync(join(ROOT, tree, app.slug)), false, `${tree}/${app.slug} stayed`);
    assert.equal(existsSync(join(ROOT, tree, newSlug)), true, `${tree}/${newSlug} missing`);
  }
  const b = db.prepare('SELECT * FROM backups WHERE id = ?').get(backup.id);
  assert.ok(b.file_path.startsWith(join(ROOT, 'backups', newSlug) + '/'), b.file_path);
  assert.equal(existsSync(b.file_path), true);
  const dump = JSON.parse(b.databases)[0].file;
  assert.equal(dump, join(ROOT, 'backups', newSlug, 'production-x.postgres.dump'));
  assert.equal(existsSync(dump), true);
  const cs = db.prepare('SELECT * FROM coder_sessions WHERE id = ?').get(`cs-${app.slug}`);
  assert.equal(cs.app_slug, newSlug);
  assert.equal(cs.workspace_dir, join(ROOT, 'app-containers', newSlug, 'workspace'));
  const { lastClaudeSessionId } = await import('../server/services/builder/appContainer.js');
  assert.equal(lastClaudeSessionId(newSlug), 'sess-1', 'the coder cannot resume its conversation after the rename');
  const att = db.prepare('SELECT dir FROM deploy_attestations WHERE app_id = ?').get(app.id).dir;
  assert.equal(att, join(ROOT, 'attestations', newSlug, 'production', '1'));
  assert.equal(existsSync(join(att, 'image.sig')), true);

  rmSync(join(ROOT, 'apps', newSlug, 'production', 'shared', 'data', 'notes.txt'));
  const restore = await call('POST', `/api/apps/${newSlug}/restore/${backup.id}`, { include_database: false, keep_running: true });
  assert.equal(restore.status, 200, JSON.stringify(restore.body));
  assert.equal(readFileSync(join(ROOT, 'apps', newSlug, 'production', 'shared', 'data', 'notes.txt'), 'utf8'), `data of ${app.slug}`);
});

test('rename refuses, before anything moves, when the target backups directory is already on disk', async () => {
  const app = mkApp(`lo-rr-${RUN}`);
  await withLeftovers(app);
  mkdirSync(join(ROOT, 'backups', `lo-rr2-${RUN}`), { recursive: true });
  const r = await call('POST', `/api/apps/${app.slug}/rename`, { new_slug: `lo-rr2-${RUN}` });
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(r.body.error?.code || r.body.code, 'TARGET_DIR_EXISTS', JSON.stringify(r.body));
  assert.equal(db.prepare('SELECT slug FROM apps WHERE id = ?').get(app.id).slug, app.slug);
  assert.equal(existsSync(join(ROOT, 'apps', app.slug)), true);
});

test('rename that cannot move the backups directory is rolled back: every directory and row as before', async () => {
  const app = mkApp(`lo-rb-${RUN}`);
  const backup = await withLeftovers(app);
  const before = db.prepare('SELECT file_path, databases FROM backups WHERE id = ?').get(backup.id);
  chmodSync(join(ROOT, 'backups'), 0o500);
  let r;
  try {
    r = await call('POST', `/api/apps/${app.slug}/rename`, { new_slug: `lo-rb2-${RUN}` });
  } finally {
    chmodSync(join(ROOT, 'backups'), 0o700);
  }
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(db.prepare('SELECT slug FROM apps WHERE id = ?').get(app.id).slug, app.slug);
  assert.equal(existsSync(join(ROOT, 'apps', app.slug, 'production', 'shared', 'data', 'notes.txt')), true, 'the data directory was not moved back');
  assert.equal(existsSync(join(ROOT, 'apps', `lo-rb2-${RUN}`)), false);
  assert.equal(existsSync(join(ROOT, 'backups', app.slug)), true);
  assert.equal(existsSync(join(ROOT, 'app-containers', app.slug)), true);
  assert.deepEqual({ ...db.prepare('SELECT file_path, databases FROM backups WHERE id = ?').get(backup.id) }, { ...before });
  assert.equal(db.prepare('SELECT app_slug FROM coder_sessions WHERE id = ?').get(`cs-${app.slug}`).app_slug, app.slug);
});

test('delete moves every per-app directory to the trash; the backups entry keeps the rows (paths in the trash) and the off-site copies', async () => {
  const app = mkApp(`lo-del-${RUN}`);
  const backup = await withLeftovers(app);
  const set = (k, v) => db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(k, v);
  set('backup_s3_bucket', 'crane-backups-test'); set('backup_s3_access_key_id', 'AKIATEST'); set('backup_s3_secret_enc', 'x');
  set('backup_s3_prefix', 'host1'); set('backup_s3_last_run', '2026-11-20 03:00:00');
  try {
    createGrant(db, adminId, 'delete_app', app.id);
    const r = await call('DELETE', `/api/apps/${app.slug}?confirm=true`);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.moved_to_trash.map((t) => t.kind).sort(), ['app_dir', 'attestations', 'backups', 'coder_workspace', 'npm_cache']);
    for (const tree of ['apps', 'backups', 'app-containers', 'attestations', 'appstudio-npm-cache']) {
      assert.equal(existsSync(join(ROOT, tree, app.slug)), false, `${tree}/${app.slug} stayed`);
    }
    const t = db.prepare("SELECT * FROM app_trash WHERE slug = ? AND kind = 'backups'").get(app.slug);
    const d = JSON.parse(t.detail_json);
    assert.equal(d.backups.length, 1);
    assert.equal(d.backups[0].id, backup.id);
    assert.equal(d.backups[0].original_file_path, backup.file_path);
    assert.ok(d.backups[0].file_path.startsWith(t.trash_path + '/'), d.backups[0].file_path);
    assert.equal(existsSync(d.backups[0].file_path), true, 'the recorded path does not hold the archive');
    assert.equal(existsSync(d.backups[0].databases[0].file), true, 'the recorded dump path does not hold the dump');
    assert.equal(d.off_site.bucket, 'crane-backups-test');
    assert.ok(JSON.stringify(r.body.off_site_copies_retained || null).includes('crane-backups-test'), 'a platform admin sees where the off-site copies are');
    assert.equal(d.off_site.prefix, 'host1/');
    assert.ok(d.off_site.holds.some((h) => h.includes(`appcrane-repo-${app.slug}-`)));
    assert.equal(JSON.stringify(d).includes('AKIATEST'), false, 'a credential was written to the trash entry');
    const coder = db.prepare("SELECT trash_path FROM app_trash WHERE slug = ? AND kind = 'coder_workspace'").get(app.slug).trash_path;
    assert.equal(existsSync(join(coder, 'claude-projects', '-workspace', 'sess-1.jsonl')), true);
    const listed = (await call('GET', '/api/state-reconcile')).body.trash.find((x) => x.id === t.id);
    assert.equal(listed.detail.backups[0].id, backup.id);
  } finally {
    for (const k of ['bucket', 'access_key_id', 'secret_enc', 'prefix', 'last_run']) db.prepare('DELETE FROM settings WHERE key = ?').run(`backup_s3_${k}`);
  }
});

test('an app owner who is not a platform admin deleting an app is told off-site copies may exist, not the bucket or prefix', async () => {
  const app = mkApp(`lo-own-${RUN}`);
  const okey = generateApiKey('dhk_user');
  const ownerId = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(`lo-owner-${RUN}`, `lo-owner-${RUN}@t.test`, 'user', hashApiKey(okey)).lastInsertRowid);
  db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(app.id, ownerId, 'owner');
  const set = (k, v) => db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(k, v);
  set('backup_s3_bucket', 'crane-backups-secretname'); set('backup_s3_access_key_id', 'AKIATEST'); set('backup_s3_secret_enc', 'x');
  set('backup_s3_prefix', 'hostprefix'); set('backup_s3_last_run', '2026-11-20 03:00:00');
  try {
    createGrant(db, ownerId, 'delete_app', app.id);
    const res = await fetch(`${BASE}/api/apps/${app.slug}?confirm=true`, { method: 'DELETE', headers: { 'X-API-Key': okey } });
    const text = await res.text();
    assert.equal(res.status, 200, text);
    assert.equal(text.includes('crane-backups-secretname'), false, 'the platform bucket was shown to an app owner');
    assert.equal(text.includes('hostprefix'), false, 'the platform prefix was shown to an app owner');
    assert.match(JSON.parse(text).off_site_copies_note, /off-site backups/);
  } finally {
    for (const k of ['bucket', 'access_key_id', 'secret_enc', 'prefix', 'last_run']) db.prepare('DELETE FROM settings WHERE key = ?').run(`backup_s3_${k}`);
  }
});

test("an app named 'local' is deleted without touching the platform's nightly archives in backups/local", async () => {
  const app = mkApp('local');
  mkdirSync(join(ROOT, 'backups', 'local'), { recursive: true });
  writeFileSync(join(ROOT, 'backups', 'local', 'appcrane-local-1.tar.gz'), 'nightly');
  createGrant(db, adminId, 'delete_app', app.id);
  const r = await call('DELETE', `/api/apps/${app.slug}?confirm=true`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(existsSync(join(ROOT, 'backups', 'local', 'appcrane-local-1.tar.gz')), true);
  assert.ok(r.body.leftovers_kept.some((k) => k.kind === 'backups'), JSON.stringify(r.body));
});

test('reconciler: orphan backups, coder, attestations and npm-cache dirs listed and moved to the trash; platform dirs and referenced dirs are not', async () => {
  const ghost = `lo-ghost-${RUN}`;
  for (const tree of ['backups', 'app-containers', 'attestations', 'appstudio-npm-cache']) {
    mkdirSync(join(ROOT, tree, ghost, 'x'), { recursive: true });
    writeFileSync(join(ROOT, tree, ghost, 'x', 'f'), '12345');
  }
  mkdirSync(join(ROOT, 'backups', 'key-rotation-20261101'), { recursive: true });
  // A backups dir an existing app's rows still name (renamed before renames moved backups).
  const kept = mkApp(`lo-kept-${RUN}`);
  const stale = `lo-stale-${RUN}`;
  mkdirSync(join(ROOT, 'backups', stale), { recursive: true });
  db.prepare("INSERT INTO backups (app_id, env, file_path) VALUES (?, 'production', ?)").run(kept.id, `data/backups/${stale}/production-1.tar.gz`);

  await rs.reconcileOnce({ trigger: 'test', deps: quiet });
  const kinds = { backups: 'orphan_backups_dir', 'app-containers': 'orphan_coder_dir', attestations: 'orphan_attestations_dir', 'appstudio-npm-cache': 'orphan_npm_cache_dir' };
  for (const [tree, kind] of Object.entries(kinds)) {
    const f = finding(kind, ghost);
    assert.ok(f, `${kind} not found`);
    assert.equal(f.fix, 'trash_dir');
    assert.equal(JSON.parse(f.detail_json).files, 1);
    const fx = await call('POST', `/api/state-reconcile/findings/${f.id}/fix`);
    assert.equal(fx.status, 200, JSON.stringify(fx.body));
    assert.equal(existsSync(join(ROOT, tree, ghost)), false);
    const t = db.prepare('SELECT trash_path FROM app_trash WHERE slug = ? AND original_path = ?').get(ghost, join(ROOT, tree, ghost));
    assert.equal(existsSync(join(t.trash_path, 'x', 'f')), true);
  }
  assert.equal(finding('orphan_backups_dir', 'local'), undefined, 'backups/local is the platform\'s own');
  assert.equal(finding('orphan_backups_dir', 'key-rotation-20261101'), undefined);
  const s = finding('orphan_backups_dir', stale);
  assert.equal(JSON.parse(s.detail_json).referenced_by_rows, 1);
  assert.equal(s.fix, null, 'a directory rows still name has a one-click move');
});

test('flybox shape: pre-fix delete leftovers apps/moorai-retired (renamed from moorai, then deleted) and apps/raisemehost are orphans', async () => {
  const moorai = mkApp('moorai');
  mkdirSync(join(ROOT, 'apps', 'moorai', 'production', 'releases', '12-git'), { recursive: true });
  const r = await call('POST', '/api/apps/moorai/rename', { new_slug: 'moorai-retired' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const raise = mkApp('raisemehost');
  // The delete as it was before deletes moved anything: rows gone, directories left.
  db.pragma('foreign_keys = OFF');
  for (const id of [moorai.id, raise.id]) {
    db.prepare('DELETE FROM app_user_roles WHERE app_id = ?').run(id);
    db.prepare('DELETE FROM app_slug_renames WHERE app_id = ?').run(id);
    db.prepare('DELETE FROM apps WHERE id = ?').run(id);
  }
  db.pragma('foreign_keys = ON');
  for (const slug of ['moorai-retired', 'raisemehost']) {
    for (const env of ['production', 'sandbox']) assert.equal(existsSync(join(ROOT, 'apps', slug, env)), true);
  }

  await rs.reconcileOnce({ trigger: 'test', deps: quiet });
  const g = (await call('GET', '/api/state-reconcile')).body.findings;
  for (const slug of ['moorai-retired', 'raisemehost']) {
    const f = g.find((x) => x.kind === 'orphan_app_dir' && x.slug === slug);
    assert.ok(f, `${slug}: ${JSON.stringify(g.filter((x) => x.slug === slug))}`);
    assert.equal(f.fix, 'trash_dir');
    assert.equal(f.detail.path, `apps/${slug}`);
  }
});
