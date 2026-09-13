import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'fs';
import net from 'net';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

// The boot wiring on the real server/index.js: upload conversion runs after the
// repo migration and before the server listens, a skipped app does not stop
// boot, and the off switch leaves uploaded apps alone.

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const dirs = [];
let child;
after(() => {
  try { child?.kill('SIGKILL'); } catch (_) {}
  for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }); } catch (_) {} }
});

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

function seed(dataDir, env) {
  const rel = (slug, files) => {
    const d = join(dataDir, 'apps', slug, 'production', 'releases', '1700000000000-upload');
    for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(d, p)), { recursive: true }); writeFileSync(join(d, p), c); }
    return d;
  };
  const conv = rel('boot-conv', { 'package.json': '{"name":"b","scripts":{"start":"node s.js"}}', 's.js': '1\n', '.env': 'TOKEN=boot-secret-VALUE\n' });
  rel('boot-skip', { 'index.js': '1\n', 'node_modules/a/i.js': '1\n', '.env': 'VITE_API=boot-vite-VALUE\n' });
  execFileSync(process.execPath, ['--input-type=module', '-e', `
    const { initDb, getDb } = await import(${JSON.stringify(join(REPO, 'server/db.js'))});
    initDb();
    const db = getDb();
    db.prepare("INSERT INTO apps (name,slug,slot,source_type,github_url,branch) VALUES ('M','boot-managed',9201,'managed','https://github.com/example-owner/AMC_boot-managed','main')").run();
    const id = db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('C','boot-conv',9202,'upload')").run().lastInsertRowid;
    db.prepare("INSERT INTO deployments (app_id,env,status,commit_hash,release_path) VALUES (?,'production','live',?,?)").run(id, 'sha256:' + 'c'.repeat(64), ${JSON.stringify(conv)});
    db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('S','boot-skip',9203,'upload')").run();
  `], { env, stdio: 'pipe' });
}

async function boot(extraEnv) {
  const dataDir = mkdtempSync(join(tmpdir(), 'crane-uploadconv-boot-'));
  dirs.push(dataDir);
  const env = {
    ...process.env, DATA_DIR: dataDir, ENCRYPTION_KEY: 'd'.repeat(64), LOG_LEVEL: 'info',
    APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1', ...extraEnv,
  };
  delete env.APPCRANE_REPO_MIGRATION;
  if (!extraEnv.APPCRANE_UPLOAD_CONVERSION) delete env.APPCRANE_UPLOAD_CONVERSION;
  seed(dataDir, env);
  const port = await freePort();
  let stdout = '';
  child = spawn(process.execPath, ['server/index.js'], { cwd: REPO, env: { ...env, PORT: String(port), HOST: '127.0.0.1' }, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', (c) => { stdout += c.toString(); });
  child.stderr.on('data', (c) => { stdout += c.toString(); });
  let up = false;
  for (let i = 0; i < 240 && !up; i++) {
    try { up = (await fetch(`http://127.0.0.1:${port}/api/info`)).ok; } catch (_) { /* booting */ }
    if (!up) await new Promise((r) => setTimeout(r, 250));
  }
  const exitCode = child.exitCode;
  child.kill('SIGKILL');
  await new Promise((r) => child.once('exit', r));
  const db = new Database(join(dataDir, 'deployhub.db'), { readonly: true });
  const apps = Object.fromEntries(db.prepare('SELECT slug, source_type, repo_backend FROM apps').all().map((a) => [a.slug, a]));
  const rows = Object.fromEntries(db.prepare('SELECT slug, status, error_code FROM upload_conversions').all().map((r) => [r.slug, r]));
  db.close();
  return { up, exitCode, stdout, apps, rows, dataDir };
}

test('boot converts uploaded apps after the repo migration and before listening; a skipped app does not stop boot', { timeout: 120000 }, async () => {
  const r = await boot({});
  assert.ok(r.up, `server never came up:\n${r.stdout.slice(-3000)}`);
  assert.equal(r.exitCode, null);
  const mig = r.stdout.indexOf('[repo-migration] boot-managed: failed (NO_SERVICE_TOKEN)');
  const conv = r.stdout.indexOf('[upload-conversion] boot-conv: converted');
  const skip = r.stdout.indexOf('[upload-conversion] boot-skip: skipped (needs_bundled_node_modules)');
  const banner = r.stdout.indexOf('Self-service app hosting and deployment');
  assert.ok(mig >= 0 && conv >= 0 && skip >= 0 && banner >= 0, r.stdout.slice(-4000));
  assert.ok(mig < conv, 'repo migration runs first');
  assert.ok(conv < banner && skip < banner, 'conversion finishes before the server listens');
  assert.ok(!r.stdout.includes('boot-secret-VALUE') && !r.stdout.includes('boot-vite-VALUE'), 'no env value in boot output');
  assert.deepEqual(r.apps['boot-conv'], { slug: 'boot-conv', source_type: 'managed', repo_backend: 'local' });
  assert.deepEqual(r.apps['boot-skip'], { slug: 'boot-skip', source_type: 'upload', repo_backend: null });
  assert.equal(r.rows['boot-conv'].status, 'converted');
  assert.equal(r.rows['boot-skip'].error_code, 'needs_bundled_node_modules');
  assert.ok(existsSync(join(r.dataDir, 'repos', 'boot-conv.git', 'HEAD')));
});

test('APPCRANE_UPLOAD_CONVERSION=off: boot leaves uploaded apps alone', { timeout: 120000 }, async () => {
  const r = await boot({ APPCRANE_UPLOAD_CONVERSION: 'off' });
  assert.ok(r.up, r.stdout.slice(-3000));
  assert.ok(r.stdout.includes('[upload-conversion] disabled by APPCRANE_UPLOAD_CONVERSION=off'), r.stdout.slice(-3000));
  assert.equal(r.apps['boot-conv'].source_type, 'upload');
  assert.deepEqual(r.rows, {});
  assert.ok(!existsSync(join(r.dataDir, 'repos', 'boot-conv.git')));
});
