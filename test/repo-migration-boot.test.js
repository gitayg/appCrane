import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'child_process';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import net from 'net';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

// The boot wiring, on the real server/index.js: the repo migration runs to
// completion BEFORE the server listens, and a managed app it cannot migrate
// does not stop boot. The seeded app has a github.com URL and no service
// token, so the migrator fails it with NO_SERVICE_TOKEN without any network.

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = mkdtempSync(join(tmpdir(), 'crane-repomig-boot-'));
let child;

after(() => {
  try { child?.kill('SIGKILL'); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

test('boot runs the migrator before listening and keeps booting when an app cannot migrate', { timeout: 90000 }, async () => {
  const env = {
    ...process.env, DATA_DIR: dataDir, ENCRYPTION_KEY: 'c'.repeat(64), LOG_LEVEL: 'info',
    APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1',
  };
  delete env.APPCRANE_REPO_MIGRATION;
  execFileSync(process.execPath, ['--input-type=module', '-e', `
    const { initDb, getDb } = await import(${JSON.stringify(join(REPO, 'server/db.js'))});
    initDb();
    getDb().prepare("INSERT INTO apps (name,slug,slot,source_type,github_url,branch) VALUES ('Boot App','boot-app',9101,'managed','https://github.com/example-owner/AMC_boot-app','main')").run();
  `], { env, stdio: 'pipe' });

  const port = await freePort();
  let stdout = '';
  child = spawn(process.execPath, ['server/index.js'], {
    cwd: REPO, env: { ...env, PORT: String(port), HOST: '127.0.0.1' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (c) => { stdout += c.toString(); });
  child.stderr.on('data', (c) => { stdout += c.toString(); });
  let up = false;
  for (let i = 0; i < 240 && !up; i++) {
    try { up = (await fetch(`http://127.0.0.1:${port}/api/info`)).ok; } catch (_) { /* booting */ }
    if (!up) await new Promise((r) => setTimeout(r, 250));
  }
  assert.ok(up, `server never came up:\n${stdout.slice(-3000)}`);
  assert.equal(child.exitCode, null, 'still running');

  const migLine = stdout.indexOf('[repo-migration] boot-app: failed (NO_SERVICE_TOKEN)');
  const banner = stdout.indexOf('Self-service app hosting and deployment');
  assert.ok(migLine >= 0, `migration outcome not logged:\n${stdout.slice(0, 3000)}`);
  assert.ok(banner > migLine, 'the migration finished before app.listen called back');

  const db = new Database(join(dataDir, 'deployhub.db'), { readonly: true });
  const row = db.prepare("SELECT status, error_code FROM repo_migrations WHERE slug = 'boot-app'").get();
  const app = db.prepare("SELECT repo_backend FROM apps WHERE slug = 'boot-app'").get();
  db.close();
  assert.deepEqual({ ...row }, { status: 'failed', error_code: 'NO_SERVICE_TOKEN' });
  assert.equal(app.repo_backend, null);
  assert.ok(!readFileSync(join(REPO, 'server/index.js'), 'utf8').includes('import { migrateManagedReposAtBoot }'),
    'a static import would crash boot if the module failed to load');
});
