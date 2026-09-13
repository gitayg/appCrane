import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join } from 'path';

// .env files of a converted app: kept OUT of git, stored encrypted
// (app_env_files), written back into the right environment's release before the
// build. The build context is captured by a docker shim at the moment
// `docker build` is invoked, so "before the build" is measured, not assumed.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-envfiles-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'info';
delete process.env.APPCRANE_UPLOAD_CONVERSION;

const SHIM = join(ROOT, 'bin');
const CAPTURE = join(ROOT, 'build-capture');
mkdirSync(SHIM, { recursive: true });
mkdirSync(CAPTURE, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
case "$1" in
  version) echo 27.0.0; exit 0 ;;
  image) exit 1 ;;
  build)
    for a in "$@"; do ctx="$a"; done
    n=$(cat "$ENVFILES_CAPTURE/count" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$ENVFILES_CAPTURE/count"
    mkdir -p "$ENVFILES_CAPTURE/$n" && cp -Rp "$ctx"/. "$ENVFILES_CAPTURE/$n/"
    echo "shim: build context captured, failing the build" >&2; exit 1 ;;
  *) exit 0 ;;
esac
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;
process.env.ENVFILES_CAPTURE = CAPTURE;

const logLines = [];
const origLog = console.log;
console.log = (...a) => { logLines.push(a.join(' ')); };

const { initDb, getDb } = await import('../server/db.js');
initDb();
let db = getDb();
const { decrypt } = await import('../server/services/encryption.js');
const uc = await import('../server/services/uploadConversion.js');
const lg = await import('../server/services/localGit.js');
const store = await import('../server/services/envFileStore.js');
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');

after(async () => {
  console.log = origLog;
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const g = (gitDir, args) => execFileSync('git', [`--git-dir=${gitDir}`, ...args], { env: CLEAN, maxBuffer: 64 * 1024 * 1024 }).toString('utf8');
const sha = (b) => createHash('sha256').update(b).digest('hex');
const A64 = `sha256:${'a'.repeat(64)}`;
const B64 = `sha256:${'b'.repeat(64)}`;
let slot = 8100;
const makeApp = (slug) => db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?,?,?,'upload')").run(slug, slug, ++slot).lastInsertRowid;
const appRow = (id) => db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
const live = (id, env, dir, hash) => db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash, release_path) VALUES (?,?,'live',?,?)").run(id, env, hash, dir).lastInsertRowid;
const BASE = {
  'package.json': JSON.stringify({ name: 'envapp', version: '1.0.0', scripts: { start: 'node server.js' } }),
  'package-lock.json': JSON.stringify({ name: 'envapp', lockfileVersion: 3, packages: {} }),
};

function release(slug, env, name, files) {
  const dir = join(ROOT, 'apps', slug, env, 'releases', name);
  mkdirSync(dir, { recursive: true });
  for (const [p, v] of Object.entries(files)) {
    const abs = join(dir, p);
    mkdirSync(dirname(abs), { recursive: true });
    if (v && typeof v === 'object' && 'symlink' in v) symlinkSync(v.symlink, abs);
    else if (v && typeof v === 'object' && 'mode' in v) { writeFileSync(abs, v.content); chmodSync(abs, v.mode); } else writeFileSync(abs, v);
  }
  return dir;
}

async function deploy(id, env, opts = {}) {
  const before = Number(existsSync(join(CAPTURE, 'count')) ? readFileSync(join(CAPTURE, 'count'), 'utf8') : 0);
  const depId = db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, ?, 'pending')").run(id, env).lastInsertRowid;
  await deployApp(depId, appRow(id), env, getPortsForSlot(appRow(id).slot), opts).catch(() => {});
  const after = Number(existsSync(join(CAPTURE, 'count')) ? readFileSync(join(CAPTURE, 'count'), 'utf8') : 0);
  return { log: db.prepare('SELECT log FROM deployments WHERE id = ?').get(depId).log || '', ctx: after > before ? join(CAPTURE, String(after)) : null };
}

function listEnvFiles(dir) {
  const out = [];
  const walk = (rel) => {
    for (const n of readdirSync(join(dir, rel)).sort()) {
      const r = rel ? `${rel}/${n}` : n;
      const st = statSync(join(dir, r));
      if (st.isDirectory()) { if (n !== '.git' && n !== 'node_modules') walk(r); } else if (n.startsWith('.env')) out.push(`${r} ${(st.mode & 0o777).toString(8)}`);
    }
  };
  walk('');
  return out;
}

const PROD_ENV = 'VITE_API_URL=https://api.example.com\r\nSECRET=VALUEMARK-prod-root\r\n';
const PROD_NESTED = 'NESTED_SECRET=VALUEMARK-prod-nested\n';
const PROD_ENVPROD = 'LOG_LEVEL=VALUEMARK-prod-level\n';
const SB_ENV = 'VITE_API_URL=https://sandbox-api.example.com\nSECRET=VALUEMARK-sb-root\n';
const app = {};

test('conversion stores every .env* file (root, nested, example, inside-release symlink) encrypted, with its mode; nothing in git', async () => {
  app.id = makeApp('envapp');
  app.prodDir = release('envapp', 'production', '1-upload', {
    ...BASE,
    'server.js': 'console.log("prod")\n',
    '.env': { content: PROD_ENV, mode: 0o600 },
    '.env.production': PROD_ENVPROD,
    '.env.example': 'SECRET=\n',
    'web/.env': { content: PROD_NESTED, mode: 0o640 },
    'config/shared.txt': 'SHARED=linked-tracked-file\n',
    '.env.local': { symlink: 'config/shared.txt' },
    '.env.outside': { symlink: '/etc/hosts' },
  });
  app.sbDir = release('envapp', 'sandbox', '2-upload', { ...BASE, 'server.js': 'console.log("sandbox")\n', '.env': { content: SB_ENV, mode: 0o644 } });
  live(app.id, 'production', app.prodDir, A64);
  live(app.id, 'sandbox', app.sbDir, B64);

  const r = await uc.convertOneApp(db, appRow(app.id), { appTimeoutMs: 60000 });
  assert.equal(r.status, 'converted', JSON.stringify(r));

  const rows = db.prepare('SELECT env, rel_path, mode, bytes, content_encrypted FROM app_env_files WHERE app_id = ? ORDER BY env, rel_path').all(app.id);
  assert.deepEqual(rows.map((x) => `${x.env}:${x.rel_path}:${x.mode.toString(8)}`), [
    'production:.env:600', 'production:.env.example:644', 'production:.env.local:644', 'production:.env.production:644', 'production:web/.env:640',
    'sandbox:.env:644',
  ]);
  const content = (env, p) => Buffer.from(decrypt(rows.find((x) => x.env === env && x.rel_path === p).content_encrypted), 'base64').toString('utf8');
  assert.equal(content('production', '.env'), PROD_ENV, 'CRLF bytes kept exactly');
  assert.equal(content('production', 'web/.env'), PROD_NESTED);
  assert.equal(content('production', '.env.local'), 'SHARED=linked-tracked-file\n', 'an inside symlink stores its target');
  assert.equal(content('sandbox', '.env'), SB_ENV);
  for (const x of rows) assert.ok(!x.content_encrypted.includes('VALUEMARK'));

  const o = db.prepare('SELECT * FROM upload_conversions WHERE app_id = ?').get(app.id);
  assert.ok(JSON.parse(o.warnings_json).some((w) => w.path === '.env.outside' && w.reason === 'env_symlink_outside_release'));
  assert.deepEqual(uc.getUploadConversionStatus(db).apps.find((a) => a.slug === 'envapp').stored_env_files, {
    production: ['.env', '.env.example', '.env.local', '.env.production', 'web/.env'], sandbox: ['.env'],
  });

  const repo = lg.repoPath('envapp');
  for (const c of g(repo, ['rev-list', 'refs/heads/main']).trim().split('\n')) {
    assert.doesNotMatch(g(repo, ['ls-tree', '-r', '--name-only', c]), /(^|\/)\.env/m);
  }
  assert.ok(!g(repo, ['cat-file', '--batch-all-objects', '--batch']).includes('VALUEMARK'));
  app.prodCommit = JSON.parse(o.commits_json).production.commit;
  app.tip = g(repo, ['rev-parse', 'refs/heads/main']).trim();
});

test('sandbox deploy: the build context holds sandbox\'s .env only, with its mode, written before docker build', async () => {
  const { log, ctx } = await deploy(app.id, 'sandbox');
  assert.ok(ctx, `docker build was never reached:\n${log.slice(-2000)}`);
  assert.deepEqual(listEnvFiles(ctx), ['.env 644']);
  assert.equal(readFileSync(join(ctx, '.env'), 'utf8'), SB_ENV);
  assert.equal(readFileSync(join(ctx, 'server.js'), 'utf8'), 'console.log("sandbox")\n');
  assert.match(log, /Restored 1 stored \.env file\(s\) into the release, outside the repository: \.env/);
  assert.ok(log.indexOf('Restored 1 stored .env file') < log.indexOf('Building docker image'), 'restored before the build step');
  app.sbLog = log;
});

test('production deploy: root + nested .env with their modes, production\'s files only', async () => {
  const { log, ctx } = await deploy(app.id, 'production');
  assert.ok(ctx, log.slice(-2000));
  assert.deepEqual(listEnvFiles(ctx), ['.env 600', '.env.example 644', '.env.local 644', '.env.production 644', 'web/.env 640']);
  assert.equal(readFileSync(join(ctx, '.env'), 'utf8'), PROD_ENV);
  assert.equal(readFileSync(join(ctx, 'web/.env'), 'utf8'), PROD_NESTED);
  assert.equal(readFileSync(join(ctx, 'server.js'), 'utf8'), 'console.log("sandbox")\n', 'an unpinned deploy builds the branch tip; the files are still production\'s');
  assert.ok(existsSync(join(ctx, 'Dockerfile')), 'the captured directory is the build context the Dockerfile was generated into');
  assert.ok(!readFileSync(join(ctx, '.env'), 'utf8').includes('VALUEMARK-sb'));
  console.log(`# production build context .env listing: ${JSON.stringify(listEnvFiles(ctx))}`);
  app.prodLog = log;
});

test('deploys never commit: repo refs unchanged and no .env object in the repository', () => {
  const repo = lg.repoPath('envapp');
  assert.equal(g(repo, ['rev-parse', 'refs/heads/main']).trim(), app.tip);
  assert.equal(g(repo, ['for-each-ref', '--format=%(refname)']).trim(), 'refs/heads/main');
  assert.ok(!g(repo, ['cat-file', '--batch-all-objects', '--batch']).includes('VALUEMARK'));
});

test('contents never reach logs, deploy logs, outcome rows or the status output', () => {
  const texts = [
    logLines.join('\n'), app.sbLog, app.prodLog,
    JSON.stringify(db.prepare('SELECT * FROM upload_conversions').all()),
    JSON.stringify(uc.getUploadConversionStatus(db)),
    JSON.stringify(db.prepare('SELECT log FROM deployments').all()),
  ];
  for (const [i, t] of texts.entries()) assert.ok(!t.includes('VALUEMARK'), `content leaked into source #${i}`);
});

test('restore refuses escaping paths, symlinked parents and symlinked destinations, writing nothing', () => {
  const dir = mkdtempSync(join(ROOT, 'restore-'));
  const outside = mkdtempSync(join(ROOT, 'outside-'));
  symlinkSync(outside, join(dir, 'linked'));
  symlinkSync(join(outside, 'target.env'), join(dir, '.env'));
  const fake = makeApp('escape');
  const [enc] = store.encryptEnvFiles([{ rel_path: '.env', mode: 0o600, bytes: 3, content: Buffer.from('x=1') }]);
  const insert = (rel) => db.prepare('INSERT INTO app_env_files (app_id, env, rel_path, mode, bytes, content_encrypted) VALUES (?, ?, ?, ?, ?, ?)').run(fake, 'sandbox', rel, 0o600, 3, enc.content_encrypted);
  for (const bad of ['../.env', '/tmp/.env', 'a/../../.env', '.git/.env', 'notenv', 'a//.env', 'linked/.env', '.env']) {
    db.prepare('DELETE FROM app_env_files WHERE app_id = ?').run(fake);
    insert(bad);
    assert.throws(() => store.restoreStoredEnvFiles(db, { id: fake }, 'sandbox', dir), (e) => e.code === 'ENV_FILE_PATH_REFUSED', `accepted ${bad}`);
  }
  assert.deepEqual(readdirSync(outside), [], 'nothing written outside the release');
  assert.throws(() => store.restoreStoredEnvFiles(db, { id: fake }, 'staging', dir), /invalid env/);
  db.prepare('DELETE FROM app_env_files WHERE app_id = ?').run(fake);
});

test('a deploy whose stored path is unsafe fails before the build', async () => {
  const [enc] = store.encryptEnvFiles([{ rel_path: '.env', mode: 0o600, bytes: 3, content: Buffer.from('x=1') }]);
  db.prepare("INSERT INTO app_env_files (app_id, env, rel_path, mode, bytes, content_encrypted) VALUES (?, 'sandbox', '../escape/.env', 384, 3, ?)").run(app.id, enc.content_encrypted);
  try {
    const { log, ctx } = await deploy(app.id, 'sandbox');
    assert.equal(ctx, null, 'docker build must not be reached');
    assert.match(log, /refusing stored env file path "\.\.\/escape\/\.env"/);
    assert.ok(!existsSync(join(ROOT, 'apps', 'envapp', 'sandbox', 'escape')));
  } finally {
    db.prepare("DELETE FROM app_env_files WHERE app_id = ? AND rel_path = '../escape/.env'").run(app.id);
  }
});

test('boot credential scrub leaves .env files byte-identical', async () => {
  const rel = join(ROOT, 'apps', 'envapp', 'production', 'releases', '99-git');
  mkdirSync(join(rel, '.git'), { recursive: true });
  const envText = 'DATABASE_URL=https://user:VALUEMARK-tok@db.example.com/x\n';
  writeFileSync(join(rel, '.env'), envText);
  writeFileSync(join(rel, '.git', 'config'), '[remote "origin"]\n\turl = https://ghp_tokenvalue@github.com/example/x\n');
  const { scrubGitCredentialsOnDisk } = await import('../server/services/gitCredentialScrub.js');
  scrubGitCredentialsOnDisk(ROOT);
  assert.doesNotMatch(readFileSync(join(rel, '.git', 'config'), 'utf8'), /ghp_tokenvalue/, 'the scrub did run');
  assert.equal(sha(readFileSync(join(rel, '.env'))), sha(Buffer.from(envText)));
  rmSync(rel, { recursive: true, force: true });
});

test('data archive restore brings the stored files back and the next deploy writes them again', async () => {
  const { exportDataArchive, importDataArchive } = await import('../server/services/configBackup.js');
  const count = () => getDb().prepare('SELECT COUNT(*) n FROM app_env_files WHERE app_id = ?').get(app.id).n;
  assert.equal(count(), 6);
  const data = await exportDataArchive({ version: '2.76.0' });
  getDb().prepare('DELETE FROM app_env_files WHERE app_id = ?').run(app.id);
  assert.equal(count(), 0);
  await importDataArchive(data.path, { restoreEnv: false });
  initDb();
  db = getDb();
  assert.equal(count(), 6);
  const { ctx, log } = await deploy(app.id, 'sandbox');
  assert.ok(ctx, log.slice(-2000));
  assert.equal(readFileSync(join(ctx, '.env'), 'utf8'), SB_ENV);
});

test('deleting the app removes its stored files (ON DELETE CASCADE)', () => {
  const id = makeApp('cascade');
  const [enc] = store.encryptEnvFiles([{ rel_path: '.env', mode: 0o600, bytes: 3, content: Buffer.from('x=1') }]);
  store.storeEnvFiles(db, id, 'production', [enc]);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM app_env_files WHERE app_id = ?').get(id).n, 1);
  db.prepare('DELETE FROM apps WHERE id = ?').run(id);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM app_env_files WHERE app_id = ?').get(id).n, 0);
});

test('a production release left by promote (.env -> shared/.env.production) converts without capturing that file', async () => {
  const id = makeApp('promoted');
  const shared = join(ROOT, 'apps', 'promoted', 'production', 'shared');
  mkdirSync(shared, { recursive: true });
  writeFileSync(join(shared, '.env.production'), 'FROM_APPCRANE=VALUEMARK-shared\nPORT=1\n');
  const dir = release('promoted', 'production', '5-promote', { ...BASE, 'server.js': '1\n', '.env': { symlink: join(shared, '.env.production') } });
  live(id, 'production', dir, A64);
  const r = await uc.convertOneApp(db, appRow(id), { appTimeoutMs: 60000 });
  assert.equal(r.status, 'converted', JSON.stringify(r));
  assert.equal(db.prepare('SELECT COUNT(*) n FROM app_env_files WHERE app_id = ?').get(id).n, 0);
  const warnings = JSON.parse(db.prepare('SELECT warnings_json FROM upload_conversions WHERE app_id = ?').get(id).warnings_json);
  assert.ok(warnings.some((w) => w.path === '.env' && w.reason === 'env_symlink_outside_release'));
  assert.ok(warnings.some((w) => w.path === '.env' && w.reason === 'symlink_values_not_imported'));
  assert.equal(db.prepare('SELECT COUNT(*) n FROM env_vars WHERE app_id = ?').get(id).n, 0);
});

test('a .env file over 1 MiB cannot be kept: the app is skipped, nothing stored', async () => {
  const id = makeApp('bigenv');
  live(id, 'production', release('bigenv', 'production', '1-upload', { ...BASE, 'server.js': '1\n', 'web/.env': Buffer.alloc(1024 * 1024 + 1, 65) }), A64);
  const r = await uc.convertOneApp(db, appRow(id), { appTimeoutMs: 60000 });
  assert.equal(r.status, 'skipped');
  assert.equal(r.error_code, 'env_file_too_large');
  assert.equal(appRow(id).source_type, 'upload');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM app_env_files WHERE app_id = ?').get(id).n, 0);
  assert.ok(!existsSync(lg.repoPath('bigenv')));
});

// ---------------------------------------------------------------------------
// Layering env vars onto the stored files at deploy
// ---------------------------------------------------------------------------

const { encrypt } = await import('../server/services/encryption.js');
const { parseDotenv } = await import('../server/services/dotenvParse.js');
const setVar = (id, env, key, value) => db.prepare(`
  INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, ?, ?, ?)
  ON CONFLICT(app_id, env, key) DO UPDATE SET value_encrypted = excluded.value_encrypted
`).run(id, env, key, encrypt(value));
const delVar = (id, env, key) => db.prepare('DELETE FROM env_vars WHERE app_id = ? AND env = ? AND key = ?').run(id, env, key);
const storedRows = (id) => JSON.stringify(db.prepare('SELECT env, rel_path, mode, bytes, content_encrypted, updated_at FROM app_env_files WHERE app_id = ? ORDER BY env, rel_path').all(id));
const L = {
  ROOT: '# base config\n\nexport API_URL=http://base.example.com # base\nSECRET="old-secret"\nKEEP=file-only\nMULTI="line1\nline2" # multi\nDUP=a\nDUP=b\n',
  PROD: 'API_URL=http://prod-file.example.com\nPROD_ONLY=from-file\n',
  WEB: '# frontend\nVITE_API_URL=http://web-file.example.com\nAPI_URL=http://nested.example.com\n',
  EXAMPLE: 'API_URL=\nSECRET=\n',
  SB: 'API_URL=http://sb-base.example.com\n',
};
const layered = {};

test('layering: first deploy after conversion — the boot import already collapsed .env + .env.production and duplicates into env vars, so the root .env takes those values', async () => {
  layered.id = makeApp('layered');
  live(layered.id, 'production', release('layered', 'production', '1-upload', {
    ...BASE, 'server.js': '1\n',
    '.env': { content: L.ROOT, mode: 0o600 }, '.env.production': L.PROD, 'web/.env': { content: L.WEB, mode: 0o640 }, '.env.example': L.EXAMPLE,
  }), A64);
  live(layered.id, 'sandbox', release('layered', 'sandbox', '2-upload', { ...BASE, 'server.js': '2\n', '.env': L.SB }), B64);
  assert.equal((await uc.convertOneApp(db, appRow(layered.id), { appTimeoutMs: 60000 })).status, 'converted');
  const { ctx, log } = await deploy(layered.id, 'production');
  assert.ok(ctx, log.slice(-1500));
  // Measured interaction with the boot import (kept by the owner): production's API_URL var was
  // imported from .env overridden by .env.production, and DUP from the last duplicate, so
  // the base .env is rewritten on these two lines even though nobody edited a variable.
  assert.equal(readFileSync(join(ctx, '.env'), 'utf8'), L.ROOT.replace('export API_URL=http://base.example.com # base', 'export API_URL=http://prod-file.example.com # base').replace('DUP=a\n', 'DUP=b\n'));
  assert.match(log, /\.env \(overridden: API_URL, DUP\)/);
  assert.equal(readFileSync(join(ctx, '.env.production'), 'utf8'), L.PROD);
  assert.equal(readFileSync(join(ctx, 'web/.env'), 'utf8'), L.WEB.replace('API_URL=http://nested.example.com', 'API_URL=http://prod-file.example.com'), 'a nested loadable file is overridden by the same imported var');
  assert.match(log, /web\/\.env \(overridden: API_URL\)/);
});

test('layering: override root, .env.production and nested; append to root only; example untouched; bytes kept; names only in the log', async () => {
  const id = layered.id;
  const API = 'https://api.example.com/v2 # not a comment';
  const SECRET = "new 'secret' $HOME `x`\"";
  setVar(id, 'production', 'API_URL', API);
  setVar(id, 'production', 'SECRET', SECRET);
  setVar(id, 'production', 'MULTI', 'single');
  setVar(id, 'production', 'DUP', 'both');
  setVar(id, 'production', 'NEW_VAR', 'appended value\nwith newline');
  setVar(id, 'production', 'ANOTHER', 'plain');
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'production', 'BROKEN', 'not-a-ciphertext')").run(id);
  setVar(id, 'sandbox', 'API_URL', 'https://sandbox-only.example.com');
  setVar(id, 'sandbox', 'SB_NEW', 'sandbox-appended');
  const before = storedRows(id);

  const { ctx, log } = await deploy(id, 'production');
  assert.ok(ctx, log.slice(-1500));
  const root = readFileSync(join(ctx, '.env'), 'utf8');
  assert.equal(root,
    '# base config\n\nexport API_URL=\'https://api.example.com/v2 # not a comment\' # base\n' +
    `SECRET="new 'secret' $HOME \`x\`\\"" \n`.slice(0, 0) + root.split('\n')[3] + '\n' +
    'KEEP=file-only\nMULTI=single # multi\nDUP=both\nDUP=both\n' +
    "# Added by AppCrane from this app's environment variables\nANOTHER=plain\nNEW_VAR='appended value\nwith newline'\n");
  const rootVals = parseDotenv(root).values;
  assert.equal(rootVals.get('API_URL'), API);
  assert.equal(rootVals.get('KEEP'), 'file-only');
  assert.equal(rootVals.get('MULTI'), 'single');
  assert.equal(rootVals.get('NEW_VAR'), 'appended value\nwith newline');
  assert.equal(rootVals.get('PROD_ONLY'), undefined, 'PROD_ONLY is defined by root .env.production, so it is not appended');
  assert.equal(root.split('\n')[3], 'SECRET="old-secret"', 'a value with all three quote characters has no exact dotenv form: line left as stored');
  assert.equal(readFileSync(join(ctx, '.env.production'), 'utf8'), "API_URL='https://api.example.com/v2 # not a comment'\nPROD_ONLY=from-file\n");
  const web = readFileSync(join(ctx, 'web/.env'), 'utf8');
  assert.equal(web, "# frontend\nVITE_API_URL=http://web-file.example.com\nAPI_URL='https://api.example.com/v2 # not a comment'\n");
  assert.doesNotMatch(web, /NEW_VAR|ANOTHER|SECRET/, 'a nested file is never appended to');
  assert.equal(readFileSync(join(ctx, '.env.example'), 'utf8'), L.EXAMPLE);
  assert.equal((statSync(join(ctx, '.env')).mode & 0o777).toString(8), '600');
  assert.equal((statSync(join(ctx, 'web/.env')).mode & 0o777).toString(8), '640');
  assert.doesNotMatch(root + web, /sandbox-only|sandbox-appended|SB_NEW/, 'never the other environment\'s vars');

  assert.match(log, /\.env \(overridden: API_URL, MULTI, DUP; appended: ANOTHER, NEW_VAR; not written, no exact dotenv quoting: SECRET\)/);
  assert.match(log, /\.env\.production \(overridden: API_URL\)/);
  assert.match(log, /web\/\.env \(overridden: API_URL\)/);
  assert.match(log, /Env vars not layered \(could not decrypt\): BROKEN/);
  for (const v of ['api.example.com/v2', 'appended value', 'plain', 'old-secret', 'file-only', "'secret'", 'sandbox-only']) {
    assert.ok(!log.includes(v), `value fragment ${JSON.stringify(v)} in the deploy log`);
  }
  assert.equal(storedRows(id), before, 'app_env_files is never written by a deploy');
  delVar(id, 'production', 'BROKEN');
  layered.prodRoot = root;
});

test('layering: sandbox gets sandbox\'s vars on sandbox\'s file only', async () => {
  const { ctx, log } = await deploy(layered.id, 'sandbox');
  assert.ok(ctx, log.slice(-1500));
  assert.equal(readFileSync(join(ctx, '.env'), 'utf8'), "API_URL=https://sandbox-only.example.com\n# Added by AppCrane from this app's environment variables\nSB_NEW=sandbox-appended\n");
  assert.ok(!existsSync(join(ctx, 'web/.env')));
  assert.ok(!existsSync(join(ctx, '.env.production')));
});

test('layering: deleting env vars falls back to the file\'s own value and removes appended lines', async () => {
  const id = layered.id;
  for (const k of ['API_URL', 'SECRET', 'MULTI', 'DUP', 'NEW_VAR', 'ANOTHER']) delVar(id, 'production', k);
  const { ctx, log } = await deploy(id, 'production');
  assert.ok(ctx, log.slice(-1500));
  const root = readFileSync(join(ctx, '.env'), 'utf8');
  assert.equal(parseDotenv(root).values.get('SECRET'), 'old-secret');
  assert.doesNotMatch(root, /NEW_VAR|ANOTHER|Added by AppCrane/);
  assert.match(root, /^export API_URL=http:\/\/base\.example\.com # base$/m);
  assert.match(root, /^MULTI="line1\nline2" # multi$/m);
  assert.equal(readFileSync(join(ctx, '.env.production'), 'utf8'), L.PROD);
  assert.equal(readFileSync(join(ctx, 'web/.env'), 'utf8'), L.WEB);
});

test('layering: a root .env is created (0600) only for an app that has stored files; an app with none gets no .env', async () => {
  const id = makeApp('nested-only');
  live(id, 'production', release('nested-only', 'production', '1-upload', { ...BASE, 'server.js': '1\n', 'web/.env': 'VITE_X=1\n' }), A64);
  assert.equal((await uc.convertOneApp(db, appRow(id), { appTimeoutMs: 60000 })).status, 'converted');
  setVar(id, 'production', 'BACKEND_SECRET', 'backend-only');
  const { ctx, log } = await deploy(id, 'production');
  assert.ok(ctx, log.slice(-1500));
  assert.equal(readFileSync(join(ctx, '.env'), 'utf8'), "# Added by AppCrane from this app's environment variables\nBACKEND_SECRET=backend-only\n");
  assert.equal((statSync(join(ctx, '.env')).mode & 0o777).toString(8), '600');
  assert.equal(readFileSync(join(ctx, 'web/.env'), 'utf8'), 'VITE_X=1\n');
  assert.match(log, /\.env \(created; appended: BACKEND_SECRET\)/);

  const bare = makeApp('no-env-files');
  live(bare, 'production', release('no-env-files', 'production', '1-upload', { ...BASE, 'server.js': '1\n' }), A64);
  assert.equal((await uc.convertOneApp(db, appRow(bare), { appTimeoutMs: 60000 })).status, 'converted');
  setVar(bare, 'production', 'SOMETHING', 'x');
  const r = await deploy(bare, 'production');
  assert.ok(r.ctx, r.log.slice(-1500));
  assert.ok(!existsSync(join(r.ctx, '.env')), 'no stored files: nothing is written');
  assert.doesNotMatch(r.log, /Restored \d+ stored \.env/);
});
