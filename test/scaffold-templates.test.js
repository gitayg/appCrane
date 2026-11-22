import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { randomBytes } from 'crypto';
import { fileURLToPath } from 'url';
import express from 'express';

// Golden-path scaffold templates (templates/scaffold/*) and the `template`
// argument of appcrane_create_managed_app.
//
// What is real: the templates' files, git (read back independently of the
// module under test), the MCP JSON-RPC route over HTTP, the release check, the
// manifest validators, the Dockerfile generator/validator, the secrets scan,
// lockfile parsing, appcrane-tenant's signer, and the static-site template's
// own test suite run with npm. What is not: OSV (the release check's
// dependency scan is given the real parsed lockfiles but no network query).

const ROOT = mkdtempSync(join(tmpdir(), 'crane-scaffold-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug', 'error']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const st = await import('../server/services/scaffoldTemplates.js');
const rc = await import('../server/services/releaseCheck.js');
const { reviewIntake } = await import('../server/services/appIntake.js');
const { findLockfiles, parseLockfile } = await import('../server/services/appScan.js');
const { parseManifestDatabase } = await import('../server/services/manifestDatabase.js');
const { parseAccessRules } = await import('../server/services/accessRules.js');
const { parseAppMcp } = await import('../server/services/appMcp/manifest.js');
const { validateDockerfile } = await import('../server/services/dockerfileValidator.js');
const { ensureDockerfile } = await import('../server/services/dockerfileGen.js');
const { scanTreeForSecrets } = await import('../server/services/releaseSecretScan.js');
const { signIdentityV2: tenantSignV2 } = await import('../packages/tenant/index.js');
const lg = await import('../server/services/localGit.js');

const IDS = ['node-react', 'python-fastapi', 'static-site'];
const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');

function scaffold(id, slug, name = `Demo ${slug}`) {
  const dir = mkdtempSync(join(ROOT, `tree-${id}-`));
  for (const f of st.renderScaffoldTemplate(id, { slug, name })) {
    mkdirSync(dirname(join(dir, f.path)), { recursive: true });
    writeFileSync(join(dir, f.path), f.content);
  }
  return dir;
}

// ---- users and the MCP route over HTTP ------------------------------------

function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(name, `${name}@t.test`, role, hashApiKey(key), 'human').lastInsertRowid;
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
}
const admin = mkUser('sc-admin', 'platform_admin');
const alice = mkUser('sc-alice', 'user');
const bob = mkUser('sc-bob', 'user');

const mcpRouter = (await import('../server/routes/mcp.js')).default;
const httpApp = express();
httpApp.use(express.json({ limit: '5mb' }));
httpApp.use('/api/mcp', mcpRouter);
httpApp.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message, code: err.code }));
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  server.closeAllConnections?.();
  server.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  rmSync(ROOT, { recursive: true, force: true });
});

async function rpc(user, method, params) {
  const res = await fetch(`${BASE}/api/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': user.key },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return res.json();
}
/** { ok, data } or { ok: false, error } for one tools/call. */
async function callCreate(user, args) {
  const body = await rpc(user, 'tools/call', { name: 'appcrane_create_managed_app', arguments: args });
  if (body.error) return { ok: false, error: body.error.message };
  const text = body.result?.content?.[0]?.text ?? '';
  if (body.result?.isError) return { ok: false, error: text };
  return { ok: true, data: JSON.parse(text) };
}

const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const git = (slug, args) => execFileSync('git', [`--git-dir=${lg.repoPath(slug)}`, ...args], { env: CLEAN_ENV }).toString('utf8');

// ---- rendering --------------------------------------------------------------

test('every template renders with slug and name filled in and no placeholder left', () => {
  assert.deepEqual([...st.SCAFFOLD_TEMPLATE_IDS], IDS);
  assert.deepEqual(st.listScaffoldTemplates().map((t) => t.id), IDS);
  for (const id of IDS) {
    const files = st.renderScaffoldTemplate(id, { slug: 'acme-tool', name: 'Acme "Tool" <x>' });
    const paths = files.map((f) => f.path);
    for (const must of ['deployhub.json', 'README.md', 'CLAUDE.md', 'env.example']) assert.ok(paths.includes(must), `${id} lacks ${must}`);
    assert.ok(!paths.includes('template.json'), `${id} ships its template.json`);
    assert.ok(!paths.some((p) => p.split('/').pop().toLowerCase().startsWith('.env')), `${id} has a .env file`);
    for (const f of files) assert.doesNotMatch(f.content, /__APP_(SLUG|NAME)__/, `${id}:${f.path} still has a placeholder`);
    const manifest = JSON.parse(files.find((f) => f.path === 'deployhub.json').content);
    assert.equal(manifest.name, 'Acme "Tool" <x>', `${id}: a quote in the name broke or changed deployhub.json`);
    const claude = files.find((f) => f.path === 'CLAUDE.md').content;
    assert.match(claude, /acme-tool/);
    assert.match(claude, /verif/i);
  }
  const pkg = JSON.parse(st.renderScaffoldTemplate('node-react', { slug: 'acme-tool' }).find((f) => f.path === 'package.json').content);
  assert.equal(pkg.name, 'acme-tool');
  assert.equal(pkg.description, 'acme-tool', 'an absent name falls back to the slug');
});

test('render refuses an unknown template and a bad slug', () => {
  assert.throws(() => st.renderScaffoldTemplate('rails', { slug: 'ok' }), /unknown template/);
  assert.throws(() => st.renderScaffoldTemplate('node-react', { slug: '../x' }), /slug/);
  assert.throws(() => st.assertScaffoldTemplateId('nope'), /template must be one of/);
  st.assertScaffoldTemplateId(undefined);
});

test('env.example lists names only, no values', () => {
  for (const id of IDS) {
    const text = st.renderScaffoldTemplate(id, { slug: 'x' }).find((f) => f.path === 'env.example').content;
    const assignments = text.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
    assert.ok(assignments.length >= 2, id);
    for (const l of assignments) assert.match(l, /^[A-Z_][A-Z0-9_]*=$/, `${id}: "${l}" carries a value`);
  }
});

// ---- identity contract -------------------------------------------------------

test('the Node templates\' identity module accepts appcrane-tenant\'s signature and refuses forgeries', async () => {
  const a = readFileSync(join(REPO, 'templates/scaffold/node-react/server/identity.js'), 'utf8');
  const b = readFileSync(join(REPO, 'templates/scaffold/static-site/server/identity.js'), 'utf8');
  assert.equal(a, b, 'the two Node templates carry different identity.js copies');
  const { verifyRequest } = await import('../templates/scaffold/node-react/server/identity.js');
  const secret = randomBytes(32).toString('base64url');
  const ts = Math.floor(Date.now() / 1000);
  const H = {
    'X-AppCrane-User': 'p@t.test', 'X-AppCrane-User-Id': '9', 'X-AppCrane-User-Email': 'p@t.test',
    'X-AppCrane-User-Name': encodeURIComponent('Pé Q'), 'X-AppCrane-User-Role': 'user', 'X-AppCrane-App-Role': 'owner',
    'X-AppCrane-Is-Admin': '1', 'X-AppCrane-App-Roles': 'approver', 'X-AppCrane-Auth-Via': 'app-key',
  };
  const sig = tenantSignV2(secret, ts, (n) => H[n]);
  const lower = Object.fromEntries(Object.entries(H).map(([k, v]) => [k.toLowerCase(), v]));
  const req = { headers: { ...lower, 'x-appcrane-identity-ts': String(ts), 'x-appcrane-identity-sig-v2': sig } };
  const ok = verifyRequest(req, { secret });
  assert.equal(ok.ok, true, ok.message);
  assert.equal(ok.identity.appRole, 'owner');
  assert.equal(ok.identity.authVia, 'app-key');
  assert.equal(ok.identity.name, 'Pé Q');
  assert.equal(verifyRequest({ headers: { ...req.headers, 'x-appcrane-app-role': 'admin' } }, { secret }).code, 'IDENTITY_FORGED');
  assert.equal(verifyRequest({ headers: lower }, { secret }).code, 'IDENTITY_UNSIGNED');
  assert.equal(verifyRequest(req, { secret: randomBytes(32).toString('base64url') }).code, 'IDENTITY_FORGED');
});

test('every template\'s known-answer vector is what appcrane-tenant signs', async () => {
  const H = {
    'X-AppCrane-User': 'kat@example.test', 'X-AppCrane-User-Id': '7', 'X-AppCrane-User-Email': 'kat@example.test',
    'X-AppCrane-User-Name': 'K%C3%A4t%20Tester', 'X-AppCrane-User-Role': 'user', 'X-AppCrane-App-Role': 'admin',
    'X-AppCrane-Is-Admin': '1', 'X-AppCrane-App-Roles': 'approver,auditor', 'X-AppCrane-Auth-Via': 'app-key',
  };
  const full = tenantSignV2('known-answer-only', 1700000000, (n) => H[n]);
  const short = tenantSignV2('known-answer-only', 1700000000, (n) => (n === 'X-AppCrane-App-Roles' || n === 'X-AppCrane-Auth-Via' ? undefined : H[n]));
  for (const f of ['node-react/test/identity.test.js', 'static-site/test/identity.test.js', 'python-fastapi/tests/test_identity.py']) {
    const text = readFileSync(join(REPO, 'templates/scaffold', f), 'utf8');
    assert.ok(text.includes(full) && text.includes(short), `${f} does not pin AppCrane's real signatures`);
  }
  const { signIdentityV3: tenantSignV3 } = await import('../packages/tenant/index.js');
  const v3 = tenantSignV3('known-answer-only', 1700000000, (n) => ({ ...H, 'X-AppCrane-Auth-Time': '1699999000', 'X-AppCrane-Auth-Mfa': 'totp' })[n]);
  for (const f of ['node-react/test/identity.test.js', 'static-site/test/identity.test.js', 'python-fastapi/tests/test_identity.py']) {
    assert.ok(readFileSync(join(REPO, 'templates/scaffold', f), 'utf8').includes(v3), `${f} does not pin AppCrane's real v3 signature`);
  }
});

// ---- deployability -----------------------------------------------------------

test('each deployhub.json passes AppCrane\'s own manifest validators', () => {
  for (const id of IDS) {
    const m = JSON.parse(st.renderScaffoldTemplate(id, { slug: 'v' }).find((f) => f.path === 'deployhub.json').content);
    assert.equal(m.be.health, '/api/health', id);
    if (m.database) assert.equal(parseManifestDatabase(m.database).engine, 'postgres');
    assert.ok(parseAccessRules(m.access).length >= 1, `${id} declares no path rule`);
    if (m.mcp) assert.equal(parseAppMcp(m.mcp).tools.length, 2);
  }
  assert.equal(JSON.parse(st.renderScaffoldTemplate('static-site', { slug: 'v' }).find((f) => f.path === 'deployhub.json').content).database, undefined);
});

test('the Python Dockerfile passes the deploy validator with no warning; the Node ones get a generated Dockerfile that does too', () => {
  const py = validateDockerfile(scaffold('python-fastapi', 'pyv'), { expectedPort: 3000 });
  assert.deepEqual(py, { valid: true, errors: [], warnings: [] });
  for (const id of ['node-react', 'static-site']) {
    const dir = scaffold(id, 'nodev');
    const manifest = JSON.parse(readFileSync(join(dir, 'deployhub.json'), 'utf8'));
    const gen = ensureDockerfile({ releaseDir: dir, manifest, appBasePath: '/nodev/', craneUrl: 'http://crane.test', craneInternalUrl: 'http://crane.test', slug: 'nodev' });
    assert.equal(gen.userProvided, undefined, `${id} should not ship its own Dockerfile`);
    const df = readFileSync(join(dir, 'Dockerfile'), 'utf8');
    assert.match(df, /CMD \["node","server\/index\.js"\]/);
    if (id === 'node-react') assert.match(df, /cd client && .*npm run build/);
    assert.equal(validateDockerfile(dir, { expectedPort: 3000 }).valid, true);
  }
});

// ---- release check against a fresh scaffold --------------------------------

async function releaseCheckOf(app, dir) {
  rc._setReleaseCheckDepsForTests({
    scanTree: async (tree) => {
      const lockfiles = findLockfiles(tree);
      const packages = lockfiles.flatMap((m) => parseLockfile(m.path, m.ecosystem, m.entry));
      return lockfiles.length ? { status: 'ok', findings_json: null, packages: packages.length } : { status: 'skipped', error: 'no recognised manifest in the release' };
    },
  });
  return rc.runReleaseCheck({ db, app, trigger: 'deploy', releaseDir: dir });
}

test('a fresh scaffold of every template passes the release check (internal, and restricted once intake is approved)', async () => {
  for (const id of IDS) {
    const slug = `rc-${id}`;
    const made = await callCreate(admin, { name: `RC ${id}`, slug });
    assert.equal(made.ok, true, made.error);
    const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
    const dir = scaffold(id, slug);

    const r = await releaseCheckOf(app, dir);
    const by = Object.fromEntries(r.checks.map((c) => [c.id, c]));
    assert.equal(r.blocked, false, `${id}: ${JSON.stringify(r.checks)}`);
    assert.deepEqual(r.checks.filter((c) => c.status === 'fail'), [], id);
    assert.equal(by.secrets.status, 'pass', `${id}: ${by.secrets.reasons}`);
    assert.equal(by.sso_gate.status, 'pass');
    assert.equal(by.sandbox_health.status, 'warn', 'a fresh app has no sandbox release yet, which only warns on deploy');

    db.prepare("UPDATE app_intake SET data_classification = 'restricted' WHERE app_id = ?").run(app.id);
    reviewIntake(db, app, { decision: 'approve' }, admin.row);
    const strict = await releaseCheckOf(app, dir);
    const sby = Object.fromEntries(strict.checks.map((c) => [c.id, c]));
    assert.equal(strict.mode, 'enforce');
    assert.equal(sby.access_rules.status, 'pass', `${id}: ${sby.access_rules.reasons}`);
    assert.equal(strict.blocked, false, `${id}: ${JSON.stringify(strict.checks.filter((c) => c.status !== 'pass'))}`);
  }
  const nodeLocks = findLockfiles(scaffold('node-react', 'locks')).map((m) => m.path.split('/').slice(-2).join('/'));
  assert.equal(nodeLocks.length, 2, `node-react should ship both lockfiles, found ${nodeLocks}`);
});

test('AppCrane\'s identity-v2 upgrade scan sees every template as already checking the v2 signature', async () => {
  const { scanRelease } = await import('../server/services/identityUpgradeRequests.js');
  for (const id of IDS) {
    const r = await scanRelease(scaffold(id, `v2-${id}`));
    assert.ok(r.reads.length > 0, `${id}: the scan found no identity read, so this proves nothing`);
    assert.equal(r.checksV2, true, `${id} would be filed an identity-v2 upgrade request`);
  }
});

test('the secrets scan would catch a key added to a scaffold (the release-check test is not blind)', () => {
  const dir = scaffold('node-react', 'leaky');
  assert.deepEqual(scanTreeForSecrets(dir).findings, []);
  writeFileSync(join(dir, 'server', 'config.js'), `export const awsKey = '${'AKIA'}${'Q'.repeat(4)}${'7'.repeat(12)}';\n`);
  assert.equal(scanTreeForSecrets(dir).findings.length, 1);
});

// ---- the template's own suite -------------------------------------------------

test('the static-site scaffold\'s own test suite passes when run with npm', () => {
  const dir = scaffold('static-site', 'own-suite');
  const env = { ...process.env, APPCRANE_IDENTITY_SECRET: '' };
  delete env.NODE_TEST_CONTEXT;
  const r = spawnSync('npm', ['test'], { cwd: dir, encoding: 'utf8', env });
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /# fail 0/);
  assert.match(r.stdout, /# pass [1-9]/);
});

// ---- creation path ------------------------------------------------------------

test('tools/list advertises template with exactly the server\'s template ids', async () => {
  const body = await rpc(admin, 'tools/list', {});
  const tool = body.result.tools.find((t) => t.name === 'appcrane_create_managed_app');
  assert.deepEqual(tool.inputSchema.properties.template.enum, IDS);
});

test('the dashboard picker offers exactly the server\'s template ids', () => {
  const tsx = readFileSync(join(REPO, 'studio-web/src/components/ScaffoldTemplatePicker.tsx'), 'utf8');
  const ids = [...tsx.matchAll(/\{ id: '([a-z-]+)', label:/g)].map((m) => m[1]);
  assert.deepEqual(ids, IDS);
  // The phrase the picker replaces must still be in the + New App prompt, or a
  // chosen template would only be appended after the agent was told to pick a stack.
  const phrase = new RegExp(/const STACK_PHRASE = \/(.+)\/\n/.exec(tsx)[1]);
  const page = readFileSync(join(REPO, 'studio-web/src/pages/Applications.tsx'), 'utf8');
  assert.match(page, phrase);
});

test('create with a template seeds the repo in one commit, starts no deploy, and records the pushed sha', async () => {
  const slug = 'seeded-node';
  const r = await callCreate(admin, { name: 'Seeded "Node"', slug, template: 'node-react' });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.data.template.seeded, true, JSON.stringify(r.data.template));
  assert.match(r.data.next, /node-react template is committed/);

  const expected = st.renderScaffoldTemplate('node-react', { slug, name: 'Seeded "Node"' });
  const tree = git(slug, ['ls-tree', '-r', '--name-only', 'refs/heads/main']).trim().split('\n').sort();
  assert.deepEqual(tree, expected.map((f) => f.path).sort());
  for (const f of expected) assert.equal(git(slug, ['show', `refs/heads/main:${f.path}`]), f.content, f.path);
  const tip = git(slug, ['rev-parse', 'refs/heads/main']).trim();
  assert.equal(r.data.template.commit, tip);
  assert.match(git(slug, ['log', '-1', '--format=%s', 'refs/heads/main']), /scaffold: node-react template/);
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  assert.equal(app.last_managed_push_sha, tip);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM deployments WHERE app_id = ?').get(app.id).n, 0);
});

test('create without a template is unchanged: an empty repo and no template field', async () => {
  const r = await callCreate(admin, { name: 'Plain', slug: 'plain-app' });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.data.template, undefined);
  assert.deepEqual(git('plain-app', ['ls-tree', '-r', '--name-only', 'refs/heads/main']).trim().split('\n'), ['README.md']);
});

test('an unknown template is refused before anything is created', async () => {
  const r = await callCreate(admin, { name: 'Bad', slug: 'bad-template', template: 'rails' });
  assert.equal(r.ok, false);
  assert.match(r.error, /template/);
  assert.equal(db.prepare('SELECT 1 FROM apps WHERE slug = ?').get('bad-template'), undefined);
  assert.equal(lg.localRepoExists('bad-template'), false);
});

test('platform role rules hold: a plain user without create_app is refused, with it they create and own the app', async () => {
  const denied = await callCreate(alice, { name: 'A', slug: 'alice-app', template: 'static-site' });
  assert.equal(denied.ok, false);
  assert.equal(db.prepare('SELECT 1 FROM apps WHERE slug = ?').get('alice-app'), undefined);

  db.prepare("UPDATE role_permissions SET granted = 1 WHERE permission = 'platform.create_app' AND role = 'user'").run();
  const made = await callCreate(alice, { name: 'A', slug: 'alice-app', template: 'static-site' });
  assert.equal(made.ok, true, made.error);
  assert.equal(made.data.template.seeded, true);
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get('alice-app');
  assert.equal(db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, alice.id).app_role, 'owner');
});

test('repair with a template: another user is refused, the owner gets the template seeded into the re-provisioned repo', async () => {
  rmSync(lg.repoPath('alice-app'), { recursive: true, force: true });
  assert.equal(lg.localRepoExists('alice-app'), false);

  const other = await callCreate(bob, { name: 'A', slug: 'alice-app', template: 'node-react' });
  assert.equal(other.ok, false);
  assert.match(other.error, /not its owner/);
  assert.equal(lg.localRepoExists('alice-app'), false, 'a refused repair must not create the repo');

  const fixed = await callCreate(alice, { name: 'A', slug: 'alice-app', template: 'python-fastapi' });
  assert.equal(fixed.ok, true, fixed.error);
  assert.equal(fixed.data.repaired, true);
  assert.equal(fixed.data.template.seeded, true, JSON.stringify(fixed.data.template));
  assert.ok(git('alice-app', ['ls-tree', '-r', '--name-only', 'refs/heads/main']).includes('app/identity.py'));
});
