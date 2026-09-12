import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

const execFileAsync = promisify(execFile);

// A redeploy that destroys data has to be acknowledged (v2.72.0).
//
// Every deploy is `docker rm -f` + create. The container's writable layer dies
// with it, and so does every image-declared VOLUME that AppCrane did not
// bind-mount: Docker parks those in ANONYMOUS volumes, `rm -f` (no -v) strands
// them, and the replacement container is given fresh empty ones. 22 catalogue
// apps had been losing state that way with nothing said anywhere.
//
// The property under test, stated once so every assertion below can be checked
// against it:
//
//   A deploy that would destroy state is REFUSED unless the caller said, in
//   that call, that it accepts the loss — and a deploy that would destroy
//   nothing is not gated at all.
//
// The second half is not a nicety. A warning that fires on the safe apps trains
// the click-through that defeats it on the app where it was true, so "an app
// that declares everything its image declares is NOT gated" is asserted as
// hard as the refusal is.
//
// EVIDENCE. The daemon facts this rests on were measured on this box before a
// line was written, and are re-measured by the LIVE section at the bottom
// against images built here rather than taken on faith:
//
//   image with `VOLUME /state`   -> .Config.Volumes = {"/state":{}}
//   same image, VOLUME removed   -> .Config.Volumes = null
//   container, no -v             -> .Mounts[0].Type = "volume", anonymous name
//   container, -v host:/state    -> .Mounts[0].Type = "bind"
//   `docker volume ls -q | wc -l` across create + `rm -f`: 163 -> 163 (stranded)
//   write /state/marker, rm -f, recreate, cat  -> No such file or directory
//
// Everything between the pure section and LIVE drives the REAL routes and the
// REAL MCP tools over a real socket, against a recording `docker` shim, because
// what is being asserted there is a refusal — and a refusal asserted against a
// mocked route is a refusal that can stop happening without anything going red.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-redeploy-guard-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const REAL_PATH = process.env.PATH;

let REAL_DOCKER = null;
try {
  REAL_DOCKER = execFileSync('/usr/bin/env', ['sh', '-c', 'command -v docker'], { encoding: 'utf8' }).trim() || null;
  if (REAL_DOCKER) {
    execFileSync(REAL_DOCKER, ['version', '--format', '{{.Server.Version}}'], { timeout: 15000, stdio: 'pipe' });
  }
} catch (_) {
  REAL_DOCKER = null;
}
const liveSkip = REAL_DOCKER ? false : 'no reachable Docker daemon on this host';

// ---------------------------------------------------------------------------
// A `docker` shim whose answers are set per-test
// ---------------------------------------------------------------------------
//
// It answers the two format templates redeployRisk.js asks for and nothing
// else, so a change that starts asking a THIRD question fails here loudly
// instead of silently reading an empty string as "no volumes".

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const RULES = join(process.env.DATA_DIR, 'docker-rules.json');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { readFileSync, existsSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'const rf = process.env.CRANE_TEST_DOCKER_RULES;\n' +
  'const r = rf && existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")) : {};\n' +
  'if (argv[0] === "inspect") {\n' +
  '  if (r.mode === "down") { process.stderr.write("Cannot connect to the Docker daemon\\n"); process.exit(1); }\n' +
  '  if (r.mode === "absent") { process.stderr.write("Error: No such object: " + argv[1] + "\\n"); process.exit(1); }\n' +
  '  const t = argv[argv.indexOf("--format") + 1];\n' +
  '  if (t === "{{json .Config.Volumes}}") { process.stdout.write((r.volumes || "null") + "\\n"); process.exit(0); }\n' +
  '  if (t === "{{json .Mounts}}") { process.stdout.write((r.mounts || "[]") + "\\n"); process.exit(0); }\n' +
  '  process.stderr.write("shim: unexpected inspect template " + JSON.stringify(t) + "\\n");\n' +
  '  process.exit(1);\n' +
  '}\n' +
  // `docker diff` is the third question the module asks (v2.72.0, writable
  // layer). The shim answers it explicitly rather than falling through to the
  // catch-all below, so that a test which forgets to set `diff` gets an empty
  // writable layer rather than an UNKNOWN verdict it did not ask for.
  'if (argv[0] === "diff") {\n' +
  '  if (r.mode === "down") { process.stderr.write("Cannot connect to the Docker daemon\\n"); process.exit(1); }\n' +
  '  if (r.diffFails) { process.stderr.write(r.diffFails + "\\n"); process.exit(1); }\n' +
  '  process.stdout.write(r.diff === undefined ? "" : r.diff);\n' +
  '  process.exit(0);\n' +
  '}\n' +
  'process.stderr.write("shim: docker " + argv[0] + " not available in this test\\n");\n' +
  'process.exit(1);\n',
  { mode: 0o755 },
);
process.env.CRANE_TEST_DOCKER_RULES = RULES;
const setDocker = (rules) => writeFileSync(RULES, JSON.stringify(rules));
const withShim = () => { process.env.PATH = `${SHIM_DIR}:${REAL_PATH}`; };
const withRealDocker = () => { process.env.PATH = REAL_PATH; };

setDocker({ mode: 'absent' });

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const risk = await import('../server/services/redeployRisk.js');
const { callTool } = await import('../server/services/mcpTools.js');

// ===========================================================================
// 1. Classification: which declared volume paths a bind is protecting
// ===========================================================================

describe('classifyVolumePaths', () => {
  test('an image VOLUME with no bind over it is at risk; one with a bind is not', () => {
    assert.deepEqual(
      risk.classifyVolumePaths({ imageVolumes: ['/config', '/var/lib/odoo'], bindDestinations: ['/data', '/config'] }),
      { atRisk: ['/var/lib/odoo'], persisted: ['/config'] },
    );
  });

  test('a bind covers the paths INSIDE it', () => {
    // Docker resolves nested mounts by mount order, so a bind at /data does
    // carry /data/db with it. Reporting /data/db as doomed would be a false
    // alarm, and false alarms are what this feature cannot afford.
    assert.deepEqual(
      risk.classifyVolumePaths({ imageVolumes: ['/data/db'], bindDestinations: ['/data'] }),
      { atRisk: [], persisted: ['/data/db'] },
    );
  });

  test('a bind does NOT cover a path that merely shares its prefix', () => {
    // '/dataset' starts with '/data' as a STRING and is a different directory.
    // Getting this wrong reports a doomed path as safe, which is the direction
    // that loses data.
    assert.deepEqual(
      risk.classifyVolumePaths({ imageVolumes: ['/dataset'], bindDestinations: ['/data'] }),
      { atRisk: ['/dataset'], persisted: [] },
    );
  });

  test('trailing slashes and dot segments are one path, not two', () => {
    assert.deepEqual(
      risk.classifyVolumePaths({ imageVolumes: ['/config/'], bindDestinations: ['/config/./'] }),
      { atRisk: [], persisted: ['/config'] },
    );
  });

  test('an image that declares nothing produces nothing at risk', () => {
    assert.deepEqual(
      risk.classifyVolumePaths({ imageVolumes: [], bindDestinations: ['/data'] }),
      { atRisk: [], persisted: [] },
    );
  });
});

test('containerNameFor still agrees with services/docker.js', () => {
  // docker.js does not export containerName(), so redeployRisk.js rebuilds the
  // string. A divergence would make every app look container-less and therefore
  // SAFE — the guard would vanish with every other test in this file still
  // green, which is the one failure mode a unit test here cannot catch.
  const src = readFileSync(new URL('../server/services/docker.js', import.meta.url), 'utf8');
  const m = src.match(/function containerName\(slug, env\) \{\s*return `([^`]+)`;/);
  assert.ok(m, 'could not find containerName() in server/services/docker.js — this test needs rewriting');
  const fromDocker = m[1].replace('${slug}', 'demo').replace('${env}', 'production');
  assert.equal(risk.containerNameFor('demo', 'production'), fromDocker);
});

// ===========================================================================
// 2. The verdict, including what "unknown" costs
// ===========================================================================

describe('assessRedeployRisk', () => {
  const app = { id: 1, slug: 'verdict-app' };
  const nodb = { prepare: () => ({ get: () => undefined }) };
  const wasLive = { prepare: () => ({ get: () => ({ 1: 1 }) }) };

  test('no container means nothing to lose', async () => {
    const v = await risk.assessRedeployRisk({ db: nodb, app, env: 'sandbox', inspect: async () => ({ present: false }) });
    assert.equal(v.at_risk, false);
    assert.equal(v.reason, 'no-container');
  });

  test('an app whose declared mounts cover every image VOLUME is NOT gated', async () => {
    const v = await risk.assessRedeployRisk({
      db: wasLive, app, env: 'production',
      inspect: async () => ({ present: true, imageVolumes: ['/config'], bindDestinations: ['/data', '/config'] }),
    });
    assert.equal(v.at_risk, false, 'a safe app must never be nagged — that is what trains the click-through');
    assert.deepEqual(v.persisted_paths, ['/config']);
  });

  test('an undeclared image VOLUME is at risk, and the verdict names it', async () => {
    const v = await risk.assessRedeployRisk({
      db: wasLive, app, env: 'production',
      inspect: async () => ({ present: true, imageVolumes: ['/config', '/var/lib/odoo'], bindDestinations: ['/data'] }),
    });
    assert.equal(v.at_risk, true);
    assert.deepEqual(v.at_risk_paths, ['/config', '/var/lib/odoo']);
    assert.deepEqual(v.always_persisted, ['/data']);
    // The summary is the ONLY channel an MCP error has, so it has to carry the
    // paths rather than a pointer to them.
    for (const p of ['/config', '/var/lib/odoo', '/data']) assert.ok(v.summary.includes(p), `summary omits ${p}`);
  });

  test('an unreadable daemon on an app that HAS been live is at risk, not safe', async () => {
    const v = await risk.assessRedeployRisk({
      db: wasLive, app, env: 'production',
      inspect: async () => ({ present: 'unknown', error: 'Cannot connect to the Docker daemon' }),
    });
    assert.equal(v.at_risk, true, 'unknown must never resolve to safe');
    assert.equal(v.unknown, true);
    assert.equal(v.reason, 'inspect-failed');
  });

  test('an unreadable daemon on an app that has NEVER been live is not at risk', async () => {
    // The narrowing that keeps the guard from firing on every app of a box
    // whose daemon is down: no deployment ever reached live, so no container
    // was ever created, so there is no container state to lose. A database
    // fact, and the only reason "unknown" is ever allowed to mean "safe".
    const v = await risk.assessRedeployRisk({
      db: nodb, app, env: 'production',
      inspect: async () => ({ present: 'unknown', error: 'docker: not found' }),
    });
    assert.equal(v.at_risk, false);
    assert.equal(v.reason, 'never-live');
  });

  test('an inspect that throws outright is unknown, not a crash', async () => {
    const v = await risk.assessRedeployRisk({
      db: wasLive, app, env: 'production',
      inspect: async () => { throw new Error('spawn ENOENT'); },
    });
    assert.equal(v.at_risk, true);
    assert.equal(v.unknown, true);
  });
});

// ===========================================================================
// 3. The REST route, over a real socket, through the real router
// ===========================================================================

describe('POST /api/apps/:slug/deploy/:env', () => {
  const KEY = generateApiKey('dhk_admin');
  let server;
  let BASE;
  let appRow;
  const SLUG = 'guard-rest-app';

  before(async () => {
    withShim();
    db.prepare(
      "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('G','g@x.io','platform_admin',?,1,'human')"
    ).run(hashApiKey(KEY));
    const id = db.prepare(
      "INSERT INTO apps (name, slug, slot, source_type, image_ref) VALUES ('Guard REST', ?, 71, 'image', 'bookstack:latest')"
    ).run(SLUG).lastInsertRowid;
    appRow = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
    // A previous LIVE deployment. Without one this app has never had a
    // container, and the guard would (correctly) let every deploy through.
    db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')").run(id);

    const api = express();
    api.use(express.json());
    api.use('/api/apps', (await import('../server/routes/deploy.js')).default);
    api.use((await import('../server/utils/errors.js')).errorHandler);
    server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
    BASE = `http://127.0.0.1:${server.address().port}`;
  });

  after(() => {
    withRealDocker();
    server?.closeAllConnections?.();
    server?.unref();
    server?.close();
  });

  const post = async (path, body) => {
    const r = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': KEY },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: r.status, body: await r.json() };
  };
  const get = async (path) => {
    const r = await fetch(`${BASE}${path}`, { headers: { 'X-API-Key': KEY } });
    return { status: r.status, body: await r.json() };
  };
  const deployCount = () => db.prepare(
    "SELECT COUNT(*) c FROM deployments WHERE app_id = ? AND env = 'production'"
  ).get(appRow.id).c;
  /** Clear whatever the previous case queued so the in-flight guard does not
   *  answer for the data-loss guard on the next one. */
  const resetDeployments = () => {
    db.prepare("DELETE FROM deployments WHERE app_id = ? AND env = 'production'").run(appRow.id);
    db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')").run(appRow.id);
  };

  test('an undeclared image VOLUME refuses the deploy and creates NO deployment row', async () => {
    setDocker({ mode: 'ok', volumes: '{"/config":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    resetDeployments();
    const before = deployCount();
    const r = await post(`/api/apps/${SLUG}/deploy/production`, {});
    assert.equal(r.status, 409, JSON.stringify(r.body));
    assert.equal(r.body.error.code, 'DATA_LOSS_NOT_ACKNOWLEDGED');
    assert.ok(r.body.error.message.includes('/config'), 'the refusal must name the path that dies');
    assert.ok(r.body.error.message.includes('acknowledge_data_loss'),
      'the refusal must name the parameter that unblocks it — an agent that has to guess will guess wrong');
    assert.deepEqual(r.body.error.risk.at_risk_paths, ['/config']);
    // The row matters: a refused deploy that still writes `pending` leaves the
    // app wedged behind its own in-flight guard.
    assert.equal(deployCount(), before, 'a refused deploy must not create a deployment row');
  });

  test('the same deploy proceeds when the loss is acknowledged', async () => {
    setDocker({ mode: 'ok', volumes: '{"/config":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    resetDeployments();
    const before = deployCount();
    const r = await post(`/api/apps/${SLUG}/deploy/production`, { acknowledge_data_loss: true });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(deployCount(), before + 1);
  });

  test('an acknowledgement that is not exactly true does not count', async () => {
    // 'false' is a non-empty string. A guard written as `if (!req.body.ack)`
    // would be satisfied by it.
    for (const value of ['false', 'no', 0, '', null, {}]) {
      setDocker({ mode: 'ok', volumes: '{"/config":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
      resetDeployments();
      const r = await post(`/api/apps/${SLUG}/deploy/production`, { acknowledge_data_loss: value });
      assert.equal(r.status, 409, `acknowledge_data_loss=${JSON.stringify(value)} must not unblock the deploy`);
    }
  });

  test('an app whose mounts cover its image VOLUMEs deploys with no acknowledgement at all', async () => {
    setDocker({
      mode: 'ok',
      volumes: '{"/config":{}}',
      mounts: '[{"Type":"bind","Destination":"/data"},{"Type":"bind","Destination":"/config"}]',
    });
    resetDeployments();
    const before = deployCount();
    const r = await post(`/api/apps/${SLUG}/deploy/production`, {});
    assert.equal(r.status, 200, `a safe app must not be gated: ${JSON.stringify(r.body)}`);
    assert.equal(deployCount(), before + 1);
  });

  test('a first deploy — no container — is not gated', async () => {
    setDocker({ mode: 'absent' });
    resetDeployments();
    const r = await post(`/api/apps/${SLUG}/deploy/production`, {});
    assert.equal(r.status, 200, JSON.stringify(r.body));
  });

  test('an unreadable daemon on an app that has been live is refused', async () => {
    setDocker({ mode: 'down' });
    resetDeployments();
    const r = await post(`/api/apps/${SLUG}/deploy/production`, {});
    assert.equal(r.status, 409, JSON.stringify(r.body));
    assert.equal(r.body.error.risk.unknown, true);
  });

  test('GET .../deploy/:env/risk answers with the same verdict the POST enforces', async () => {
    setDocker({ mode: 'ok', volumes: '{"/config":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    resetDeployments();
    const r = await get(`/api/apps/${SLUG}/deploy/production/risk`);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.risk.at_risk, true);
    assert.deepEqual(r.body.risk.at_risk_paths, ['/config']);
    assert.equal(r.body.risk.acknowledge_with, 'acknowledge_data_loss');
    // Side-effect free: the dashboard calls it on every deploy click.
    assert.equal(deployCount(), 1);
  });

  test('the risk endpoint refuses an anonymous caller', async () => {
    const r = await fetch(`${BASE}/api/apps/${SLUG}/deploy/production/risk`);
    assert.equal(r.status, 401);
  });

  // POST /deploy/upload reaches the same stopApp + startApp pair, so it
  // destroys the same container and has to be gated the same way. Asserted
  // against the REAL multipart route: the bytes are deliberately not a valid
  // archive, which is what makes the two outcomes distinguishable — 409 means
  // the guard refused before anything was unpacked, and 400
  // UPLOAD_DEPLOY_FAILED means the request got PAST the guard and died later on
  // the corrupt bundle. A test that only asserted "not 200" could not tell
  // those apart.
  const upload = async (fields = {}) => {
    const body = new FormData();
    body.set('env', 'production');
    for (const [k, v] of Object.entries(fields)) body.set(k, v);
    body.set('file', new Blob([Buffer.from('not really a zip')]), 'app.zip');
    const r = await fetch(`${BASE}/api/apps/${SLUG}/deploy/upload`, {
      method: 'POST', body, headers: { 'X-API-Key': KEY },
    });
    return { status: r.status, body: await r.json() };
  };

  test('an artifact upload is refused too when it would destroy state', async () => {
    setDocker({ mode: 'ok', volumes: '{"/config":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    resetDeployments();
    const r = await upload();
    assert.equal(r.status, 409, JSON.stringify(r.body));
    assert.equal(r.body.error.code, 'DATA_LOSS_NOT_ACKNOWLEDGED');
    assert.ok(r.body.error.message.includes('/config'));
  });

  test('an acknowledged artifact upload gets past the guard', async () => {
    setDocker({ mode: 'ok', volumes: '{"/config":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    resetDeployments();
    // A multipart field is a STRING, never a boolean — so 'true' has to be
    // accepted on this route while the JSON route gets a real boolean. Both
    // spellings go through one reader for exactly that reason.
    const r = await upload({ acknowledge_data_loss: 'true' });
    assert.equal(r.status, 400, JSON.stringify(r.body));
    assert.equal(r.body.error.code, 'UPLOAD_DEPLOY_FAILED',
      'the acknowledged upload must fail on the corrupt bundle, i.e. downstream of the guard');
  });
});

// ===========================================================================
// 4. The MCP surface — where most deploys on this platform actually come from
// ===========================================================================

describe('appcrane_deploy (MCP)', () => {
  const SLUG = 'guard-mcp-app';
  let user;
  let appId;

  before(() => {
    withShim();
    const uid = db.prepare(
      "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('M','m@x.io','platform_admin',?,1,'human')"
    ).run(hashApiKey(generateApiKey('dhk_admin'))).lastInsertRowid;
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(uid);
    appId = db.prepare(
      "INSERT INTO apps (name, slug, slot, source_type, image_ref) VALUES ('Guard MCP', ?, 72, 'image', 'odoo:19')"
    ).run(SLUG).lastInsertRowid;
  });

  after(() => { withRealDocker(); });

  const reset = () => {
    db.prepare("DELETE FROM deployments WHERE app_id = ? AND env = 'sandbox'").run(appId);
    db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'sandbox', 'live')").run(appId);
  };
  const count = () => db.prepare(
    "SELECT COUNT(*) c FROM deployments WHERE app_id = ? AND env = 'sandbox'"
  ).get(appId).c;

  test('the tool advertises acknowledge_data_loss, so an agent can find it', async () => {
    // getToolCatalog(), not the raw array: it is the shape the connector and
    // the /mcp page publish, so a parameter that survives here is a parameter
    // an agent can actually see.
    const { getToolCatalog } = await import('../server/services/mcpTools.js');
    const catalog = getToolCatalog();
    for (const name of ['appcrane_deploy', 'appcrane_deploy_artifact']) {
      const tool = catalog.find((t) => t.name === name);
      assert.ok(tool, `${name} is missing`);
      assert.equal(tool.inputSchema.properties.acknowledge_data_loss?.type, 'boolean',
        `${name} must declare the parameter — additionalProperties is false, so an undeclared one is unusable`);
      assert.ok(/data loss/i.test(tool.description),
        `${name}'s description must say the deploy can destroy data; the schema alone is not read as a warning`);
    }
  });

  test('a deploy that would strand an image VOLUME is refused, and the error names the paths', async () => {
    setDocker({ mode: 'ok', volumes: '{"/var/lib/odoo":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    reset();
    const before = count();
    await assert.rejects(
      () => callTool(user, 'appcrane_deploy', { slug: SLUG, env: 'sandbox' }),
      (e) => {
        assert.match(e.message, /DATA_LOSS_NOT_ACKNOWLEDGED/);
        assert.ok(e.message.includes('/var/lib/odoo'), `error does not name the path: ${e.message}`);
        assert.ok(e.message.includes('/data'), 'the error must say what survives too, not only what dies');
        assert.match(e.message, /acknowledge_data_loss=true/);
        return true;
      },
    );
    assert.equal(count(), before, 'a refused MCP deploy must not queue a deployment');
  });

  test('acknowledge_data_loss=true lets the same call through', async () => {
    setDocker({ mode: 'ok', volumes: '{"/var/lib/odoo":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    reset();
    const before = count();
    const out = await callTool(user, 'appcrane_deploy', { slug: SLUG, env: 'sandbox', acknowledge_data_loss: true });
    assert.equal(JSON.parse(out.content[0].text).status, 'pending');
    assert.equal(count(), before + 1);
  });

  test('a truthy-but-not-true acknowledgement does not count', async () => {
    setDocker({ mode: 'ok', volumes: '{"/var/lib/odoo":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    reset();
    await assert.rejects(
      () => callTool(user, 'appcrane_deploy', { slug: SLUG, env: 'sandbox', acknowledge_data_loss: 'true' }),
      /DATA_LOSS_NOT_ACKNOWLEDGED/,
    );
  });

  test('an app with nothing at risk is deployed without any acknowledgement', async () => {
    setDocker({ mode: 'ok', volumes: 'null', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    reset();
    const before = count();
    await callTool(user, 'appcrane_deploy', { slug: SLUG, env: 'sandbox' });
    assert.equal(count(), before + 1, 'a safe app must deploy on the first call');
  });

  // appcrane_deploy_artifact is the OTHER door an agent can push a release
  // through, and it replaces the container just as thoroughly. Gated with a
  // real staged_files row so the token checks pass first — a caller holding a
  // stale token should be told that, not asked to accept a loss it cannot
  // cause.
  const stage = () => {
    const dir = mkdtempSync(join(tmpdir(), 'rg-staged-'));
    const path = join(dir, 'dist.zip');
    writeFileSync(path, 'not really a zip either');
    const token = `tok${Date.now()}${Math.random().toString(36).slice(2, 8)}`;
    const sha = execFileSync('/usr/bin/env', ['sh', '-c', `shasum -a 256 "${path}" | cut -d' ' -f1`], { encoding: 'utf8' }).trim();
    db.prepare(
      'INSERT INTO staged_files (token,user_id,filename,size_bytes,sha256,scratch_path,expires_at) ' +
      "VALUES (?,?,?,?,?,?, datetime('now','+1 hour'))"
    ).run(token, user.id, 'dist.zip', 23, sha, path);
    return token;
  };

  test('appcrane_deploy_artifact is gated on the same acknowledgement', async () => {
    setDocker({ mode: 'ok', volumes: '{"/var/lib/odoo":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    reset();
    const before = count();
    await assert.rejects(
      () => callTool(user, 'appcrane_deploy_artifact', { slug: SLUG, env: 'sandbox', token: stage() }),
      /DATA_LOSS_NOT_ACKNOWLEDGED[\s\S]*\/var\/lib\/odoo/,
    );
    assert.equal(count(), before, 'a refused artifact deploy must not queue a deployment');
  });

  test('an acknowledged appcrane_deploy_artifact gets past the guard', async () => {
    setDocker({ mode: 'ok', volumes: '{"/var/lib/odoo":{}}', mounts: '[{"Type":"bind","Destination":"/data"}]' });
    reset();
    // The bundle is deliberately corrupt, so "past the guard" shows up as a
    // DIFFERENT failure. Asserting merely that it threw would pass against a
    // guard that never stopped refusing.
    await assert.rejects(
      () => callTool(user, 'appcrane_deploy_artifact', { slug: SLUG, env: 'sandbox', token: stage(), acknowledge_data_loss: true }),
      (e) => {
        assert.doesNotMatch(e.message, /DATA_LOSS_NOT_ACKNOWLEDGED/,
          `the acknowledgement was ignored: ${e.message}`);
        return true;
      },
    );
  });
});

// ===========================================================================
// 5. LIVE — the daemon facts the whole design rests on
// ===========================================================================

describe('LIVE', { skip: liveSkip }, () => {
  const SUFFIX = `rg${process.pid}`;
  const VOL_IMAGE = `crane-redeploy-vol-${SUFFIX}:1`;
  const PLAIN_IMAGE = `crane-redeploy-plain-${SUFFIX}:1`;
  const CN_ANON = `crane-redeploy-anon-${SUFFIX}`;
  const CN_BOUND = `crane-redeploy-bound-${SUFFIX}`;
  const CN_PLAIN = `crane-redeploy-plain-${SUFFIX}`;
  const HOST_DIR = join(process.env.DATA_DIR, 'livebind');

  let problem = null;
  const dk = (args, timeout = 180000) =>
    execFileAsync(REAL_DOCKER, args, { timeout, maxBuffer: 8 * 1024 * 1024 }).then((r) => r.stdout.trim());

  before(async () => {
    withRealDocker();
    mkdirSync(HOST_DIR, { recursive: true });
    const ctxVol = join(process.env.DATA_DIR, 'ctx-vol');
    const ctxPlain = join(process.env.DATA_DIR, 'ctx-plain');
    mkdirSync(ctxVol, { recursive: true });
    mkdirSync(ctxPlain, { recursive: true });
    // The ONLY difference between the two images is the VOLUME line. That is
    // the control: if the plain image also reported a volume path, this section
    // would be measuring something other than the VOLUME instruction.
    writeFileSync(join(ctxVol, 'Dockerfile'),
      'FROM alpine:3.20\nRUN mkdir -p /state && echo seed > /state/seed.txt\nVOLUME /state\nCMD ["sleep","900"]\n');
    writeFileSync(join(ctxPlain, 'Dockerfile'),
      'FROM alpine:3.20\nRUN mkdir -p /state && echo seed > /state/seed.txt\nCMD ["sleep","900"]\n');
    try {
      await dk(['build', '-q', '-t', VOL_IMAGE, ctxVol]);
      await dk(['build', '-q', '-t', PLAIN_IMAGE, ctxPlain]);
      await dk(['run', '-d', '--name', CN_ANON, VOL_IMAGE]);
      await dk(['run', '-d', '--name', CN_BOUND, '-v', `${HOST_DIR}:/state`, VOL_IMAGE]);
      await dk(['run', '-d', '--name', CN_PLAIN, PLAIN_IMAGE]);
    } catch (e) {
      // An unreachable registry is an environment fact, not a defect.
      problem = `could not prepare live fixtures: ${String(e.message).split('\n')[0].slice(0, 160)}`;
    }
  });

  after(async () => {
    for (const n of [CN_ANON, CN_BOUND, CN_PLAIN]) await dk(['rm', '-fv', n], 60000).catch(() => {});
    for (const i of [VOL_IMAGE, PLAIN_IMAGE]) await dk(['rmi', '-f', i], 60000).catch(() => {});
  });

  test('a VOLUME with no bind over it is read off the real daemon as at risk', async (t) => {
    if (problem) return t.skip(problem);
    const state = await risk.inspectContainerState(CN_ANON);
    assert.equal(state.present, true, JSON.stringify(state));
    assert.deepEqual(state.imageVolumes, ['/state']);
    assert.deepEqual(state.bindDestinations, [],
      'the daemon gave /state an ANONYMOUS volume, not a bind — that is exactly the losing case');
    assert.deepEqual(risk.classifyVolumePaths(state), { atRisk: ['/state'], persisted: [] });
  });

  test('the same image WITH a bind over the same path reads as safe', async (t) => {
    if (problem) return t.skip(problem);
    const state = await risk.inspectContainerState(CN_BOUND);
    assert.equal(state.present, true, JSON.stringify(state));
    assert.deepEqual(state.imageVolumes, ['/state'],
      'Config.Volumes still lists the path when a bind covers it — which is why the image alone cannot answer');
    assert.deepEqual(state.bindDestinations, ['/state']);
    assert.deepEqual(risk.classifyVolumePaths(state), { atRisk: [], persisted: ['/state'] });
  });

  test('the control: the identical image without the VOLUME line declares nothing', async (t) => {
    if (problem) return t.skip(problem);
    const state = await risk.inspectContainerState(CN_PLAIN);
    assert.equal(state.present, true, JSON.stringify(state));
    assert.deepEqual(state.imageVolumes, [],
      'CONTROL FAILED: a container from an image with no VOLUME reported volume paths, so a pass above ' +
      'could not be attributed to the VOLUME instruction');
    assert.deepEqual(risk.classifyVolumePaths(state), { atRisk: [], persisted: [] });
  });

  test('a container that does not exist is a definite "no risk", not an unknown', async (t) => {
    if (problem) return t.skip(problem);
    const state = await risk.inspectContainerState(`crane-nonexistent-${SUFFIX}`);
    assert.equal(state.present, false,
      'a missing container must be told apart from a broken daemon: the first is a first deploy, ' +
      'the second is a deploy whose risk is unknown');
  });

  test('the at-risk path really does lose its contents across rm -f and recreate', async (t) => {
    if (problem) return t.skip(problem);
    // The claim the whole warning makes, measured end to end rather than
    // reasoned about. WITH the bind-mounted container as the control: if the
    // marker survived in both, the warning would be describing a loss that does
    // not happen.
    const MARKER = `marker-${Date.now()}`;
    await dk(['exec', CN_ANON, 'sh', '-c', `printf %s ${MARKER} > /state/marker`]);
    await dk(['exec', CN_BOUND, 'sh', '-c', `printf %s ${MARKER} > /state/marker`]);
    assert.equal(await dk(['exec', CN_ANON, 'cat', '/state/marker']), MARKER);

    // Exactly what services/docker.js stopApp does: rm -f, no -v.
    await dk(['rm', '-f', CN_ANON]);
    await dk(['rm', '-f', CN_BOUND]);
    await dk(['run', '-d', '--name', CN_ANON, VOL_IMAGE]);
    await dk(['run', '-d', '--name', CN_BOUND, '-v', `${HOST_DIR}:/state`, VOL_IMAGE]);

    const gone = await dk(['exec', CN_ANON, 'sh', '-c', 'cat /state/marker 2>&1 || true']);
    assert.ok(!gone.includes(MARKER),
      `the unbound VOLUME kept its contents across rm -f + recreate, so the warning would be false. Got: ${gone}`);
    assert.equal(await dk(['exec', CN_BOUND, 'cat', '/state/marker']), MARKER,
      'CONTROL FAILED: the bind-mounted path lost its contents too, so the test cannot tell a stranded ' +
      'anonymous volume from a container that simply restarted');
  });
});
