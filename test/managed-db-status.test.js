import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// GET /api/managed-db/servers — is the shared Postgres / MariaDB up?
//
// Three properties are worth a test here, and none of them is "it returns 200":
//
//   1. IT MUST NOT PROVISION. serverStatus() sits one function away from
//      ensureServer(), which docker-runs a real database container. This
//      endpoint is meant to be POLLED by a dashboard, so an accidental
//      ensureServer() would stand a Postgres up because somebody opened a tab.
//      The docker shim below records every argv the module issues, and the
//      assertion is over that log: `inspect`, and nothing else, ever.
//
//   2. NO CREDENTIAL. managed_db_servers carries admin_password_enc — the
//      engine superuser password. A `SELECT *` plus a spread is one careless
//      edit away from putting it in a browser tab, so the check is over the
//      serialized response BYTES, with a real encrypted row in the table.
//
//   3. PLATFORM-ADMIN ONLY. There is no :slug here; the resource is the
//      platform's own infrastructure, and container states, host ports and
//      restart counts are not app-team information.
//
// Docker is replaced with a shim on PATH — the mechanism test/docker-resource-
// flags.js, test/container-port.test.js and test/image-deploy.test.js already
// use — rather than with an engine double, because the parsing of `docker
// inspect`'s output IS most of what serverStatus() does. A double would leave
// it untested.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mdbstatus-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';
// Never adopt — or report on — a developer's real appcrane-db-* containers.
process.env.MANAGED_DB_CONTAINER_PREFIX = 'crane-test-mdbstatus';

// ── A `docker` that records instead of running ─────────────────────────────

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_DIR = join(process.env.DATA_DIR, 'docker-calls');
mkdirSync(SHIM_DIR, { recursive: true });
mkdirSync(ARGV_DIR, { recursive: true });
// ONE FILE PER CALL, not one shared append-log. The two engines are inspected
// in parallel, and two shells appending to the same file interleave inside a
// single record — measured, twice: an argv-per-line log produced
// "inspect\ninspect\n-f\n-f\n…" (two calls fused into one), and a single
// `printf '%b\0'` still interleaved often enough to redden the argv assertions
// under unrelated edits. Separate files cannot race.
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/bin/sh\n'
  + 'f=$(mktemp "$CRANE_TEST_DOCKER_DIR/call.XXXXXX")\n'
  + 'for a in "$@"; do printf \'%s\\n\' "$a"; done > "$f"\n'
  + 'if [ -n "$CRANE_TEST_DOCKER_FAIL" ]; then printf \'%s\\n\' "$CRANE_TEST_DOCKER_FAIL" >&2; exit 1; fi\n'
  + 'last=""; for a in "$@"; do last="$a"; done\n'
  + 'case "$last" in\n'
  + '  *-postgres) [ -n "$CRANE_TEST_PG_INSPECT" ] || { printf \'Error: No such object: %s\\n\' "$last" >&2; exit 1; }\n'
  + '              printf \'%s\\n\' "$CRANE_TEST_PG_INSPECT"; exit 0 ;;\n'
  + '  *-mariadb)  [ -n "$CRANE_TEST_MARIA_INSPECT" ] || { printf \'Error: No such object: %s\\n\' "$last" >&2; exit 1; }\n'
  + '              printf \'%s\\n\' "$CRANE_TEST_MARIA_INSPECT"; exit 0 ;;\n'
  + '  *) printf \'Error: No such object: %s\\n\' "$last" >&2; exit 1 ;;\n'
  + 'esac\n',
  { mode: 0o755 },
);
process.env.CRANE_TEST_DOCKER_DIR = ARGV_DIR;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

function dockerCalls() {
  return readdirSync(ARGV_DIR)
    .sort()
    .map(f => readFileSync(join(ARGV_DIR, f), 'utf8').split('\n').filter(l => l !== ''));
}
function clearDockerCalls() {
  for (const f of readdirSync(ARGV_DIR)) rmSync(join(ARGV_DIR, f));
}

// A container that is up: status | restarts | exit code | oom | started at
// Six fields now: the template also asks for {{.HostConfig.Memory}}, the cap
// the RUNNING container actually has. 536870912 = 512 MB, deliberately NOT the
// 1024 MB the config carries — a container keeps the limit it was created with,
// and reporting the config as though it were live is the bug this field fixes.
const RUNNING = 'running|0|0|false|2026-09-08T21:40:00.123456789Z|536870912';

// ── Fixtures ───────────────────────────────────────────────────────────────

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
initDb();
const db = getDb();

let slot = 0;
const mkApp = (slug) => db.prepare(
  'INSERT INTO apps (name,slug,slot,source_type,auth_mode,branch) VALUES (?,?,?,?,?,?)'
).run(slug, slug, ++slot, 'image', 'forward_auth', 'main').lastInsertRowid;

const APP_A = mkApp('bookstack');
const APP_B = mkApp('wiki');

let seq = 0;
function mkUser(role) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  db.prepare(
    'INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)'
  ).run(`s${n}`, `s${n}@t.test`, role, hashApiKey(key), 'human');
  return key;
}

const PLATFORM = mkUser('platform_admin');
const ADMIN = mkUser('admin');
const USER = mkUser('user');

// The real superuser password, stored the way ensureServer() stores it.
const ADMIN_PASSWORD = 'sup3rus3r-must-never-ship-9c1f4a2b';
const ADMIN_PASSWORD_ENC = encrypt(ADMIN_PASSWORD);

function seedServerRow(engine, { container, image, port }) {
  db.prepare(`
    INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc)
    VALUES (?,?,?,?,?)
  `).run(engine, container, image, port, ADMIN_PASSWORD_ENC);
}

function seedDatabase(appId, engine, name) {
  db.prepare(`
    INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc)
    VALUES (?,?,?,?,?,?)
  `).run(appId, '', engine, name, `${name}_u`, encrypt('per-app-password-3d7e'));
}

function resetTables() {
  db.prepare('DELETE FROM managed_databases').run();
  db.prepare('DELETE FROM managed_db_servers').run();
}

const svc = await import('../server/services/managedDb.js');
const routes = await import('../server/routes/managedDb.js');

const api = express();
api.use(express.json());
api.use('/api/managed-db', routes.serversRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

async function call(path, key) {
  const headers = {};
  if (key) headers['X-API-Key'] = key;
  const res = await fetch(`${BASE}${path}`, { headers });
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch { /* html/empty */ }
  return { status: res.status, text, body };
}

beforeEach(() => {
  resetTables();
  clearDockerCalls();
  delete process.env.CRANE_TEST_DOCKER_FAIL;
  delete process.env.CRANE_TEST_PG_INSPECT;
});

// ── 1. Authorization ───────────────────────────────────────────────────────

test('a platform admin gets every engine back, in SUPPORTED_ENGINES order', async () => {
  const { status, body } = await call('/api/managed-db/servers', PLATFORM);
  assert.equal(status, 200);
  assert.deepEqual(body.servers.map(s => s.engine), svc.SUPPORTED_ENGINES);
  assert.deepEqual(body.servers.map(s => s.engine), ['postgres', 'mariadb', 'redis']);
});

test('an anonymous caller is refused', async () => {
  const { status } = await call('/api/managed-db/servers', null);
  assert.equal(status, 401);
  assert.deepEqual(dockerCalls(), [], 'nothing may reach docker without authentication');
});

test('a plain user is refused', async () => {
  const { status, body } = await call('/api/managed-db/servers', USER);
  assert.equal(status, 403);
  assert.equal(body.error.code, 'FORBIDDEN_PLATFORM_ADMIN');
  assert.deepEqual(dockerCalls(), []);
});

test('a non-platform ADMIN is refused — this is platform infrastructure', async () => {
  // requireAdmin would let this through. Container states, host ports and
  // restart counts of the platform's own database servers are not app-team
  // information, so the gate is the platform tier.
  const { status, body } = await call('/api/managed-db/servers', ADMIN);
  assert.equal(status, 403);
  assert.equal(body.error.code, 'FORBIDDEN_PLATFORM_ADMIN');
  assert.deepEqual(dockerCalls(), []);
});

// ── 2. It must never provision ─────────────────────────────────────────────

test('the endpoint issues docker inspect and NOTHING else', async () => {
  seedServerRow('postgres', {
    container: 'crane-test-mdbstatus-postgres', image: 'postgres:16-alpine', port: 45432,
  });
  process.env.CRANE_TEST_PG_INSPECT = RUNNING;

  const { status } = await call('/api/managed-db/servers', PLATFORM);
  assert.equal(status, 200);

  const calls = dockerCalls();
  assert.ok(calls.length > 0, 'the shim recorded nothing — the seam is not wired');
  for (const argv of calls) {
    assert.equal(argv[0], 'inspect',
      `a status poll issued \`docker ${argv.join(' ')}\` — it must only inspect`);
  }
  const verbs = new Set(calls.map(a => a[0]));
  for (const forbidden of ['run', 'create', 'start', 'exec', 'pull', 'rm', 'network']) {
    assert.ok(!verbs.has(forbidden), `a status poll must never \`docker ${forbidden}\``);
  }
});

test('ONE inspect per engine, not one per field', async () => {
  process.env.CRANE_TEST_PG_INSPECT = RUNNING;
  await svc.serverStatus();
  const inspects = dockerCalls().filter(a => a[0] === 'inspect');
  assert.equal(inspects.length, 2, 'two engines, two inspects');
  // The five facts come out of a single -f template.
  const fmt = inspects[0][inspects[0].indexOf('-f') + 1];
  for (const field of ['.State.Status', '.RestartCount', '.State.ExitCode',
    '.State.OOMKilled', '.State.StartedAt']) {
    assert.ok(fmt.includes(field), `the inspect template must carry ${field}`);
  }
});

test('the inspect template never asks docker for the container environment', async () => {
  // `{{json .}}` would be shorter and would include .Config.Env, which holds
  // POSTGRES_PASSWORD / MARIADB_ROOT_PASSWORD.
  process.env.CRANE_TEST_PG_INSPECT = RUNNING;
  await svc.serverStatus();
  for (const argv of dockerCalls()) {
    const fmt = argv[argv.indexOf('-f') + 1] || '';
    assert.ok(!fmt.includes('json .'), 'the template must not dump the whole inspect object');
    assert.ok(!/Env/i.test(fmt), 'the template must not read the container environment');
    // ...and it must ASK for the real memory cap. The shim echoes a fixture and
    // ignores the template, so nothing else in this file can tell that the
    // field was dropped: removing it leaves every value assertion green while
    // the dashboard silently goes back to reporting the config as though it
    // were the live limit. This is the only assertion that sees the template.
    assert.ok(fmt.includes('{{.HostConfig.Memory}}'),
      'the template must read the container\'s actual memory limit');
  }
});

// ── 3. Shape and semantics ─────────────────────────────────────────────────

test('a running container reports its docker facts', async () => {
  seedServerRow('postgres', {
    container: 'crane-test-mdbstatus-postgres', image: 'postgres:16-alpine', port: 45432,
  });
  seedDatabase(APP_A, 'postgres', 'crane_a1');
  seedDatabase(APP_B, 'postgres', 'crane_a2');
  process.env.CRANE_TEST_PG_INSPECT = 'running|3|0|false|2026-09-08T21:40:00Z|536870912';

  const [pg] = await svc.serverStatus();
  assert.deepEqual(pg, {
    engine: 'postgres',
    container: 'crane-test-mdbstatus-postgres',
    image: 'postgres:16-alpine',
    configured: true,
    state: 'running',
    running: true,
    host_port: 45432,
    // The container's REAL cap, from {{.HostConfig.Memory}} — not the config.
    memory_mb: 512,
    configured_memory_mb: 512,
    databases: 2,
    restart_count: 3,
    last_exit_code: 0,
    oom_killed: false,
    started_at: '2026-09-08T21:40:00Z',
    error: null,
  });
});

test('an OOM-killed exited container is reported as such', async () => {
  seedServerRow('postgres', {
    container: 'crane-test-mdbstatus-postgres', image: 'postgres:16-alpine', port: 45432,
  });
  process.env.CRANE_TEST_PG_INSPECT = 'exited|7|137|true|2026-09-08T20:00:00Z|536870912';

  const [pg] = await svc.serverStatus();
  assert.equal(pg.state, 'exited');
  assert.equal(pg.running, false, 'only `running` is running');
  assert.equal(pg.restart_count, 7);
  assert.equal(pg.last_exit_code, 137);
  assert.equal(pg.oom_killed, true);
  assert.equal(pg.error, null, 'a stopped container is a state, not an error');
});

test("a created-but-never-started container reports started_at:null", async () => {
  // Docker's StartedAt for a container that has never run is the zero time,
  // 0001-01-01T00:00:00Z. Passing that through puts "started 1 January, year 1"
  // in the dashboard.
  seedServerRow('postgres', {
    container: 'crane-test-mdbstatus-postgres', image: 'postgres:16-alpine', port: 45432,
  });
  process.env.CRANE_TEST_PG_INSPECT = 'created|0|0|false|0001-01-01T00:00:00Z|536870912';
  const [pg] = await svc.serverStatus();
  assert.equal(pg.state, 'created');
  assert.equal(pg.running, false);
  assert.equal(pg.started_at, null, 'the zero time is not a start time');
});

test('an engine with no managed_db_servers row still appears, configured:false', async () => {
  // Nothing seeded at all: neither engine has ever been used.
  const { status, body } = await call('/api/managed-db/servers', PLATFORM);
  assert.equal(status, 200);
  assert.equal(body.servers.length, 3);
  // Redis is a container PER SCOPE: with nothing provisioned it has no
  // container and no host port, and carries null for both. The shared engines
  // are the ones this block is about.
  for (const s of body.servers.filter(x => svc.SHARED_SERVER_ENGINES.includes(x.engine))) {
    assert.equal(s.configured, false, `${s.engine} has no row and must say so`);
    assert.equal(s.databases, 0);
    assert.equal(s.state, null);
    assert.equal(s.running, false);
    assert.equal(s.restart_count, null);
    assert.equal(s.last_exit_code, null);
    assert.equal(s.started_at, null);
    assert.equal(s.error, null, 'an absent container is not a docker failure');
    // What it WOULD be, from the ENGINES config, so the UI can render a row.
    assert.ok(s.container.startsWith('crane-test-mdbstatus-'));
    assert.ok(s.image.length > 0);
    assert.equal(typeof s.host_port, 'number');
    assert.ok(s.host_port > 0);
    // No container, so there is no real cap to report. The config value is
    // carried separately so the row can still say what the engine WOULD get —
    // reporting it as `memory_mb` would be claiming a live limit that no
    // running process has.
    assert.equal(s.memory_mb, null, 'an absent container has no actual memory cap');
    assert.ok(s.configured_memory_mb > 0);
  }
  assert.equal(body.servers[0].host_port, 45432, 'the postgres config default');
  assert.equal(body.servers[1].host_port, 43306, 'the mariadb config default');
});

test('a recorded host_port wins over the config default', async () => {
  seedServerRow('mariadb', {
    container: 'crane-test-mdbstatus-mariadb', image: 'mariadb:11.4', port: 43999,
  });
  const [, maria] = await svc.serverStatus();
  assert.equal(maria.configured, true);
  assert.equal(maria.host_port, 43999);
});

test('the database count is per engine, across all apps', async () => {
  seedDatabase(APP_A, 'postgres', 'crane_a1');
  seedDatabase(APP_B, 'postgres', 'crane_a2');
  seedDatabase(APP_A, 'mariadb', 'crane_m1');
  const [pg, maria] = await svc.serverStatus();
  assert.equal(pg.databases, 2);
  assert.equal(maria.databases, 1);
});

test('a docker failure that is NOT "no such container" lands in error', async () => {
  process.env.CRANE_TEST_DOCKER_FAIL = 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock.';
  const servers = await svc.serverStatus();
  // Redis with no instances issues no `docker inspect`, so there is no daemon
  // failure for it to report.
  for (const s of servers.filter(x => svc.SHARED_SERVER_ENGINES.includes(x.engine))) {
    assert.match(s.error, /Cannot connect to the Docker daemon/);
    assert.equal(s.state, null);
    assert.equal(s.running, false);
  }
});

test('an absent container is state:null with error:null, not an error', async () => {
  // The shim answers "No such object" for anything it has no fixture for.
  const servers = await svc.serverStatus();
  for (const s of servers) {
    assert.equal(s.state, null);
    assert.equal(s.error, null,
      '"the container does not exist" is a state to report, not a failure');
  }
});

// ── 4. No secrets, over the serialized body ────────────────────────────────

test('no response field contains a password, encrypted or otherwise', async () => {
  // Both engines configured, both carrying a real encrypted superuser password,
  // plus per-app rows whose password_enc is also in the database.
  seedServerRow('postgres', {
    container: 'crane-test-mdbstatus-postgres', image: 'postgres:16-alpine', port: 45432,
  });
  seedServerRow('mariadb', {
    container: 'crane-test-mdbstatus-mariadb', image: 'mariadb:11.4', port: 43306,
  });
  seedDatabase(APP_A, 'postgres', 'crane_a1');
  process.env.CRANE_TEST_PG_INSPECT = RUNNING;

  const { status, text } = await call('/api/managed-db/servers', PLATFORM);
  assert.equal(status, 200);

  assert.ok(!text.includes(ADMIN_PASSWORD),
    'the decrypted superuser password appeared in the response body');
  assert.ok(!text.includes(ADMIN_PASSWORD_ENC),
    'the ENCRYPTED superuser password appeared in the response body');
  assert.ok(!/password/i.test(text),
    'no password-shaped field may appear at all — not even an encrypted one');
  assert.ok(!text.includes('postgresql://') && !text.includes('mysql://'),
    'a connection URL embeds the credential and must not be returned');
  assert.ok(!/admin_password_enc|password_enc/.test(text));
});

test('serverStatus() selects columns by name rather than spreading the row', async () => {
  // The response check above only proves today's field list is clean. This one
  // is the reason it will stay clean: `SELECT *` plus a spread is the edit that
  // would break it, and it would break it silently.
  const src = readFileSync(new URL('../server/services/managedDb.js', import.meta.url), 'utf8');
  const start = src.indexOf('export async function serverStatus');
  assert.ok(start > 0, 'could not locate serverStatus in services/managedDb.js');
  const body = src.slice(start, src.indexOf('\n}\n', start));

  // Comments stripped before the call checks below. Matching the bare NAME
  // would forbid documenting why the call must not be there, which is the one
  // piece of context that stops a future reader from adding it back.
  const code = body
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n').filter(l => !/^\s*\/\//.test(l)).join('\n');

  assert.ok(!/SELECT \*/i.test(code), 'serverStatus must not SELECT * from managed_db_servers');
  assert.ok(!code.includes('admin_password_enc'), 'serverStatus must not read the password column');
  assert.ok(!/\bdecrypt\s*\(/.test(code), 'serverStatus must never decrypt anything');
  assert.ok(!/\bensureServer\s*\(/.test(code),
    'serverStatus must never CALL ensureServer — this endpoint is polled, and ensureServer '
    + 'creates and starts a container, pulls the image and hardens the server');
});

// ── 5. Drift ───────────────────────────────────────────────────────────────

test('services/managedDb.js exports serverStatus() and the route calls it', async () => {
  assert.equal(typeof svc.serverStatus, 'function');
  assert.equal(svc.serverStatus.length, 0, 'serverStatus() takes no arguments');
  const src = readFileSync(new URL('../server/routes/managedDb.js', import.meta.url), 'utf8');
  assert.ok(src.includes('svc.serverStatus()'),
    'the route must go through the engine module, not re-implement the query');
  assert.ok(!/serversRouter[\s\S]*ensureServer/.test(src),
    'the status router must not reach ensureServer');
});

// ── 6. Configured vs actual memory ─────────────────────────────────────────

test('the memory a container HAS is reported, not the memory config wants', async () => {
  // The bug this covers shipped and was caught on the first real page load: the
  // row read `memory_mb` straight off the ENGINES config, so raising
  // MANAGED_DB_MARIADB_MEMORY_MB from 512 to 1024 made the dashboard claim
  // 1024 MB while the live container was still capped at 512. A container's
  // memory limit is fixed when it is CREATED; changing the config changes what
  // the NEXT one gets. The dashboard said the raise had landed, most
  // confidently to someone reading the page straight after an OOM.
  //
  // mariadb's configured default is 1024 and the fixture container was created
  // at 512, so this is exactly that drift.
  process.env.CRANE_TEST_MARIA_INSPECT = 'running|0|0|false|2026-09-08T21:40:00Z|536870912';
  seedServerRow('mariadb', {
    container: 'crane-test-mdbstatus-mariadb', image: 'mariadb:11.4', port: 43306,
  });
  const { body } = await call('/api/managed-db/servers', PLATFORM);
  delete process.env.CRANE_TEST_MARIA_INSPECT;

  const maria = body.servers.find(s => s.engine === 'mariadb');
  assert.equal(maria.memory_mb, 512, 'must report the cap the container actually has');
  assert.equal(maria.configured_memory_mb, 1024, 'and separately what config would give the next one');
  assert.notEqual(maria.memory_mb, maria.configured_memory_mb,
    'the two must be distinguishable — collapsing them is the bug');
});

test('an unlimited container reports null rather than 0 MB', async () => {
  // Docker writes 0 for "no limit". Rounding that to "0 MB" would read as a
  // container throttled to nothing, which is the opposite of the truth.
  process.env.CRANE_TEST_MARIA_INSPECT = 'running|0|0|false|2026-09-08T21:40:00Z|0';
  seedServerRow('mariadb', {
    container: 'crane-test-mdbstatus-mariadb', image: 'mariadb:11.4', port: 43306,
  });
  const { body } = await call('/api/managed-db/servers', PLATFORM);
  delete process.env.CRANE_TEST_MARIA_INSPECT;

  const maria = body.servers.find(s => s.engine === 'mariadb');
  assert.equal(maria.memory_mb, null, '0 bytes means unlimited, not zero');
});
