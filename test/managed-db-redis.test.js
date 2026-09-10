import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import crypto from 'crypto';

const execFileAsync = promisify(execFile);

// Managed Redis (server/services/managedRedis.js + the per-scope half of
// server/services/managedDb.js).
//
// THE REQUIREMENT IS THE SAME ONE test/managed-db.test.js EXISTS FOR: "an app's
// credentials must reach that app's data and NOTHING else." What changed is the
// mechanism. Postgres and MariaDB share one server and isolate with grants;
// Redis cannot isolate at all inside a shared server — measured, and written up
// in managedRedis.js's header — so each app gets its own container, and the
// boundary is a process plus a password.
//
// That makes the attack surface DIFFERENT, and the attacks below are chosen for
// it rather than translated from the SQL file:
//
//   * a managed Redis must never answer an UNAUTHENTICATED connection. An open
//     Redis on a reachable port is not a data leak, it is a total compromise,
//     and it is the single most common way self-hosted Redis goes wrong.
//   * app A's credential, pointed at app B's INSTANCE, must be refused. With
//     one container per app the port is the only thing distinguishing them, and
//     a shared or reused password would make the whole design decorative.
//   * the app's own user must not hold CONFIG. `CONFIG SET dir` +
//     `CONFIG SET dbfilename` is Redis's write-anywhere primitive.
//   * and the CONTROL, without which every denial above could be a broken
//     client: each app can actually use its own instance, over the exact URL
//     AppCrane injects.
//
// Plus the two facts that would silently make this a worse Redis than the one
// people expect: the modules must be loaded, and maxmemory must be set with a
// noeviction policy — an unbounded Redis is an outage and an LRU one throws
// away queued jobs.

const PREFIX = `crane-rdstest-${crypto.randomBytes(4).toString('hex')}`;
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mrds-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
// A per-RUN unique prefix, not a fixed one. test/managed-db.test.js uses fixed
// names and two concurrent runs of it collide on the same container; every
// object this file creates is namespaced by the random suffix above so it
// cannot happen here, and so a leftover container from a killed run cannot be
// adopted by the next one.
process.env.MANAGED_DB_CONTAINER_PREFIX = PREFIX;
// Well clear of the 46379-46878 default range, so a run cannot take a port a
// real instance on a developer's machine is already holding.
process.env.MANAGED_DB_REDIS_PORT_MIN = '48411';
// Small on purpose: the assertions below check the derived maxmemory, and a
// non-default ceiling proves the derivation rather than a hard-coded constant.
process.env.MANAGED_DB_REDIS_MEMORY_MB = '128';

let dockerOk = false;
try {
  execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 10000, stdio: 'pipe' });
  dockerOk = true;
} catch (_) { /* left false */ }
const noDocker = dockerOk ? false : 'no reachable Docker daemon on this host';

const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const mrds = await import('../server/services/managedRedis.js');

let APP_A;
let APP_B;

before(() => {
  initDb(process.env.DATA_DIR);
  const db = getDb();
  const ins = db.prepare('INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)');
  APP_A = Number(ins.run('App A', 'app-a', 1).lastInsertRowid);
  APP_B = Number(ins.run('App B', 'app-b', 2).lastInsertRowid);
});

after(async () => {
  if (dockerOk) {
    await mdb.stopServer('redis').catch(() => {});
    // stopServer only removes what the rows still name. Sweep by label so a
    // failed test mid-provision cannot leave a container behind.
    try {
      const { stdout } = await execFileAsync('docker', ['ps', '-aq', '--filter', `name=${PREFIX}-redis-`]);
      const ids = stdout.trim().split('\n').filter(Boolean);
      if (ids.length) await execFileAsync('docker', ['rm', '-f', ...ids]);
    } catch (_) { /* best effort */ }
  }
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

// ---------------------------------------------------------------------------
// Migration and wiring — no daemon needed
// ---------------------------------------------------------------------------

test('migration 089 gives managed_databases somewhere to put a port and a container', () => {
  const cols = getDb().prepare('PRAGMA table_info(managed_databases)').all().map(c => c.name);
  assert.ok(cols.includes('host_port'), `host_port missing; got ${cols.join(', ')}`);
  assert.ok(cols.includes('container_name'), `container_name missing; got ${cols.join(', ')}`);

  const idx = getDb().prepare(
    "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='managed_databases'"
  ).all().map(r => r.name);
  // The guard that stops a port being handed to two scopes — a recycled port
  // plus a still-valid password is how an app reaches a stranger's Redis.
  assert.ok(idx.includes('idx_managed_databases_host_port'));
  assert.ok(idx.includes('idx_managed_databases_container'));

  assert.ok(getDb().prepare("SELECT 1 FROM _migrations WHERE name = '089-managed-redis-instances.sql'").get());
});

test('the host-port index catches a reused port and leaves the SQL engines alone', () => {
  const db = getDb();
  const ins = db.prepare(
    'INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc, host_port, container_name) VALUES (?,?,?,?,?,?,?,?)'
  );
  // Two shared-engine rows, both with a NULL port, still insert.
  //
  // Honest about what this proves: NOT that the index's WHERE clause is doing
  // the work. SQLite treats every NULL in a UNIQUE index as distinct, so this
  // passes with an unqualified index too — measured by deleting the WHERE and
  // re-running. It is here so a future change to how shared-engine rows are
  // written cannot start colliding unnoticed.
  ins.run(APP_A, '', 'postgres', 'idxprobe_a', 'idxprobe_a_u', 'x', null, null);
  ins.run(APP_B, '', 'postgres', 'idxprobe_b', 'idxprobe_b_u', 'x', null, null);

  ins.run(APP_A, '', 'redis', 'idxprobe_ra', 'idxprobe_ra_u', 'x', 49991, 'c-a');
  assert.throws(
    () => ins.run(APP_B, '', 'redis', 'idxprobe_rb', 'idxprobe_rb_u', 'x', 49991, 'c-b'),
    /UNIQUE constraint/,
  );

  db.prepare("DELETE FROM managed_databases WHERE db_name LIKE 'idxprobe%'").run();
});

test('redis is a supported engine, and is NOT a shared-server one', () => {
  assert.ok(mdb.SUPPORTED_ENGINES.includes('redis'));
  assert.ok(!mdb.SHARED_SERVER_ENGINES.includes('redis'));
  assert.deepEqual(mdb.SHARED_SERVER_ENGINES, ['postgres', 'mariadb']);
  assert.equal(mdb.isPerScopeEngine('redis'), true);
  assert.equal(mdb.isPerScopeEngine('postgres'), false);
});

test('ensureServer refuses redis rather than inventing a shared server', async () => {
  // A caller that reaches ensureServer('redis') is holding an assumption that
  // does not apply. Returning something would hand an app a port belonging to
  // nothing, and the failure would surface as an app that cannot connect.
  await assert.rejects(() => mdb.ensureServer('redis'), /has no shared server/);
});

test('the run command keeps the password out of argv and the modules in', () => {
  const cmd = mrds.serverCommand(96);
  // The literal `$REDISCLI_AUTH`, expanded by the container's own shell from an
  // --env-file. A password interpolated here would be readable in the host's
  // process table by any local user, which is the reason createServerContainer
  // uses --env-file for POSTGRES_PASSWORD too.
  const line = cmd.join(' ');
  assert.match(line, /--requirepass "\$REDISCLI_AUTH"/,
    'the only thing that may follow --requirepass is the env reference the container expands');
  // Belt: whatever the value is, it may not be sitting in argv as a literal.
  assert.equal(/--requirepass (?!"\$REDISCLI_AUTH")/.test(line), false,
    'the secret must never be a literal in argv');
  // docker-entrypoint.sh, not redis-server: the entrypoint is what appends
  // --loadmodule for each module the image ships. Bypassing it starts a Redis
  // with no search and no JSON, silently.
  assert.ok(cmd.join(' ').includes('docker-entrypoint.sh redis-server'));
  assert.match(cmd.join(' '), /--maxmemory 96mb/);
  assert.match(cmd.join(' '), /--maxmemory-policy noeviction/);
});

test('maxmemory is derived from the container ceiling, never set above it', () => {
  for (const cap of [64, 128, 256, 1024, 4096]) {
    const mm = mrds.maxmemoryMbFor(cap);
    assert.ok(mm < cap, `maxmemory ${mm} must sit below the cgroup wall ${cap}`);
    assert.ok(mm >= cap * 0.5, `maxmemory ${mm} is uselessly small next to ${cap}`);
  }
});

test('port allocation reuses the lowest free slot and refuses to run off the end', () => {
  assert.equal(mrds.pickPort([]), mrds.REDIS_PORT_MIN);
  assert.equal(mrds.pickPort([mrds.REDIS_PORT_MIN, mrds.REDIS_PORT_MIN + 1]), mrds.REDIS_PORT_MIN + 2);
  // A freed port is handed out again — a monotonic allocator would walk off the
  // end of the range while hundreds of ports sat idle.
  assert.equal(mrds.pickPort([mrds.REDIS_PORT_MIN + 1]), mrds.REDIS_PORT_MIN);

  const all = [];
  for (let p = mrds.REDIS_PORT_MIN; p <= mrds.REDIS_PORT_MAX; p++) all.push(p);
  assert.throws(() => mrds.pickPort(all), /no free port/);
});

test('the ACL is ONE atomic SETUSER, and it denies @admin', () => {
  const script = mrds.aclScript('crane_a9_u', 'AbC-123_xyz');
  const lines = script.trim().split('\n');
  // Two commands would leave a window where the user exists but is `off` — an
  // authentication outage every time a live instance is re-ensured.
  assert.equal(lines.length, 1, `the ACL must be applied atomically, got:\n${script}`);
  assert.match(lines[0], /^ACL SETUSER crane_a9_u reset on >AbC-123_xyz /);
  assert.ok(lines[0].includes('-@admin'), 'CONFIG SET dir is Redis\'s write-anywhere primitive');
  assert.ok(!lines[0].includes('-@dangerous'),
    'INFO/CLIENT/KEYS/FLUSHDB are @dangerous and every Redis-backed app in the catalogue calls them');
});

test('the injected URL always addresses database 0', () => {
  // Numbered databases are not a boundary here and the modules refuse to run
  // outside 0, so anything else would be decoration that breaks apps.
  assert.equal(
    mrds.redisUrl({ username: 'u', password: 'p', host: 'host.docker.internal', port: 46379 }),
    'redis://u:p@host.docker.internal:46379/0',
  );
  assert.equal(mrds.REDIS_DB_INDEX, '0');
});

// ---------------------------------------------------------------------------
// The live engine
// ---------------------------------------------------------------------------

/**
 * redis-cli inside a given container, with explicit credentials, over TCP.
 *
 * Always port 6379 — the port INSIDE the container. The `port` on a credentials
 * object is the HOST port, and an earlier draft spread it in here: every call
 * then dialled a port nothing was listening on inside the container, every
 * ATTACK was "refused", and the suite went green while proving nothing. The
 * CONTROL is what caught it, which is why it is there.
 */
async function asUser(container, { username, password, sql }) {
  assert.ok(username && password, 'asUser needs real credentials, or a denial proves nothing');
  const args = [
    'exec', '-i', container, 'redis-cli',
    '-h', '127.0.0.1', '-p', '6379',
    '--user', username, '--pass', password, '--no-auth-warning',
    ...sql,
  ];
  try {
    const { stdout } = await execFileAsync('docker', args, { timeout: 60000 });
    const out = stdout.trim();
    // redis-cli exits 0 on a server-side error and prints it. Treat any
    // NOAUTH/NOPERM/WRONGPASS/ERR as a failure, or every ATTACK below would
    // pass by simply not throwing.
    if (/^(NOAUTH|NOPERM|WRONGPASS|ERR|OOM)/.test(out)) return { ok: false, out };
    return { ok: true, out };
  } catch (e) {
    return { ok: false, out: (e.stderr?.toString() || e.stdout?.toString() || e.message).trim() };
  }
}

test('redis provisions, isolates, and deprovisions', { skip: noDocker, timeout: 600000 }, async (t) => {
  const a = await mdb.provision({ appId: APP_A }, 'redis');
  const b = await mdb.provision({ appId: APP_B }, 'redis');

  const rowA = getDb().prepare('SELECT * FROM managed_databases WHERE app_id = ? AND engine = ?').get(APP_A, 'redis');
  const rowB = getDb().prepare('SELECT * FROM managed_databases WHERE app_id = ? AND engine = ?').get(APP_B, 'redis');

  await t.test('each app got its OWN container, port and password', () => {
    assert.notEqual(rowA.container_name, rowB.container_name);
    assert.notEqual(rowA.host_port, rowB.host_port);
    assert.notEqual(a.password, b.password);
    assert.match(a.password, /^[A-Za-z0-9_-]{24,}$/);
    assert.equal(a.host, 'host.docker.internal');
    assert.equal(a.database, '0');
    assert.equal(a.url, `redis://${a.username}:${a.password}@host.docker.internal:${a.port}/0`);

    // The stored blob is a ciphertext, not the password.
    assert.ok(!rowA.password_enc.includes(a.password));
    assert.match(rowA.password_enc, /^[0-9a-f]{32}:[0-9a-f]{32}:/, 'iv:tag:ciphertext, per encryption.js');

    // And the listing an API would return still carries no secret.
    const listed = mdb.listForApp(APP_A).find(r => r.engine === 'redis');
    assert.ok(listed);
    assert.equal(listed.password_enc, undefined);
    assert.equal(listed.password, undefined);
  });

  await t.test('the instance is published on loopback and never on 0.0.0.0', async () => {
    const { stdout } = await execFileAsync('docker', ['port', rowA.container_name]);
    const lines = stdout.trim().split('\n').filter(Boolean);
    assert.ok(lines.length > 0, 'the instance must publish at least one host port');
    assert.ok(lines.some(l => l.includes('127.0.0.1:')), `expected a loopback publish, got:\n${stdout}`);
    for (const line of lines) {
      assert.ok(
        !/(^|\s|>)0\.0\.0\.0:/.test(line) && !/\[::\]:/.test(line),
        `a managed database must never be published on a wildcard address, got: ${line}`,
      );
    }
  });

  // ---- CONTROL. Without this, every denial below could be a broken client.
  await t.test('CONTROL: each app can use its own instance', async () => {
    const set = await asUser(rowB.container_name, { ...b, sql: ['SET', 'secrets', 'B-SECRET'] });
    assert.ok(set.ok, `app B must be able to write to its own Redis: ${set.out}`);
    const get = await asUser(rowB.container_name, { ...b, sql: ['GET', 'secrets'] });
    assert.ok(get.ok && get.out.includes('B-SECRET'), `control read failed: ${get.out}`);

    const own = await asUser(rowA.container_name, { ...a, sql: ['PING'] });
    assert.ok(own.ok, `app A must be able to use its own Redis: ${own.out}`);
  });

  // ---- THE ATTACKS. Every one of these must fail.
  await t.test('ATTACK: an unauthenticated connection is refused', async () => {
    // The failure mode that matters most. An open Redis on a port any container
    // with the host gateway can reach is not a leak, it is a shell.
    //
    // `env -u REDISCLI_AUTH` is load-bearing. Without it this probe is not
    // unauthenticated at all: the instance's own environment carries the
    // password precisely so administrative execs need no credential in argv,
    // and redis-cli reads it. An earlier draft omitted it, the "unauthenticated"
    // client authenticated, and the test still passed only because it happened
    // to read a key that did not exist.
    const { stdout } = await execFileAsync('docker', [
      'exec', '-i', rowB.container_name, 'env', '-u', 'REDISCLI_AUTH',
      'redis-cli', '-h', '127.0.0.1', '-p', '6379', 'GET', 'secrets',
    ], { timeout: 60000 });
    assert.match(stdout.trim(), /^NOAUTH/, `an unauthenticated client got a reply: ${stdout}`);
    assert.ok(!stdout.includes('B-SECRET'));
  });

  await t.test("ATTACK: app A's credential does not open app B's instance", async () => {
    // With one container per app the port is all that separates them, so a
    // shared or reused password would make the whole design decorative.
    //
    // redis-cli reports a rejected AUTH on STDERR and then runs the command
    // anyway, which the server answers NOAUTH — measured, both streams checked,
    // because asserting only on stdout would have accepted a client that never
    // sent the credential at all.
    const cross = await execFileAsync('docker', [
      'exec', '-i', rowB.container_name, 'env', '-u', 'REDISCLI_AUTH',
      'redis-cli', '-h', '127.0.0.1', '-p', '6379',
      '--user', a.username, '--pass', a.password, '--no-auth-warning', 'GET', 'secrets',
    ], { timeout: 60000 });
    assert.match(cross.stderr.trim(), /AUTH failed: WRONGPASS/,
      `app A's credential was ACCEPTED by app B's Redis — ISOLATION BROKEN: ${cross.stderr}`);
    assert.match(cross.stdout.trim(), /^NOAUTH/);
    assert.ok(!cross.stdout.includes('B-SECRET'), "app B's data must not appear");
  });

  await t.test('ATTACK: the app cannot reconfigure the server it runs on', async () => {
    // CONFIG SET dir + CONFIG SET dbfilename is how a Redis becomes a file
    // writer. -@admin is the rule that removes it.
    for (const sql of [['CONFIG', 'GET', 'dir'], ['CONFIG', 'SET', 'dir', '/tmp'], ['MODULE', 'LIST'],
      ['REPLICAOF', 'NO', 'ONE'], ['SHUTDOWN', 'NOSAVE'], ['ACL', 'LIST']]) {
      const r = await asUser(rowA.container_name, { ...a, sql });
      assert.ok(!r.ok, `${sql.join(' ')} succeeded — the app's user holds @admin: ${r.out}`);
      assert.match(r.out, /^NOPERM/, `${sql.join(' ')}: expected NOPERM, got ${r.out}`);
    }
    // Still alive after all that.
    const alive = await asUser(rowA.container_name, { ...a, sql: ['PING'] });
    assert.ok(alive.ok, `the instance died during the attacks: ${alive.out}`);
  });

  await t.test('the app KEEPS the commands real apps actually use', async () => {
    // The other half of the -@admin decision. Denying @dangerous would have
    // been tidier and would break Sidekiq, BullMQ and every Redis dashboard.
    for (const sql of [['INFO', 'server'], ['CLIENT', 'SETNAME', 'x'], ['KEYS', '*'],
      ['DBSIZE'], ['SCRIPT', 'LOAD', 'return 1'], ['ACL', 'WHOAMI']]) {
      const r = await asUser(rowA.container_name, { ...a, sql });
      assert.ok(r.ok, `${sql.join(' ')} was denied — real apps call this: ${r.out}`);
    }
  });

  await t.test('memory is bounded and a full instance ERRORS instead of evicting', async () => {
    const info = await asUser(rowA.container_name, { ...a, sql: ['INFO', 'memory'] });
    assert.ok(info.ok, info.out);
    const maxmemory = Number(/^maxmemory:(\d+)/m.exec(info.out)?.[1]);
    assert.ok(maxmemory > 0, `an unbounded Redis on a shared box is an outage waiting: ${info.out}`);
    // 128 MB container ceiling for this run -> 96 MB maxmemory, and it must sit
    // BELOW the cgroup wall or "OOM command not allowed" becomes exit 137.
    assert.equal(maxmemory, mrds.maxmemoryMbFor(128) * 1024 * 1024);
    assert.match(info.out, /maxmemory_policy:noeviction/,
      'allkeys-lru answers a full queue by deleting queued jobs, silently');
  });

  await t.test('the modules the image ships are actually loaded', async () => {
    // Running `redis-server` directly instead of through docker-entrypoint.sh
    // starts a Redis with none of them and says nothing. The app's user is
    // denied MODULE LIST, so this asks as the admin does — over REDISCLI_AUTH,
    // with no credential in argv.
    const { stdout } = await execFileAsync('docker', [
      'exec', rowA.container_name, 'redis-cli', 'MODULE', 'LIST',
    ], { timeout: 60000 });
    for (const mod of ['search', 'ReJSON']) {
      assert.ok(stdout.includes(mod), `module ${mod} not loaded — the entrypoint was bypassed:\n${stdout}`);
    }
  });

  await t.test('provisioning is idempotent — a redeploy gets the SAME instance', async () => {
    const again = await mdb.provision({ appId: APP_A }, 'redis');
    assert.equal(again.password, a.password);
    assert.equal(again.port, a.port);
    assert.equal(again.username, a.username);
    const n = getDb().prepare('SELECT COUNT(*) c FROM managed_databases WHERE app_id = ? AND engine = ?')
      .get(APP_A, 'redis').c;
    assert.equal(n, 1);
  });

  await t.test('an instance removed behind AppCrane\'s back comes back with its data', async () => {
    await asUser(rowA.container_name, { ...a, sql: ['SET', 'survives', 'A-DATA'] });
    // Redis only writes an RDB on its own schedule; force one so the restart
    // has something to load. This asserts the VOLUME is wired up, not that
    // Redis persists by magic.
    await execFileAsync('docker', ['exec', rowA.container_name, 'redis-cli', 'SAVE'], { timeout: 60000 });
    await execFileAsync('docker', ['rm', '-f', rowA.container_name], { timeout: 60000 });

    const back = await mdb.provision({ appId: APP_A }, 'redis');
    assert.equal(back.password, a.password, 'the credential must survive a recreate');
    assert.equal(back.port, a.port);
    const r = await asUser(rowA.container_name, { ...a, sql: ['GET', 'survives'] });
    assert.ok(r.ok && r.out.includes('A-DATA'), `the volume did not survive: ${r.out}`);
  });

  await t.test('the data directory lives under DATA_DIR, and the init credential does not', () => {
    const dir = join(process.env.DATA_DIR, 'managed-db', 'redis', rowA.db_name);
    assert.ok(existsSync(dir), `expected ${dir}`);
    assert.ok(!existsSync(join(dir, '.init-env')),
      'the plaintext password file must be deleted after the container starts');
  });

  await t.test('deprovision destroys the instance and its data, and leaves app B alone', async () => {
    const dir = join(process.env.DATA_DIR, 'managed-db', 'redis', rowA.db_name);
    assert.equal(await mdb.deprovision({ appId: APP_A }, 'redis'), true);
    assert.equal(mdb.credentialsFor({ appId: APP_A }, 'redis'), null);

    const gone = await execFileAsync('docker', ['inspect', '-f', '{{.State.Status}}', rowA.container_name])
      .then(() => ({ ok: true }), () => ({ ok: false }));
    assert.ok(!gone.ok, 'the container must be removed, not merely stopped');
    // The volume goes too. Leaving it would hand a later scope that derived the
    // same name a stranger's keyspace.
    assert.ok(!existsSync(dir), `the data directory survived deprovision: ${dir}`);

    const survivor = await asUser(rowB.container_name, { ...b, sql: ['GET', 'secrets'] });
    assert.ok(survivor.ok && survivor.out.includes('B-SECRET'),
      `deprovisioning app A damaged app B: ${survivor.out}`);

    assert.equal(await mdb.deprovision({ appId: APP_A }, 'redis'), false, 'must be idempotent');
  });

  await t.test('the freed port is available again', () => {
    const used = getDb().prepare('SELECT host_port FROM managed_databases WHERE host_port IS NOT NULL')
      .all().map(r => Number(r.host_port));
    assert.ok(!used.includes(rowA.host_port));
    assert.equal(mrds.pickPort(used), rowA.host_port,
      'the lowest free port after A left should be the one A had');
  });

  await t.test('deprovisionApp clears the redis instance too', async () => {
    const res = await mdb.deprovisionApp(APP_B);
    assert.ok(res.dropped >= 1);
    assert.equal(mdb.listForApp(APP_B).length, 0);
    const left = readdirSync(join(process.env.DATA_DIR, 'managed-db', 'redis'));
    assert.deepEqual(left, [], `orphaned instance data: ${left.join(', ')}`);
  });
});

test('an app container on appcrane-apps reaches its Redis over the URL AppCrane injects',
  { skip: noDocker, timeout: 600000 }, async (t) => {
  // THE CLAIM THE WHOLE DESIGN RESTS ON, for Redis this time. enable_icc=false
  // means the app cannot route to the instance over the docker network, so it
  // goes out through host.docker.internal — and a loopback-only publish is
  // unreachable that way on Linux. See the measurement table in managedDb.js.
  //
  // And it uses `creds.url` VERBATIM, not a reassembled host/port: the URL is
  // what deployer.js injects, so a URL that does not round-trip is a broken
  // deploy no unit test would catch.
  const { ensureAppNetwork } = await import('../server/services/docker.js');
  const network = await ensureAppNetwork();

  const conn = await mdb.provision({ appId: APP_A }, 'redis');

  await t.test('redis-cli -u <the injected URL>, from inside the isolated app network', async () => {
    const { stdout } = await execFileAsync('docker', [
      'run', '--rm',
      '--network', network,
      '--add-host', 'host.docker.internal:host-gateway',
      mrds.REDIS_IMAGE,
      'redis-cli', '-u', conn.url, '--no-auth-warning', 'SET', 'reached', 'REACHED',
    ], { timeout: 120000 });
    assert.equal(stdout.trim(), 'OK', `the injected URL did not round-trip: ${stdout}`);

    const read = await execFileAsync('docker', [
      'run', '--rm', '--network', network, '--add-host', 'host.docker.internal:host-gateway',
      mrds.REDIS_IMAGE, 'redis-cli', '-u', conn.url, '--no-auth-warning', 'GET', 'reached',
    ], { timeout: 120000 });
    assert.equal(read.stdout.trim(), 'REACHED');
  });

  await t.test("but that container cannot open another app's instance", async () => {
    const other = await mdb.provision({ appId: APP_B }, 'redis');
    const stolen = conn.url.replace(`:${conn.port}/`, `:${other.port}/`);
    const { stdout, stderr } = await execFileAsync('docker', [
      'run', '--rm', '--network', network, '--add-host', 'host.docker.internal:host-gateway',
      mrds.REDIS_IMAGE, 'redis-cli', '-u', stolen, '--no-auth-warning', 'SET', 'pwned', '1',
    ], { timeout: 120000 });
    assert.match(stderr.trim(), /AUTH failed: WRONGPASS/,
      `an app container authenticated against a sibling's Redis — ISOLATION BROKEN: ${stderr}`);
    assert.match(stdout.trim(), /^NOAUTH/,
      `the write was ACCEPTED against a sibling's Redis: ${stdout}`);
  });

  await mdb.deprovisionApp(APP_A);
  await mdb.deprovisionApp(APP_B);
});

test('serverStatus reports redis without ever provisioning it', { skip: noDocker, timeout: 600000 }, async (t) => {
  await t.test('with nothing provisioned it is reported as absent, not omitted', async () => {
    const servers = await mdb.serverStatus();
    const r = servers.find(s => s.engine === 'redis');
    assert.ok(r, 'redis must appear in the status list even with no instances');
    assert.equal(r.configured, false);
    assert.equal(r.running, false);
    assert.equal(r.databases, 0);
    assert.deepEqual(r.instances, []);
    // Per-scope: there is no single container or port, and reporting a
    // placeholder would be a lie a dashboard would render as fact.
    assert.equal(r.container, null);
    assert.equal(r.host_port, null);
    assert.equal(r.image, mrds.REDIS_IMAGE);
  });

  await t.test('a live instance shows up with its real docker facts', async () => {
    await mdb.provision({ appId: APP_A }, 'redis');
    const r = (await mdb.serverStatus()).find(s => s.engine === 'redis');
    assert.equal(r.configured, true);
    assert.equal(r.running, true);
    assert.equal(r.databases, 1);
    assert.equal(r.instances.length, 1);
    const i = r.instances[0];
    assert.equal(i.state, 'running');
    assert.equal(i.running, true);
    assert.equal(i.scope.app_id, APP_A);
    assert.equal(i.memory_mb, 128, 'the cap the RUNNING container has, not the configured one');
    assert.ok(i.host_port >= mrds.REDIS_PORT_MIN && i.host_port <= mrds.REDIS_PORT_MAX);
    assert.equal(i.oom_killed, false);
  });

  await t.test('ONE dead instance among several makes the aggregate NOT running', async () => {
    // TWO instances, one killed. With a single instance "every running" and
    // "some running" are the same expression, so a one-instance version of this
    // test cannot tell them apart — verified by flipping every() to some() in
    // the production line and watching it stay green.
    await mdb.provision({ appId: APP_B }, 'redis');
    const row = getDb().prepare('SELECT container_name FROM managed_databases WHERE app_id = ? AND engine = ?')
      .get(APP_A, 'redis');
    await execFileAsync('docker', ['stop', row.container_name], { timeout: 60000 });

    const r = (await mdb.serverStatus()).find(s => s.engine === 'redis');
    assert.equal(r.instances.length, 2);
    assert.ok(r.instances.some(i => i.running), 'the surviving instance should still read as up');
    assert.equal(r.running, false, 'a fleet with a dead instance must not read as green');
    assert.equal(r.instances.find(i => i.container === row.container_name).running, false);

    // ...and reporting it must not have RESTARTED it. serverStatus is polled.
    const state = await execFileAsync('docker', ['inspect', '-f', '{{.State.Status}}', row.container_name]);
    assert.equal(state.stdout.trim(), 'exited', 'serverStatus must never start anything');
  });

  await mdb.deprovisionApp(APP_A);
  await mdb.deprovisionApp(APP_B);
});
