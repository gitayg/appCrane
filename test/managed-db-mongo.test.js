import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import crypto from 'crypto';

const execFileAsync = promisify(execFile);

// Managed MongoDB (server/services/managedMongo.js + the mongo branches of
// server/services/managedDb.js).
//
// THE REQUIREMENT IS THE ONE test/managed-db.test.js EXISTS FOR: "an app's
// credentials must reach that app's data and NOTHING else." Mongo is on the
// SHARED-SERVER side of that file, with Postgres and MariaDB, so the attacks
// below are the SQL file's attacks retargeted — one credential, one server,
// every other app's data one `getSiblingDB()` away.
//
// Every denial is paired with a CONTROL that must SUCCEED. A test where
// everything fails proves nothing: a mistyped username is denied too, and that
// exact mistake (destructuring `user` from a `{ username }` object) once turned
// the SQL file's whole attack suite green against a role that did not exist.
//
// Two things here have no counterpart in the SQL file, and both are the ones
// most likely to be broken silently:
//
//   * THE REPLICA SET. Rocket.Chat is a Meteor app and cannot start against a
//     standalone mongod. A set that failed to initiate does not look broken —
//     inserts and reads still work — so the tests assert on the two features
//     that ONLY a replica set provides: change streams and multi-document
//     transactions.
//   * THE MEMBER HOST. A client that does replica set discovery follows the
//     config, not the URL. Measured, the default injected URL does NOT discover
//     — a single seed with no `replicaSet=` keeps talking to the seed and works
//     even against a set configured for 127.0.0.1 — but the same URL with
//     `?replicaSet=rs0` answers `ECONNREFUSED 127.0.0.1`. So the assertion below
//     is on the CONFIG the server advertises rather than on whether this
//     particular client survived it, which is the version that catches the
//     regression before an operator appending a query string does.
//
// And the injected-URL round trip, because the design deliberately puts NO
// query string on the URL: deployer.js rebuilds it from the discrete fields and
// would drop an `?authSource=`, so the fact that it does not need one is a
// property this file has to hold onto.

const SUFFIX = crypto.randomBytes(4).toString('hex');
const PREFIX = `crane-mgotest-${SUFFIX}`;
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mmgo-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
// A per-RUN unique prefix and port, not fixed ones. Fixed names are how two
// concurrent runs of test/managed-db.test.js collide on the same container, and
// a fixed port is how a run adopts — or fails to bind against — a real managed
// server on a developer's machine.
process.env.MANAGED_DB_CONTAINER_PREFIX = PREFIX;
process.env.MANAGED_DB_MONGO_PORT = String(48600 + (parseInt(SUFFIX, 16) % 300));

let dockerOk = false;
try {
  execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 10000, stdio: 'pipe' });
  dockerOk = true;
} catch (_) { /* left false */ }
const noDocker = dockerOk ? false : 'no reachable Docker daemon on this host';

const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const mgo = await import('../server/services/managedMongo.js');
const { managedDbUrl } = await import('../server/services/deployer.js');

let APP_A;
let APP_B;

before(() => {
  initDb(process.env.DATA_DIR);
  const db = getDb();
  const ins = db.prepare('INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)');
  APP_A = Number(ins.run('Mongo App A', `mgo-a-${SUFFIX}`, 901).lastInsertRowid);
  APP_B = Number(ins.run('Mongo App B', `mgo-b-${SUFFIX}`, 902).lastInsertRowid);
});

after(async () => {
  if (dockerOk) await mdb.stopServer('mongo').catch(() => {});
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

// ---------------------------------------------------------------------------
// Pure — no daemon needed
// ---------------------------------------------------------------------------

test('mongo is a supported engine, and a SHARED-SERVER one', () => {
  assert.ok(mdb.SUPPORTED_ENGINES.includes('mongo'));
  // The distinction that matters: Redis gets a container per scope because it
  // cannot isolate inside one server. Mongo can, so it must not accidentally be
  // handled by the per-scope path — which allocates a port and a container name
  // per app and would leave the shared server unused.
  assert.ok(mdb.SHARED_SERVER_ENGINES.includes('mongo'));
  assert.equal(mdb.isPerScopeEngine('mongo'), false);
});

test('migration 085 already carries mongo — no engine CHECK to widen', () => {
  // 085 deliberately put no CHECK on `engine` (SQLite cannot ALTER one, so it
  // would force a table rebuild the first time an engine is added). If that
  // ever changes, adding an engine silently stops working at the INSERT and
  // this is where it should be caught.
  const sql = getDb().prepare(
    "SELECT sql FROM sqlite_master WHERE type='table' AND name='managed_databases'"
  ).get().sql;
  assert.equal(/CHECK/i.test(sql), false, `managed_databases has a CHECK constraint: ${sql}`);

  const ins = getDb().prepare(`
    INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc)
    VALUES (?, '', 'mongo', ?, ?, 'x')
  `);
  ins.run(APP_A, `probe_${SUFFIX}`, `probe_${SUFFIX}_u`);
  getDb().prepare("DELETE FROM managed_databases WHERE db_name LIKE 'probe_%'").run();
});

test('the run command keeps the key out of argv and the entrypoint in', () => {
  const cmd = mgo.serverCommand(47017);
  const line = cmd.join(' ');

  // The literal `$APPCRANE_MONGO_KEYFILE`, expanded by the container's own
  // shell from an --env-file. Interpolating the key here would put it in the
  // host's process table for every local user to read.
  assert.match(line, /"\$APPCRANE_MONGO_KEYFILE"/);
  assert.equal(/printf '%s' (?!"\$APPCRANE_MONGO_KEYFILE")/.test(line), false,
    'the key must never be a literal in argv');

  // docker-entrypoint.sh, not mongod: the entrypoint is what creates the
  // superuser on an empty data directory. Bypassing it starts a server with no
  // root user and nothing can ever be provisioned in it.
  assert.match(line, /exec docker-entrypoint\.sh mongod/);

  // The replica set, without which Rocket.Chat cannot start.
  assert.match(line, new RegExp(`--replSet ${mgo.MONGO_REPLICA_SET}\\b`));
  // Internal auth is mandatory once auth and replication are both on; mongod
  // refuses to start with `security.keyFile is required` otherwise.
  assert.match(line, /--keyFile \/tmp\//);
  // 0400 and owned by the runtime user, or mongod rejects the key as too open.
  assert.match(line, /chmod 400/);
  assert.match(line, /chown mongodb/);
  // The port is mirrored, and bind_ip_all is what makes the routable-address
  // readiness probe (and the published port) work at all.
  assert.match(line, /--port 47017\b/);
  assert.match(line, /--bind_ip_all/);

  // No `umask`. It was the first spelling of the keyfile permissions and it
  // applies to the ENTRYPOINT'S file creation too — the run died with
  // `/data/db/journal: directory-list: opendir` / Permission denied.
  assert.equal(/umask/.test(line), false, 'umask breaks the entrypoint\'s own data directory setup');
});

test('the run command refuses a port that is not a port', () => {
  for (const bad of [0, -1, 70000, 'abc', null, undefined, 47017.5]) {
    assert.throws(() => mgo.serverCommand(bad), /must be a valid TCP port/);
  }
});

test('the keyfile is derived, stable, and in the alphabet mongod accepts', () => {
  const k1 = mgo.keyfileFor('AbC-123_xyz');
  // Stable for the life of the volume: a key that changed on every recreate
  // would leave a replica set that cannot authenticate to itself.
  assert.equal(k1, mgo.keyfileFor('AbC-123_xyz'));
  assert.notEqual(k1, mgo.keyfileFor('AbC-123_xyZ'));
  // STANDARD base64, not base64url. Generated passwords are base64url, whose
  // '-' and '_' are outside a keyfile's permitted alphabet — which is the whole
  // reason the key is a hash of the password rather than the password.
  assert.match(k1, /^[A-Za-z0-9+/]+=*$/);
  assert.ok(k1.length >= 6 && k1.length <= 1024);
  assert.throws(() => mgo.keyfileFor(''), /empty password/);
});

test('the env file carries the init credentials and the derived key, and nothing else', () => {
  const body = mgo.envFileBody('AbC-123_xyz');
  const keys = body.trim().split('\n').map(l => l.split('=')[0]).sort();
  assert.deepEqual(keys, ['APPCRANE_MONGO_KEYFILE', 'MONGO_INITDB_ROOT_PASSWORD', 'MONGO_INITDB_ROOT_USERNAME']);
  assert.ok(body.includes('MONGO_INITDB_ROOT_PASSWORD=AbC-123_xyz\n'));
  assert.ok(body.includes(`APPCRANE_MONGO_KEYFILE=${mgo.keyfileFor('AbC-123_xyz')}\n`));
});

test('the container maps the app-facing hostname to its own loopback', () => {
  // This one line is what removes the NAT hairpin from replica set initiation.
  // `host.docker.internal:PORT` has to mean "me" inside this container and
  // "the host gateway" inside an app container; --add-host is what makes one
  // string carry both meanings. Remove it and rs.initiate depends on the host
  // reflecting a published port back into the container that published it.
  assert.deepEqual(mgo.extraRunArgs('host.docker.internal'), ['--add-host', 'host.docker.internal:127.0.0.1']);
});

test('the readiness probe carries no credential and does not target the container loopback', () => {
  const args = mgo.readyProbeArgs('c1', 47017);
  const line = args.join(' ');
  // 127.0.0.1 inside the container is where the image's TEMPORARY init server
  // binds, so a loopback probe goes green in the middle of initialisation and
  // provisioning lands on a server about to be shut down and reinitialised.
  assert.equal(/127\.0\.0\.1/.test(line), false, 'the probe must not target the init server\'s address');
  assert.match(line, /hostname -i/);
  assert.match(line, /--port 47017\b/);
  assert.match(line, /db\.hello\(\)/);
  assert.equal(/-u |-p |--username|--password/.test(line), false, 'the probe must carry no credential');
});

test('admin scripts run with --file, not as a piped REPL', () => {
  const line = mgo.adminShellArgs('c1', 47017).join(' ');
  // MEASURED, and this is the whole reliability of provisioning:
  //   printf "throw new Error('BOOM')" | mongosh --quiet                    -> exit 0
  //   printf "throw new Error('BOOM')" | mongosh --quiet --file /dev/stdin  -> exit 1
  // A piped REPL reports a failed createUser as a successful provision.
  assert.match(line, /--file \/dev\/stdin/);
  assert.equal(/-u |-p |--username|--password/.test(line), false, 'no credential may reach argv');
  assert.ok(mgo.adminShellArgs('c1', 47017).includes('-i'), 'the script arrives on stdin');
});

test('the app user is created in its OWN database, with readWrite + dbAdmin only', () => {
  const s = mgo.createUserScript({
    adminPassword: 'ADMINPW', database: 'crane_a7', username: 'crane_a7_u', password: 'APPPW',
  });
  // In its own database, which makes that database the authSource — the reason
  // the injected URL needs no query string.
  assert.match(s, /getSiblingDB\("crane_a7"\)\.createUser/);
  assert.equal(/getSiblingDB\('admin'\)\.createUser|getSiblingDB\("admin"\)\.createUser/.test(s), false,
    'a user created in admin would need ?authSource=admin, which deployer.js drops');

  // Both roles, both scoped. `readWrite` alone cannot collMod (TTL index
  // changes) or drop its own database — measured.
  assert.match(s, /role: 'readWrite', db: "crane_a7"/);
  assert.match(s, /role: 'dbAdmin', db: "crane_a7"/);

  // An exact set, not a forbidden list. A denylist has to guess the name of the
  // next over-broad role someone reaches for; this cannot be widened at all
  // without the test noticing. (It also cannot be written as a substring check:
  // 'root' appears in the script as the SUPERUSER'S NAME on the auth line, and
  // an earlier draft of this test failed on exactly that.)
  const granted = [...s.matchAll(/role: '([^']+)'/g)].map(m => m[1]).sort();
  assert.deepEqual(granted, ['dbAdmin', 'readWrite'],
    'clusterMonitor is server-wide, dbOwner adds only userAdmin, and anything *AnyDatabase is the whole platform');
  // No role may be scoped to anything but this app's database.
  const scopes = [...s.matchAll(/role: '[^']+', db: "([^"]+)"/g)].map(m => m[1]);
  assert.equal(scopes.length, granted.length, 'every role must carry an explicit database scope');
  for (const d of scopes) assert.equal(d, 'crane_a7');
  assert.equal(/anyResource|AnyDatabase|privileges/.test(s), false, s);
});

test('the replica set script initiates once, waits for a primary, and refuses a mismatched config', () => {
  const s = mgo.initiateScript({ adminPassword: 'ADMINPW', memberHost: 'host.docker.internal:47017' });
  assert.match(s, /replSetInitiate/);
  assert.match(s, /"host\.docker\.internal:47017"/);
  // Guarded by hello().setName rather than a try/catch: a second initiate
  // answers `already initialized`, and this runs on EVERY ensureServer().
  assert.match(s, /db\.hello\(\)\.setName === undefined/);
  // A write immediately after initiate goes to a node that has not been elected
  // yet unless this wait is here.
  assert.match(s, /isWritablePrimary/);
  // The mismatch check. A config naming an unpublished port leaves every app
  // hanging on "no primary" with a URL that looks perfectly correct.
  assert.match(s, /replSetGetConfig/);
  assert.match(s, /throw new Error\("replica set is configured for/);
  // It is a real script, not a fragment.
  assert.doesNotThrow(() => new Function(s));
});

test('the drop script removes the user before the data, and tolerates a missing user', () => {
  const s = mgo.dropScript({ adminPassword: 'ADMINPW', database: 'crane_a7', username: 'crane_a7_u' });
  assert.ok(s.indexOf('dropUser') < s.indexOf('dropDatabase'),
    'a live credential over surviving data is worse than data nothing can open');
  assert.match(s, /UserNotFound/);
  assert.doesNotThrow(() => new Function(s));
});

test('the injected URL survives deployer.js rebuilding it — no query string to lose', () => {
  const creds = {
    engine: 'mongo', host: 'host.docker.internal', port: 47017,
    database: 'crane_a7', username: 'crane_a7_u', password: 'AbC-123_xyz',
    url: mgo.mongoUrl({
      username: 'crane_a7_u', password: 'AbC-123_xyz',
      host: 'host.docker.internal', port: 47017, database: 'crane_a7',
    }),
  };
  assert.equal(creds.url, 'mongodb://crane_a7_u:AbC-123_xyz@host.docker.internal:47017/crane_a7');
  assert.equal(creds.url.includes('?'), false, 'a query string here is silently dropped by deployer.js');
  // deployer.js rebuilds the URL from the discrete fields, taking only the
  // scheme from `url`. If they ever disagree, the app gets a URL AppCrane never
  // tested.
  assert.equal(managedDbUrl(creds), creds.url);
});

// ---------------------------------------------------------------------------
// Against a real daemon
// ---------------------------------------------------------------------------

/** Run a mongosh script as a given app's credentials, from OUTSIDE the server. */
async function asApp(network, conn, script, { database = conn.database } = {}) {
  // `username`, not `user` — connectionFor() returns `username`, and a helper
  // that reads the wrong key connects as the user literally named "undefined",
  // is denied everything, and turns every attack below green while proving
  // nothing. The CONTROL tests are what catch it; this assertion is cheaper.
  assert.ok(conn.username && conn.password, 'a denial against empty credentials proves nothing');
  const url = `mongodb://${conn.username}:${conn.password}@${conn.host}:${conn.port}/${database}`;
  const args = [
    'run', '--rm', '-i',
    '--network', network,
    '--add-host', 'host.docker.internal:host-gateway',
    '--entrypoint', 'sh', mgo.MONGO_IMAGE,
    '-c', `exec mongosh ${JSON.stringify(url)} --quiet --file /dev/stdin`,
  ];
  return new Promise((resolve) => {
    const child = execFile('docker', args, { timeout: 180000 }, (err, stdout, stderr) => {
      const out = `${stdout || ''}${stderr || ''}`.trim();
      resolve({ ok: !err, out });
    });
    child.stdin.end(script);
  });
}

test('mongo provisions, isolates, and deprovisions', { skip: noDocker, timeout: 900000 }, async (t) => {
  const { ensureAppNetwork } = await import('../server/services/docker.js');
  const network = await ensureAppNetwork();

  const a = await mdb.provision({ appId: APP_A }, 'mongo');
  const b = await mdb.provision({ appId: APP_B }, 'mongo');

  await t.test('the server is published on loopback and never on a wildcard', async () => {
    const { stdout } = await execFileAsync('docker', ['port', `${PREFIX}-mongo`]);
    const lines = stdout.trim().split('\n').filter(Boolean);
    assert.ok(lines.length > 0);
    assert.ok(lines.some(l => l.includes('127.0.0.1:')), `expected a loopback publish, got:\n${stdout}`);
    for (const line of lines) {
      assert.ok(!/(^|\s|>)0\.0\.0\.0:/.test(line) && !/\[::\]:/.test(line),
        `a managed database must never be published on a wildcard address, got: ${line}`);
    }
    // The mirrored port. `47017/tcp -> 127.0.0.1:47017`, not `27017/tcp -> ...`:
    // the replica set config names one host:port and it has to be the same
    // number on both sides.
    assert.ok(lines.every(l => l.startsWith(`${a.port}/tcp`)),
      `the container port must mirror the host port, got:\n${stdout}`);
  });

  await t.test('credentials are returned to the caller but stored encrypted', () => {
    assert.match(a.password, /^[A-Za-z0-9_-]{24,}$/);
    assert.notEqual(a.password, b.password);
    assert.equal(a.host, 'host.docker.internal');
    assert.equal(a.url, `mongodb://${a.username}:${a.password}@${a.host}:${a.port}/${a.database}`);

    const row = getDb().prepare('SELECT password_enc FROM managed_databases WHERE app_id = ? AND engine = ?')
      .get(APP_A, 'mongo');
    assert.ok(!row.password_enc.includes(a.password), 'the stored blob must not contain the plaintext');
    assert.match(row.password_enc, /^[0-9a-f]{32}:[0-9a-f]{32}:/);
    const listed = mdb.listForApp(APP_A).find(r => r.engine === 'mongo');
    assert.equal(listed.password_enc, undefined);
  });

  await t.test('provisioning is idempotent — a redeploy gets the SAME database', async () => {
    const again = await mdb.provision({ appId: APP_A }, 'mongo');
    assert.equal(again.database, a.database);
    assert.equal(again.password, a.password);
    assert.equal(getDb().prepare(
      'SELECT COUNT(*) c FROM managed_databases WHERE app_id = ? AND engine = ?'
    ).get(APP_A, 'mongo').c, 1);
  });

  // ---- CONTROL. Without this, every denial below could be a broken client.
  await t.test('CONTROL: each app reaches its own database from an app container', async () => {
    for (const conn of [a, b]) {
      const r = await asApp(network, conn,
        `db.secrets.insertOne({_id:'s1', v:${JSON.stringify(conn.database)}});\n`
        + "print('WROTE ' + db.secrets.findOne()._id);\n");
      assert.ok(r.ok, `an app could not use its OWN database: ${r.out}`);
      assert.match(r.out, /WROTE s1/);
    }
  });

  await t.test('CONTROL: the credential really is a replica set primary', async () => {
    // If the set failed to initiate, inserts and reads still work — nothing
    // looks broken until Rocket.Chat refuses to boot. Change streams and
    // multi-document transactions exist ONLY on a replica set, so they are the
    // assertions that can tell the difference.
    const r = await asApp(network, a, [
      "print('SET ' + db.hello().setName);",
      "print('HOSTS ' + JSON.stringify(db.hello().hosts));",
      "print('PRIMARY ' + db.hello().isWritablePrimary);",
      "const cs = db.secrets.watch(); cs.close(); print('CHANGESTREAM ok');",
      "const s = db.getMongo().startSession(); s.startTransaction();",
      `s.getDatabase(${JSON.stringify(a.database)}).secrets.insertOne({_id:'txn'});`,
      "s.commitTransaction(); print('TXN ok');",
      '',
    ].join('\n'));
    assert.ok(r.ok, r.out);
    assert.match(r.out, new RegExp(`SET ${mgo.MONGO_REPLICA_SET}`));
    assert.match(r.out, /PRIMARY true/);
    assert.match(r.out, /CHANGESTREAM ok/);
    assert.match(r.out, /TXN ok/);
    // THE MEMBER HOST, asserted on the SERVER's config rather than on this
    // client's survival. Measured: a single-seed URL with no `replicaSet=` — the
    // one AppCrane injects — keeps talking to the seed and writes successfully
    // even against a set configured for 127.0.0.1, so "the app worked" does not
    // prove the config is right. Add `?replicaSet=rs0` and the same URL answers
    // `ECONNREFUSED 127.0.0.1`. This line is what fails first instead.
    assert.match(r.out, new RegExp(`HOSTS \\["${a.host}:${a.port}"\\]`));
  });

  await t.test("ATTACK: A cannot read or write B's database", async () => {
    const read = await asApp(network, a, `print(JSON.stringify(db.getSiblingDB(${JSON.stringify(b.database)}).secrets.findOne()));\n`);
    assert.ok(!read.ok, `app A read app B's data — ISOLATION BROKEN: ${read.out}`);
    assert.match(read.out, new RegExp(`not authorized on ${b.database}`));

    const write = await asApp(network, a, `db.getSiblingDB(${JSON.stringify(b.database)}).evil.insertOne({x:1});\n`);
    assert.ok(!write.ok, `app A wrote into app B's database — ISOLATION BROKEN: ${write.out}`);
    assert.match(write.out, new RegExp(`not authorized on ${b.database}`));

    // Authenticating AGAINST B's database with A's credential, rather than
    // reaching sideways from A's — a different code path in the server, and the
    // one a client would take if the URL were edited.
    const direct = await asApp(network, a, "print('IN');\n", { database: b.database });
    assert.ok(!direct.ok, `app A authenticated against app B's database: ${direct.out}`);
  });

  await t.test('ATTACK: A cannot read the oplog, which carries every app\'s writes', async () => {
    // local.oplog.rs is the one collection on a replica set that would defeat
    // the whole design: it records the operations of EVERY database. The
    // rocketchat catalogue entry's note mentions MONGO_OPLOG_URL for exactly
    // this collection, and this is why AppCrane does not provision one.
    const r = await asApp(network, a, "print(JSON.stringify(db.getSiblingDB('local').oplog.rs.findOne()));\n");
    assert.ok(!r.ok, `an app read the oplog — every other app's writes are exposed: ${r.out}`);
    assert.match(r.out, /not authorized on local/);
  });

  await t.test('ATTACK: A cannot read the credential store or administer the server', async () => {
    for (const [label, js, expect] of [
      ['admin.system.users', "db.getSiblingDB('admin').system.users.findOne()", /not authorized on admin/],
      ['createUser', "db.createUser({user:'evil',pwd:'xxxxxxxxxxxxxxxxxxxxxxxx',roles:[]})", /not authorized on/],
      ['grant self root', "db.getSiblingDB('admin').runCommand({grantRolesToUser:'x',roles:[{role:'root',db:'admin'}]})", /not authorized on admin/],
      ['replSetReconfig', "db.adminCommand({replSetReconfig:{_id:'rs0',version:9,members:[{_id:0,host:'evil:1'}]}})", /not authorized on admin/],
      ['shutdown', 'db.adminCommand({shutdown:1})', /not authorized on admin/],
      ['setParameter', 'db.adminCommand({setParameter:1,logLevel:5})', /not authorized on admin/],
      ['serverStatus', 'db.adminCommand({serverStatus:1})', /not authorized on admin/],
    ]) {
      const r = await asApp(network, a, `const x = ${js}; if (x && x.ok === 0) throw new Error(x.errmsg); print('ALLOWED ' + JSON.stringify(x));\n`);
      assert.ok(!r.ok, `an app was allowed to ${label}: ${r.out}`);
      assert.match(r.out, expect, `${label} was refused for the wrong reason: ${r.out}`);
    }
  });

  await t.test("ATTACK: A cannot even see that B's database exists", async () => {
    // Stricter than Postgres, which leaks every database NAME through
    // pg_database with no supported way to stop it. Mongo filters
    // listDatabases by authorization.
    const r = await asApp(network, a, "print('DBS ' + JSON.stringify(db.adminCommand({listDatabases:1}).databases.map(d=>d.name)));\n");
    assert.ok(r.ok, r.out);
    assert.match(r.out, new RegExp(`DBS \\["${a.database}"\\]`));
    assert.equal(r.out.includes(b.database), false, `app A can see app B's database name: ${r.out}`);
  });

  await t.test('ATTACK: an unauthenticated connection gets nothing', async () => {
    const r = await asApp(network, { username: 'nobody', password: 'wrongwrongwrongwrongwrong', host: a.host, port: a.port, database: a.database },
      "print('IN');\n");
    assert.ok(!r.ok, `the server accepted a bogus credential: ${r.out}`);
    assert.match(r.out, /Authentication failed/i);
  });

  await t.test('CONTROL: the app owns its own schema — indexes, collMod, its own drop', async () => {
    // The reason `readWrite` alone was not enough. An app that cannot collMod
    // cannot change a TTL index on upgrade, which is a normal Meteor operation.
    const r = await asApp(network, b, [
      "db.ttl.createIndex({t:1},{expireAfterSeconds:60});",
      "print('COLLMOD ' + JSON.stringify(db.runCommand({collMod:'ttl', index:{keyPattern:{t:1}, expireAfterSeconds:120}}).ok));",
      "db.createCollection('made_by_app'); print('CREATECOLL ok');",
      '',
    ].join('\n'));
    assert.ok(r.ok, r.out);
    assert.match(r.out, /COLLMOD 1/);
    assert.match(r.out, /CREATECOLL ok/);
  });

  await t.test('deprovision drops the user AND the data, and is idempotent', async () => {
    const gone = await mdb.deprovision({ appId: APP_B }, 'mongo');
    assert.equal(gone, true);
    assert.equal(mdb.listForApp(APP_B).length, 0);

    // The credential must stop working. A dropped row with a live user is an
    // orphan holding a deleted app's data.
    const r = await asApp(network, b, "print('STILL IN');\n");
    assert.ok(!r.ok, `a deprovisioned credential still authenticates: ${r.out}`);

    assert.equal(await mdb.deprovision({ appId: APP_B }, 'mongo'), false);
  });

  await t.test('deprovisionApp removes what is left', async () => {
    const res = await mdb.deprovisionApp(APP_A);
    assert.ok(res.dropped >= 1);
    assert.equal(mdb.listForApp(APP_A).length, 0);
  });
});

test('the data directory lives under DATA_DIR and the init credential does not survive the run',
  { skip: noDocker, timeout: 600000 }, async () => {
  await mdb.ensureServer('mongo');
  const dir = join(process.env.DATA_DIR, 'managed-db', 'mongo');
  assert.ok(existsSync(dir));
  // The env file carries the superuser password AND the replica set's internal
  // auth key. Leaving it behind puts both on disk in plaintext for the life of
  // the volume.
  assert.ok(!existsSync(join(dir, '.init-env')),
    'the superuser/keyfile env file must be deleted after the container starts');
});

test('serverStatus reports mongo as a shared server, with no secret in it',
  { skip: noDocker, timeout: 600000 }, async () => {
  await mdb.ensureServer('mongo');
  const rows = await mdb.serverStatus();
  const row = rows.find(r => r.engine === 'mongo');
  assert.ok(row, 'mongo must appear in serverStatus');
  assert.equal(row.running, true);
  assert.equal(row.container, `${PREFIX}-mongo`);
  assert.equal(row.image, mgo.MONGO_IMAGE);
  assert.equal(row.configured_memory_mb, mgo.MONGO_MEMORY_MB);
  // Shared engines have no `instances` array — that field is Redis's shape, and
  // a dashboard branching on it must not see mongo as per-scope.
  assert.equal(row.instances, undefined);
  // The row is handed to an HTTP response. `admin_password_enc` is on the
  // managed_db_servers row and must not travel with it.
  assert.equal(JSON.stringify(row).includes('password'), false, JSON.stringify(row));
});
