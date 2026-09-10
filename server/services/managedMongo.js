/**
 * Managed MongoDB — the engine-specific half of services/managedDb.js.
 *
 * Everything here is PURE: it builds argv arrays and mongosh scripts and
 * returns them. managedDb.js owns the docker calls, the SQLite rows and the
 * encryption, exactly as it does for the other engines. provisionSql() is the
 * function this file's createUserScript() is the counterpart of, and keeping it
 * pure is what makes the argv assertions in test/managed-db-mongo.test.js
 * possible without a daemon.
 *
 * =========================================================================
 * MONGO IS A SHARED-SERVER ENGINE, AND REDIS'S PROBLEM DOES NOT APPLY
 * =========================================================================
 * Redis had to be given a container per scope because it has no in-engine
 * boundary (services/managedRedis.js carries that transcript). Mongo does have
 * one, and it is stronger than Postgres's. Measured against mongo:8.0
 * (v8.0.30), as app A's credential from a container on the live `appcrane-apps`
 * bridge, over the exact URL AppCrane injects:
 *
 *   own insert/read        OK   {"_id":1,"v":"A"}
 *   own createIndex        OK   "v_1"
 *   own collMod            OK   {"ok":1,...}
 *   own dropDatabase       OK   1
 *   change stream          OK
 *   transaction            OK
 *   READ crane_a2.secrets  DENIED  not authorized on crane_a2 to execute command { find: "secrets" ...
 *   WRITE crane_a2         DENIED  not authorized on crane_a2 to execute command { insert: "evil" ...
 *   READ local.oplog.rs    DENIED  not authorized on local to execute command { find: "oplog.rs" ...
 *   READ admin.system.users DENIED not authorized on admin to execute command { find: "system.users" ...
 *   listDatabases          OK   ["crane_a1"]        <-- only its own
 *   createUser             DENIED  not authorized on crane_a1 ...
 *   grantRolesToUser root  DENIED  not authorized on admin ...
 *   replSetReconfig        DENIED  not authorized on admin ...
 *   shutdown               DENIED  not authorized on admin ...
 *   setParameter           DENIED  not authorized on admin ...
 *
 * Note the `listDatabases` line. Postgres leaks the NAMES of every other app's
 * database through pg_database and there is no supported way to stop it (see
 * provisionSql() in managedDb.js). Mongo filters that command by authorization,
 * so an app sees only its own — this is the one place it is stricter than both
 * SQL engines.
 *
 * =========================================================================
 * THE ROLES: readWrite + dbAdmin, BOTH SCOPED TO THE APP'S OWN DATABASE
 * =========================================================================
 * `readWrite` alone was tried first and is not enough. Measured, as a plain
 * readWrite user:
 *
 *   collMod              -> DENIED  not authorized on crane_a1 to execute command { collMod: "mine" ...
 *   dropDatabase (own)   -> DENIED  not authorized on crane_a1_scratch to execute command { dropDatabase: 1 ...
 *
 * collMod is how an application changes a TTL index's expireAfterSeconds, which
 * Rocket.Chat and every Meteor app in this catalogue do on upgrade, and an app
 * that cannot drop its own database cannot reset itself. `dbAdmin` on the same
 * database adds both, measured:
 *
 *   collMod own          -> OK  {"ok":1}
 *   collMod TTL change   -> OK  {"expireAfterSeconds_old":60,...}
 *   dropDatabase own     -> OK  {"ok":1,"dropped":"crane_a3"}
 *   CROSS read a2        -> DENIED     CROSS dropDatabase a2 -> DENIED
 *   createUser own db    -> DENIED
 *
 * `dbOwner` — the obvious one-role spelling — was rejected. It is
 * readWrite + dbAdmin + userAdmin, and the only thing the third adds is the
 * ability to create users inside the app's own database. Measured, a dbOwner
 * cannot escalate out of its database (grantRolesToUser for a role on another
 * db, createRole carrying a cross-db privilege, and createRole with
 * anyResource were all DENIED), so it is not a security hole — it is simply a
 * privilege nothing in the catalogue asks for.
 *
 * `clusterMonitor` is deliberately NOT granted, which is why serverStatus,
 * replSetGetStatus and getParameter answer NOPERM above. Those are SERVER-wide:
 * serverStatus reports every database's activity and replSetGetStatus reports
 * topology, so granting them to one app hands it a window onto the others.
 *
 * THE USER IS CREATED IN THE APP'S OWN DATABASE, not in `admin`. That makes the
 * database in the connection URL's path the authSource as well, so the URL
 * needs no `?authSource=` query — which matters, because deployer.js's
 * managedDbUrl() rebuilds the URL from the discrete fields and would drop one.
 *
 * =========================================================================
 * WHY A SINGLE-NODE REPLICA SET, AND NOT A STANDALONE mongod
 * =========================================================================
 * Three catalogue entries declare `"engine": "mongo"` — rocketchat, opensign
 * and wekan — and the first is a Meteor application. Change streams and
 * multi-document transactions do not exist on a standalone server; measured on
 * a standalone mongo:8:
 *
 *   db.mine.watch()  ->  The $changeStream stage is only supported on replica sets or mongos
 *
 * and on this single-node replica set, from an app container, both succeed. A
 * standalone would serve OpenSign and Wekan and would leave Rocket.Chat unable
 * to start, so the set is the shape that covers all three.
 *
 * AUTH FORCES A KEYFILE. Verbatim, from a mongod given --replSet with auth on
 * and no keyfile:
 *
 *   BadValue: security.keyFile is required when authorization is enabled with replica sets
 *
 * even for one member. The key is DERIVED from the superuser password rather
 * than stored in a new column: it must be stable for the life of the volume,
 * and the superuser password already is (migration 085's whole reason for
 * existing). sha256 -> standard base64, because a keyfile's alphabet is base64
 * and generated passwords are base64url, whose '-' and '_' are not in it.
 *
 * =========================================================================
 * THE REPLICA SET MEMBER HOST, AND WHY IT IS NOT THE CONTAINER'S OWN ADDRESS
 * =========================================================================
 * This is the part that is easy to get wrong, and it is invisible until an app
 * tries to connect.
 *
 * A client that does replica set DISCOVERY does not keep talking to the address
 * in its URL. It asks `hello`, learns it is talking to a set, and then connects
 * to the member addresses named IN THE REPLICA SET CONFIG. So the config must
 * name an address the APP CONTAINER can resolve — `host.docker.internal:<published
 * port>`, the same address the URL carries — and not the container's own
 * hostname or 127.0.0.1, either of which sends every app to its own loopback.
 *
 * HOW MUCH THIS MATTERS WAS MEASURED, AND IT IS LESS THAN THE PARAGRAPH ABOVE
 * IMPLIES — this file said otherwise until a deliberately broken config was
 * tried. Against a set whose single member is `127.0.0.1:47030`, from a
 * container on appcrane-apps:
 *
 *   mongodb://u1:pw@host.docker.internal:47030/crane_a1
 *       -> WROTE topology_hosts=["127.0.0.1:47030"]
 *   mongodb://u1:pw@host.docker.internal:47030/crane_a1?replicaSet=rs0
 *       -> MongoNetworkError: connect ECONNREFUSED 127.0.0.1:47030
 *
 * A single-seed URL with no `replicaSet=` — which is exactly what AppCrane
 * injects — keeps talking to the seed and works even with a nonsense member
 * host. The moment a client opts into discovery, the member host is the whole
 * connection. So this is not what makes the DEFAULT injected URL work; it is
 * what stops an operator who appends `?replicaSet=rs0`, or a driver that does
 * not apply the single-seed direct-connection default, from being handed a
 * server that answers `hello` and then points them at nothing.
 *
 * But mongod also has to recognise that address as ITSELF before it will accept
 * the config. Its isSelf check resolves the host, and if the address is not
 * local it opens a connection to it and asks whether the process on the other
 * end is the same one. Measured: with the container given
 * `--add-host host.docker.internal:host-gateway`, that NAT hairpin does work on
 * Docker Desktop — the container reached itself through the published port and
 * rs.initiate returned ok:1.
 *
 * IT IS STILL THE WRONG DESIGN, because it makes replica set initiation depend
 * on a hairpin through the host's NAT, which the measurement table in
 * managedDb.js's header shows differs between Linux and Desktop and is the
 * single most fragile thing in this subsystem.
 *
 * So the hairpin is removed instead of relied on. Two facts do it:
 *
 *   1. mongod listens on the SAME port number the host publishes (see
 *      MONGO_PORT and `portMirrors` in managedDb.js's ENGINES table). Every
 *      other engine maps 45432->5432; this one maps 47017->47017.
 *   2. Inside the mongo container ONLY, `host.docker.internal` is mapped to
 *      127.0.0.1 with --add-host.
 *
 * Together, `host.docker.internal:47017` resolves to 127.0.0.1:47017 inside the
 * container — trivially local, isSelf answers yes without a single packet
 * leaving the container — and to the host gateway inside an app container,
 * where the published port answers. One string, two correct meanings.
 *
 * Measured on mongo:8.0 with that mapping and no host-gateway route at all:
 *
 *   initiate -> {"ok":1}
 *   primary=true hosts=["host.docker.internal:47017"]
 *   # from a container on appcrane-apps (enable_icc=false):
 *   hosts=["host.docker.internal:47017"] primary=true
 *   insert ok / change stream ok / txn committed
 *   # after `docker restart`:
 *   after restart: primary=true set=rs0
 *   app after restart: {"_id":1,"v":"A"}
 *
 * =========================================================================
 * THE PASSWORD NEVER REACHES THE HOST'S PROCESS TABLE
 * =========================================================================
 * Same rule as createServerContainer() and managedRedis.js: the superuser
 * password and the derived keyfile arrive through --env-file, and the run
 * command is a FIXED literal that dereferences them inside the container.
 * Nothing variable is interpolated into serverCommand().
 *
 * Administrative calls carry no credential in argv either, but for a different
 * reason than Redis's: mongosh has no REDISCLI_AUTH equivalent, so instead of
 * putting `-u root -p <secret>` on a command line the script AUTHENTICATES
 * ITSELF — `db.getSiblingDB('admin').auth(...)` is the first line of every
 * script in this file, and the script travels on stdin. That is the same route
 * the SQL engines' DDL takes.
 *
 * The scripts run with `--file /dev/stdin`, NOT as a piped REPL. Measured, and
 * the difference is the whole reliability of provisioning:
 *
 *   $ printf "throw new Error('BOOM')" | mongosh --quiet                     -> exit 0
 *   $ printf "throw new Error('BOOM')" | mongosh --quiet --file /dev/stdin   -> exit 1
 *
 * A piped REPL reports a failed createUser as success. `--file /dev/stdin` is
 * mongosh's ON_ERROR_STOP=1.
 *
 * =========================================================================
 * READINESS
 * =========================================================================
 * The official image runs a TEMPORARY mongod during first-time initialisation,
 * exactly as the postgres and mariadb images do — docker-entrypoint.sh forces
 * `--bind_ip 127.0.0.1` and `--port 27017` on it and strips --auth, --keyFile
 * and --replSet. So a probe against the container's loopback goes GREEN in the
 * middle of init and the provisioning that follows lands on a server about to
 * be shut down. Measured, polling both addresses once a second from container
 * start:
 *
 *   t=1s  tempmongod(127.0.0.1:27017)=[up]                realport(routableIP:47021)=[MongoNetworkError: conne]
 *   t=2s  tempmongod(127.0.0.1:27017)=[MongoNetworkError] realport(routableIP:47021)=[MongoNetworkError: conne]
 *   t=3s  tempmongod(127.0.0.1:27017)=[MongoNetworkError] realport(routableIP:47021)=[up]
 *
 * The probe therefore targets the container's ROUTABLE address on the REAL
 * port, which the temporary server offers on neither count. It carries no
 * credential: `hello` is answerable before authentication, and a successful
 * hello proves the server is accepting TCP just as well as an authenticated
 * ping would.
 */

import { createHash } from 'crypto';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * mongo:8.0.
 *
 * MINOR pin, matching mariadb:11.4 and redis:8.10-alpine rather than
 * postgres:16-alpine — patch releases arrive, a minor bump does not.
 *
 * 8.0 rather than the `8` or `latest` tag, and that is a production choice, not
 * a conservative one. MongoDB ships rapid releases (8.1, 8.2, 8.3) alongside
 * the supported major release, and `mongo:8` follows the rapid line: pulling it
 * on 2026-09-09 gave v8.3.9. Read from hub.docker.com's tags API rather than
 * assumed, `8.0` (8.0.30) and `8.3` (8.3.9) were both republished the same day,
 * so the 8.0 line is current and maintained — it is the one with long-term
 * support behind it. Every measurement in this file's header was taken on
 * mongo:8.0 / v8.0.30.
 *
 * There is no -alpine variant to prefer: MongoDB publishes no Alpine image (the
 * tag listing has none), so the Debian-based official image is the only option.
 */
export const MONGO_IMAGE = process.env.MANAGED_DB_MONGO_IMAGE || 'mongo:8.0';

/**
 * The port, on BOTH sides of the publish.
 *
 * Every other engine maps a distinct host port onto the image's default
 * (45432->5432, 43306->3306). This one is deliberately mirrored, 47017->47017,
 * and the reason is the replica set member host: see the header. mongod is
 * started with `--port <this>` so the number in the config means the same thing
 * inside the container and outside it.
 *
 * 47017 is 27017 with a 20000 offset, clear of portAllocator.js (under ~6000),
 * tcpIngress.js (31000-31999) and the other managed servers (43306, 45432,
 * 46379+).
 */
export const MONGO_PORT = Number(process.env.MANAGED_DB_MONGO_PORT) || 47017;

/** Where the data files live inside the container. The image's own default. */
export const MONGO_DATA_PATH = '/data/db';

/**
 * The hard container ceiling, in MB. 1024, matching MariaDB rather than
 * Postgres's 512, and for the same reason: this is a shared general-purpose
 * database serving every mongo app on the platform, behind a --memory-swap wall
 * equal to --memory, so the limit is not a slow-down but a kill.
 *
 * Honest about the evidence: 512 was NOT measured to fail. A 100k-document
 * (~44 MB) insert burst against a 512m instance finished with the container at
 * 294.4MiB / 512MiB and no OOM. The same burst at 1024m finished at
 * 411.4MiB / 1GiB. What argues for 1024 is the floor underneath those numbers —
 * WiredTiger's cache does not shrink below 256 MB whichever limit it is given
 * (measured: `cache_size=256M` at both 512m and 1024m), and that floor plus
 * per-connection buffers plus sort/aggregation memory for three apps at once is
 * most of a 512 MB budget before any data is cached.
 */
export const MONGO_MEMORY_MB = Number(process.env.MANAGED_DB_MONGO_MEMORY_MB) || 1024;

/** The superuser the image creates on first init. */
export const MONGO_ADMIN_USER = 'root';

/** The image's own init variables. Delivered by --env-file, never by -e. */
export const MONGO_PASSWORD_ENV = 'MONGO_INITDB_ROOT_PASSWORD';
export const MONGO_USERNAME_ENV = 'MONGO_INITDB_ROOT_USERNAME';

/**
 * AppCrane's own variable, carrying the derived internal-auth key. Not an
 * image convention — the image has no keyfile support — so the run command
 * materialises the file from it.
 */
export const MONGO_KEYFILE_ENV = 'APPCRANE_MONGO_KEYFILE';

/**
 * Inside the container's writable layer, NOT the volume. It is rewritten on
 * every start from the environment, so a volume restored onto a box with a
 * different key cannot leave a stale file behind.
 */
export const MONGO_KEYFILE_PATH = '/tmp/appcrane-mongo.key';

/** The replica set name. One member, always; see the header. */
export const MONGO_REPLICA_SET = 'rs0';

/** The URL scheme apps are handed. */
export const MONGO_SCHEME = 'mongodb';

// ---------------------------------------------------------------------------
// The keyfile
// ---------------------------------------------------------------------------

/**
 * The internal-auth key for the replica set, derived from the superuser
 * password.
 *
 * DERIVED, not generated: the key has to be identical every time the container
 * is recreated over the life of the data directory, and adding a column to
 * migration 085 to store a second secret would be storing something that is
 * already implied by the first. The superuser password is generated once and
 * kept for the life of the volume (085's header explains why), so a pure
 * function of it has the same lifetime.
 *
 * Standard base64, not base64url. A mongod keyfile's contents must come from
 * the base64 alphabet, and generated passwords are base64url — whose '-' and
 * '_' are not in it — so the password cannot simply be used as the key.
 */
export function keyfileFor(adminPassword) {
  if (!adminPassword) throw new Error('managedMongo: refusing to derive a keyfile from an empty password');
  return createHash('sha256').update(String(adminPassword)).digest('base64');
}

// ---------------------------------------------------------------------------
// Container argv
// ---------------------------------------------------------------------------

/**
 * The --env-file body: the two init variables the image reads and the key the
 * run command materialises. Written at 0600 by managedDb.js and deleted as soon
 * as `docker run` has consumed it.
 */
export function envFileBody(adminPassword) {
  return `${MONGO_USERNAME_ENV}=${MONGO_ADMIN_USER}\n`
    + `${MONGO_PASSWORD_ENV}=${adminPassword}\n`
    + `${MONGO_KEYFILE_ENV}=${keyfileFor(adminPassword)}\n`;
}

/**
 * Extra `docker run` flags this engine needs.
 *
 * The --add-host is what makes the replica set member address resolve to the
 * container itself, so rs.initiate needs no NAT hairpin — the header has the
 * full argument. `host` is passed in rather than hardcoded so it cannot drift
 * from managedDb.js's DB_HOST_FOR_CONTAINERS, which is the address apps
 * actually use and therefore the address the config must name.
 */
export function extraRunArgs(host) {
  return ['--add-host', `${host}:127.0.0.1`];
}

/**
 * The command mongod is started with.
 *
 * A FIXED literal apart from the port, which is a validated integer. The
 * password and the key are never members of this array: `$APPCRANE_MONGO_KEYFILE`
 * is expanded by the container's own shell from a variable delivered by
 * --env-file, exactly as managedRedis.js does with $REDISCLI_AUTH.
 *
 * The keyfile is written, chmod'd to 0400 and chowned to `mongodb` BEFORE the
 * entrypoint runs, because mongod refuses a key file that is group- or
 * world-readable and runs as `mongodb` rather than root. `umask` was the first
 * spelling of that and is wrong: it applies to the entrypoint's own file
 * creation too, and the run failed with
 * `/data/db/journal: directory-list: opendir` / `Permission denied`.
 *
 * docker-entrypoint.sh is invoked EXPLICITLY rather than bypassed, for the same
 * reason managedRedis.js does it: the entrypoint is what creates the superuser
 * on an empty data directory. Running mongod directly would start a server with
 * no root user and no way to provision anything.
 */
export function serverCommand(port) {
  const p = Number(port);
  if (!Number.isInteger(p) || p <= 0 || p > 65535) {
    throw new Error(`managedMongo: port must be a valid TCP port, got ${JSON.stringify(port)}`);
  }
  return [
    'sh', '-c',
    `printf '%s' "$${MONGO_KEYFILE_ENV}" > ${MONGO_KEYFILE_PATH}`
    + ` && chmod 400 ${MONGO_KEYFILE_PATH}`
    + ` && chown mongodb ${MONGO_KEYFILE_PATH}`
    + ' && exec docker-entrypoint.sh mongod'
    + ` --keyFile ${MONGO_KEYFILE_PATH}`
    + ` --replSet ${MONGO_REPLICA_SET}`
    + ` --port ${p}`
    + ' --bind_ip_all',
  ];
}

/**
 * `docker exec` argv for the readiness probe. Carries no credential.
 *
 * `$(hostname -i)` is expanded INSIDE the container and is the container's
 * routable address — deliberately not 127.0.0.1, which the image's temporary
 * init server also binds. See the header's polling transcript.
 */
export function readyProbeArgs(container, port) {
  return [
    'exec', container, 'sh', '-c',
    `exec mongosh --host "$(hostname -i)" --port ${Number(port)} --quiet --eval 'print("MONGO_READY " + db.hello().ok)'`,
  ];
}

/** `docker exec` argv for an administrative script arriving on stdin. */
export function adminShellArgs(container, port) {
  return [
    'exec', '-i', container, 'sh', '-c',
    // --file /dev/stdin, NOT a piped REPL: the REPL exits 0 on a thrown error
    // and would report a failed createUser as a successful provision.
    `exec mongosh --host "$(hostname -i)" --port ${Number(port)} --quiet --file /dev/stdin`,
  ];
}

// ---------------------------------------------------------------------------
// Scripts
// ---------------------------------------------------------------------------

/**
 * Every script starts by authenticating as the superuser, so no credential ever
 * reaches argv. managedDb.js redacts BOTH this password and any generated one
 * from the error before it is thrown, because mongosh echoes the offending
 * source line back on a syntax error.
 *
 * The value is interpolated into a single-quoted JS string literal. It has
 * already been through managedDb.js's assertPassword(), whose alphabet is
 * base64url — no quote, no backslash, no newline — so it cannot break out.
 */
function authLine(adminPassword) {
  return `db.getSiblingDB('admin').auth('${MONGO_ADMIN_USER}', '${adminPassword}');`;
}

/**
 * Bring the replica set up, or leave an already-configured one alone.
 *
 * Idempotent and self-healing, in the same spirit as hardenServer() for
 * Postgres: it runs on EVERY ensureServer(), so a hand-restored data directory
 * or a container recreated after `docker rm` is put back into a known state.
 *
 * `db.hello().setName` is the branch rather than a try/catch around initiate:
 * it is undefined on an uninitialised server and 'rs0' on a configured one
 * (measured — `replSetGetConfig` on an uninitialised server answers
 * `MongoServerError: no replset config has been received`, and a second
 * `replSetInitiate` answers `already initialized`).
 *
 * A set configured for a DIFFERENT address is a hard error, not a warning. The
 * member host is where clients get redirected after discovery, so a config
 * naming a port that is no longer published leaves every app hanging on "no
 * primary" with a URL that looks perfectly correct. Refusing at provision time
 * is the only place that failure is legible.
 */
export function initiateScript({ adminPassword, memberHost }) {
  return [
    authLine(adminPassword),
    `const want = ${JSON.stringify(memberHost)};`,
    'if (db.hello().setName === undefined) {',
    `  const r = db.adminCommand({ replSetInitiate: { _id: ${JSON.stringify(MONGO_REPLICA_SET)}, members: [{ _id: 0, host: want }] } });`,
    '  if (!r.ok) throw new Error("replSetInitiate failed: " + JSON.stringify(r));',
    '}',
    // Wait for the election. A single member elects itself in well under a
    // second (measured: primary within 1s of initiate), but provisioning writes
    // immediately afterwards and a write to a non-primary is refused.
    'let primary = false;',
    'for (let i = 0; i < 60; i++) {',
    '  if (db.hello().isWritablePrimary) { primary = true; break; }',
    '  sleep(500);',
    '}',
    'if (!primary) throw new Error("replica set member did not become primary");',
    'const hosts = db.adminCommand({ replSetGetConfig: 1 }).config.members.map(m => m.host);',
    'if (hosts.length !== 1 || hosts[0] !== want) {',
    '  throw new Error("replica set is configured for " + JSON.stringify(hosts) + " but apps are handed " + want + "; the member host must match the published address or clients will be redirected somewhere unreachable");',
    '}',
    'print("MONGO_RS_OK " + hosts[0]);',
  ].join('\n') + '\n';
}

/**
 * Create the app's database user. The counterpart of provisionSql().
 *
 * The user is created IN `database`, which makes that database its authSource
 * and lets the injected URL stay free of query parameters. Roles are
 * readWrite + dbAdmin, both scoped to the same database — see the header for
 * what each one buys and why dbOwner and clusterMonitor were rejected.
 *
 * Mongo creates a database lazily on first write, so there is no CREATE
 * DATABASE here and none is needed: createUser against a database that does not
 * exist yet succeeds, and the database appears when the app writes to it.
 */
export function createUserScript({ adminPassword, database, username, password }) {
  return [
    authLine(adminPassword),
    `db.getSiblingDB(${JSON.stringify(database)}).createUser({`,
    `  user: ${JSON.stringify(username)},`,
    `  pwd: ${JSON.stringify(password)},`,
    `  roles: [{ role: 'readWrite', db: ${JSON.stringify(database)} }, { role: 'dbAdmin', db: ${JSON.stringify(database)} }],`,
    '});',
    'print("MONGO_USER_CREATED");',
  ].join('\n') + '\n';
}

/**
 * Drop the user and the database. Idempotent — `dropUser` on a user that is
 * already gone throws `UserNotFound`, which is the state we wanted, so it is
 * swallowed; `dropDatabase` is already a no-op on a missing database.
 *
 * The user goes FIRST. If the drop is interrupted between the two, a live
 * credential pointing at surviving data is a worse outcome than an empty
 * database nothing can open.
 */
export function dropScript({ adminPassword, database, username }) {
  return [
    authLine(adminPassword),
    `const target = db.getSiblingDB(${JSON.stringify(database)});`,
    `try { target.dropUser(${JSON.stringify(username)}); }`,
    'catch (e) { if (!/UserNotFound/.test(String(e.message))) throw e; }',
    'target.dropDatabase();',
    'print("MONGO_DROPPED");',
  ].join('\n') + '\n';
}

/**
 * The connection URL an app is handed.
 *
 * No query string, deliberately. deployer.js's managedDbUrl() rebuilds this
 * from the discrete fields when it injects it, and a `?authSource=` or
 * `?replicaSet=` appended here would be silently dropped there — so anything
 * that has to be true of the connection is arranged in the SERVER instead: the
 * user lives in its own database (so the path IS the authSource) and the
 * replica set advertises the same host:port the URL carries (so discovery
 * lands back where it started).
 */
export function mongoUrl({ username, password, host, port, database }) {
  return `${MONGO_SCHEME}://${username}:${password}@${host}:${port}/${database}`;
}
