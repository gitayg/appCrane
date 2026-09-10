/**
 * Managed Redis — the engine-specific half of services/managedDb.js.
 *
 * Everything here is PURE: it builds argv arrays and redis-cli scripts and
 * returns them. managedDb.js owns the docker calls, the SQLite rows and the
 * encryption, exactly as it does for the SQL engines, and provisionSql() is the
 * function this file is the counterpart of. Keeping it pure is also what makes
 * the argv assertions in test/managed-db-redis.test.js possible without a
 * daemon.
 *
 * =========================================================================
 * WHY ONE CONTAINER PER SCOPE, AND NOT ONE SHARED SERVER — MEASURED
 * =========================================================================
 * The shared-server shape is the whole point of managedDb.js: one Postgres and
 * one MariaDB for the platform, with isolation enforced INSIDE the engine by
 * grants, because the network cannot enforce it (see that file's header). The
 * obvious thing to do for Redis is the same: one shared Redis, each app on its
 * own numbered database, an ACL user per app.
 *
 * That was tried first and measured against redis:8.10-alpine. It does not
 * work. Verbatim:
 *
 *   # user `ua` created with: on >passA ~* &* +@all -@admin -@dangerous
 *   $ redis-cli --user ub -n 2 SET bsecret B-SECRET      -> OK
 *   $ redis-cli --user ua -n 2 GET bsecret               -> "B-SECRET"
 *
 * ACL key patterns are NOT scoped to a numbered database. `~*` is every key in
 * whichever database the connection has selected, and SELECT is just a command.
 * Redis's numbered databases are a namespace, not a boundary.
 *
 * Restricting SELECT looked like the fix, and is not:
 *
 *   # ua re-created with: ... -select +select|1 (so it can only sit in db 1)
 *   $ redis-cli --user ua -n 1 COPY asecret stolen DB 2  -> 1
 *   $ redis-cli --user ua -n 1 MOVE asecret 2            -> 1
 *   $ redis-cli -n 2 KEYS '*'                            -> stolen, bsecret, asecret
 *
 * Two commands carry a destination database of their own and wrote straight
 * into another app's keyspace. Adding `-copy -move` closes those two — measured
 * — and that is the shape of the whole approach: a DENY-LIST of commands that
 * take a database index, maintained by hand, against a command surface that
 * grows every release. `COMMAND DOCS` on this image reports 447 commands.
 *
 * And it would be a crippled Redis even if the deny-list held:
 *
 *   $ redis-cli -n 1 FT.CREATE idxA ON HASH PREFIX 1 doc: SCHEMA body TEXT
 *   Cannot create index on db != 0
 *
 * Redis 8 ships search, JSON, timeseries, bloom and vectorset as core modules,
 * and they refuse to work anywhere but database 0. Parking apps on numbered
 * databases takes those away from all of them and gives db 0 to nobody.
 *
 * So the boundary is a PROCESS. One Redis per scope: its own container, its own
 * volume, its own port, its own password, database 0, the full command set.
 * The isolation story then reads EXACTLY like the SQL engines' — any container
 * with the host gateway can open a socket, and the credential is what stops it
 * — with no per-command reasoning in it at all.
 *
 * The cost is what made this impossible for Postgres, and Redis is not
 * Postgres. Measured on this host, redis:8.10-alpine with the five modules
 * loaded and an empty keyspace:
 *
 *   used_memory_human:1.41M   used_memory_rss_human:21.62M
 *   docker stats: 6.074MiB / 256MiB
 *
 * 57 idle Postgres servers were never affordable. 57 idle Redises are ~350 MB.
 *
 * =========================================================================
 * AUTHENTICATION — BOTH ROUTES, ONE SECRET
 * =========================================================================
 * The instance sets `requirepass` AND creates an ACL user named after the
 * scope, with the same password. That is deliberate, not belt-and-braces:
 *
 *   - managed_databases has a UNIQUE index on (engine, db_user) and the column
 *     is NOT NULL, so every row needs a distinct, REAL username. Storing
 *     'default' for every Redis row violates the index; storing the derived
 *     name without creating it would put a username in the app's environment
 *     that Redis answers WRONGPASS to.
 *   - Plenty of self-hosted apps only offer a REDIS_PASSWORD field and send
 *     `AUTH <password>`, which Redis resolves against `default`. requirepass is
 *     what keeps those working.
 *
 * Both identities carry the same secret, so the second route grants nothing the
 * first did not. In a single-tenant container that is the honest position:
 * there is no one to isolate from inside it.
 *
 * The user gets `+@all -@admin`. Measured, as the app's own user:
 *
 *   INFO server        -> # Server            CONFIG GET dir  -> NOPERM
 *   CLIENT SETNAME x   -> OK                  CONFIG SET dir  -> NOPERM
 *   KEYS *             -> (empty)             SHUTDOWN NOSAVE -> NOPERM
 *   FLUSHDB / FLUSHALL -> OK                  MODULE LIST     -> NOPERM
 *   SCRIPT LOAD ...    -> e0e1f9fa...         REPLICAOF NO ONE-> NOPERM
 *   ACL WHOAMI         -> crane_a1_u          SLOWLOG GET     -> NOPERM
 *
 * -@dangerous was rejected: it takes away INFO, CLIENT, KEYS and FLUSHDB, and
 * Sidekiq, BullMQ and every Redis dashboard in the catalogue's world call those
 * on a normal day. -@admin is the line that matters, because it removes CONFIG
 * — `CONFIG SET dir` + `CONFIG SET dbfilename` is the classic Redis
 * write-anywhere primitive — along with MODULE, REPLICAOF, DEBUG and SHUTDOWN.
 *
 * ACL users live in memory. There is no aclfile, so managedDb.js re-applies
 * this on every ensure, the same way ensureAdminCredentialFile() and
 * hardenServer() are re-applied for the SQL engines.
 *
 * =========================================================================
 * THE PASSWORD NEVER REACHES THE HOST'S PROCESS TABLE
 * =========================================================================
 * `redis-server --requirepass <secret>` would put the credential in the docker
 * CLI's own argv, where any local user can read it — the reason
 * createServerContainer() feeds POSTGRES_PASSWORD through --env-file. Redis has
 * no init-from-environment convention to borrow, so the command line is a fixed
 * literal that dereferences an environment variable INSIDE the container:
 *
 *   sh -c 'exec docker-entrypoint.sh redis-server --requirepass "$REDISCLI_AUTH" ...'
 *
 * Nothing is interpolated into that string; the variable arrives via
 * --env-file. It is still visible in `docker inspect`, which is unavoidable and
 * already accepted for the SQL engines — reading it needs docker socket access,
 * which is root-equivalent.
 *
 * REDISCLI_AUTH is the variable name on purpose: redis-cli reads it and
 * authenticates itself, so every administrative `docker exec` in managedDb.js
 * is a bare `redis-cli` with no credential in argv anywhere. Measured:
 *
 *   $ docker exec c redis-cli PING                       -> PONG
 *   $ redis-cli -h 127.0.0.1 -p 46399 PING  (no auth)    -> NOAUTH Authentication required.
 *
 * docker-entrypoint.sh is invoked EXPLICITLY rather than bypassed. The image's
 * entrypoint is what appends `--loadmodule` for each .so it ships; running
 * `redis-server` directly starts a Redis with no search, no JSON and no
 * timeseries, and nothing says so. Measured both ways — `MODULE LIST` returns 5
 * modules through the entrypoint and 0 without it.
 *
 * =========================================================================
 * MEMORY
 * =========================================================================
 * The default Redis has NO maxmemory (measured: `maxmemory_human:0B`), which on
 * a shared box means one app's queue backlog takes the host down. Two limits,
 * and the gap between them is measured rather than picked:
 *
 *   docker --memory / --memory-swap : the hard wall. Equal to each other, so
 *                                     there is no swap, same as the SQL engines.
 *   redis maxmemory                 : 75% of that wall.
 *
 * Why not 100%: Redis overshoots. Filling a 192 MB maxmemory instance from a
 * Lua script reached `used_memory_human:213.63M` — 11% over — before the next
 * write was refused, and the cgroup was then at 220.1MiB of 256MiB. It survived
 * because of the headroom. An unbounded single value was allowed to run past it
 * and the kernel answered the way it always does:
 *
 *   $ docker inspect ... -> status=exited oom=true exit=137
 *
 * That is the same failure the MariaDB comment in managedDb.js describes, seen
 * live rather than inferred, and serverStatus() reports `oom_killed` for it.
 *
 * maxmemory-policy is `noeviction`, NOT allkeys-lru. Redis in this catalogue's
 * world is a job broker and a session store — Sidekiq, Celery, BullMQ — and an
 * LRU policy answers a full queue by DELETING QUEUED JOBS, silently, with
 * `evicted_keys` as the only trace. noeviction answers it loudly:
 *
 *   $ redis-cli SET plainkey aaaa
 *   OOM command not allowed when used memory > 'maxmemory'.
 *   $ redis-cli INFO stats | grep evicted   -> evicted_keys:0
 *
 * A cache that returns errors is a bad cache; a queue that loses jobs is a bug
 * report nobody can reproduce. An app that genuinely wants LRU can set its own
 * policy — the app's user is denied CONFIG SET, so that is an operator change
 * to MANAGED_DB_REDIS_MEMORY_MB and a redeploy, which is the correct amount of
 * friction for "start deleting my data when full".
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * redis:8.10-alpine.
 *
 * MINOR pin, matching mariadb:11.4 rather than postgres:16-alpine — patch
 * releases arrive, a minor bump does not. 8.10 is the current line: Docker
 * Hub's own tag listing has 8.10.1 as the newest (2026-08-27) and the -alpine
 * variants are still published alongside it (2026-08-20), both read from
 * hub.docker.com's tags API rather than assumed.
 *
 * 8.x, not 7.4, for a measured reason and a stated-but-unverified one. Measured:
 * 8.10.1 ships search, JSON, timeseries, bloom and vectorset as core modules
 * (`MODULE LIST` -> 5), which 7.4 does not, and the ACL behaviour this file
 * depends on was measured on exactly this image. Stated: Redis 8 is available
 * under AGPLv3, which is AppCrane's own licence, where 7.4 is RSALv2/SSPLv1
 * only. That second point could NOT be verified from the artifact — the image
 * ships no LICENSE file (checked) — so it is a reason to prefer 8.x, not a
 * finding.
 */
export const REDIS_IMAGE = process.env.MANAGED_DB_REDIS_IMAGE || 'redis:8.10-alpine';

export const REDIS_CONTAINER_PORT = 6379;

/** Where the RDB snapshot lives inside the container. The image's own default. */
export const REDIS_DATA_PATH = '/data';

/**
 * The hard container ceiling, in MB. 256 by default: measured, a full 192 MB
 * keyspace sat at 220.1MiB of it during a write burst, which is the headroom
 * the 75% ratio below exists to provide.
 *
 * Deliberately a fraction of Postgres's 512 and MariaDB's 1024. A Redis here is
 * a broker and a session store, not a system of record, and it is per-app
 * rather than shared — the number is multiplied by the number of apps that ask
 * for one, not paid once.
 */
export const REDIS_MEMORY_MB = Number(process.env.MANAGED_DB_REDIS_MEMORY_MB) || 256;

/**
 * maxmemory as a fraction of the container ceiling.
 *
 * ONE knob, not two. An operator who raises MANAGED_DB_REDIS_MEMORY_MB gets a
 * proportionally raised maxmemory and keeps the measured headroom; two
 * independent settings let someone set maxmemory above the cgroup limit, which
 * converts a clean "OOM command not allowed" into exit 137.
 */
const MAXMEMORY_FRACTION = 0.75;

export function maxmemoryMbFor(containerMemoryMb = REDIS_MEMORY_MB) {
  return Math.max(16, Math.floor(containerMemoryMb * MAXMEMORY_FRACTION));
}

/**
 * The host port range for per-scope instances.
 *
 * Clear of everything that already allocates: portAllocator.js hands apps
 * 3000+2*slot and 4000+2*slot (so under ~6000 at the 1000-slot horizon),
 * tcpIngress.js auto-allocates 31000-31999, and managedDb.js's shared servers
 * sit on 43306 and 45432. 46379 is 6379 with a 40000 offset, which makes a
 * `netstat` line readable at a glance.
 */
// MANAGED_DB_REDIS_PORT_MIN exists for the same reason
// MANAGED_DB_CONTAINER_PREFIX does: a test run on a developer's machine must
// not take a port a real instance is already holding, and the failure if it
// does is an unrelated-looking bind error mid-provision.
export const REDIS_PORT_MIN = Number(process.env.MANAGED_DB_REDIS_PORT_MIN) || 46379;
export const REDIS_PORT_MAX = REDIS_PORT_MIN + 499;

/**
 * The environment variable the password travels in.
 *
 * redis-cli reads REDISCLI_AUTH and authenticates with it, so administrative
 * `docker exec`s carry no credential in argv. redis-server does not read it —
 * the run command dereferences it explicitly.
 */
export const REDIS_PASSWORD_ENV = 'REDISCLI_AUTH';

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/**
 * The container for a scope's instance, derived from the SAME db_name
 * namesForScope() produces — so the collision guarantee that name carries (a
 * fixed-width hash of the full scope, plus migration 085's UNIQUE index) is the
 * one the container name inherits, rather than a second scheme that could
 * disagree with it.
 */
export function containerNameFor(prefix, dbName) {
  return `${prefix}-redis-${dbName}`;
}

/**
 * The lowest free port in the range.
 *
 * Lowest-free rather than highest-plus-one: a platform that provisions and
 * deprovisions over months would walk a monotonic allocator off the end of the
 * range while 400 ports sat idle. Reuse is safe here because deprovision()
 * destroys the container and its volume in the same call that frees the row —
 * there is no window where an old credential still opens something on a
 * recycled port.
 */
export function pickPort(usedPorts) {
  const taken = new Set(Array.from(usedPorts, Number));
  for (let p = REDIS_PORT_MIN; p <= REDIS_PORT_MAX; p++) {
    if (!taken.has(p)) return p;
  }
  throw new Error(
    `managedDb: no free port in the managed-Redis range ${REDIS_PORT_MIN}-${REDIS_PORT_MAX} ` +
    `(${taken.size} in use). Raise the range in services/managedRedis.js or deprovision an instance.`
  );
}

// ---------------------------------------------------------------------------
// Argv and scripts
// ---------------------------------------------------------------------------

/**
 * The command redis-server is started with.
 *
 * A fixed literal. The only variable part is "$REDISCLI_AUTH", which the
 * container's own shell expands from an env var delivered by --env-file — the
 * password is never a member of this array and never reaches the host's process
 * table. docker-entrypoint.sh is called explicitly so the image's module
 * loading still happens (see the header).
 */
export function serverCommand(maxmemoryMb) {
  const mb = Number(maxmemoryMb);
  if (!Number.isInteger(mb) || mb <= 0) {
    throw new Error(`managedRedis: maxmemory must be a positive integer of MB, got ${JSON.stringify(maxmemoryMb)}`);
  }
  return [
    'sh', '-c',
    'exec docker-entrypoint.sh redis-server'
    + ` --requirepass "$${REDIS_PASSWORD_ENV}"`
    + ` --maxmemory ${mb}mb`
    + ' --maxmemory-policy noeviction'
    // Loud rather than silent when the snapshot cannot be written. The default
    // is already yes; pinning it means a future image default cannot quietly
    // turn "the disk is full" into "the queue is being written to /dev/null".
    + ' --stop-writes-on-bgsave-error yes',
  ];
}

/** `docker exec` argv for the readiness probe. Carries no credential. */
export function readyProbeArgs(container) {
  return ['exec', container, 'redis-cli', '-h', '127.0.0.1', '-p', String(REDIS_CONTAINER_PORT), 'PING'];
}

/**
 * The redis-cli script that creates (or re-creates) the app's ACL user.
 *
 * Travels on STDIN, never in argv: redis-cli reads commands from stdin when it
 * is not a tty (measured), so the password is not in the container's process
 * table either.
 *
 * ONE `ACL SETUSER`, with `reset` as its first rule, and it has to stay one.
 * Splitting it into a reset followed by a setup is the obvious spelling and
 * leaves a window where the app's user exists but is `off` — harmless during
 * provisioning, an authentication outage when this is re-applied on a LIVE
 * instance, which is exactly what every ensure does. Redis applies the rules of
 * a single SETUSER atomically, so `reset on >pw ...` is a replacement with no
 * gap. It is also what makes re-applying idempotent AND self-healing: a user
 * edited by hand inside the container is put back to this exact definition.
 *
 * The caller has already run this password through managedDb.js's
 * assertPassword(), whose alphabet is base64url: no whitespace, no quote, no
 * newline, so it cannot break out of the token it sits in.
 */
export function aclScript(username, password) {
  return `ACL SETUSER ${username} reset on >${password} ~* &* +@all -@admin\n`;
}

/** Drop the ACL user. The container is destroyed separately; this is for the
 *  case where it survives (a shared instance restored by hand, a partial
 *  teardown) and the credential must stop working regardless. */
export function aclDropScript(username) {
  return `ACL DELUSER ${username}\n`;
}

/**
 * The connection URL an app is handed.
 *
 * Database 0, always. Numbered databases are not a boundary here (see the
 * header) and there is exactly one tenant per instance, so anything else would
 * be decoration that breaks the modules.
 *
 * The password is not encoded here because managedDb.js's connectionFor() is
 * the only caller and base64url needs none; deployer.js rebuilds this URL with
 * percent-encoding for the env var it actually injects.
 */
export function redisUrl({ username, password, host, port }) {
  return `redis://${username}:${password}@${host}:${port}/0`;
}

/** The database index every managed Redis credential addresses. */
export const REDIS_DB_INDEX = '0';
