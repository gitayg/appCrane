/**
 * Managed databases — one shared Postgres and one shared MariaDB for the whole
 * platform, with a database and a login role per scope inside each; plus Redis,
 * which is one small container PER SCOPE.
 *
 * =========================================================================
 * WHY REDIS BREAKS THE SHARED-SERVER SHAPE
 * =========================================================================
 * Everything below rests on isolation being enforceable INSIDE the engine: a
 * credential reaches one database and the engine refuses the rest. Redis has no
 * such mechanism. Measured, not assumed — ACL key patterns do not scope to a
 * numbered database, `COPY ... DB n` and `MOVE key n` write across it even for
 * a user pinned to one index, and Redis 8's core modules refuse to run outside
 * database 0. services/managedRedis.js carries the verbatim transcript.
 *
 * So the Redis boundary is a PROCESS: one container per (app, tenant), its own
 * port, its own volume, its own password, database 0, the full command set.
 * That is affordable for Redis (measured: ~6 MiB resident at rest) and was
 * never affordable for Postgres, which is why the two shapes differ. See
 * SHARED_SERVER_ENGINES below — the split has a name so nothing has to
 * special-case 'redis' by string.
 *
 * The reachability and publishing notes that follow apply to BOTH shapes: a
 * per-scope Redis is published on the same addresses, on the same host-gateway
 * route, with the same "any container can open a socket, the credential is the
 * boundary" consequence.
 *
 * =========================================================================
 * WHY APPS REACH THE DATABASE THROUGH THE HOST GATEWAY, AND NOT THE NETWORK
 * =========================================================================
 * Every app container runs on the single shared `appcrane-apps` bridge with
 * com.docker.network.bridge.enable_icc=false (services/docker.js, v2.42.1).
 * The daemon DROPS container-to-container traffic there. That is a shipped
 * security fix — before it, one compromised app could open a sibling's origin
 * directly, behind Caddy, with no auth, audit or rate limit — and a network per
 * app was considered and rejected in the same change, because Docker's default
 * address pools run out at ~16-31 networks and the failure lands mid-deploy as
 * an unrelated-looking subnet error.
 *
 * So an app cannot reach a database container over the docker network, and
 * neither icc nor the one-network design is negotiable. Apps reach it the way
 * they already reach AppCrane itself: `host.docker.internal`, the host-gateway
 * convention deployer.js:1349/1382 established for CRANE_INTERNAL_URL.
 *
 * The consequence has to be said out loud: ANY container that gets
 * --add-host host.docker.internal:host-gateway can open a TCP socket to these
 * servers. Network isolation is not available to us. EVERY isolation guarantee
 * in this file is enforced INSIDE THE ENGINE, by grants — a credential reaches
 * exactly one database and nothing else. See provisionSql() below.
 *
 * =========================================================================
 * WHERE THE PORT IS PUBLISHED — MEASURED, NOT REASONED
 * =========================================================================
 * "Publish on 127.0.0.1 so the database is never on the internet" and "apps must
 * reach it via host.docker.internal" are in direct conflict on Linux, which is
 * what the production box runs. Measured against a real Linux daemon (Docker
 * 27.5.1 in privileged dind, aarch64), probing from a container ON
 * appcrane-apps with icc=false and --add-host host.docker.internal:host-gateway:
 *
 *   victim container -p 127.0.0.1:P     ->  wget: can't connect (172.18.0.1)
 *   victim container -p 0.0.0.0:P       ->  200   (works; database on the
 *                                                  internet — rejected)
 *   host process on 0.0.0.0:P           ->  200   (this is why the existing
 *                                                  CRANE_INTERNAL_URL works:
 *                                                  AppCrane is a host process,
 *                                                  not a container)
 *   host process on 127.0.0.1:P         ->  wget: can't connect (172.18.0.1)
 *   victim container -p 127.0.0.1:P
 *                    -p 172.18.0.1:P    ->  200, and `netstat -ltn` shows
 *                                           listeners on 127.0.0.1 and
 *                                           172.18.0.1 only, never 0.0.0.0
 *
 * On Linux, host.docker.internal resolves to the default bridge's gateway, and a
 * port bound to loopback is simply not on that interface. On macOS Docker
 * Desktop the same probe against a 127.0.0.1 publish returns 200, because
 * host.docker.internal there is 192.168.65.254 — an address on the Mac side that
 * the VM's port forwarder routes back to the host's loopback, and one that
 * cannot be bound inside the daemon (measured: `bind: cannot assign requested
 * address`).
 *
 * So we publish on BOTH 127.0.0.1 and the default bridge gateway, and treat the
 * second as best-effort — it is what makes Linux work and it is unbindable on
 * Desktop, where the first already works. Neither address is 0.0.0.0 and neither
 * is on a public NIC: the gateway of a docker bridge is reachable from the host
 * and from containers routing through it, and from nowhere else.
 *
 * NOTE the servers are deliberately NOT placed on `appcrane-apps`. If they were,
 * an app reaching them through the gateway would be a same-bridge hairpin, and
 * docker.js measured that path as blocked by icc=false. On the default bridge it
 * is a cross-bridge hairpin, which the matrix above measured as working.
 */

import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import crypto from 'crypto';
import { join, resolve } from 'path';
import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import log from '../utils/logger.js';
import * as redis from './managedRedis.js';

const execFileAsync = promisify(execFile);

/** The hostname an app container uses. Same convention as CRANE_INTERNAL_URL. */
export const DB_HOST_FOR_CONTAINERS = 'host.docker.internal';

export const SUPPORTED_ENGINES = ['postgres', 'mariadb', 'redis'];

/**
 * The engines served by ONE shared container for the whole platform.
 *
 * Redis is deliberately not one of them: it gets a container PER SCOPE, because
 * Redis has no in-engine boundary to enforce isolation with — ACL key patterns
 * do not scope to a numbered database, two commands carry a destination
 * database of their own, and the modules refuse to run outside database 0. All
 * three were measured; services/managedRedis.js carries the transcript.
 *
 * This split exists so nothing has to ask "is this engine shared?" by naming
 * redis. ensureServer(), stopServer() and the managed_db_servers table are for
 * this list and only this list.
 */
export const SHARED_SERVER_ENGINES = ['postgres', 'mariadb'];

/** True for engines whose container is created once per (app, tenant). */
export function isPerScopeEngine(engine) {
  return engine === 'redis';
}

// Ports sit well clear of tcpIngress.js's 31000-31999 auto-allocation range and
// of the 3000 control plane, so an app can never be handed a port a database is
// already holding.
// Container names carry a prefix so a test run cannot adopt — or destroy — the
// platform's real database servers on a developer's machine. Production never
// sets it.
const CONTAINER_PREFIX = process.env.MANAGED_DB_CONTAINER_PREFIX || 'appcrane-db';

const ENGINES = {
  postgres: {
    image: process.env.MANAGED_DB_POSTGRES_IMAGE || 'postgres:16-alpine',
    container: `${CONTAINER_PREFIX}-postgres`,
    defaultPort: Number(process.env.MANAGED_DB_POSTGRES_PORT) || 45432,
    containerPort: 5432,
    dataPath: '/var/lib/postgresql/data',
    // Honoured only on first init of an empty data dir — see migration 085 for
    // why the value is stored rather than regenerated.
    passwordEnv: 'POSTGRES_PASSWORD',
    memoryMb: Number(process.env.MANAGED_DB_POSTGRES_MEMORY_MB) || 512,
    scheme: 'postgresql',
  },
  mariadb: {
    image: process.env.MANAGED_DB_MARIADB_IMAGE || 'mariadb:11.4',
    container: `${CONTAINER_PREFIX}-mariadb`,
    defaultPort: Number(process.env.MANAGED_DB_MARIADB_PORT) || 43306,
    containerPort: 3306,
    dataPath: '/var/lib/mysql',
    passwordEnv: 'MARIADB_ROOT_PASSWORD',
    // 1024, not the 512 this shipped with (v2.65.7).
    //
    // The ceiling is enforced with --memory-swap set equal to it, which is
    // Docker's spelling for "no swap at all", so this is a hard wall rather than
    // a point where the kernel starts paging: MariaDB does not get slow at the
    // limit, it gets killed. mariadb:11.4's resident set at rest is already in
    // the mid-hundreds of MB before the InnoDB buffer pool, the log buffer and
    // per-connection buffers are counted, so 512 left almost no headroom and the
    // first real workload takes the process out. Postgres stays at 512: the
    // alpine image's baseline is a fraction of MariaDB's, and nothing has been
    // observed pressing against it.
    //
    // Honest about the evidence: this is not confirmed to be what failed on the
    // instance that prompted it — the container was found RUNNING, so an OOM
    // kill was never observed, only a restart in the right window. The change is
    // made because a hard 512MB wall with no swap under a general-purpose
    // database is a bad default on its own terms, not because it is a diagnosed
    // fix. If a provision still fails at 1024, the cause is elsewhere.
    memoryMb: Number(process.env.MANAGED_DB_MARIADB_MEMORY_MB) || 1024,
    scheme: 'mysql',
  },
  // Per-scope, so there is no `container` and no `defaultPort` here: both are
  // allocated per instance and stored on the managed_databases row (migration
  // 089). Everything engine-specific lives in services/managedRedis.js; this
  // entry exists so ENGINES[engine] stays the one place that answers "is this a
  // real engine, and what is its URL scheme".
  redis: {
    image: redis.REDIS_IMAGE,
    container: null,
    defaultPort: null,
    containerPort: redis.REDIS_CONTAINER_PORT,
    dataPath: redis.REDIS_DATA_PATH,
    passwordEnv: redis.REDIS_PASSWORD_ENV,
    memoryMb: redis.REDIS_MEMORY_MB,
    scheme: 'redis',
    perScope: true,
  },
};

// Identifiers this module generates. Anything that fails this never reaches an
// engine: db_name and db_user are interpolated into DDL (they are identifiers,
// which no driver can bind as parameters), so this regex is the injection
// boundary, not a tidiness check.
const SAFE_IDENT = /^[a-z][a-z0-9_]{0,62}$/;

// Generated passwords are base64url, so this alphabet contains no quote,
// backslash or backtick and the literal below cannot be broken out of. Checked
// rather than assumed, because an operator-supplied or migrated password would
// reach the same code path.
const SAFE_PASSWORD = /^[A-Za-z0-9_-]{24,128}$/;

// MariaDB's user column was 32 bytes before 10.6 and Postgres truncates every
// identifier at 63. Both ceilings are enforced against the SHORTER one, so a
// name that works here works on any supported engine.
const MAX_IDENT_BYTES = 31;

// "the daemon cannot bind that host address". Native Linux says "cannot assign
// requested address"; Docker Desktop says "ports are not available: ... can't
// assign requested address". Matching only the first spelling is how the first
// run of this code failed on Desktop — the fallback never fired and the bad
// container was left behind for every later call to trip over.
const ADDR_UNAVAILABLE = /can(?:no|')t assign requested address|address not available|ports are not available/i;

/**
 * Remove a known secret from a message so it can be logged.
 *
 * Takes the secret as an argument rather than pattern-matching for
 * password-shaped strings: generated passwords are base64url, which is the same
 * alphabet as container ids, image digests and identifiers, so a shape-based
 * redactor would mangle every useful error while still missing an
 * operator-supplied password that happened to look different.
 */
function redactSecret(message, secret) {
  const text = String(message ?? '');
  if (!secret) return text;
  return text.split(secret).join('[redacted]');
}

async function dockerExec(args, opts = {}) {
  try {
    const { stdout } = await execFileAsync('docker', args, { timeout: 60000, ...opts });
    return stdout.trim();
  } catch (e) {
    // stderr first, matching docker.js: `docker run -d` writes the new container
    // id to stdout even when the run fails, so a stdout-first pick returns a
    // bare hex string and discards the reason.
    const output = e.stderr?.toString().trim() || e.stdout?.toString().trim() || e.message;
    throw new Error(output);
  }
}

/**
 * `docker ...` with a body on STDIN.
 *
 * spawn, not execFile: execFile has no `input` option (that belongs to the
 * *Sync* family), so passing one is silently ignored — the child gets an
 * inherited-empty stdin and psql/mariadb read EOF, which for psql looks like a
 * successful run of an empty script. Every provisioning statement in this module
 * travels this path, so getting it wrong would mean rows in SQLite and no
 * database in the engine. execFileSync would work and would block the event
 * loop for the length of a database DDL, which is not acceptable in a server.
 */
function dockerExecStdin(args, input, { timeout = 60000 } = {}) {
  return new Promise((resolve_, reject) => {
    const child = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`docker ${args[0]} timed out after ${timeout}ms`));
    }, timeout);
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { err += d; });
    child.on('error', e => { clearTimeout(timer); reject(e); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code === 0) return resolve_(out.trim());
      reject(new Error(err.trim() || out.trim() || `docker exited ${code}`));
    });
    // EPIPE if the child died before reading — the close handler already has the
    // real reason, so swallow it rather than replacing a useful SQL error with
    // a write error.
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}

// ---------------------------------------------------------------------------
// Scope -> names. ONE function, deliberately.
// ---------------------------------------------------------------------------

/**
 * A scope is `{ appId, tenant }`. tenant is null/'' today — the app itself — and
 * is the dimension multitenancy will fill in (services/tenants.js already models
 * a tenant as org+user). Everything downstream keys on the value this returns,
 * so adding the tenant dimension is a change HERE and nowhere else.
 */
export function normalizeScope(scope) {
  const appId = Number(scope?.appId);
  if (!Number.isInteger(appId) || appId <= 0) {
    throw new Error(`managedDb: scope.appId must be a positive integer, got ${JSON.stringify(scope?.appId)}`);
  }
  const tenant = scope?.tenant == null ? '' : String(scope.tenant);
  return { appId, tenant };
}

/**
 * Derive the database and role names for a scope.
 *
 *   app-scoped     { appId: 42 }                     -> crane_a42       / crane_a42_u
 *   tenant-scoped  { appId: 42, tenant: 'acme.com/u7' } -> crane_a42_t3f9a1c2b7e0
 *                                                       / crane_a42_t3f9a1c2b7e0_u
 *
 * THE TENANT IS HASHED, NOT SLUGGED, and so is anything else variable-length.
 * The tempting version builds the name from the app slug and the tenant string
 * and lets Postgres truncate at 63 bytes. Postgres truncates SILENTLY, and two
 * long scopes sharing a prefix truncate to the SAME identifier — at which point
 * the second app is handed the first app's database and every isolation grant in
 * this file is satisfied while the data is shared. That is a cross-app data leak
 * that presents as a successful deploy. A fixed-width hash of the full scope
 * string removes the failure mode instead of making it less likely, and the app
 * id (already unique, already short) carries the readable half.
 *
 * 12 hex characters is 48 bits: at the ~57 apps this platform runs, times any
 * plausible tenant count, the collision probability is negligible — and it is
 * not the last line of defence anyway, because migration 085's UNIQUE index on
 * (engine, db_name) turns a collision into a failed INSERT rather than a leak.
 */
export function namesForScope(scope) {
  const { appId, tenant } = normalizeScope(scope);
  let base = `crane_a${appId}`;
  if (tenant) {
    const h = crypto.createHash('sha256').update(tenant).digest('hex').slice(0, 12);
    base += `_t${h}`;
  }
  const database = base;
  const username = `${base}_u`;

  // Not defensive padding: an appId large enough to breach this would produce a
  // name Postgres silently truncates, which is the exact leak the hash exists to
  // prevent. Refusing to provision is the only safe answer.
  if (Buffer.byteLength(username) > MAX_IDENT_BYTES) {
    throw new Error(
      `managedDb: derived identifier "${username}" is ${Buffer.byteLength(username)} bytes, ` +
      `over the ${MAX_IDENT_BYTES}-byte ceiling. Shorten the naming scheme rather than letting ` +
      `the engine truncate it — truncation can collide with another scope's database.`
    );
  }
  if (!SAFE_IDENT.test(database) || !SAFE_IDENT.test(username)) {
    throw new Error(`managedDb: derived unsafe identifier from scope ${JSON.stringify(scope)}`);
  }
  return { database, username };
}

function assertIdent(name) {
  if (!SAFE_IDENT.test(name) || Buffer.byteLength(name) > MAX_IDENT_BYTES) {
    throw new Error(`managedDb: refusing to build SQL with identifier ${JSON.stringify(name)}`);
  }
  return name;
}

function assertPassword(pw) {
  if (!SAFE_PASSWORD.test(pw)) {
    // The value is NEVER echoed, here or anywhere else in this module.
    throw new Error('managedDb: password contains characters outside the safe alphabet; refusing to build SQL');
  }
  return pw;
}

/** 32 chars of base64url — no quote, backslash or backtick, and URL-safe, so it
 *  needs no escaping in SQL or in a connection string. Never logged. */
function generatePassword() {
  return crypto.randomBytes(24).toString('base64url');
}

// ---------------------------------------------------------------------------
// The shared server containers
// ---------------------------------------------------------------------------

function dataDirFor(engine) {
  const root = resolve(process.env.DATA_DIR || './data');
  return join(root, 'managed-db', engine);
}

/**
 * Host addresses to publish on. See the header: 127.0.0.1 alone is unreachable
 * from app containers on Linux, and 0.0.0.0 puts a database on the internet.
 */
async function bindAddresses() {
  const override = process.env.MANAGED_DB_BIND;
  if (override) return override.split(',').map(s => s.trim()).filter(Boolean);

  const addrs = ['127.0.0.1'];
  try {
    const gw = await dockerExec(
      ['network', 'inspect', 'bridge', '--format', '{{range .IPAM.Config}}{{.Gateway}}{{end}}'],
      { timeout: 10000 }
    );
    // host.docker.internal:host-gateway resolves to the default bridge gateway
    // on Linux. A daemon started with an explicit --host-gateway-ip breaks that
    // assumption; MANAGED_DB_BIND is the escape hatch for it.
    if (/^\d+\.\d+\.\d+\.\d+$/.test(gw) && gw !== '127.0.0.1') addrs.push(gw);
  } catch (e) {
    log.debug(`managedDb: could not read the default bridge gateway (${e.message}); publishing on loopback only`);
  }
  return addrs;
}

async function containerState(name) {
  try {
    return await dockerExec(['inspect', '-f', '{{.State.Status}}', name], { timeout: 10000 });
  } catch (_) {
    return null;
  }
}

function serverRow(engine) {
  return getDb().prepare('SELECT * FROM managed_db_servers WHERE engine = ?').get(engine) || null;
}

function upsertServerRow(engine, cfg, port, adminPassword) {
  getDb().prepare(`
    INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(engine) DO UPDATE SET container_name = excluded.container_name, image = excluded.image
  `).run(engine, cfg.container, cfg.image, port, encrypt(adminPassword));
}

/**
 * Wait until the server is serving on TCP, which is the only readiness signal
 * that means anything here.
 *
 * BOTH images run a TEMPORARY server during first-time initialisation — postgres
 * with listen_addresses='', MariaDB with --skip-networking — and then restart it
 * for real. A readiness probe over the unix socket therefore goes GREEN in the
 * middle of init, and the provisioning statements that follow land on a server
 * that is about to be shut down and reinitialised. Probing TCP on 127.0.0.1
 * inside the container is the check that cannot pass early, because TCP is
 * exactly what the temporary server does not offer.
 *
 * NEITHER probe carries a credential. pg_isready needs none, and mariadb-admin
 * is given a username that does not exist: once the server is up it answers
 * "Access denied", which proves the server is accepting and authenticating TCP
 * connections just as well as a successful ping would — without putting the
 * superuser password in the host's process table on every poll.
 */
async function waitReady(engine, timeoutMs = 120000) {
  const cfg = ENGINES[engine];
  const probe = engine === 'postgres'
    ? ['exec', cfg.container, 'pg_isready', '-q', '-h', '127.0.0.1', '-p', String(cfg.containerPort), '-U', 'postgres']
    : ['exec', cfg.container, 'mariadb-admin', 'ping', '--protocol=tcp', '-h', '127.0.0.1',
       '-P', String(cfg.containerPort), '-u', 'appcrane_readiness_probe'];
  const upAnyway = /access denied|using password/i;
  const deadline = Date.now() + timeoutMs;
  let last = '';
  while (Date.now() < deadline) {
    try {
      await dockerExec(probe, { timeout: 15000 });
      return;
    } catch (e) {
      if (engine === 'mariadb' && upAnyway.test(e.message)) return;
      last = e.message;
      await new Promise(r => setTimeout(r, 1000));
    }
  }
  throw new Error(`managedDb: ${engine} container did not become ready within ${timeoutMs}ms (last probe: ${last})`);
}

/**
 * Start the shared server for an engine if it is not already running, and return
 * its connection coordinates. Idempotent, and LAZY — nothing here runs until an
 * app actually asks for a database, so a platform whose apps need no SQL server
 * never pays for one.
 */
export async function ensureServer(engine) {
  const cfg = ENGINES[engine];
  if (!cfg) throw new Error(`managedDb: unknown engine '${engine}' (supported: ${SUPPORTED_ENGINES.join(', ')})`);
  if (cfg.perScope) {
    // Not a "not implemented" — there is no such object to ensure. A caller
    // that reaches here is holding an engine-shaped assumption that does not
    // apply, and silently returning something would let it hand an app a port
    // that belongs to nothing.
    throw new Error(
      `managedDb: '${engine}' has no shared server — it runs one container per scope. ` +
      `Use provision(scope, '${engine}') instead of ensureServer('${engine}').`
    );
  }

  let row = serverRow(engine);
  const port = row?.host_port || cfg.defaultPort;
  const adminPassword = row ? decrypt(row.admin_password_enc) : generatePassword();
  if (!row) {
    upsertServerRow(engine, cfg, port, adminPassword);
    row = serverRow(engine);
  }

  const state = await containerState(cfg.container);

  if (state && state !== 'running') {
    // exited / created / paused: the volume is intact and the password matches
    // the row, so a start is enough and a recreate would only risk the data.
    try {
      await dockerExec(['start', cfg.container], { timeout: 60000 });
    } catch (e) {
      // A container CREATED with a port binding the host cannot provide never
      // starts, and retrying `docker start` forever just repeats the same
      // error — which is what a run against Docker Desktop produced before this
      // branch existed. Recreate it against the bindable address instead. The
      // data is in the volume, not the container, so nothing is lost.
      if (!ADDR_UNAVAILABLE.test(e.message)) throw e;
      log.info(`managedDb: ${cfg.container} cannot start on its recorded bindings; recreating`);
      await dockerExec(['rm', '-f', cfg.container], { timeout: 60000 }).catch(() => {});
      await createServerContainer(engine, cfg, port, adminPassword);
    }
  } else if (!state) {
    await createServerContainer(engine, cfg, port, adminPassword);
  }

  await waitReady(engine);
  await ensureAdminCredentialFile(engine, adminPassword);
  await hardenServer(engine);
  return { engine, host: DB_HOST_FOR_CONTAINERS, port, container: cfg.container };
}

/**
 * Create and start the shared server container.
 *
 * The bridge-gateway publish is best-effort by design (see the header): it is
 * what makes Linux work and it is unbindable on Docker Desktop, where the
 * loopback publish alone is what apps reach. Rather than sniffing the platform,
 * ask for both and fall back when the daemon says it cannot bind — the daemons
 * disagree on the wording ("cannot assign requested address" on native Linux,
 * "ports are not available: ... can't assign requested address" on Desktop), so
 * ADDR_UNAVAILABLE matches both. A miss here is not silent: it surfaces as a
 * failed provision, not as a database quietly published somewhere else.
 */
async function createServerContainer(engine, cfg, port, adminPassword) {
  const dir = dataDirFor(engine);
  mkdirSync(dir, { recursive: true });

  // The superuser password goes in through --env-file rather than -e so it
  // never appears in the host's process table, where any local user can read
  // it. It is still visible in `docker inspect` — that is unavoidable for an
  // image that takes its init credential from the environment, and reading it
  // needs docker socket access, which is already root-equivalent.
  const envFile = join(dir, '.init-env');
  writeFileSync(envFile, `${cfg.passwordEnv}=${adminPassword}\n`, { mode: 0o600 });

  const args = [
    'run', '-d',
    '--name', cfg.container,
    '--label', 'appcrane=true',
    '--label', `appcrane-db=${engine}`,
    '--restart=on-failure:2',
    `--memory=${cfg.memoryMb}m`,
    // Equal to --memory: Docker's spelling for "no swap at all". Omitting it
    // silently doubles the real ceiling on any host that has swap. Same
    // reasoning as docker.js's app containers.
    `--memory-swap=${cfg.memoryMb}m`,
    '--security-opt', 'no-new-privileges',
    '--cap-drop', 'NET_RAW',
    '--log-opt', 'max-size=10m',
    '--log-opt', 'max-file=3',
    '--env-file', envFile,
    '-v', `${dir}:${cfg.dataPath}`,
  ];
  // NOT `--network appcrane-apps`: see the header. On that bridge the
  // app -> gateway -> database hop is a same-bridge hairpin, which
  // enable_icc=false drops. The default bridge makes it a cross-bridge hop,
  // which is the one that was measured working.
  for (const addr of await bindAddresses()) {
    args.push('-p', `${addr}:${port}:${cfg.containerPort}`);
  }
  args.push(cfg.image);

  try {
    await dockerExec(args, { timeout: 180000 });
  } catch (e) {
    // Retry without the bridge-gateway publish. On Docker Desktop
    // host.docker.internal is a Mac-side address that cannot be bound inside
    // the VM ("bind: cannot assign requested address"), and there the
    // loopback publish alone is what apps actually reach — measured.
    if (ADDR_UNAVAILABLE.test(e.message)) {
      log.info(`managedDb: bridge-gateway publish unavailable for ${engine}; publishing on loopback only`);
      // Drop every `-p <addr>:...` pair whose address is not loopback, taking
      // the flag and its value together. A filter that tests each element
      // independently leaves the orphaned `-p` behind and docker then reads
      // the image name as the port spec.
      const loopbackOnly = [];
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '-p' && !args[i + 1].startsWith('127.0.0.1')) { i++; continue; }
        loopbackOnly.push(args[i]);
      }
      // A half-created container from the failed run would make the retry fail
      // with "name already in use", which reads as an unrelated problem.
      await dockerExec(['rm', '-f', cfg.container], { timeout: 60000 }).catch(() => {});
      await dockerExec(loopbackOnly, { timeout: 180000 });
    } else {
      throw e;
    }
  } finally {
    // The plaintext credential must not outlive the one `docker run` that
    // needs it. Best-effort: a leftover file is a finding, not a crash.
    try { rmSync(envFile, { force: true }); } catch (_) {}
  }
  log.info(`managedDb: started shared ${engine} server on 127.0.0.1:${port}`);
}

/**
 * MariaDB's client cannot take a password on stdin while stdin is carrying the
 * script, and passing --password on the command line publishes the superuser
 * credential to the host's process table on every provisioning call. So the
 * credential is written INSIDE the container, over stdin, at 0600, and the
 * client picks it up from there. Rewritten on every ensureServer() because it
 * lives in the container's writable layer, not the volume, and so does not
 * survive a recreate.
 *
 * Postgres needs nothing equivalent: the official image ships
 * `local all all trust` in pg_hba.conf (verified by reading the file out of a
 * running container), so `docker exec -u postgres ... psql` authenticates over
 * the unix socket with no password anywhere.
 */
async function ensureAdminCredentialFile(engine, adminPassword) {
  if (engine !== 'mariadb') return;
  const body = `[client]\nuser=root\npassword=${adminPassword}\nprotocol=socket\n`;
  // The credential travels on stdin. It is a fixed shell string with nothing
  // interpolated into it, so this does not violate the "no user strings in
  // sh -c" rule — the variable part never touches argv at all.
  await dockerExecStdin(
    ['exec', '-i', ENGINES.mariadb.container, 'sh', '-c', 'cat > /root/.my.cnf && chmod 600 /root/.my.cnf'],
    body,
    { timeout: 30000 }
  );
}

/**
 * Server-wide hardening, applied on every ensure so a hand-restored volume or a
 * hand-created role cannot leave the server in the pre-hardening state.
 *
 * Postgres only, and it is the single most important statement in this module.
 * A FRESH POSTGRES ROLE CAN CONNECT TO EVERY DATABASE BY DEFAULT — CONNECT is
 * granted to PUBLIC on database creation. Without these revokes, app A's role
 * logs into `postgres` (or template1, or any database provisioned before the
 * revoke shipped) and the per-database grants below are decorative.
 *
 * MariaDB needs no equivalent: its privileges are per-database from the start
 * and a user with no grant on a database cannot USE it.
 */
async function hardenServer(engine) {
  if (engine !== 'postgres') return;
  await runAdminSql('postgres', [
    'REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;',
    'REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;',
  ].join('\n'));
}

/** Stop the shared server. The volume, and therefore the data, is untouched. */
export async function stopServer(engine) {
  const cfg = ENGINES[engine];
  if (!cfg) throw new Error(`managedDb: unknown engine '${engine}'`);
  if (cfg.perScope) {
    // Every instance this platform knows about. Same contract as the shared
    // case: the containers go, the volumes under DATA_DIR stay, so a later
    // provision() finds its data where it left it.
    for (const row of getDb().prepare(
      'SELECT container_name FROM managed_databases WHERE engine = ? AND container_name IS NOT NULL'
    ).all(engine)) {
      await dockerExec(['rm', '-f', row.container_name], { timeout: 60000 }).catch(() => {});
    }
    return;
  }
  await dockerExec(['rm', '-f', cfg.container], { timeout: 60000 }).catch(() => {});
}

// ---------------------------------------------------------------------------
// Redis: one container per scope
// ---------------------------------------------------------------------------
//
// The SQL half of this file provisions INSIDE a server that is already running.
// Redis provisions the server itself, so the two halves of "create the thing"
// and "create the credential" collapse into one function — but the ordering
// discipline is identical: the SQLite row is written first, and a failure after
// it rolls both back.

/** Each instance keeps its snapshot in its own directory under DATA_DIR. */
function redisDataDir(dbName) {
  return join(dataDirFor('redis'), assertIdent(dbName));
}

/**
 * Start (or restart) one scope's Redis and put its ACL user back.
 *
 * Idempotent and self-healing, in the same spirit as ensureServer(): a
 * container that exists but is stopped is started, one that has been removed is
 * recreated against its recorded port, and the ACL user is re-applied every
 * time because Redis holds ACLs in memory only — there is no aclfile, so a
 * restart drops every user except `default`.
 */
async function ensureRedisInstance({ container, dbName, username, password, port }) {
  assertIdent(dbName);
  assertIdent(username);
  assertPassword(password);

  const state = await containerState(container);
  if (state && state !== 'running') {
    try {
      await dockerExec(['start', container], { timeout: 60000 });
    } catch (e) {
      // Same recreate-on-unbindable-address branch the shared servers carry:
      // a container CREATED against a host address the daemon cannot provide
      // never starts, and retrying `docker start` repeats the error forever.
      if (!ADDR_UNAVAILABLE.test(e.message)) throw e;
      log.info(`managedDb: ${container} cannot start on its recorded bindings; recreating`);
      await dockerExec(['rm', '-f', container], { timeout: 60000 }).catch(() => {});
      await createRedisContainer({ container, dbName, password, port });
    }
  } else if (!state) {
    await createRedisContainer({ container, dbName, password, port });
  }

  await waitRedisReady(container);
  // Redacted at the throw: ACL SETUSER carries the password, and redis-cli
  // echoes the failing command back on an error.
  try {
    await dockerExecStdin(['exec', '-i', container, 'redis-cli'], redis.aclScript(username, password), { timeout: 30000 });
  } catch (e) {
    throw new Error(redactSecret(e.message, password));
  }
  return { engine: 'redis', host: DB_HOST_FOR_CONTAINERS, port, container };
}

async function createRedisContainer({ container, dbName, password, port }) {
  const dir = redisDataDir(dbName);
  mkdirSync(dir, { recursive: true });

  // Same --env-file reasoning as createServerContainer(): the credential must
  // not appear in the host's process table, and `docker run ... -e X=secret`
  // puts it there for every local user to read.
  const envFile = join(dir, '.init-env');
  writeFileSync(envFile, `${redis.REDIS_PASSWORD_ENV}=${password}\n`, { mode: 0o600 });

  const memoryMb = ENGINES.redis.memoryMb;
  const args = [
    'run', '-d',
    '--name', container,
    '--label', 'appcrane=true',
    '--label', 'appcrane-db=redis',
    '--label', `appcrane-db-name=${dbName}`,
    '--restart=on-failure:2',
    `--memory=${memoryMb}m`,
    `--memory-swap=${memoryMb}m`,
    '--security-opt', 'no-new-privileges',
    '--cap-drop', 'NET_RAW',
    '--log-opt', 'max-size=10m',
    '--log-opt', 'max-file=3',
    '--env-file', envFile,
    '-v', `${dir}:${ENGINES.redis.dataPath}`,
  ];
  // NOT `--network appcrane-apps` — see this file's header. Same publish
  // matrix, same best-effort bridge-gateway address.
  for (const addr of await bindAddresses()) {
    args.push('-p', `${addr}:${port}:${redis.REDIS_CONTAINER_PORT}`);
  }
  args.push(ENGINES.redis.image, ...redis.serverCommand(redis.maxmemoryMbFor(memoryMb)));

  try {
    await dockerExec(args, { timeout: 180000 });
  } catch (e) {
    if (ADDR_UNAVAILABLE.test(e.message)) {
      log.info(`managedDb: bridge-gateway publish unavailable for ${container}; publishing on loopback only`);
      const loopbackOnly = [];
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '-p' && !args[i + 1].startsWith('127.0.0.1')) { i++; continue; }
        loopbackOnly.push(args[i]);
      }
      await dockerExec(['rm', '-f', container], { timeout: 60000 }).catch(() => {});
      await dockerExec(loopbackOnly, { timeout: 180000 });
    } else {
      throw e;
    }
  } finally {
    try { rmSync(envFile, { force: true }); } catch (_) {}
  }
  log.info(`managedDb: started redis instance ${container} on 127.0.0.1:${port}`);
}

/**
 * Wait until the instance answers PING.
 *
 * Unlike the SQL images there is no two-phase init to outrun — Redis binds TCP
 * once and stays bound — so a plain PING is a real readiness signal. It carries
 * no credential in argv: redis-cli authenticates from REDISCLI_AUTH, which the
 * container already has in its environment.
 */
async function waitRedisReady(container, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  let last = '';
  while (Date.now() < deadline) {
    try {
      const out = await dockerExec(redis.readyProbeArgs(container), { timeout: 15000 });
      if (/PONG/.test(out)) return;
      last = out;
    } catch (e) {
      last = e.message;
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(`managedDb: redis instance ${container} did not become ready within ${timeoutMs}ms (last probe: ${last})`);
}

/** Ports this platform has already handed to a Redis instance. */
function usedRedisPorts() {
  return getDb().prepare(
    'SELECT host_port FROM managed_databases WHERE host_port IS NOT NULL'
  ).all().map(r => Number(r.host_port));
}

// ---------------------------------------------------------------------------
// Read-only status
// ---------------------------------------------------------------------------

/**
 * One `docker inspect` per engine, in one call, with the five facts the
 * dashboard needs. Several `-f` invocations would be several round trips to the
 * daemon per engine per poll, and this endpoint is polled.
 *
 * The template is an EXPLICIT field list and must stay one. `{{json .}}` would
 * be shorter and would put .Config.Env — which carries POSTGRES_PASSWORD /
 * MARIADB_ROOT_PASSWORD, the superuser credential — into a string this module
 * hands to an HTTP response.
 *
 * '|' as the separator is safe against every value in the list: Docker's status
 * vocabulary is created/running/paused/restarting/removing/exited/dead, the
 * three numeric/boolean fields cannot contain one, and StartedAt is RFC3339.
 */
const STATUS_FIELDS = [
  '{{.State.Status}}',
  '{{.RestartCount}}',
  '{{.State.ExitCode}}',
  '{{.State.OOMKilled}}',
  '{{.State.StartedAt}}',
  // The cap the RUNNING container actually has, in bytes (0 = unlimited).
  //
  // Reported alongside the configured value rather than instead of it because a
  // container's memory limit is fixed when it is CREATED. Raising
  // MANAGED_DB_*_MEMORY_MB changes what the next container would get and does
  // nothing to the one already running, so a dashboard that showed only the
  // config would tell an operator their raise had taken effect while the live
  // cgroup was unchanged -- and it would say so most confidently in the one
  // situation where it matters, someone reading this page right after an OOM.
  '{{.HostConfig.Memory}}',
];
const STATUS_SEP = '|';
const STATUS_FORMAT = STATUS_FIELDS.join(STATUS_SEP);

// "the container is not there", which is a STATE to report, not an error to
// report. Anything else from inspect — daemon unreachable, docker not
// installed, permission denied — is a genuine failure and belongs in `error`.
const NO_SUCH_CONTAINER = /no such (?:object|container)/i;

// Docker's zero value for a container that has never run.
const ZERO_TIME = '0001-01-01T00:00:00Z';

function intOrNull(s) {
  if (s === undefined || s === '') return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

/**
 * The shared servers, as the platform dashboard sees them. READ ONLY.
 *
 * This function must never start, create or provision anything — in particular
 * it must never call ensureServer(). It exists to be POLLED by a dashboard, and
 * lazily standing up a Postgres container because somebody opened a browser tab
 * is not a side effect an admin can consent to. `docker inspect` is the only
 * command it issues.
 *
 * It also never decrypts. managed_db_servers carries admin_password_enc; the
 * SELECT below names its columns rather than spreading the row, so the
 * superuser credential cannot reach a caller through a careless `...row`.
 *
 * An engine with no managed_db_servers row has simply never been used. It is
 * still reported — the dashboard needs to say "Postgres: not provisioned"
 * rather than omit it — with what the config says it WOULD be, `databases: 0`,
 * and null docker facts.
 *
 * REDIS IS REPORTED AS ONE ROW WITH AN `instances` ARRAY, because it is one
 * container per app and there is no single server to inspect. The row keeps the
 * same field names so a dashboard written against the shared engines does not
 * have to special-case it; `container` and `host_port` are null on it, which is
 * the truth rather than a placeholder. The aggregate `running` is "there is at
 * least one instance and every one of them is up" — a fleet where one app's
 * Redis is dead must not read as green.
 */

/**
 * One `docker inspect` for one container, parsed. Null when there is no such
 * container, which is a STATE to report and not an error.
 */
async function inspectFacts(container) {
  let raw;
  try {
    raw = await dockerExec(['inspect', '-f', STATUS_FORMAT, container], { timeout: 10000 });
  } catch (e) {
    if (NO_SUCH_CONTAINER.test(e.message)) return { absent: true, error: null };
    return { absent: true, error: e.message };
  }
  const [state, restarts, exitCode, oom, startedAt, memBytes] = raw.split(STATUS_SEP);
  const bytes = intOrNull(memBytes);
  return {
    absent: false,
    error: null,
    state: state || null,
    running: state === 'running',
    restart_count: intOrNull(restarts),
    last_exit_code: intOrNull(exitCode),
    oom_killed: oom === 'true',
    started_at: startedAt && startedAt !== ZERO_TIME ? startedAt : null,
    // 0 is Docker's "no limit", which is a different fact from "unknown" and
    // must not be rounded into 0 MB.
    memory_mb: bytes === null || bytes === 0 ? null : Math.round(bytes / (1024 * 1024)),
  };
}

async function perScopeStatus(engine, cfg, count) {
  const rows = getDb().prepare(
    'SELECT app_id, tenant, db_name, container_name, host_port FROM managed_databases WHERE engine = ? ORDER BY id'
  ).all(engine);

  const instances = await Promise.all(rows.map(async (r) => {
    const facts = await inspectFacts(r.container_name);
    return {
      container: r.container_name,
      database: r.db_name,
      host_port: r.host_port,
      scope: { app_id: r.app_id, tenant: r.tenant || null },
      state: facts.absent ? null : facts.state,
      running: facts.absent ? false : facts.running,
      restart_count: facts.absent ? null : facts.restart_count,
      last_exit_code: facts.absent ? null : facts.last_exit_code,
      oom_killed: facts.absent ? null : facts.oom_killed,
      started_at: facts.absent ? null : facts.started_at,
      memory_mb: facts.absent ? null : facts.memory_mb,
      error: facts.error,
    };
  }));

  const firstError = instances.find(i => i.error)?.error || null;
  return {
    engine,
    container: null,
    image: cfg.image,
    configured: instances.length > 0,
    state: null,
    running: instances.length > 0 && instances.every(i => i.running),
    host_port: null,
    memory_mb: null,
    configured_memory_mb: cfg.memoryMb,
    databases: count,
    // Aggregated across instances rather than invented: the maximum restart
    // count and "did ANY of them get OOM-killed", which is the question an
    // operator is actually asking when they open this page.
    restart_count: instances.length ? Math.max(...instances.map(i => i.restart_count ?? 0)) : null,
    last_exit_code: null,
    oom_killed: instances.length ? instances.some(i => i.oom_killed === true) : null,
    started_at: null,
    error: firstError,
    instances,
  };
}

export async function serverStatus() {
  const db = getDb();
  const counts = new Map(
    db.prepare('SELECT engine, COUNT(*) AS n FROM managed_databases GROUP BY engine')
      .all().map(r => [r.engine, r.n])
  );
  const rows = new Map(
    db.prepare('SELECT engine, container_name, image, host_port FROM managed_db_servers')
      .all().map(r => [r.engine, r])
  );

  return Promise.all(SUPPORTED_ENGINES.map(async (engine) => {
    const cfg = ENGINES[engine];
    const count = counts.get(engine) || 0;
    if (cfg.perScope) return perScopeStatus(engine, cfg, count);

    const row = rows.get(engine) || null;
    // The recorded container/image win over the config: they are what actually
    // exists on the host, and are what inspect has to be pointed at. A config
    // change (a new image pin, a renamed prefix) must not make a running server
    // read as absent.
    const container = row?.container_name || cfg.container;

    const out = {
      engine,
      container,
      image: row?.image || cfg.image,
      configured: Boolean(row),
      state: null,
      running: false,
      host_port: row?.host_port ?? cfg.defaultPort,
      memory_mb: null,
      configured_memory_mb: cfg.memoryMb,
      databases: count,
      restart_count: null,
      last_exit_code: null,
      oom_killed: null,
      started_at: null,
      error: null,
    };

    const facts = await inspectFacts(container);
    if (facts.absent) {
      out.error = facts.error;
      return out;
    }
    out.state = facts.state;
    out.running = facts.running;
    out.restart_count = facts.restart_count;
    out.last_exit_code = facts.last_exit_code;
    out.oom_killed = facts.oom_killed;
    out.started_at = facts.started_at;
    out.memory_mb = facts.memory_mb;
    return out;
  }));
}

// ---------------------------------------------------------------------------
// Admin SQL
// ---------------------------------------------------------------------------

/**
 * Run SQL as the engine's superuser, over the container's unix socket. The
 * script goes in on STDIN, never in argv — identifiers are interpolated by the
 * callers (assertIdent'd first; an identifier cannot be a bind parameter in any
 * driver) and passwords are interpolated as literals from an alphabet with no
 * quoting characters in it (assertPassword). Neither ever reaches a shell.
 */
async function runAdminSql(engine, sql, { database } = {}) {
  const cfg = ENGINES[engine];
  if (engine === 'postgres') {
    return dockerExecStdin(
      ['exec', '-u', 'postgres', '-i', cfg.container,
        'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', database ? assertIdent(database) : 'postgres', '-f', '-'],
      sql,
      { timeout: 60000 }
    );
  }
  const args = ['exec', '-i', cfg.container, 'mariadb', '--batch'];
  if (database) args.push(assertIdent(database));
  return dockerExecStdin(args, sql, { timeout: 60000 });
}

// ---------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------

/**
 * The grants. Requirement 1 in one place: "an app's credentials must reach that
 * app's database and NOTHING else."
 *
 * POSTGRES. Four things have to be true, and three of them are revokes:
 *   - The role is created with every attribute off. NOSUPERUSER is obvious;
 *     NOCREATEDB stops it provisioning around us, NOCREATEROLE stops it minting
 *     a role with different grants, NOREPLICATION stops it streaming the whole
 *     cluster — which would include every other app's database — out of a
 *     replication slot without ever "connecting" to those databases at all.
 *   - REVOKE ALL ... FROM PUBLIC on the new database. CONNECT is granted to
 *     PUBLIC at creation, so without this, every existing and future role on the
 *     server can open this app's database. This is the whole failure mode.
 *   - REVOKE ALL ON SCHEMA public FROM PUBLIC. PG15+ already removes PUBLIC's
 *     CREATE here, but the platform must not depend on a default that differed
 *     in PG14 and could differ again; on an older image the omission lets any
 *     role plant objects in every app's schema.
 *   - The app's role OWNS its database and its public schema, so it can do
 *     everything an application needs (DDL, extensions it is allowed) inside
 *     that one database and has no route out of it.
 *
 * MEASURED, as app A's role against app B's database on postgres:16-alpine:
 *   connect to B's database   FATAL: permission denied for database "crane_a2"
 *   connect to `postgres`     FATAL: permission denied for database "postgres"
 *   connect to `template1`    FATAL: permission denied for database "template1"
 *   CREATE DATABASE           ERROR: permission denied to create database
 *   CREATE ROLE               ERROR: permission denied to create role
 *   SELECT * FROM pg_shadow   ERROR: permission denied for view pg_shadow
 *   COPY TO PROGRAM 'id'      ERROR: permission denied ... pg_execute_server_program
 *
 * KNOWN AND ACCEPTED LEAK, stated rather than glossed: from inside its own
 * database the role can still read pg_database and pg_roles, so it learns the
 * NAMES `crane_a2` / `crane_a2_u` exist. Postgres offers no supported way to
 * hide those — revoking SELECT on pg_database breaks psql, pg_dump and most
 * drivers — and the names are opaque ids, not app slugs. No row of another app's
 * data is reachable. test/managed-db.test.js asserts this boundary explicitly so
 * it cannot quietly widen from "names" to "data".
 *
 * MARIADB is simpler because its grants are per-database by construction:
 * GRANT ALL PRIVILEGES ON `db`.* — no *.*, and no WITH GRANT OPTION, so the role
 * cannot re-grant itself or anyone else. Measured, as app A against app B:
 *   SELECT ... FROM crane_a2.secrets  ERROR 1142 SELECT command denied
 *   USE crane_a2                      ERROR 1044 Access denied
 *   CREATE DATABASE evil              ERROR 1044 Access denied
 *   CREATE USER                       ERROR 1227 need CREATE USER privilege
 *   SELECT * FROM mysql.global_priv   ERROR 1142 SELECT command denied
 *   SHOW DATABASES                    lists only crane_a1 + information_schema
 * MariaDB does not even leak the other database's name, which is the one place
 * it is stricter than Postgres.
 */
function provisionSql(engine, database, username, password) {
  assertIdent(database);
  assertIdent(username);
  assertPassword(password);

  if (engine === 'postgres') {
    return {
      onServer: [
        `CREATE ROLE "${username}" LOGIN PASSWORD '${password}'`,
        '  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;',
        `CREATE DATABASE "${database}" OWNER "${username}";`,
        `REVOKE ALL ON DATABASE "${database}" FROM PUBLIC;`,
        `GRANT CONNECT, TEMPORARY ON DATABASE "${database}" TO "${username}";`,
      ].join('\n'),
      onDatabase: [
        'REVOKE ALL ON SCHEMA public FROM PUBLIC;',
        `ALTER SCHEMA public OWNER TO "${username}";`,
        `GRANT ALL ON SCHEMA public TO "${username}";`,
      ].join('\n'),
    };
  }

  return {
    onServer: [
      `CREATE USER '${username}'@'%' IDENTIFIED BY '${password}';`,
      `CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`,
      `GRANT ALL PRIVILEGES ON \`${database}\`.* TO '${username}'@'%';`,
      'FLUSH PRIVILEGES;',
    ].join('\n'),
    onDatabase: null,
  };
}

function rowFor(scope, engine) {
  const { appId, tenant } = normalizeScope(scope);
  return getDb().prepare(
    'SELECT * FROM managed_databases WHERE app_id = ? AND tenant = ? AND engine = ?'
  ).get(appId, tenant, engine) || null;
}

function connectionFor(row, port) {
  const password = decrypt(row.password_enc);
  const scheme = ENGINES[row.engine].scheme;

  // REDIS HAS NO DATABASE NAME, and the one thing a Redis client can do with a
  // `database` field is SELECT an integer — so that is what it gets.
  //
  // `row.db_name` is AppCrane's own handle: it names the container and the
  // volume and it is what migration 085's UNIQUE (engine, db_name) collision
  // guard is computed over. It is never sent to Redis. Returning it here would
  // put REDIS_DB=crane_a42 into an app's environment and every client would
  // fail parsing it as an index.
  if (row.engine === 'redis') {
    return {
      engine: 'redis',
      host: DB_HOST_FOR_CONTAINERS,
      port,
      database: redis.REDIS_DB_INDEX,
      username: row.db_user,
      password,
      url: redis.redisUrl({ username: row.db_user, password, host: DB_HOST_FOR_CONTAINERS, port }),
    };
  }

  return {
    engine: row.engine,
    host: DB_HOST_FOR_CONTAINERS,
    port,
    database: row.db_name,
    username: row.db_user,
    password,
    // base64url passwords need no percent-encoding, which is the other reason
    // the alphabet is what it is.
    url: `${scheme}://${row.db_user}:${password}@${DB_HOST_FOR_CONTAINERS}:${port}/${row.db_name}`,
  };
}

/**
 * Provision (or return the existing) database for a scope. Returns full
 * connection details INCLUDING the password, for the caller to inject into a
 * container's environment. The password is never logged, here or anywhere.
 */
export async function provision(scope, engine) {
  if (!ENGINES[engine]) throw new Error(`managedDb: unknown engine '${engine}' (supported: ${SUPPORTED_ENGINES.join(', ')})`);
  if (ENGINES[engine].perScope) return provisionPerScope(scope, engine);
  const { appId, tenant } = normalizeScope(scope);

  const server = await ensureServer(engine);

  const existing = rowFor(scope, engine);
  if (existing) return connectionFor(existing, server.port);

  const { database, username } = namesForScope(scope);
  const password = generatePassword();

  // The row goes in FIRST. If the INSERT loses a race — two deploys of the same
  // app, or migration 085's (engine, db_name) collision guard firing — we must
  // not have already created a role in the engine that nothing points at.
  const db = getDb();
  try {
    db.prepare(`
      INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(appId, tenant, engine, database, username, encrypt(password));
  } catch (e) {
    if (/UNIQUE constraint/i.test(e.message)) {
      const raced = rowFor(scope, engine);
      if (raced) return connectionFor(raced, server.port);
      throw new Error(
        `managedDb: identifier '${database}' is already provisioned on ${engine} for a different scope. ` +
        `This is a name-derivation collision and provisioning is refusing rather than handing over ` +
        `another scope's database.`
      );
    }
    throw e;
  }

  const sql = provisionSql(engine, database, username, password);
  try {
    await runAdminSql(engine, sql.onServer);
    if (sql.onDatabase) await runAdminSql(engine, sql.onDatabase, { database });
  } catch (e) {
    // Engine-side failure with a row already written would leave AppCrane
    // believing in a database that does not exist. Roll both back.
    db.prepare('DELETE FROM managed_databases WHERE app_id = ? AND tenant = ? AND engine = ?')
      .run(appId, tenant, engine);
    await dropInEngine(engine, database, username).catch(() => {});
    // Redacted HERE, where the password is in scope, rather than by the route.
    //
    // The engine can echo a failing statement back in its error, and
    // provisionSql embeds the generated password in CREATE ROLE / CREATE USER.
    // Scrubbing it at the throw is what makes this message safe to log, and
    // until now nothing logged it at all: routes/managedDb.js replaced it with a
    // fixed 502 string and did not even import a logger, so a failed provision
    // left no record of its cause anywhere. Three separate wrong theories were
    // argued about one such failure before anyone noticed the reason was simply
    // never written down.
    throw new Error(`managedDb: provisioning ${engine} database failed: ${redactSecret(e.message, password)}`);
  }

  log.info(`managedDb: provisioned ${engine} database ${database} for app ${appId}${tenant ? ` tenant ${tenant}` : ''}`);
  return connectionFor(rowFor(scope, engine), server.port);
}

/**
 * Provision a scope's OWN server — today, Redis.
 *
 * The row is written FIRST, exactly as the shared path does and for a stronger
 * reason: the row is where the port and the container name are ALLOCATED, so
 * two concurrent deploys of the same app race on migration 089's UNIQUE index
 * rather than on `docker run --name`, which would leave one of them holding a
 * half-created container nothing points at.
 *
 * A row that already exists is not re-created — it is ensured. That covers the
 * ordinary case (a redeploy) and the interesting one (the host rebooted, or an
 * operator ran `docker rm`): the container comes back on its recorded port with
 * its recorded volume, and the app's credential keeps working.
 */
async function provisionPerScope(scope, engine) {
  const { appId, tenant } = normalizeScope(scope);
  const { database, username } = namesForScope(scope);
  const db = getDb();

  const existing = rowFor(scope, engine);
  if (existing) {
    await ensureRedisInstance({
      container: existing.container_name,
      dbName: existing.db_name,
      username: existing.db_user,
      password: decrypt(existing.password_enc),
      port: existing.host_port,
    });
    return connectionFor(existing, existing.host_port);
  }

  const password = generatePassword();
  const container = redis.containerNameFor(CONTAINER_PREFIX, database);
  const port = redis.pickPort(usedRedisPorts());

  try {
    db.prepare(`
      INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc, host_port, container_name)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(appId, tenant, engine, database, username, encrypt(password), port, container);
  } catch (e) {
    if (/UNIQUE constraint/i.test(e.message)) {
      const raced = rowFor(scope, engine);
      if (raced) {
        await ensureRedisInstance({
          container: raced.container_name,
          dbName: raced.db_name,
          username: raced.db_user,
          password: decrypt(raced.password_enc),
          port: raced.host_port,
        });
        return connectionFor(raced, raced.host_port);
      }
      throw new Error(
        `managedDb: identifier '${database}' is already provisioned on ${engine} for a different scope. ` +
        `This is a name-derivation collision and provisioning is refusing rather than handing over ` +
        `another scope's database.`
      );
    }
    throw e;
  }

  try {
    await ensureRedisInstance({ container, dbName: database, username, password, port });
  } catch (e) {
    db.prepare('DELETE FROM managed_databases WHERE app_id = ? AND tenant = ? AND engine = ?')
      .run(appId, tenant, engine);
    await destroyRedisInstance(container, database).catch(() => {});
    throw new Error(`managedDb: provisioning ${engine} database failed: ${redactSecret(e.message, password)}`);
  }

  log.info(`managedDb: provisioned redis instance ${container} for app ${appId}${tenant ? ` tenant ${tenant}` : ''}`);
  return connectionFor(rowFor(scope, engine), port);
}

/**
 * Destroy an instance and its data.
 *
 * THE VOLUME GOES TOO, which is the opposite of stopServer(). Deprovisioning is
 * the destructive call — routes/managedDb.js makes the caller confirm with the
 * app's slug — and leaving the RDB snapshot behind would mean a later app that
 * happened to derive the same name inherited a stranger's keyspace. The
 * directory is under DATA_DIR/managed-db/redis and is named by an assertIdent'd
 * identifier this module derived, never by anything a caller supplied.
 */
async function destroyRedisInstance(container, dbName) {
  if (container) await dockerExec(['rm', '-f', container], { timeout: 60000 }).catch(() => {});
  if (dbName) {
    try { rmSync(redisDataDir(dbName), { recursive: true, force: true }); } catch (e) {
      log.warn(`managedDb: could not remove the data directory for redis instance ${container}: ${e.message}`);
    }
  }
}

/** Existing credentials for a scope, or null. Does not start a server. */
export function credentialsFor(scope, engine) {
  const row = rowFor(scope, engine);
  if (!row) return null;
  // A per-scope engine carries its port on the ROW: there is no server row to
  // read it from, and ENGINES[engine].defaultPort is deliberately null so a
  // missed branch here fails loudly rather than handing out port `null`.
  if (ENGINES[engine].perScope) return connectionFor(row, row.host_port);
  const server = serverRow(engine);
  return connectionFor(row, server?.host_port || ENGINES[engine].defaultPort);
}

/** Rows for an app, without decrypting anything. Safe to hand to an API. */
export function listForApp(appId) {
  return getDb().prepare(
    'SELECT id, app_id, tenant, engine, db_name, db_user, created_at FROM managed_databases WHERE app_id = ?'
  ).all(Number(appId));
}

async function dropInEngine(engine, database, username) {
  assertIdent(database);
  assertIdent(username);
  if (engine === 'postgres') {
    // WITH (FORCE) terminates any session the app still holds — without it a
    // container that has not shut down yet keeps the database undroppable, and
    // a delete that half-succeeds is worse than one that fails.
    await runAdminSql('postgres', [
      `DROP DATABASE IF EXISTS "${database}" WITH (FORCE);`,
      `DROP ROLE IF EXISTS "${username}";`,
    ].join('\n'));
    return;
  }
  await runAdminSql('mariadb', [
    `DROP DATABASE IF EXISTS \`${database}\`;`,
    `DROP USER IF EXISTS '${username}'@'%';`,
    'FLUSH PRIVILEGES;',
  ].join('\n'));
}

/**
 * Drop a scope's database and login role, then forget it. Idempotent: a scope
 * that was never provisioned is a no-op.
 */
export async function deprovision(scope, engine) {
  const row = rowFor(scope, engine);
  if (!row) return false;
  await dropRow(row);
  getDb().prepare('DELETE FROM managed_databases WHERE id = ?').run(row.id);
  log.info(`managedDb: deprovisioned ${engine} database ${row.db_name}`);
  return true;
}

/**
 * Remove one row's engine-side objects, whichever engine it is.
 *
 * ONE function, so the two teardown callers below cannot drift into handling
 * different engine sets — which is precisely how an orphaned container holding
 * a deleted app's data would happen.
 */
async function dropRow(row) {
  if (ENGINES[row.engine]?.perScope) {
    // Best-effort ACL drop BEFORE the container goes, so that a container this
    // module fails to remove — a daemon hiccup, a `docker rm` that hangs — is
    // at least no longer answering to the credential AppCrane just forgot.
    if (row.container_name) {
      await dockerExecStdin(
        ['exec', '-i', row.container_name, 'redis-cli'],
        redis.aclDropScript(assertIdent(row.db_user)),
        { timeout: 15000 },
      ).catch(() => {});
    }
    await destroyRedisInstance(row.container_name, row.db_name);
    return;
  }
  await ensureServer(row.engine);
  await dropInEngine(row.engine, row.db_name, row.db_user);
}

/**
 * Every managed database an app owns, across engines and (later) tenants.
 *
 * THIS MUST BE CALLED BEFORE `DELETE FROM apps`. Migration 085's foreign key
 * cascades the ROW away, and SQLite obviously cannot reach into Postgres to drop
 * the database — so a delete that skips this leaves an orphaned database and a
 * live login role holding the deleted app's data, with nothing in AppCrane
 * pointing at either. See the wiring note in the migration.
 */
export async function deprovisionApp(appId) {
  const rows = getDb().prepare('SELECT * FROM managed_databases WHERE app_id = ?').all(Number(appId));
  let dropped = 0;
  for (const row of rows) {
    try {
      await dropRow(row);
      getDb().prepare('DELETE FROM managed_databases WHERE id = ?').run(row.id);
      dropped++;
    } catch (e) {
      // Never block an app delete on a database server that is down: report it
      // so the orphan is visible, rather than leaving the app undeletable.
      log.warn(`managedDb: could not deprovision ${row.engine} database ${row.db_name} for app ${appId}: ${e.message}`);
    }
  }
  return { requested: rows.length, dropped };
}
