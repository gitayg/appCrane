/**
 * Backup and restore of managed databases — one logical dump per
 * (app, scope, engine), streamed between the engine container and a host file.
 *
 * Where these dumps end up:
 *   - per-app backups (routes/backups.js): a backup of app X env E dumps the
 *     databases of the scope E connects to, next to the /data archive, in the
 *     SAME backup record (backups.databases, migration 109). Restoring that
 *     record can restore the databases too.
 *   - the whole-system export (configBackup.js, contents 'full'): every
 *     managed database under managed-db/<engine>/<db>.dump, which is what the
 *     nightly off-site upload ships.
 *
 * The argv and SQL come from managedDbDumpCmd.js (pure, tested without a
 * daemon); the engine handles (ensureServer, the admin SQL path, the mongo
 * admin credential) come from managedDb.backupAccess, so this module never
 * holds a second copy of how AppCrane authenticates as a superuser.
 *
 * STREAMED, NOT BUFFERED. A dump goes docker stdout -> fs write stream, and a
 * restore fs read stream -> docker stdin, with backpressure handled by pipe().
 * managedDb's dockerExecStdin collects output in a string, which is right for
 * a provisioning statement and wrong for a multi-GB database.
 *
 * WHAT A RESTORE NEVER DOES: it never touches a login's TLS / certificate /
 * limit policy except to put it back. The database's contents are replaced;
 * the role or user, its password and its certificate requirement are
 * server-level objects a single-database dump does not contain, and after the
 * load the policy is RE-APPLIED from the row (reapplyLoginPolicy) so that a
 * restore can only ever leave a login as strict as managed-database TLS made it.
 */

import { spawn } from 'child_process';
import { createReadStream, createWriteStream } from 'fs';
import { rm, stat } from 'fs/promises';
import { randomBytes } from 'crypto';
import { getDb } from '../db.js';
import * as cmd from './managedDbDumpCmd.js';
import * as tlsCfg from './managedDbTls.js';
import * as redis from './managedRedis.js';
import * as mongo from './managedMongo.js';
import { getManagedDbSettings } from './managedDbSettings.js';
import log from '../utils/logger.js';

// A large database takes a while; a hung one must still end. Overridable for
// a host whose biggest database needs longer.
const STREAM_TIMEOUT_MS = Number(process.env.MANAGED_DB_DUMP_TIMEOUT_MS) || 60 * 60 * 1000;

let defaultOps = null;
async function engineOps(ops) {
  if (ops) return ops;
  // Lazy for the same reason routes/managedDb.js loads the engine lazily: a
  // broken engine module must fail a backup, not the boot.
  if (!defaultOps) defaultOps = (await import('./managedDb.js')).backupAccess;
  return defaultOps;
}

/** Only the last few KB of stderr: enough for the reason, never a whole log. */
function tail(s, n = 4000) { return s.length > n ? s.slice(-n) : s; }

/**
 * `docker <args>` with stdout written to `file` (0600). Resolves when the
 * process exited 0 AND the file is fully flushed; anything else rejects and
 * removes the partial file, so a failed dump can never be mistaken for a
 * small one.
 */
export function execToFile(args, file, { input = null, timeout = STREAM_TIMEOUT_MS } = {}) {
  return new Promise((resolve_, reject) => {
    const out = createWriteStream(file, { mode: 0o600 });
    const child = spawn('docker', args, { stdio: [input == null ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
    let err = '';
    let code = null;
    let flushed = false;
    let failed = false;
    const fail = (e) => {
      if (failed) return;
      failed = true;
      clearTimeout(timer);
      child.kill('SIGKILL');
      out.destroy();
      rm(file, { force: true }).finally(() => reject(e));
    };
    const done = () => {
      if (failed || code === null || !flushed) return;
      clearTimeout(timer);
      if (code === 0) resolve_();
      else fail(new Error(tail(err.trim()) || `docker exited ${code}`));
    };
    const timer = setTimeout(() => fail(new Error(`docker ${args[0]} timed out after ${timeout}ms`)), timeout);
    child.stderr.on('data', (d) => { err = tail(err + d, 16000); });
    child.on('error', fail);
    out.on('error', fail);
    out.on('finish', () => { flushed = true; done(); });
    child.stdout.pipe(out);
    child.on('close', (c) => { code = c; done(); });
    if (input != null) {
      child.stdin.on('error', () => {});
      child.stdin.end(input);
    }
  });
}

/** `docker <args>` with `file` streamed to its stdin. Resolves with stdout (capped). */
export function execFromFile(args, file, { timeout = STREAM_TIMEOUT_MS, env = null } = {}) {
  return new Promise((resolve_, reject) => {
    // `env` carries a value that `docker exec -e NAME` forwards by name, so it
    // reaches the tool without ever being an argv element.
    const child = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'], ...(env ? { env: { ...process.env, ...env } } : {}) });
    let out = '';
    let err = '';
    let settled = false;
    const settle = (fn, v) => { if (!settled) { settled = true; clearTimeout(timer); fn(v); } };
    const timer = setTimeout(() => { child.kill('SIGKILL'); settle(reject, new Error(`docker ${args[0]} timed out after ${timeout}ms`)); }, timeout);
    child.stdout.on('data', (d) => { out = tail(out + d, 16000); });
    child.stderr.on('data', (d) => { err = tail(err + d, 16000); });
    child.on('error', (e) => settle(reject, e));
    child.on('close', (c) => {
      if (c === 0) settle(resolve_, out.trim());
      else settle(reject, new Error(tail(err.trim()) || tail(out.trim()) || `docker exited ${c}`));
    });
    // EPIPE when the tool dies early: the close handler carries the reason.
    child.stdin.on('error', () => {});
    const src = createReadStream(file);
    src.on('error', (e) => { child.kill('SIGKILL'); settle(reject, e); });
    src.pipe(child.stdin);
  });
}

/** Small capture helper for redis-cli and other short commands. */
function execCapture(args, { input = null, timeout = 60000 } = {}) {
  return new Promise((resolve_, reject) => {
    const child = spawn('docker', args, { stdio: [input == null ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`docker ${args[0]} timed out after ${timeout}ms`)); }, timeout);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (c) => {
      clearTimeout(timer);
      if (c === 0) resolve_(out.trim());
      else reject(new Error(tail(err.trim()) || tail(out.trim()) || `docker exited ${c}`));
    });
    if (input != null) { child.stdin.on('error', () => {}); child.stdin.end(input); }
  });
}

/**
 * Run `fn(configPath)` with mongo's tool config present inside the container
 * for exactly that long. The password goes in on stdin and the file is
 * removed in `finally`, so it does not outlive the one dump or restore.
 */
async function withMongoToolConfig(ops, fn) {
  const container = ops.containerFor('mongo');
  const { port, adminPassword } = ops.adminCoordsFor('mongo');
  const configPath = `/tmp/appcrane-mongotool-${randomBytes(12).toString('hex')}.yaml`;
  await execCapture(cmd.mongoConfigWriteArgs(container, configPath), { input: cmd.mongoConfigBody(ops.assertPassword(adminPassword)) });
  try {
    return await fn({ container, port, configPath, adminPassword });
  } catch (e) {
    throw new Error(ops.redactSecret(e.message, adminPassword));
  } finally {
    await execCapture(cmd.mongoConfigRemoveArgs(container, configPath)).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Dump
// ---------------------------------------------------------------------------

/** Parse `INFO persistence` into an object. */
function parseInfo(text) {
  const o = {};
  for (const line of String(text).split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i > 0) o[line.slice(0, i)] = line.slice(i + 1).trim();
  }
  return o;
}

/**
 * Redis: BGSAVE, wait for THAT save to finish, then copy the RDB out.
 *
 * Waits on rdb_saves (a counter, Redis 7+) rather than LASTSAVE, whose
 * one-second resolution cannot tell a save that finished in the same second as
 * the previous one from no save at all. BGSAVE SCHEDULE instead of plain
 * BGSAVE: if Redis's own save schedule is already writing, plain BGSAVE errors
 * out, while SCHEDULE queues ours behind it.
 */
async function dumpRedis(row, file, { timeoutMs = 120000 } = {}) {
  const tls = row.client_cert_required === 1;
  const cli = redis.cliArgs(row.container_name, { tls });
  const before = Number(parseInfo(await execCapture([...cli, 'INFO', 'persistence'])).rdb_saves || 0);
  await execCapture([...cli, 'BGSAVE', 'SCHEDULE']);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const info = parseInfo(await execCapture([...cli, 'INFO', 'persistence']));
    if (Number(info.rdb_saves || 0) > before && info.rdb_bgsave_in_progress === '0') {
      if (info.rdb_last_bgsave_status !== 'ok') throw new Error(`redis BGSAVE failed (status ${info.rdb_last_bgsave_status})`);
      break;
    }
    if (Date.now() > deadline) throw new Error(`redis BGSAVE did not finish within ${timeoutMs}ms`);
    await new Promise((r) => setTimeout(r, 250));
  }
  await execToFile(cmd.dumpArgs('redis', { container: row.container_name, database: row.db_name }), file);
}

/**
 * Dump ONE managed_databases row to `file`. The row decides the database,
 * so a caller holding app X's row can only ever dump app X's database.
 * Returns { bytes }.
 */
export async function dumpDatabase(row, file, { ops = null } = {}) {
  const o = await engineOps(ops);
  o.assertIdent(row.db_name);
  if (row.engine === 'redis') {
    await dumpRedis(row, file);
  } else if (row.engine === 'mongo') {
    await o.ensureServer('mongo');
    await withMongoToolConfig(o, ({ container, port, configPath }) =>
      execToFile(cmd.dumpArgs('mongo', { container, database: row.db_name, port, configPath }), file));
  } else if (row.engine === 'postgres' || row.engine === 'mariadb') {
    await o.ensureServer(row.engine);
    await execToFile(cmd.dumpArgs(row.engine, { container: o.containerFor(row.engine), database: row.db_name }), file);
  } else {
    throw new Error(`managedDbBackup: unknown engine '${row.engine}'`);
  }
  return { bytes: (await stat(file)).size };
}

/**
 * The managed_databases rows of ONE scope. `app_id = ?` is the cross-app
 * boundary for per-app backups: nothing else selects which databases a
 * per-app backup contains.
 */
export function rowsForScope(appId, tenant) {
  return getDb().prepare(
    'SELECT * FROM managed_databases WHERE app_id = ? AND tenant = ? ORDER BY engine'
  ).all(Number(appId), tenant == null ? '' : String(tenant));
}

/**
 * Dump every database of one scope into `dir` as `<base>.<engine>.dump`.
 * A failing engine fails the whole call: a per-app backup that silently
 * omitted the database would be restored later as if it were complete.
 */
export async function dumpScope({ appId, tenant }, dir, base, { ops = null } = {}) {
  const out = [];
  for (const row of rowsForScope(appId, tenant)) {
    const file = `${dir}/${base}.${row.engine}.dump`;
    const { bytes } = await dumpDatabase(row, file, { ops });
    out.push({ engine: row.engine, tenant: row.tenant || '', db_name: row.db_name, file, size_bytes: bytes });
  }
  return out;
}

/**
 * Dump every managed database on the platform under `stageDir`, as
 * managed-db/<engine>/<db>.dump, for the whole-system export.
 *
 * Unlike dumpScope, ONE failure does not fail the call: the nightly off-site
 * upload also carries deployhub.db and the ENCRYPTION_KEY, and one stopped
 * database server must not cost the platform its only off-site copy. Each
 * failure is returned (and logged) so the manifest says exactly which
 * database is missing.
 */
export async function dumpAll(stageDir, { ops = null } = {}) {
  const { mkdir } = await import('fs/promises');
  const rows = getDb().prepare('SELECT * FROM managed_databases ORDER BY engine, db_name').all();
  const databases = [];
  const failed = [];
  for (const row of rows) {
    const rel = `managed-db/${row.engine}/${row.db_name}.dump`;
    try {
      await mkdir(`${stageDir}/managed-db/${row.engine}`, { recursive: true, mode: 0o700 });
      const { bytes } = await dumpDatabase(row, `${stageDir}/${rel}`, { ops });
      databases.push({ engine: row.engine, db_name: row.db_name, app_id: row.app_id, tenant: row.tenant || '', member: rel, bytes });
    } catch (e) {
      log.warn(`[managed-db-backup] could not dump ${row.engine} database ${row.db_name}: ${e.message}`);
      failed.push({ engine: row.engine, db_name: row.db_name, app_id: row.app_id, error: String(e.message).slice(0, 300) });
    }
  }
  return { databases, failed, bytes: databases.reduce((n, d) => n + d.bytes, 0) };
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

/**
 * Put the login back under policy after its database was replaced: the
 * ownership/grants provisioning gives it, and the managed-database TLS/cert/limit policy
 * from the row and the platform settings. certRequired comes from the ROW,
 * which is sticky at 1 (migration 108), so this can only re-assert a
 * certificate requirement, never drop one.
 */
export async function reapplyLoginPolicy(row, ops) {
  const settings = getManagedDbSettings(getDb());
  const certRequired = row.client_cert_required === 1;
  if (row.engine === 'postgres') {
    await ops.runAdminSql('postgres', cmd.pgSchemaGrantsSql(row.db_user), { database: row.db_name });
    await ops.runAdminSql('postgres', tlsCfg.loginPolicySql('postgres', row.db_user, {
      certRequired, connLimit: settings.conn_limit, statementTimeoutS: settings.statement_timeout_s,
    }));
  } else if (row.engine === 'mariadb') {
    await ops.runAdminSql('mariadb', cmd.mariadbGrantSql(row.db_name, row.db_user));
    await ops.runAdminSql('mariadb', tlsCfg.loginPolicySql('mariadb', row.db_user, {
      certRequired, connLimit: settings.conn_limit, statementTimeoutS: settings.statement_timeout_s,
    }));
  } else if (row.engine === 'mongo') {
    // Users live in admin/$external, which a --db dump does not contain and
    // dropDatabase does not touch. A converted login is re-asserted anyway
    // (idempotent): it also drops a SCRAM user if one had come back.
    if (certRequired) {
      await ops.runAdminMongo(mongo.x509UserScript({
        adminPassword: ops.adminCoordsFor('mongo').adminPassword,
        database: row.db_name,
        username: row.db_user,
      }));
    }
  }
  // Redis: ensureRedisInstance (called by restoreRedis) already re-applies
  // the ACL user and the TLS start flags from the row.
}

async function restorePostgres(row, file, o) {
  await o.ensureServer('postgres');
  const container = o.containerFor('postgres');
  await o.runAdminSql('postgres', cmd.pgPrepareStagingSql(row.db_name, row.db_user));
  await o.runAdminSql('postgres', cmd.pgSchemaGrantsSql(row.db_user), { database: cmd.pgStagingName(row.db_name) });
  try {
    await execFromFile(cmd.restoreArgs('postgres', { container, database: row.db_name, username: row.db_user }), file);
  } catch (e) {
    // The live database was never touched; only the staging copy goes.
    await o.runAdminSql('postgres', cmd.pgDropStagingSql(row.db_name)).catch(() => {});
    throw e;
  }
  await o.runAdminSql('postgres', cmd.pgSwapSql(row.db_name, row.db_user));
}

/**
 * Run `fn(dir)` with a private scratch directory inside the server container
 * holding what the APP login needs to authenticate for the restore: its
 * client certificate and key (certificate-required logins) and, for a mongo
 * password login, a --config file with its password. Bodies go in on stdin;
 * the directory is removed in `finally`.
 */
async function withAppLoginScratch(o, engine, row, fn) {
  const container = o.containerFor(engine);
  const dir = `/tmp/appcrane-restore-${randomBytes(12).toString('hex')}`;
  const put = (name, body) => execCapture(cmd.scratchWriteArgs(container, dir, name), { input: body });
  const certRequired = row.client_cert_required === 1;
  const password = certRequired && engine === 'mongo' ? null : o.decrypt(row.password_enc);
  try {
    if (certRequired) {
      const c = o.clientCert(row.db_user);
      if (engine === 'mongo') await put('client.pem', c.certPem + c.keyPem);
      else { await put('client.crt', c.certPem); await put('client.key', c.keyPem); }
    } else if (engine === 'mongo') {
      await put('app.yaml', cmd.mongoConfigBody(o.assertPassword(password)));
    }
    return await fn({ container, dir, certRequired, password });
  } catch (e) {
    throw new Error(password ? o.redactSecret(e.message, password) : e.message);
  } finally {
    await execCapture(cmd.scratchRemoveArgs(container, dir)).catch(() => {});
  }
}

async function restoreMariadb(row, file, o) {
  await o.ensureServer('mariadb');
  // Locked first, so the app cannot reconnect between the KILLs and the
  // DROP and read a half-loaded database. Unlocked in `finally` whatever
  // happens: a restore that failed must not also leave the app locked out.
  // (ACCOUNT LOCK refuses NEW connections; the load below connects as the
  // app login, so the lock is lifted just before it — after the KILLs and the
  // recreate, which are the steps the lock exists to protect.)
  await o.runAdminSql('mariadb', cmd.mariadbLockSql(row.db_user, true));
  let unlocked = false;
  try {
    const sessions = await o.runAdminSql('mariadb', cmd.mariadbSessionsSql(row.db_user));
    const kill = cmd.mariadbKillSql(String(sessions || '').split(/\s+/));
    if (kill) await o.runAdminSql('mariadb', kill).catch(() => {});
    await o.runAdminSql('mariadb', cmd.mariadbRecreateSql(row.db_name));
    await o.runAdminSql('mariadb', cmd.mariadbGrantSql(row.db_name, row.db_user));
    await o.runAdminSql('mariadb', cmd.mariadbLockSql(row.db_user, false));
    unlocked = true;
    await withAppLoginScratch(o, 'mariadb', row, ({ container, dir, certRequired, password }) =>
      execFromFile(cmd.restoreArgs('mariadb', {
        container, database: row.db_name, username: row.db_user, scratch: dir, certRequired,
      }), file, { env: { MYSQL_PWD: password } }));
  } finally {
    if (!unlocked) await o.runAdminSql('mariadb', cmd.mariadbLockSql(row.db_user, false));
  }
}

async function restoreMongo(row, file, o) {
  await o.ensureServer('mongo');
  const { port, adminPassword } = o.adminCoordsFor('mongo');
  // Admin step, no dump content: empty the database.
  await o.runAdminMongo(cmd.mongoDropDatabaseScript(o.assertPassword(adminPassword), row.db_name));
  // The load itself, as the app login.
  await withAppLoginScratch(o, 'mongo', row, ({ container, dir, certRequired }) =>
    execFromFile(cmd.restoreArgs('mongo', {
      container, database: row.db_name, username: row.db_user, port, scratch: dir, certRequired,
    }), file));
}

async function restoreRedis(row, file, o) {
  const instance = {
    container: row.container_name,
    dbName: row.db_name,
    username: row.db_user,
    password: o.decrypt(row.password_enc),
    port: row.host_port,
    tls: row.client_cert_required === 1,
  };
  // Stop first: Redis writes its RDB on shutdown, so a file swapped in while
  // it runs would be overwritten by the live data on the way down.
  await execCapture(['stop', row.container_name], { timeout: 60000 });
  try {
    await execFromFile(cmd.redisSwapArgs({ hostDir: o.redisDataDir(row.db_name), image: o.redisImage }), file);
  } finally {
    // Starts the instance (it loads dump.rdb at boot), waits for PONG and
    // re-applies the ACL user and TLS flags — also after a failed swap, so a
    // failure never leaves the app's Redis stopped.
    await o.ensureRedisInstance(instance);
  }
}

/**
 * Restore ONE scope's database from a dump file. Destructive: the
 * database's current contents are replaced.
 *
 * CROSS-APP REFUSAL LIVES HERE, not in a route: the target is looked up from
 * (appId, tenant, engine), and `expectDbName` — the database the dump was
 * taken from, as recorded with it — must be that row's database. A backup
 * record of app X carries X's database name; asked to restore into app Y it
 * names a database Y does not own and is refused before anything runs.
 */
export async function restoreDatabase({ appId, tenant, engine, expectDbName }, file, { ops = null } = {}) {
  const o = await engineOps(ops);
  const row = o.rowFor({ appId, tenant }, engine);
  if (!row) throw Object.assign(new Error(`app has no ${engine} database for that environment`), { status: 404 });
  if (!expectDbName || row.db_name !== expectDbName) {
    throw Object.assign(new Error(`this dump is of database ${JSON.stringify(expectDbName)}, which is not this app's ${engine} database; refusing to restore across apps`), { status: 403, code: 'CROSS_APP_RESTORE' });
  }
  o.assertIdent(row.db_name);
  o.assertIdent(row.db_user);
  if (engine === 'postgres') await restorePostgres(row, file, o);
  else if (engine === 'mariadb') await restoreMariadb(row, file, o);
  else if (engine === 'mongo') await restoreMongo(row, file, o);
  else if (engine === 'redis') await restoreRedis(row, file, o);
  else throw new Error(`managedDbBackup: unknown engine '${engine}'`);
  await reapplyLoginPolicy(row, o);
  log.warn(`[managed-db-backup] restored ${engine} database ${row.db_name} for app ${row.app_id}${row.tenant ? ` (${row.tenant})` : ''}`);
  return { engine, db_name: row.db_name };
}

/**
 * Restore ONE app's database from a whole-system export archive
 * (managed-db/<engine>/<db>.dump). Platform-admin only — the route enforces
 * it; this is the disaster path, per-app backups are the everyday one.
 *
 * The archive member is DERIVED from the target app's own row
 * (managed-db/<engine>/<that row's db_name>.dump), never chosen by the
 * caller, so there is no request that extracts app Y's dump and loads it into
 * app X: the only dump this can read is the target's own.
 *
 * env 'sandbox' means the app's SEPARATE sandbox database. An app whose
 * sandbox shares production's database has no such row, and is told so
 * rather than silently restoring production.
 */
export async function restoreFromExport({ archivePath, appId, env, engine }, { ops = null } = {}) {
  const { SANDBOX_TENANT } = await import('./sandboxDb.js');
  const { newWorkDir, extractTar } = await import('./backupFiles.js');
  if (!['production', 'sandbox'].includes(env)) throw Object.assign(new Error('env must be production or sandbox'), { status: 400 });
  const o = await engineOps(ops);
  const tenant = env === 'sandbox' ? SANDBOX_TENANT : '';
  const row = o.rowFor({ appId, tenant }, engine);
  if (!row) {
    throw Object.assign(new Error(env === 'sandbox'
      ? `this app has no separate sandbox ${engine} database (its sandbox shares production's)`
      : `this app has no ${engine} database`), { status: 404 });
  }
  const member = `managed-db/${engine}/${o.assertIdent(row.db_name)}.dump`;
  const work = await newWorkDir('mdb-restore');
  try {
    try {
      await extractTar(archivePath, work, { gzip: true, members: [member] });
    } catch (_) {
      throw Object.assign(new Error(`that archive has no dump of this app's ${engine} database (${member})`), { status: 404 });
    }
    return await restoreDatabase({ appId, tenant, engine, expectDbName: row.db_name }, `${work}/${member}`, { ops: o });
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

/**
 * Which backups carry managed databases, for Settings → Backup and the MCP
 * status tool. Stated rather than left for the reader to infer from the
 * contents lists, because "is my Postgres backed up" is the question asked.
 */
export function managedDbBackupCoverage() {
  const count = getDb().prepare('SELECT COUNT(*) AS n FROM managed_databases').get().n;
  return {
    count,
    format: 'one logical dump per database (pg_dump custom format, mariadb-dump, mongodump archive, Redis RDB)',
    included_in: ['full export (Settings → Backup → Export)', 'nightly off-site upload', 'per-app backups (that app\'s databases only)'],
    excluded_from: ['local nightly archive (deployhub.db + .env only)'],
    point_in_time_recovery: false,
  };
}
