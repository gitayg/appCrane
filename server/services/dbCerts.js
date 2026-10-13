/**
 * Storage and on-disk placement for the managed databases' certificates.
 *
 * services/dbPki.js builds certificates; this file decides where they live:
 *
 *   SQLite (managed_db_certs, migration 108)
 *     cert_pem  public, stored as PEM so expiry can be reported without
 *               decrypting anything
 *     key_enc   the private key, ONLY ever stored through encryption.js
 *               encrypt(). No plaintext key is written to SQLite, ever.
 *
 *   DATA_DIR/managed-db/_tls/   (0700, never mounted as a whole)
 *     server/<engine>/   ca.crt, server.crt, server.key, server.pem
 *                        (+ pg_hba.conf for postgres). Bind-mounted READ-ONLY
 *                        into that engine's container only, at
 *                        /etc/appcrane-tls; the container copies them to a
 *                        private directory owned by the engine user at start.
 *     client/<login>/    ca.crt, client.crt, client.key, client.pem. Bind-
 *                        mounted READ-ONLY into the ONE app container (one app,
 *                        one env) whose database login is <login>, at
 *                        CLIENT_MOUNT_PATH. A login with a managed Redis also
 *                        gets redis-client.crt/.key/.pem here (see below).
 *     redis/<db_name>/   one per-scope Redis instance's server files — see
 *                        "PER-INSTANCE REDIS CLIENT CA".
 *
 * PER-INSTANCE REDIS CLIENT CA. Postgres and MariaDB check the
 * client certificate's CN against the login (clientcert=verify-full, REQUIRE
 * SUBJECT), so one platform CA is enough there: app B's certificate names
 * app B's login and is refused by app A's. Redis cannot express that — it only
 * checks that a client certificate chains to tls-ca-cert-file (see
 * managedRedis.tlsServerFlags) — so while every Redis trusted the platform CA,
 * app B's certificate plus app A's Redis password opened app A's Redis.
 *
 * So each per-scope Redis gets its OWN small CA (managed_db_certs row
 * `redis-ca:<db_name>`, key encrypted like every other key), and that CA is
 * the ONLY thing in the instance's tls-ca-cert-file. It signs exactly two
 * certificates: the app's Redis client certificate (`redis-client:<db_name>`,
 * CN = the login, written to client/<login>/redis-client.*) and the admin
 * certificate redis-cli presents inside the container (`redis-admin:<db_name>`,
 * never leaves redis/<db_name>/). A certificate from any other app — or from
 * the platform CA — fails the handshake, before AUTH is ever reached.
 *
 * The SERVER certificate is still the platform CA's `server:redis`: clients
 * verify the server with the same ca.crt they always have, so nothing changes
 * on the app's verifying side. Distinct file names for the Redis client
 * certificate keep a login that also has Postgres/MariaDB/Mongo working: those
 * engines keep reading client.* (platform-CA-signed), Redis reads
 * redis-client.* (instance-CA-signed), and both live in the one directory the
 * app's container already mounts.
 *
 * WHY _tls IS A SIBLING OF THE ENGINE DATA DIRECTORIES AND NEVER INSIDE ONE.
 * Same reasoning as managedDb.envFileFor(): DATA_DIR/managed-db/<engine> IS the
 * database's own volume. A key placed there is readable by the database
 * process for the life of the container, and on Linux the engine chowns what
 * it mounts, after which AppCrane can no longer rewrite (renew) the file.
 *
 * WHO CAN READ A CLIENT KEY. Three populations, three mechanisms:
 *   - other host users: `_tls` and `_tls/client` are 0700, so nothing below
 *     them can be reached by path at all.
 *   - other app containers: the directory is bind-mounted into exactly one
 *     container; no other container has a path to it.
 *   - the owning app's process, which must read it: when AppCrane runs as root
 *     (the production install), the key is chowned to the image's runtime
 *     uid:gid and set 0400, which is also what libpq demands of a key file
 *     ("must be u=rw (0600) or less"). When AppCrane is NOT root it cannot
 *     chown, and a 0400 file owned by AppCrane's uid would be unreadable to the
 *     app's uid on Linux — so the files are 0444 instead and the two 0700
 *     parents plus the single mount carry the boundary. libpq refuses such a
 *     key; node-postgres, mysql2, mongodb and ioredis do not check. Measured on
 *     Docker Desktop: it remaps bind-mount ownership to the reading uid, so
 *     there a 0400 file is readable by any container uid and the distinction
 *     only matters on native Linux.
 */

import crypto from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { join, resolve } from 'path';
import { mkdirSync, writeFileSync, renameSync, chmodSync, chownSync, rmSync, existsSync, readFileSync } from 'fs';
import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import * as pki from './dbPki.js';

const execFileAsync = promisify(execFile);

/** Where an app container finds its client certificate. */
export const CLIENT_MOUNT_PATH = '/run/appcrane/db';

/**
 * The Redis client certificate's file-name prefix inside the same mount:
 * redis-client.crt/.key/.pem, next to (never replacing) client.* — see the
 * header for why Redis needs a certificate of its own.
 */
export const REDIS_CLIENT_PREFIX = 'redis-';
const REDIS_CLIENT_FILES = ['redis-client.crt', 'redis-client.key', 'redis-client.pem'];

/** Container paths of a login's files. ca.crt is shared: it verifies the SERVER. */
export function clientFilePaths(prefix = '') {
  return {
    ca: `${CLIENT_MOUNT_PATH}/ca.crt`,
    cert: `${CLIENT_MOUNT_PATH}/${prefix}client.crt`,
    key: `${CLIENT_MOUNT_PATH}/${prefix}client.key`,
    pem: `${CLIENT_MOUNT_PATH}/${prefix}client.pem`,
  };
}

/** Where an engine container finds its server certificate (read-only source). */
export const SERVER_MOUNT_PATH = '/etc/appcrane-tls';

/** The private copy the engine actually reads, owned by the engine user. */
export const SERVER_RUNTIME_PATH = '/tmp/appcrane-tls';

const SAFE_LOGIN = /^[a-z][a-z0-9_]{0,62}$/;

function tlsRoot() {
  return join(resolve(process.env.DATA_DIR || './data'), 'managed-db', '_tls');
}

function privateDir(p) {
  mkdirSync(p, { recursive: true, mode: 0o700 });
  // mkdirSync's mode is masked by umask and ignored for a directory that
  // already exists, so the mode is asserted rather than requested.
  chmodSync(p, 0o700);
  return p;
}

export function serverTlsDir(engine) {
  if (!/^[a-z]+$/.test(engine)) throw new Error(`dbCerts: bad engine ${JSON.stringify(engine)}`);
  privateDir(tlsRoot());
  privateDir(join(tlsRoot(), 'server'));
  return join(tlsRoot(), 'server', engine);
}

/** One per-scope Redis instance's server-side files (never mounted into an app). */
export function redisInstanceTlsDir(dbName) {
  if (!SAFE_LOGIN.test(dbName)) throw new Error(`dbCerts: bad instance name ${JSON.stringify(dbName)}`);
  privateDir(tlsRoot());
  privateDir(join(tlsRoot(), 'redis'));
  return join(tlsRoot(), 'redis', dbName);
}

export function clientTlsDir(login) {
  if (!SAFE_LOGIN.test(login)) throw new Error(`dbCerts: bad login ${JSON.stringify(login)}`);
  privateDir(tlsRoot());
  privateDir(join(tlsRoot(), 'client'));
  return join(tlsRoot(), 'client', login);
}

// ---------------------------------------------------------------------------
// SQLite
// ---------------------------------------------------------------------------

function rowNamed(name) {
  return getDb().prepare('SELECT * FROM managed_db_certs WHERE name = ?').get(name) || null;
}

function store(name, { certPem, keyPem, notAfter }, sans = null) {
  getDb().prepare(`
    INSERT INTO managed_db_certs (name, cert_pem, key_enc, not_after, sans, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(name) DO UPDATE SET cert_pem = excluded.cert_pem, key_enc = excluded.key_enc,
      not_after = excluded.not_after, sans = excluded.sans, updated_at = datetime('now')
  `).run(name, certPem, encrypt(keyPem), notAfter, sans);
}

function load(row) {
  return { certPem: row.cert_pem, keyPem: decrypt(row.key_enc), notAfter: row.not_after };
}

/**
 * The CA, generated on first use.
 *
 * NOT renewed automatically. A new CA invalidates every certificate it signed
 * at once, server and client, so rotating it is an operation (reissue all,
 * redeploy all) rather than something a provision may do on the side. It is
 * issued for ten years; caInfo() reports its expiry so it is visible long
 * before it matters.
 */
export function ensureCa() {
  const row = rowNamed('ca');
  if (row) return load(row);
  const ca = pki.generateCa();
  store('ca', ca);
  return { certPem: ca.certPem, keyPem: ca.keyPem, notAfter: ca.notAfter };
}

export function caInfo() {
  const row = rowNamed('ca');
  return row ? { not_after: row.not_after } : null;
}

/**
 * The server certificate for an engine, issued or renewed as needed.
 * `renewed` is true when a new certificate was issued by this call, which is
 * the signal managedDb uses to make a running server reload its files.
 */
export function ensureServerCert(engine, { dnsNames, ips, bothUsages = false }) {
  const ca = ensureCa();
  const name = `server:${engine}`;
  const sans = JSON.stringify({ dnsNames: [...dnsNames].sort(), ips: [...ips].sort() });
  const row = rowNamed(name);
  if (row && row.sans === sans && !pki.needsRenewal(row.cert_pem)) {
    return { ...load(row), ca, renewed: false };
  }
  const cert = pki.issueCert({ ca, commonName: `appcrane-db-${engine}`, usage: 'server', dnsNames, ips, bothUsages });
  store(name, cert, sans);
  return { certPem: cert.certPem, keyPem: cert.keyPem, notAfter: cert.notAfter, ca, renewed: true };
}

/** A login's client certificate (CN = login), issued or renewed as needed. */
export function ensureClientCert(login) {
  if (!SAFE_LOGIN.test(login)) throw new Error(`dbCerts: bad login ${JSON.stringify(login)}`);
  const ca = ensureCa();
  const name = `client:${login}`;
  const row = rowNamed(name);
  if (row && !pki.needsRenewal(row.cert_pem)) return { ...load(row), ca, renewed: false };
  const cert = pki.issueCert({ ca, commonName: login, usage: 'client' });
  store(name, cert);
  return { certPem: cert.certPem, keyPem: cert.keyPem, notAfter: cert.notAfter, ca, renewed: true };
}

// ---------------------------------------------------------------------------
// Per-instance Redis client CA (see the header)
// ---------------------------------------------------------------------------

/**
 * The CA's CN. Readable when it fits dbPki's 63-character CN limit, which
 * every name namesForScope() derives today does; a hash otherwise, because the
 * CN is a label for an operator reading `openssl x509 -text`, not the thing
 * that isolates — the key is.
 */
export function redisCaCommonName(dbName) {
  const cn = `AppCrane Redis CA ${dbName}`;
  if (cn.length <= 63) return cn;
  return `AppCrane Redis CA ${crypto.createHash('sha256').update(dbName).digest('hex').slice(0, 16)}`;
}

/**
 * The instance's own client CA, generated ONCE and then only ever loaded.
 * Ten years, not renewed, for the same reason as ensureCa(): a new CA
 * invalidates the app's certificate, and that is a deploy, not a side effect.
 */
export function ensureRedisCa(dbName) {
  if (!SAFE_LOGIN.test(dbName)) throw new Error(`dbCerts: bad instance name ${JSON.stringify(dbName)}`);
  const name = `redis-ca:${dbName}`;
  const row = rowNamed(name);
  if (row) return load(row);
  const ca = pki.generateCa({ commonName: redisCaCommonName(dbName) });
  store(name, ca);
  return { certPem: ca.certPem, keyPem: ca.keyPem, notAfter: ca.notAfter };
}

/**
 * A leaf signed by an instance CA, re-issued when it is due for renewal OR no
 * longer verifies against that CA. The second check is what makes the
 * certificate follow its CA: a CA row that was dropped and regenerated (an
 * instance deprovisioned and provisioned again under the same name) would
 * otherwise leave a stored leaf that the new instance refuses.
 */
function ensureLeafUnder(name, issuer, { commonName, usage }) {
  const row = rowNamed(name);
  if (row && !pki.needsRenewal(row.cert_pem)) {
    let chained = false;
    try { chained = new crypto.X509Certificate(row.cert_pem).verify(crypto.createPublicKey(issuer.certPem)); } catch (_) {}
    if (chained) return { ...load(row), renewed: false };
  }
  const cert = pki.issueCert({ ca: issuer, commonName, usage });
  store(name, cert);
  return { certPem: cert.certPem, keyPem: cert.keyPem, notAfter: cert.notAfter, renewed: true };
}

/**
 * The app's Redis client certificate: CN = its login, signed by the
 * instance's CA. `ca` is the PLATFORM CA — what the app verifies the server
 * with — so writeClientFiles() writes the same ca.crt it always has.
 */
export function ensureRedisClientCert(dbName, login) {
  if (!SAFE_LOGIN.test(login)) throw new Error(`dbCerts: bad login ${JSON.stringify(login)}`);
  const issuer = ensureRedisCa(dbName);
  const leaf = ensureLeafUnder(`redis-client:${dbName}`, issuer, { commonName: login, usage: 'client' });
  return { ...leaf, ca: ensureCa() };
}

/**
 * The certificate AppCrane's own redis-cli presents inside the instance's
 * container (readiness, ACL SETUSER, BGSAVE for backups, ACL LOG for alerts).
 * It used to be the server certificate, issued with clientAuth for exactly
 * this; that stopped working the moment the instance stopped trusting the
 * platform CA, so it is now a client certificate of the instance's own CA.
 */
export function ensureRedisAdminCert(dbName) {
  const issuer = ensureRedisCa(dbName);
  return ensureLeafUnder(`redis-admin:${dbName}`, issuer, { commonName: 'appcrane-admin', usage: 'client' });
}

/**
 * Write an instance's server files: the platform CA (ca.crt, what redis-cli
 * verifies the server with), the instance CA (client-ca.crt, the ONLY anchor
 * Redis accepts clients from), the shared Redis server certificate and the
 * admin client certificate. 0700 directory, keys 0600.
 */
export function writeRedisServerFiles(dbName, { server, instanceCa, admin }) {
  const dir = privateDir(redisInstanceTlsDir(dbName));
  atomicWrite(join(dir, 'ca.crt'), server.ca.certPem, 0o644);
  atomicWrite(join(dir, 'client-ca.crt'), instanceCa.certPem, 0o644);
  atomicWrite(join(dir, 'server.crt'), server.certPem, 0o644);
  atomicWrite(join(dir, 'server.key'), server.keyPem, 0o600);
  atomicWrite(join(dir, 'server.pem'), server.certPem + server.keyPem, 0o600);
  atomicWrite(join(dir, 'admin.crt'), admin.certPem, 0o644);
  atomicWrite(join(dir, 'admin.key'), admin.keyPem, 0o600);
  return dir;
}

/** Expiry of the app's Redis client certificate. Never decrypts. */
export function redisClientCertInfo(dbName) {
  const row = rowNamed(`redis-client:${dbName}`);
  return row ? { not_after: row.not_after } : null;
}

/**
 * Forget an instance's CA and certificates and remove their files
 * (deprovision). Only the redis-client.* files leave the login's directory:
 * client.* there may belong to the same login's Postgres/MariaDB/Mongo.
 */
export function dropRedisCerts(dbName, login) {
  if (!SAFE_LOGIN.test(dbName)) return;
  const del = getDb().prepare('DELETE FROM managed_db_certs WHERE name = ?');
  for (const n of [`redis-ca:${dbName}`, `redis-client:${dbName}`, `redis-admin:${dbName}`]) del.run(n);
  rmSync(join(tlsRoot(), 'redis', dbName), { recursive: true, force: true });
  if (login && SAFE_LOGIN.test(login)) {
    for (const f of REDIS_CLIENT_FILES) rmSync(join(tlsRoot(), 'client', login, f), { force: true });
  }
}

/** Expiry only — for the API. Never decrypts. */
export function clientCertInfo(login) {
  const row = rowNamed(`client:${login}`);
  return row ? { not_after: row.not_after } : null;
}

/** Forget a login's certificate and remove its files (deprovision). */
export function dropClientCert(login) {
  if (!SAFE_LOGIN.test(login)) return;
  getDb().prepare('DELETE FROM managed_db_certs WHERE name = ?').run(`client:${login}`);
  const dir = join(tlsRoot(), 'client', login);
  rmSync(dir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/**
 * Write a file atomically: a reader (an app opening a new connection, an
 * engine copying at start) sees the old file or the new one, never half of
 * one. That is what makes renewal safe to do under a running container.
 */
function atomicWrite(path, body, mode, owner = null) {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, body, { mode });
  chmodSync(tmp, mode);
  if (owner) chownSync(tmp, owner.uid, owner.gid);
  renameSync(tmp, path);
}

/** Write an engine's server files. The directory is 0700; keys are 0600. */
export function writeServerFiles(engine, cert, extra = {}) {
  const dir = privateDir(serverTlsDir(engine));
  atomicWrite(join(dir, 'ca.crt'), cert.ca.certPem, 0o644);
  atomicWrite(join(dir, 'server.crt'), cert.certPem, 0o644);
  atomicWrite(join(dir, 'server.key'), cert.keyPem, 0o600);
  // Mongo takes certificate and key in one file.
  atomicWrite(join(dir, 'server.pem'), cert.certPem + cert.keyPem, 0o600);
  for (const [file, body] of Object.entries(extra)) atomicWrite(join(dir, file), body, 0o644);
  return dir;
}

/**
 * Write a login's client files for the container that will read them.
 *
 * `owner` is the image's runtime { uid, gid } (resolveImageOwner) or null.
 * With an owner and root privileges: key 0400 owned by that uid. Otherwise
 * 0444 — see the header for why that is still bounded.
 *
 * Returns the host directory to bind-mount and the container paths.
 */
export function writeClientFiles(login, cert, owner = null, { prefix = '' } = {}) {
  if (prefix !== '' && prefix !== REDIS_CLIENT_PREFIX) throw new Error(`dbCerts: bad client file prefix ${JSON.stringify(prefix)}`);
  const dir = clientTlsDir(login);
  mkdirSync(dir, { recursive: true });
  const canChown = Boolean(owner) && typeof process.getuid === 'function' && process.getuid() === 0;
  const keyMode = canChown ? 0o400 : 0o444;
  // The directory itself has to be traversable by the container's uid; its
  // 0700 parent is what keeps everyone else out on the host.
  chmodSync(dir, 0o755);
  if (canChown) chownSync(dir, owner.uid, owner.gid);
  const o = canChown ? owner : null;
  atomicWrite(join(dir, 'ca.crt'), cert.ca.certPem, 0o444, o);
  atomicWrite(join(dir, `${prefix}client.crt`), cert.certPem, 0o444, o);
  atomicWrite(join(dir, `${prefix}client.key`), cert.keyPem, keyMode, o);
  atomicWrite(join(dir, `${prefix}client.pem`), cert.certPem + cert.keyPem, keyMode, o);
  return {
    hostDir: dir,
    keyMode,
    chowned: canChown,
    files: clientFilePaths(prefix),
  };
}

/** True when the host files exist and match the stored certificate. */
export function clientFilesCurrent(login) {
  const row = rowNamed(`client:${login}`);
  const path = join(tlsRoot(), 'client', login, 'client.crt');
  if (!row || !existsSync(path)) return false;
  try { return readFileSync(path, 'utf8') === row.cert_pem; } catch (_) { return false; }
}

/**
 * The uid:gid an image's process runs as, so its key can be chowned to it.
 *
 * Read from the image, never by RUNNING it. This used `docker run --entrypoint
 * id <image>`, and the image is the app author's: its `id` can be any program,
 * and it ran on every deploy outside the app container's own limits (no memory,
 * CPU or pids cap, default capabilities). Now: `docker image inspect` gives
 * Config.User; a numeric uid[:gid] is used as is; a name is looked up in the
 * image's /etc/passwd and /etc/group, copied out of a container that is CREATED
 * but never started (`docker create` + `docker cp`), then removed. No user set
 * means root. Null when it cannot be worked out (the 0444 fallback, never a
 * failed deploy). argv only, nothing interpolated into a shell.
 */
export async function resolveImageOwner(image, { exec = execFileAsync } = {}) {
  if (!image) return null;
  try {
    const { stdout } = await exec('docker', ['image', 'inspect', '--format', '{{.Config.User}}', image], { timeout: 30000 });
    const spec = String(stdout).trim();
    if (!spec) return { uid: 0, gid: 0 };
    const [u, g] = spec.split(':');
    const isNum = (v) => /^\d+$/.test(v || '');
    if (isNum(u) && isNum(g)) return { uid: Number(u), gid: Number(g) };

    const passwd = await readImageFile(image, '/etc/passwd', exec);
    const group = g && !isNum(g) ? await readImageFile(image, '/etc/group', exec) : '';
    const pw = (passwd || '').split('\n').map(l => l.split(':')).find(f => f.length >= 4 && (isNum(u) ? f[2] === u : f[0] === u));
    const uid = isNum(u) ? Number(u) : (pw ? Number(pw[2]) : NaN);
    let gid;
    if (isNum(g)) gid = Number(g);
    else if (g) {
      const gr = group.split('\n').map(l => l.split(':')).find(f => f.length >= 3 && f[0] === g);
      gid = gr ? Number(gr[2]) : NaN;
    } else gid = pw ? Number(pw[3]) : 0;
    return Number.isInteger(uid) && Number.isInteger(gid) ? { uid, gid } : null;
  } catch (_) {
    return null;
  }
}

/** One file out of an image, through a created-but-never-started container. */
async function readImageFile(image, path, exec) {
  let id = null;
  try {
    // The trailing `true` only satisfies images with no CMD; create never runs it.
    ({ stdout: id } = await exec('docker', ['create', '--network', 'none', image, 'true'], { timeout: 30000 }));
    id = String(id).trim();
    const { stdout } = await exec('docker', ['cp', `${id}:${path}`, '-'], { timeout: 30000, encoding: 'buffer', maxBuffer: 4 * 1024 * 1024 });
    return untarFirst(Buffer.isBuffer(stdout) ? stdout : Buffer.from(String(stdout), 'binary'));
  } catch (_) {
    return '';
  } finally {
    if (id) await exec('docker', ['rm', '-f', id], { timeout: 30000 }).catch(() => {});
  }
}

/** The first regular file's contents from a tar stream (`docker cp ... -`). */
function untarFirst(buf) {
  if (buf.length < 512) return '';
  const size = parseInt(buf.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim() || '0', 8);
  return buf.subarray(512, 512 + size).toString('utf8');
}
