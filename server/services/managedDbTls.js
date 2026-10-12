/**
 * TLS, client certificates and per-login limits for the managed databases —
 * the engine-specific builders.
 *
 * PURE, in the same way services/managedMongo.js and managedRedis.js are: this
 * file returns argv arrays, config files and SQL, and managedDb.js runs them.
 * That is what lets test/managed-db-tls.test.js assert on the exact pg_hba
 * lines and ALTER statements without a daemon.
 *
 * =========================================================================
 * WHY THE IDENTITY HAS TO BE CRYPTOGRAPHIC
 * =========================================================================
 * Every app reaches the shared servers through host.docker.internal, and the
 * docker-proxy in front of a published port rewrites the source: measured,
 * every connection arrives from the bridge gateway, whichever container opened
 * it. So the engine cannot tell apps apart by address, and pg_hba / MariaDB
 * host patterns cannot express "only app A". What the engine CAN check is a
 * certificate: a login whose database came from the app's own deployhub.json
 * must present a client certificate whose CN is that login, signed by
 * AppCrane's CA, AND its password. The key is mounted into that one app's
 * container only (services/dbCerts.js), so a sibling that learns the password
 * still cannot log in — the identity guarantee comes from the engine checking
 * cert + password, not from the network.
 *
 * =========================================================================
 * THE SPLIT: REQUIRED FOR MANIFEST LOGINS, OFFERED FOR CATALOGUE LOGINS
 * =========================================================================
 * Catalogue apps run third-party images that frequently cannot be configured
 * for database TLS at all, so their logins keep working in plain text; the
 * server OFFERS TLS to anyone who asks. Manifest logins are code the app
 * author controls, so for them TLS and the client certificate are REQUIRED and
 * a plain connection is refused by the engine. How each engine expresses that
 * split is below, per engine — and where an engine cannot, the gap is named.
 */

import { CA_COMMON_NAME } from './dbPki.js';
import { SERVER_MOUNT_PATH, SERVER_RUNTIME_PATH } from './dbCerts.js';

/**
 * Bumped whenever the server-side TLS configuration changes shape. It is part
 * of the label ensureServer() compares against a running container, so a
 * container created by an older AppCrane (no TLS at all, for every server that
 * exists today) is recreated once on the next ensureServer(). The data is in
 * the volume; the recreate costs the connections open at that moment.
 */
export const TLS_CONFIG_VERSION = 'tls1';

/**
 * Postgres group role whose MEMBERS must present a client certificate. pg_hba
 * matches `+role` on membership, so converting a login is one GRANT and the
 * hba file never has to list individual logins (and never has to be rewritten
 * when an app is provisioned).
 *
 * Members cannot leave it: dropping a membership needs ADMIN OPTION on the
 * group or CREATEROLE, and app roles are created NOCREATEROLE with no admin
 * option. The group holds no privileges, so membership grants nothing.
 */
export const PG_CERT_GROUP = 'appcrane_cert_required';

/** The engine user each image runs its server as (fixed; never user input). */
const ENGINE_USER = { postgres: 'postgres', mariadb: 'mysql', mongo: 'mongodb', redis: 'redis' };

const R = SERVER_RUNTIME_PATH;

/**
 * Shell snippet that copies the read-only mounted files to a private
 * directory owned by the engine user, with the key at 0600.
 *
 * Why a copy rather than pointing the engine at the mount: Postgres refuses a
 * server key that is not 0600-and-owned-by-postgres (or 0640 root), mongod and
 * redis likewise want their key private, and the engine users differ by image
 * (postgres:16-alpine is uid 70, the others 999). A bind mount carries the HOST
 * owner, which AppCrane cannot match for four images at once without being
 * root and knowing each uid. Copying inside the container, as root, before the
 * entrypoint drops privileges, sidesteps all of it.
 *
 * A FIXED literal: the only variable part is the engine user, which comes from
 * the table above. Nothing a caller supplies reaches this string.
 */
export function installSnippet(engine) {
  const user = ENGINE_USER[engine];
  if (!user) throw new Error(`managedDbTls: no engine user for '${engine}'`);
  return `mkdir -p ${R} && cp ${SERVER_MOUNT_PATH}/* ${R}/ && chown -R ${user} ${R} && chmod 700 ${R} && chmod 600 ${R}/server.key ${R}/server.pem`;
}

/** `-v` value for the read-only server mount. */
export function serverMountArg(hostDir) {
  return `${hostDir}:${SERVER_MOUNT_PATH}:ro`;
}

// ---------------------------------------------------------------------------
// Postgres
// ---------------------------------------------------------------------------

/**
 * The pg_hba.conf AppCrane owns (passed with -c hba_file=, so the one initdb
 * wrote into the data directory is no longer consulted).
 *
 * ORDER IS THE WHOLE POLICY — Postgres uses the FIRST line that matches:
 *   1. unix socket, trust: the administrative path (`docker exec ... psql`).
 *      Only processes inside the container reach the socket.
 *   2. members of PG_CERT_GROUP over TLS: scram-sha-256 AND clientcert=
 *      verify-full, i.e. the password AND a certificate signed by the CA whose
 *      CN equals the login name. Both, not either.
 *   3. members of PG_CERT_GROUP over anything else: reject. Without this line
 *      a plain-text connection would fall through to line 4 and get in with
 *      the password alone.
 *   4. everyone else (catalogue logins, the superuser): password, TLS
 *      optional — `host` matches both TLS and plain connections.
 *
 * The image's own default also had `host all all 127.0.0.1/32 trust`. It is
 * dropped: a TCP connection that arrived from 127.0.0.1 inside the container
 * would have been let in as ANY role with no password.
 */
export function pgHbaConf() {
  return [
    '# Written by AppCrane (services/managedDbTls.js). Do not edit: it is rewritten on every ensureServer().',
    'local   all  all                       trust',
    `hostssl all  +${PG_CERT_GROUP}  all  scram-sha-256 clientcert=verify-full`,
    `host    all  +${PG_CERT_GROUP}  all  reject`,
    'host    all  all                  all  scram-sha-256',
    '',
  ].join('\n');
}

/**
 * Server flags. `-c` pairs go to the entrypoint as separate argv elements, so
 * nothing here is parsed by a shell (log_line_prefix contains spaces and %).
 *
 * log_line_prefix carries user and database on every line, which is how
 * dbAuthAlerts.js attributes a failure: Postgres's own auth-failure message
 * names the user but not the database.
 */
export function pgServerArgs({ maxConnections }) {
  const n = Number(maxConnections);
  if (!Number.isInteger(n) || n < 1) throw new Error(`managedDbTls: bad max_connections ${JSON.stringify(maxConnections)}`);
  return [
    'postgres',
    '-c', 'ssl=on',
    '-c', `ssl_cert_file=${R}/server.crt`,
    '-c', `ssl_key_file=${R}/server.key`,
    '-c', `ssl_ca_file=${R}/ca.crt`,
    '-c', 'ssl_min_protocol_version=TLSv1.2',
    '-c', `hba_file=${R}/pg_hba.conf`,
    '-c', `max_connections=${n}`,
    // Stated rather than inherited: max_connections=300 does not grow these,
    // and the defaults are what was sized against the 512 MB container (see
    // the memory note in managedDb.js).
    '-c', 'shared_buffers=128MB',
    '-c', 'work_mem=4MB',
    '-c', 'log_connections=on',
    '-c', 'log_line_prefix=%m [%p] user=%u db=%d ',
  ];
}

/** Idempotent: the group exists afterwards whether or not it did before. */
export function pgCertGroupSql() {
  return [
    'DO $$ BEGIN',
    `  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${PG_CERT_GROUP}') THEN`,
    `    CREATE ROLE ${PG_CERT_GROUP} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`,
    '  END IF;',
    'END $$;',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// MariaDB
// ---------------------------------------------------------------------------

/**
 * mariadbd flags. TLS is offered to every connection; whether a login MUST use
 * it is per user (REQUIRE ... in loginPolicySql), which MariaDB supports
 * natively — no server-wide choice is forced.
 *
 * log_warnings=2 makes every "Access denied for user" a log line, which
 * dbAuthAlerts.js reads.
 */
export function mariadbServerArgs() {
  return [
    'mariadbd',
    `--ssl-cert=${R}/server.crt`,
    `--ssl-key=${R}/server.key`,
    `--ssl-ca=${R}/ca.crt`,
    '--log-warnings=2',
  ];
}

// ---------------------------------------------------------------------------
// Per-login policy
// ---------------------------------------------------------------------------

const SAFE_IDENT = /^[a-z][a-z0-9_]{0,62}$/;

/**
 * The statements that put a login under policy. Re-applied on every deploy
 * and restart, so a changed platform setting reaches existing logins then.
 *
 *   certRequired  Postgres: GRANT the cert group (see pgHbaConf).
 *                 MariaDB: REQUIRE SUBJECT '/CN=<login>' AND ISSUER '/CN=<CA>'
 *                 — implies TLS, demands a CA-signed cert for exactly this
 *                 login, and the password is still checked.
 *   connLimit     Postgres CONNECTION LIMIT / MariaDB MAX_USER_CONNECTIONS.
 *   statementTimeoutS  Postgres statement_timeout (role default) / MariaDB
 *                 MAX_STATEMENT_TIME. 0 = none.
 *
 * certRequired=false never REMOVES a requirement: the flag is sticky
 * (migration 108), and a catalogue login never had one. So the MariaDB branch
 * leaves REQUIRE untouched rather than writing REQUIRE NONE.
 */
export function loginPolicySql(engine, username, { certRequired, connLimit, statementTimeoutS }) {
  if (!SAFE_IDENT.test(username)) throw new Error(`managedDbTls: refusing identifier ${JSON.stringify(username)}`);
  const limit = Number(connLimit);
  const timeout = Number(statementTimeoutS);
  if (!Number.isInteger(limit) || limit < 1) throw new Error('managedDbTls: connLimit must be a positive integer');
  if (!Number.isInteger(timeout) || timeout < 0) throw new Error('managedDbTls: statementTimeoutS must be a non-negative integer');

  if (engine === 'postgres') {
    return [
      `ALTER ROLE "${username}" CONNECTION LIMIT ${limit};`,
      timeout > 0
        ? `ALTER ROLE "${username}" SET statement_timeout = '${timeout}s';`
        : `ALTER ROLE "${username}" RESET statement_timeout;`,
      ...(certRequired ? [`GRANT ${PG_CERT_GROUP} TO "${username}";`] : []),
    ].join('\n');
  }
  if (engine === 'mariadb') {
    const require = certRequired ? ` REQUIRE SUBJECT '/CN=${username}' AND ISSUER '/CN=${CA_COMMON_NAME}'` : '';
    return `ALTER USER '${username}'@'%'${require} WITH MAX_USER_CONNECTIONS ${limit} MAX_STATEMENT_TIME ${timeout};\n`;
  }
  throw new Error(`managedDbTls: no login policy for engine '${engine}'`);
}

/** Engines whose logins take loginPolicySql. Mongo and Redis are handled apart. */
export const POLICY_ENGINES = ['postgres', 'mariadb'];

// ---------------------------------------------------------------------------
// Reload after a server certificate renewal
// ---------------------------------------------------------------------------

/**
 * How a RUNNING server picks up renewed files without a restart:
 *   postgres  pg_reload_conf() re-reads ssl_* files and pg_hba (PG10+)
 *   mariadb   FLUSH SSL (10.4+)
 *   mongo     rotateCertificates (5.0+)
 *   redis     re-setting tls-cert-file re-reads the files
 * managedDb.js re-runs installSnippet() inside the container first.
 */
export const RELOAD_STATEMENT = {
  postgres: 'SELECT pg_reload_conf();',
  mariadb: 'FLUSH SSL;',
};
