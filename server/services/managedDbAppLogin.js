/**
 * The second, lower-privilege login per scope (deployhub.json
 * `"database": { "engine": "postgres", "app_login": true }`) — SQL builders.
 *
 * PURE, like managedDbTls.js: SQL strings in, nothing run. managedDb.js runs
 * them; test/managed-db-app-login.test.js pins them without a daemon.
 *
 * WHY A SECOND LOGIN. The owner login owns its database and its public schema,
 * so the running app can drop or rewrite any table. With `app_login` the
 * migrations keep running as the owner (DATABASE_URL) and the app's request
 * path uses `<owner>_app` (APP_DATABASE_URL by default), which can read and
 * write rows and nothing else: a SQL injection in the app can no longer
 * `DROP TABLE`, and a bug cannot `ALTER` the schema under the migrations.
 *
 * NAME. `<owner login>_app`: owner logins end in `_u` (managedDb.namesForScope),
 * so the suffix can never produce another scope's owner login, and the longest
 * owner name (`crane_a<id>_t<12 hex>_u`) plus `_app` still fits the 31-byte
 * ceiling the rest of the module enforces (checked, never truncated).
 */

export const APP_LOGIN_SUFFIX = '_app';
export const APP_LOGIN_ENGINES = ['postgres', 'mariadb'];
export const DEFAULT_APP_URL_ENV = 'APP_DATABASE_URL';

// Same boundaries as managedDb.js: identifiers are interpolated into DDL, and
// the password is a literal from an alphabet with no quoting character in it.
const SAFE_IDENT = /^[a-z][a-z0-9_]{0,62}$/;
const SAFE_PASSWORD = /^[A-Za-z0-9_-]{24,128}$/;
const MAX_IDENT_BYTES = 31;

function ident(name) {
  if (!SAFE_IDENT.test(String(name)) || Buffer.byteLength(String(name)) > MAX_IDENT_BYTES) {
    throw new Error(`managedDbAppLogin: refusing identifier ${JSON.stringify(name)}`);
  }
  return name;
}

function password(pw) {
  if (!SAFE_PASSWORD.test(String(pw))) throw new Error('managedDbAppLogin: password outside the safe alphabet; refusing to build SQL');
  return pw;
}

export function appLoginName(owner) {
  return ident(`${ident(owner)}${APP_LOGIN_SUFFIX}`);
}

// ---------------------------------------------------------------------------
// Postgres
// ---------------------------------------------------------------------------

/**
 * Run on the server (`postgres` database). Creates the role if it is missing,
 * then (re)asserts its attributes and password every time: a restored host or
 * a hand-edited role converges on the row. CONNECT only — no TEMPORARY, since
 * temporary tables are DDL too.
 */
export function pgAppRoleSql(database, appUser, pw) {
  ident(database); ident(appUser); password(pw);
  return [
    'DO $$ BEGIN',
    `  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${appUser}') THEN`,
    `    CREATE ROLE "${appUser}" NOLOGIN;`,
    '  END IF;',
    'END $$;',
    `ALTER ROLE "${appUser}" WITH LOGIN PASSWORD '${pw}'`,
    '  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;',
    `REVOKE ALL ON DATABASE "${database}" FROM "${appUser}";`,
    `GRANT CONNECT ON DATABASE "${database}" TO "${appUser}";`,
  ].join('\n');
}

/**
 * Run on the scope's own database. DML on everything in `public` now, and —
 * through DEFAULT PRIVILEGES for the OWNER — on every table and sequence the
 * owner creates later, so a migration that adds a table does not need a GRANT
 * of its own.
 *
 * The REVOKE CREATE is the one statement here that is not a grant: the owner
 * owns the schema and could hand CREATE to the app login itself. Re-asserting
 * the revoke on every deploy keeps "the app login cannot do DDL" true even
 * then. Sequences get USAGE + SELECT + UPDATE: nextval() and setval() are what
 * an INSERT into a serial/identity column and a typical ORM need.
 */
export function pgAppGrantsSql(owner, appUser) {
  ident(owner); ident(appUser);
  return [
    `REVOKE CREATE ON SCHEMA public FROM "${appUser}";`,
    `GRANT USAGE ON SCHEMA public TO "${appUser}";`,
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "${appUser}";`,
    `GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO "${appUser}";`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE "${owner}" IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "${appUser}";`,
    `ALTER DEFAULT PRIVILEGES FOR ROLE "${owner}" IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO "${appUser}";`,
  ].join('\n');
}

/** The role exists afterwards, unable to log in if it had to be created. */
export function pgAppRoleExistsSql(appUser) {
  ident(appUser);
  return [
    'DO $$ BEGIN',
    `  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${appUser}') THEN`,
    `    CREATE ROLE "${appUser}" NOLOGIN;`,
    '  END IF;',
    'END $$;',
  ].join('\n');
}

/** Opting out: the role stays (dumps name it), it just cannot log in. */
export function pgAppDisableSql(appUser) {
  ident(appUser);
  return [
    'DO $$ BEGIN',
    `  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${appUser}') THEN`,
    `    ALTER ROLE "${appUser}" NOLOGIN;`,
    '  END IF;',
    'END $$;',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// MariaDB
// ---------------------------------------------------------------------------

/**
 * DML on the scope's database only. No REVOKE is needed the way Postgres
 * needs one: the MariaDB owner has ALL on `db`.* WITHOUT GRANT OPTION, so it
 * cannot widen the app login's grants.
 */
export function mariadbAppUserSql(database, appUser, pw) {
  ident(database); ident(appUser); password(pw);
  return [
    `CREATE USER IF NOT EXISTS '${appUser}'@'%' IDENTIFIED BY '${pw}';`,
    `ALTER USER '${appUser}'@'%' IDENTIFIED BY '${pw}' ACCOUNT UNLOCK;`,
    `GRANT SELECT, INSERT, UPDATE, DELETE ON \`${database}\`.* TO '${appUser}'@'%';`,
    'FLUSH PRIVILEGES;',
  ].join('\n');
}

export function mariadbAppDisableSql(appUser) {
  ident(appUser);
  return `ALTER USER IF EXISTS '${appUser}'@'%' ACCOUNT LOCK;\n`;
}

// ---------------------------------------------------------------------------
// Both
// ---------------------------------------------------------------------------

/** Server-side setup for the engine (Postgres also needs pgAppGrantsSql on the database). */
export function appLoginServerSql(engine, database, appUser, pw) {
  if (engine === 'postgres') return pgAppRoleSql(database, appUser, pw);
  if (engine === 'mariadb') return mariadbAppUserSql(database, appUser, pw);
  throw new Error(`managedDbAppLogin: no app login for engine '${engine}' (supported: ${APP_LOGIN_ENGINES.join(', ')})`);
}

export function appLoginDisableSql(engine, appUser) {
  if (engine === 'postgres') return pgAppDisableSql(appUser);
  if (engine === 'mariadb') return mariadbAppDisableSql(appUser);
  throw new Error(`managedDbAppLogin: no app login for engine '${engine}'`);
}

/** Deprovision: after the database itself is gone. */
export function appLoginDropSql(engine, appUser) {
  ident(appUser);
  if (engine === 'postgres') return `DROP ROLE IF EXISTS "${appUser}";\n`;
  if (engine === 'mariadb') return `DROP USER IF EXISTS '${appUser}'@'%';\nFLUSH PRIVILEGES;\n`;
  throw new Error(`managedDbAppLogin: no app login for engine '${engine}'`);
}
