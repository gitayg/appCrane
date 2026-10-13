// deployhub.json `database` block: a custom app declaring the managed database it
// needs, in the same shape a catalogue entry's `needs` uses.
//
// Why this exists: a custom app could already have a database provisioned, but
// the deployer only injected credentials for catalogue apps, and the password is
// never returned by any API — so a custom app had a database it could not
// connect to. Declaring it here lets the deployer provision it and inject the
// connection details the same way it does for the catalogue.
//
// Why the validation is strict: the variable names chosen here are written into
// the container environment. A typo in `engine` or a field key would otherwise
// deploy an app with no database and no error; a var named PORT or
// APPCRANE_SERVICE_TOKEN would be silently overwritten by (or overwrite) a value
// the platform relies on. Every rejection names the field so the author can fix
// it from the deploy log alone.

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { SUPPORTED_ENGINES, provision as defaultProvision, credentialsFor as defaultCredentialsFor } from './managedDb.js';
import { APP_LOGIN_ENGINES, DEFAULT_APP_URL_ENV } from './managedDbAppLogin.js';
import { SUPPORTED_EXTENSIONS } from './managedDbStats.js';

const ENV_NAME_RE = /^[A-Z_][A-Z0-9_]*$/;

// The fields buildManagedDbEnv knows how to fill. Anything else would be accepted
// and then never injected, which is the silent failure the strictness prevents.
export const DATABASE_ENV_FIELDS = ['host', 'port', 'name', 'user', 'password'];

const ALLOWED_KEYS = ['engine', 'url_env', 'env', 'app_login', 'app_url_env', 'sandbox_url_env', 'extensions'];

// Engines whose logins take the per-login policy (TLS + certificate + limits)
// the sandbox URL relies on; Mongo's and Redis's sandbox access would need a
// different design and is refused rather than half-done.
const SANDBOX_URL_ENGINES = ['postgres', 'mariadb'];

// URL variable used when the manifest names only the engine: the name each
// engine's ecosystem reads by default, so the minimal block works unchanged for
// most frameworks.
export const DEFAULT_URL_ENV = {
  postgres: 'DATABASE_URL',
  mariadb: 'DATABASE_URL',
  mongo: 'MONGODB_URI',
  redis: 'REDIS_URL',
};

// Names the deployer or docker.startApp set on every container. There was no
// shared list before this one: these are collected from deployer.js (the
// CRANE_* and APPCRANE_* injections) and docker.js startApp (PORT, NODE_ENV,
// DATA_DIR). APP_BASE_PATH is build-time only but still AppCrane's. FE_PORT is
// written into the legacy env file. The whole APPCRANE_ prefix is reserved
// because new platform variables land there.
export const RESERVED_ENV_NAMES = [
  'PORT', 'FE_PORT', 'NODE_ENV', 'DATA_DIR', 'APP_BASE_PATH',
  'CRANE_URL', 'CRANE_INTERNAL_URL',
  // The client-certificate paths deployer.tlsFileEnv() injects for a login
  // that requires TLS. Mapping a field onto one of these would overwrite (or be
  // overwritten by) a path the driver needs.
  'DB_CA_FILE', 'DB_CERT_FILE', 'DB_KEY_FILE', 'DB_CERT_KEY_FILE',
  'PGSSLMODE', 'PGSSLROOTCERT', 'PGSSLCERT', 'PGSSLKEY',
  'REDIS_TLS_CA_FILE', 'REDIS_TLS_CERT_FILE', 'REDIS_TLS_KEY_FILE',
  // The same paths for the second login (app_login) and for production's
  // sandbox URL (sandbox_url_env): deployer.peerTlsFileEnv().
  'APP_DB_CA_FILE', 'APP_DB_CERT_FILE', 'APP_DB_KEY_FILE',
  'SANDBOX_DB_CA_FILE', 'SANDBOX_DB_CERT_FILE', 'SANDBOX_DB_KEY_FILE',
];
export const RESERVED_ENV_PREFIX = 'APPCRANE_';

function fail(field, why) {
  throw new Error(`deployhub.json ${field}: ${why}`);
}

function checkVarName(field, value) {
  if (typeof value !== 'string' || !ENV_NAME_RE.test(value)) {
    fail(field, `must be an env var name matching ${ENV_NAME_RE} (got ${JSON.stringify(value)})`);
  }
  if (RESERVED_ENV_NAMES.includes(value) || value.startsWith(RESERVED_ENV_PREFIX)) {
    fail(field, `"${value}" is reserved by AppCrane (reserved: ${RESERVED_ENV_NAMES.join(', ')}, ${RESERVED_ENV_PREFIX}*)`);
  }
}

/**
 * Validate a manifest `database` block and return it as a `needs` object for
 * buildManagedDbEnv, or null when the manifest declares no database.
 *
 * Throws an Error naming the offending field; the deployer lets it fail the
 * deploy. `url_env` defaults per engine when omitted; `url_env: null` opts out
 * of the URL variable (only meaningful alongside `env`).
 */
export function parseManifestDatabase(block) {
  if (block === undefined || block === null) return null;
  if (typeof block !== 'object' || Array.isArray(block)) fail('database', 'must be an object like { "engine": "postgres" }');

  for (const key of Object.keys(block)) {
    if (!ALLOWED_KEYS.includes(key)) fail(`database.${key}`, `unknown key (allowed: ${ALLOWED_KEYS.join(', ')})`);
  }

  const engine = block.engine;
  if (typeof engine !== 'string' || !SUPPORTED_ENGINES.includes(engine)) {
    fail('database.engine', `must be one of: ${SUPPORTED_ENGINES.join(', ')} (got ${JSON.stringify(engine)})`);
  }

  const env = {};
  if (block.env !== undefined) {
    if (!block.env || typeof block.env !== 'object' || Array.isArray(block.env)) {
      fail('database.env', `must be an object mapping ${DATABASE_ENV_FIELDS.join('/')} to env var names`);
    }
    for (const [field, varName] of Object.entries(block.env)) {
      if (!DATABASE_ENV_FIELDS.includes(field)) {
        fail(`database.env.${field}`, `unknown field (allowed: ${DATABASE_ENV_FIELDS.join(', ')})`);
      }
      checkVarName(`database.env.${field}`, varName);
      env[field] = varName;
    }
  }

  let urlEnv;
  if (block.url_env === undefined) urlEnv = DEFAULT_URL_ENV[engine];
  else if (block.url_env === null) urlEnv = null;
  else { checkVarName('database.url_env', block.url_env); urlEnv = block.url_env; }

  // Two fields under one name would inject whichever is written last and drop
  // the other with no signal.
  const names = [...Object.values(env), ...(urlEnv ? [urlEnv] : [])];
  const dup = names.find((n, i) => names.indexOf(n) !== i);
  if (dup) fail('database', `env var "${dup}" is mapped more than once`);
  if (!names.length) fail('database', 'declares no variable to inject (url_env is null and env is empty)');

  // app_login: a second, DML-only login per stage (managedDbAppLogin.js).
  if (block.app_login !== undefined && typeof block.app_login !== 'boolean') {
    fail('database.app_login', `must be true or false (got ${JSON.stringify(block.app_login)})`);
  }
  const wantsAppLogin = block.app_login === true;
  if (wantsAppLogin && !APP_LOGIN_ENGINES.includes(engine)) {
    fail('database.app_login', `is supported for ${APP_LOGIN_ENGINES.join(' and ')} only (engine is ${engine})`);
  }
  let appUrlEnv = null;
  if (block.app_url_env !== undefined) {
    if (!wantsAppLogin) fail('database.app_url_env', 'only applies with "app_login": true');
    checkVarName('database.app_url_env', block.app_url_env);
    appUrlEnv = block.app_url_env;
  } else if (wantsAppLogin) {
    appUrlEnv = DEFAULT_APP_URL_ENV;
  }

  // sandbox_url_env: PRODUCTION gets the sandbox database's URL under this
  // name (the deployer never gives it to sandbox). Its presence is the
  // opt-in, so there is no default.
  let sandboxUrlEnv = null;
  if (block.sandbox_url_env !== undefined) {
    if (!SANDBOX_URL_ENGINES.includes(engine)) {
      fail('database.sandbox_url_env', `is supported for ${SANDBOX_URL_ENGINES.join(' and ')} only (engine is ${engine})`);
    }
    checkVarName('database.sandbox_url_env', block.sandbox_url_env);
    sandboxUrlEnv = block.sandbox_url_env;
  }

  // extensions: installed by AppCrane as the superuser, because the app login
  // cannot. A closed list: anything else would be refused by the engine at
  // deploy time, or worse, accepted and never wired up.
  let extensions = [];
  if (block.extensions !== undefined) {
    const allowed = SUPPORTED_EXTENSIONS[engine] || [];
    if (!Array.isArray(block.extensions)) fail('database.extensions', 'must be an array like ["pg_stat_statements"]');
    for (const ext of block.extensions) {
      if (!allowed.includes(ext)) {
        fail('database.extensions', `${JSON.stringify(ext)} is not one AppCrane installs for ${engine} `
          + `(supported: ${allowed.length ? allowed.join(', ') : 'none'}). Trusted extensions such as pgcrypto `
          + 'need no entry here: the owner login can CREATE EXTENSION them itself.');
      }
    }
    extensions = [...new Set(block.extensions)];
  }

  // Two fields under one name would inject whichever is written last and drop
  // the other with no signal.
  const allNames = [...names, ...(appUrlEnv ? [appUrlEnv] : []), ...(sandboxUrlEnv ? [sandboxUrlEnv] : [])];
  const dup2 = allNames.find((n, i) => allNames.indexOf(n) !== i);
  if (dup2) fail('database', `env var "${dup2}" is mapped more than once`);

  const needs = { engine, env };
  if (urlEnv) needs.url_env = urlEnv;
  if (appUrlEnv) needs.app_url_env = appUrlEnv;
  if (sandboxUrlEnv) needs.sandbox_url_env = sandboxUrlEnv;
  if (extensions.length) needs.extensions = extensions;
  return needs;
}

/**
 * Make sure the database a manifest declares exists, provisioning it when it
 * does not. Idempotent: provision() returns the existing database for the scope
 * rather than rotating its credential, and the credentialsFor() check first
 * keeps an existing app from even starting the server-side path.
 *
 * Scope defaults to { appId } — the app's one database per engine, shared by
 * sandbox and production. The deployer passes the sandbox's own scope instead
 * when the app has "Separate sandbox database" on (services/sandboxDb.js).
 *
 * The return value of provision() carries the plaintext password and is
 * deliberately discarded. Only the engine name reaches the log.
 */
export async function ensureManifestDatabase(app, needs, {
  appendLog = () => {},
  provision = defaultProvision,
  credentialsFor = defaultCredentialsFor,
  scope = null,
  // Set by a PRODUCTION deploy that provisions the sandbox database only so
  // it can hand production that database's URL (deployhub.json
  // sandbox_url_env). The log then says that, not that the sandbox
  // setting is on: nothing about the sandbox's own deploy happened.
  forSandboxUrlEnv = null,
} = {}) {
  const dbScope = scope?.tenant ? scope : { appId: app.id };
  const what = dbScope.tenant ? `sandbox ${needs.engine} database` : `${needs.engine} database declared in deployhub.json`;
  let existing = null;
  try { existing = credentialsFor(dbScope, needs.engine); } catch (_) { existing = null; }
  if (existing) return { provisioned: false };

  try {
    await provision(dbScope, needs.engine);
  } catch (err) {
    // managedDb redacts the generated password at its throw sites, so its
    // message is safe to put in the deploy log.
    throw new Error(`Provisioning the managed ${what} failed: ${err.message}`);
  }
  appendLog(dbScope.tenant && forSandboxUrlEnv
    ? `Provisioned the ${what} so production can reach it via ${forSandboxUrlEnv}`
    : dbScope.tenant
    ? `Provisioned a separate managed ${what} for this app (Separate sandbox database is on)`
    : `Provisioned a managed ${needs.engine} database for this app (declared in deployhub.json)`);
  return { provisioned: true };
}

/**
 * The `database` needs of the release a container is running, for the restart
 * path. Restart rebuilds the container's whole environment, and unlike the
 * deploy it has no manifest in hand — skipping this would strip DATABASE_URL off
 * a custom app on every restart. Reads the `current` release's deployhub.json,
 * the file the last successful deploy validated.
 *
 * Never throws: a restart is a recovery action, and an unreadable manifest
 * there should cost the app its database variables (logged by the caller), not
 * the restart itself. Never provisions either — the deploy did that.
 */
export function readReleaseManifestDatabase(appEnvDir) {
  const manifestPath = join(appEnvDir, 'current', 'deployhub.json');
  if (!existsSync(manifestPath)) return { needs: null, error: null };
  try {
    return { needs: parseManifestDatabase(JSON.parse(readFileSync(manifestPath, 'utf8')).database), error: null };
  } catch (e) {
    return { needs: null, error: e.message };
  }
}
