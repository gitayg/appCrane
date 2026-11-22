// Connections to outside secret stores. A platform connection (app_id NULL) is
// set by a platform admin and usable by every app; an app connection belongs to
// one app. Lookup always takes the app: nothing a reference says can select a
// connection of another app.
import { getDb } from '../../db.js';
import { encrypt, decrypt } from '../encryption.js';
import { CONNECTION_NAME_RE, PROVIDERS } from './refs.js';

export class ConnectionError extends Error {
  constructor(message, code = 'VALIDATION', status = 400) {
    super(message);
    this.name = 'ConnectionError';
    this.code = code;
    this.status = status;
  }
}

const str = (v, max = 2048) => typeof v === 'string' && v.length > 0 && v.length <= max && !/[\r\n\0]/.test(v);
const httpUrl = (v) => {
  if (!str(v)) return false;
  try {
    const u = new URL(v);
    return (u.protocol === 'https:' || u.protocol === 'http:') && !u.username && !u.password && !u.search && !u.hash;
  } catch (_) { return false; }
};

// For each provider: settings keys (non-secret) with a check, and the credential
// sets one of which must be given. A key outside these is refused.
const appIdList = (v) => Array.isArray(v) && v.length > 0 && v.length <= 500 && v.every((x) => Number.isInteger(x) && x > 0) && new Set(v).size === v.length;
const SCHEMA = {
  vault: {
    settings: {
      address: httpUrl, namespace: (v) => str(v, 256), kv_version: (v) => v === 1 || v === 2,
      auth: (v) => v === 'token' || v === 'approle', approle_mount: (v) => str(v, 128) && /^[A-Za-z0-9_-]+$/.test(v), path_prefix: (v) => str(v, 512), allowed_apps: appIdList,
    },
    required: ['address'],
    credentials: (s) => (s.auth === 'approle' ? ['role_id', 'secret_id'] : ['token']),
  },
  infisical: {
    settings: { site_url: httpUrl, path_prefix: (v) => str(v, 512), allowed_apps: appIdList },
    required: [],
    credentials: () => ['client_id', 'client_secret'],
  },
  onepassword: {
    settings: { mode: (v) => v === 'connect' || v === 'service_account', connect_url: httpUrl, path_prefix: (v) => str(v, 512), allowed_apps: appIdList },
    required: [],
    credentials: () => ['token'],
  },
  awsssm: {
    settings: { region: (v) => str(v, 64) && /^[a-z0-9-]+$/.test(v), endpoint: httpUrl, path_prefix: (v) => str(v, 512), allowed_apps: appIdList },
    required: [],
    credentials: () => [],
  },
};

function checkSettings(provider, settings) {
  const schema = SCHEMA[provider];
  if (settings === null || typeof settings !== 'object' || Array.isArray(settings)) throw new ConnectionError('settings must be an object');
  for (const [k, v] of Object.entries(settings)) {
    if (!schema.settings[k]) throw new ConnectionError(`unknown setting for ${provider}: ${k}`);
    if (!schema.settings[k](v)) throw new ConnectionError(`invalid setting ${k}`);
  }
  for (const k of schema.required) if (settings[k] === undefined) throw new ConnectionError(`${provider} needs setting ${k}`);
  if (provider === 'onepassword' && (settings.mode ?? 'connect') === 'connect' && !settings.connect_url) {
    throw new ConnectionError('onepassword in connect mode needs setting connect_url');
  }
}

const slugPrefix = (settings) => typeof settings.path_prefix === 'string' && settings.path_prefix.includes('{slug}');
const listed = (settings) => Array.isArray(settings.allowed_apps) && settings.allowed_apps.length > 0;

// A platform connection is open to no app until it is scoped: a path_prefix
// holding {slug} (each app reaches only its own subtree) or an allowed_apps list
// of app ids. awsssm is the host's AWS identity, so it always needs the prefix.
function checkScope(appId, provider, settings) {
  if (appId != null) {
    if (settings.allowed_apps !== undefined) throw new ConnectionError('allowed_apps is for platform connections; an app connection already belongs to one app');
    return;
  }
  if (provider === 'awsssm' && !slugPrefix(settings)) {
    throw new ConnectionError('an awsssm connection needs a path_prefix containing {slug}, e.g. /appcrane/{slug}, so each app reaches only its own parameters');
  }
  if (!slugPrefix(settings) && !listed(settings)) {
    throw new ConnectionError('a platform connection must be scoped: set path_prefix containing {slug}, or allowed_apps with the ids of the apps that may use it');
  }
  if (listed(settings)) {
    const db = getDb();
    const missing = settings.allowed_apps.filter((id) => !db.prepare('SELECT 1 FROM apps WHERE id = ?').get(id));
    if (missing.length) throw new ConnectionError(`allowed_apps names no app with id ${missing.join(', ')}`);
  }
}

/** Whether a platform connection row is open to this app. An unscoped row (one that bypassed checkScope) is open to none. */
export function platformAdmits(row, app) {
  const settings = rowSettings(row);
  if (row.provider === 'awsssm' && !slugPrefix(settings)) return false;
  if (listed(settings)) return Number.isInteger(app?.id) && settings.allowed_apps.includes(app.id);
  return slugPrefix(settings);
}

function checkCredentials(provider, settings, credentials) {
  const need = SCHEMA[provider].credentials(settings);
  const given = credentials ?? {};
  if (typeof given !== 'object' || Array.isArray(given)) throw new ConnectionError('credentials must be an object');
  for (const k of Object.keys(given)) if (!need.includes(k)) throw new ConnectionError(`unexpected credential for ${provider}: ${k}`);
  for (const k of need) if (!str(given[k], 8192)) throw new ConnectionError(`${provider} needs credential ${k}`);
  return need.length ? given : null;
}

function rowSettings(row) {
  try { return JSON.parse(row.settings_json || '{}'); } catch (_) { return {}; }
}

/** What an API may show: never the credentials, not even their length. */
export function publicView(row, { detail = true } = {}) {
  const base = { id: row.id, name: row.name, provider: row.provider, scope: row.app_id == null ? 'platform' : 'app' };
  if (!detail) return base;
  return { ...base, settings: rowSettings(row), credentials_set: Boolean(row.credentials_enc), created_at: row.created_at, updated_at: row.updated_at };
}

export function listConnections(appId) {
  const db = getDb();
  return appId == null
    ? db.prepare('SELECT * FROM secret_connections WHERE app_id IS NULL ORDER BY name').all()
    : db.prepare('SELECT * FROM secret_connections WHERE app_id = ? ORDER BY name').all(appId);
}

export function getConnection(appId, id) {
  const db = getDb();
  return appId == null
    ? db.prepare('SELECT * FROM secret_connections WHERE id = ? AND app_id IS NULL').get(id)
    : db.prepare('SELECT * FROM secret_connections WHERE id = ? AND app_id = ?').get(id, appId);
}

export function createConnection({ appId = null, name, provider, settings = {}, credentials, userId = null }) {
  if (!str(name, 63) || !CONNECTION_NAME_RE.test(name)) throw new ConnectionError('name must be lowercase letters, digits and -, up to 63 characters');
  if (!PROVIDERS[provider]) throw new ConnectionError(`provider must be one of ${Object.keys(PROVIDERS).join(', ')}`);
  // The default credential chain is the AppCrane host's own AWS identity: an
  // app owner must not be able to wield it under their own connection.
  if (provider === 'awsssm' && appId != null) throw new ConnectionError('awsssm uses this server\'s AWS credentials, so it is a platform connection only', 'FORBIDDEN', 403);
  checkSettings(provider, settings);
  checkScope(appId, provider, settings);
  const creds = checkCredentials(provider, settings, credentials);
  try {
    const id = getDb().prepare(`
      INSERT INTO secret_connections (name, provider, app_id, settings_json, credentials_enc, created_by)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(name, provider, appId, JSON.stringify(settings), creds ? encrypt(JSON.stringify(creds)) : null, userId).lastInsertRowid;
    return getConnection(appId, id);
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') throw new ConnectionError(`a connection named ${name} already exists here`, 'CONFLICT', 409);
    throw e;
  }
}

/** settings replace the stored settings when given; credentials replace the stored ones when given. */
export function updateConnection(appId, id, { settings, credentials }) {
  const row = getConnection(appId, id);
  if (!row) throw new ConnectionError('connection not found', 'NOT_FOUND', 404);
  const nextSettings = settings === undefined ? rowSettings(row) : settings;
  checkSettings(row.provider, nextSettings);
  checkScope(appId, row.provider, nextSettings);
  let enc = row.credentials_enc;
  if (credentials !== undefined) {
    const creds = checkCredentials(row.provider, nextSettings, credentials);
    enc = creds ? encrypt(JSON.stringify(creds)) : null;
  } else if (settings !== undefined) {
    const prev = rowSettings(row);
    const moved = Object.keys({ ...prev, ...nextSettings })
      .filter((k) => k !== 'path_prefix' && k !== 'allowed_apps')
      .some((k) => JSON.stringify(prev[k]) !== JSON.stringify(nextSettings[k]));
    if (moved && enc) throw new ConnectionError('changing where a connection points, or how it signs in, needs its credentials re-entered in the same request');
    // An auth change needs the matching credentials in the same request.
    const need = SCHEMA[row.provider].credentials(nextSettings);
    const have = enc ? Object.keys(JSON.parse(decrypt(enc))) : [];
    if (need.some((k) => !have.includes(k))) throw new ConnectionError('these settings need new credentials in the same request');
  }
  getDb().prepare("UPDATE secret_connections SET settings_json = ?, credentials_enc = ?, updated_at = datetime('now') WHERE id = ?")
    .run(JSON.stringify(nextSettings), enc, id);
  return getConnection(appId, id);
}

export function deleteConnection(appId, id) {
  const row = getConnection(appId, id);
  if (!row) throw new ConnectionError('connection not found', 'NOT_FOUND', 404);
  getDb().prepare('DELETE FROM secret_connections WHERE id = ?').run(id);
  return row;
}

/**
 * The connection a reference uses for this app, or a ConnectionError saying why
 * there is none. Only rows with app_id = this app or app_id IS NULL are read.
 */
export function connectionForRef(app, ref) {
  if (!app?.id) throw new ConnectionError('the app is unknown', 'SECRET_REF_NO_CONNECTION');
  const db = getDb();
  const label = PROVIDERS[ref.provider].label;
  if (ref.connection) {
    const own = db.prepare('SELECT * FROM secret_connections WHERE app_id = ? AND name = ?').get(app.id, ref.connection);
    const row = own || db.prepare('SELECT * FROM secret_connections WHERE app_id IS NULL AND name = ?').get(ref.connection);
    if (!row) throw new ConnectionError(`no connection named ${ref.connection} is available to this app`, 'SECRET_REF_NO_CONNECTION');
    if (row.provider !== ref.provider) throw new ConnectionError(`connection ${ref.connection} is not a ${label} connection`, 'SECRET_REF_NO_CONNECTION');
    if (row.app_id == null && !platformAdmits(row, app)) throw new ConnectionError(`connection ${ref.connection} is not open to this app`, 'SECRET_REF_NO_CONNECTION');
    return row;
  }
  for (const rows of [
    db.prepare('SELECT * FROM secret_connections WHERE app_id = ? AND provider = ?').all(app.id, ref.provider),
    db.prepare('SELECT * FROM secret_connections WHERE app_id IS NULL AND provider = ?').all(ref.provider).filter((r) => platformAdmits(r, app)),
  ]) {
    if (rows.length === 1) return rows[0];
    if (rows.length > 1) throw new ConnectionError(`more than one ${label} connection is available; name one with ?connection=<name>`, 'SECRET_REF_NO_CONNECTION');
  }
  throw new ConnectionError(`no ${label} connection is configured for this app or the platform`, 'SECRET_REF_NO_CONNECTION');
}

/** { settings, credentials } of a row, decrypted for one resolution. */
export function openConnection(row) {
  return {
    id: row.id, name: row.name, provider: row.provider, scope: row.app_id == null ? 'platform' : 'app',
    settings: rowSettings(row),
    credentials: row.credentials_enc ? JSON.parse(decrypt(row.credentials_enc)) : {},
  };
}
