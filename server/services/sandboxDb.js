/**
 * Per-app "Separate sandbox database" (migration 107).
 *
 * Off (the default): sandbox and production share the app's one managed
 * database per engine, as they always have. On: production keeps that database
 * untouched and sandbox gets a second one, scoped (app, SANDBOX_TENANT).
 *
 * WHY THE TENANT COLUMN AND NOT A NEW env COLUMN. managed_databases is already
 * keyed (app_id, tenant, engine) with UNIQUE indexes on that triple and on the
 * derived names, and every engine path (provision, the per-scope Redis
 * container, credentialsFor, deprovision, deprovisionApp) takes a scope object.
 * A reserved tenant value rides all of that unchanged; an env column would mean
 * a new unique index and a second scope dimension threaded through every one of
 * those functions. The value cannot collide with a real tenant: tenants are
 * org/user paths (services/tenants.js), never "env:...", and the API refuses a
 * client-supplied tenant outright.
 *
 * Kept free of managedDb.js imports: routes/apps.js reads the setting, and
 * managedDb.js is loaded lazily elsewhere so a broken engine module fails the
 * database routes rather than the boot.
 */
export const SANDBOX_TENANT = 'env:sandbox';

/** No row, or 0, means shared: what every app had before 107. */
export function getSeparateSandboxDb(db, appId) {
  const row = db.prepare('SELECT separate_sandbox_db FROM app_settings WHERE app_id = ?').get(appId);
  return row ? row.separate_sandbox_db === 1 : false;
}

export function setSeparateSandboxDb(db, appId, on) {
  db.prepare(`
    INSERT INTO app_settings (app_id, separate_sandbox_db) VALUES (?, ?)
    ON CONFLICT(app_id) DO UPDATE SET separate_sandbox_db = excluded.separate_sandbox_db, updated_at = datetime('now')
  `).run(appId, on ? 1 : 0);
}

/** Accepts a real boolean, or 0/1; anything else is refused (undefined). */
export function parseSeparateSandboxDb(v) {
  if (v === true || v === 1) return true;
  if (v === false || v === 0) return false;
  return undefined;
}

/**
 * The managed-database scope a container of `env` connects to. Read at every
 * deploy and restart, which is why a change takes effect only then: a running
 * container keeps the environment it was started with.
 */
export function managedDbScopeFor(db, app, env) {
  if (env === 'sandbox' && getSeparateSandboxDb(db, app.id)) {
    return { appId: app.id, tenant: SANDBOX_TENANT };
  }
  return { appId: app.id, tenant: null };
}

/** Which environment a managed_databases row serves, for the API and the UI. */
export function envForTenant(tenant) {
  return tenant === SANDBOX_TENANT ? 'sandbox' : (tenant ? null : 'production');
}

export const SEPARATE_SANDBOX_DB_NOTE =
  'Takes effect on the next sandbox deploy or restart. Production\'s database is unchanged, '
  + 'and turning this off later does not delete the sandbox database.';
