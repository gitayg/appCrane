// Managed database logins that can still authenticate WITHOUT a client
// certificate, and the Job Health check that reports them.
//
// A login is password-only while its row has client_cert_required = 0 and
// tls_required = 0 (a "TLS required" login, migration 315, is listed apart by
// tlsOnlyLogins(): TLS + password, no client certificate):
//   postgres  not in the cert group, so pg_hba's last line lets it in with the
//             password over TLS or plain text
//   mariadb   no REQUIRE SUBJECT/ISSUER, so the password alone is enough
//   mongo     a SCRAM (password) user rather than the x509 one
//   redis     the per-scope instance speaks plain text with a password
// The scope's `_app` login follows its owner row (ensureAppLogin applies the
// same certRequired), so it is listed with it while it is enabled.
//
// SQLite only, no daemon: the list is what the platform admin page shows and
// what managedDb.syncPgHba() decides strict pg_hba on (together with the
// engine's own view of its roles, which only managedDb can ask for).

import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';
import { envForTenant } from './sandboxDb.js';
import { findEntry } from './catalogService.js';

export const JOB_ID = 'managed-db-logins';
const CHECK_MS = 60 * 60_000;
let timer = null;

const CONVERT_NOTE = {
  postgres: 'Joins the certificate group: TLS, its own client certificate and the password.',
  mariadb: 'REQUIRE SUBJECT/ISSUER: TLS, its own client certificate and the password.',
  mongo: 'Becomes an x509 login: TLS and its own client certificate, no password.',
  redis: 'The instance is recreated with TLS and its own CA (the Redis container restarts once).',
};

/** Engines with a "TLS required" level (managedDb.requireTls). */
export const TLS_LEVEL_ENGINES = ['postgres', 'mariadb'];
export const TLS_LEVEL_LABEL = 'TLS + password (no client certificate)';
const TLS_NOTE = {
  postgres: 'Joins the TLS group: TLS and the password, no client certificate; plain connections are refused.',
  mariadb: 'REQUIRE SSL: TLS and the password, no client certificate; plain connections are refused.',
};

/**
 * Whether AppCrane can point the app at the CA after Require TLS: a catalogue
 * entry that names its image's CA variable (appCatalog.json `tls_ca_env`).
 * Otherwise the app gets DB_CA_FILE and, for a URL AppCrane builds, the TLS
 * parameters, and may still not use TLS.
 */
function tlsCaEnvFor(catalogSlug) {
  const needs = catalogSlug ? findEntry(catalogSlug)?.needs : null;
  return typeof needs?.tls_ca_env === 'string' && needs.tls_ca_env ? needs.tls_ca_env : null;
}

function loginsWhere(where, args, extra) {
  const rows = getDb().prepare(
    `SELECT m.id, m.app_id, a.slug AS app_slug, a.catalog_slug, m.tenant, m.engine, m.db_name, m.db_user,
            m.app_user, m.app_password_enc IS NOT NULL AS app_enabled
       FROM managed_databases m LEFT JOIN apps a ON a.id = m.app_id
      WHERE ${where}
      ORDER BY a.slug, m.engine, m.tenant`
  ).all(...args);
  const out = [];
  for (const r of rows) {
    const base = {
      database_id: r.id,
      app_id: r.app_id,
      app_slug: r.app_slug || null,
      env: envForTenant(r.tenant) || r.tenant,
      engine: r.engine,
      ...extra(r),
    };
    out.push({ ...base, login: r.db_user, kind: 'owner' });
    if (r.app_user && r.app_enabled) out.push({ ...base, login: r.app_user, kind: 'app' });
  }
  return out;
}

/** Logins under "TLS required": TLS and the password, no client certificate. */
export function tlsOnlyLogins({ engine = null } = {}) {
  return loginsWhere(
    `m.client_cert_required IS NOT 1 AND m.tls_required = 1 ${engine ? 'AND m.engine = ?' : ''}`,
    engine ? [engine] : [],
    (r) => ({ level: 'tls', level_label: TLS_LEVEL_LABEL, convert_note: CONVERT_NOTE[r.engine] || null }),
  );
}

export function passwordOnlyLogins({ engine = null } = {}) {
  return loginsWhere(
    `m.client_cert_required IS NOT 1 AND m.tls_required IS NOT 1 ${engine ? 'AND m.engine = ?' : ''}`,
    engine ? [engine] : [],
    (r) => {
      const tlsAvailable = TLS_LEVEL_ENGINES.includes(r.engine);
      return {
        level: 'password',
        convert_note: CONVERT_NOTE[r.engine] || null,
        tls_available: tlsAvailable,
        tls_note: tlsAvailable ? TLS_NOTE[r.engine] : null,
        tls_ca_env: tlsAvailable ? tlsCaEnvFor(r.catalog_slug) : null,
        catalogue: Boolean(r.catalog_slug),
      };
    },
  );
}

/**
 * Certificate-required rows that still do not work end to end for an app
 * that declares no database (deployer.mountUndeclaredCertLogins records what
 * its last deploy or restart found, in `settings`, keyed by row id + login):
 *   not_sent      the engine enforces the certificate, but none of the app's
 *                 environment variables points at the mounted files, so its
 *                 own URL cannot send it (new connections are refused)
 *   not_enforced  the row says certificate, the engine does not hold the
 *                 login to it, so the password alone still works
 */
export const CERT_PROBLEM_LABEL = {
  not_sent: 'certificate required but the app is not configured to send it',
  not_enforced: 'certificate required in AppCrane, but the database engine does not enforce it (the password alone still works)',
};
const NOTE_PREFIX = 'managed_db_cert_problem:';

export function recordCertProblem(row, problem, { db = getDb(), env = null } = {}) {
  const key = `${NOTE_PREFIX}${row.id}`;
  if (!problem) {
    db.prepare('DELETE FROM settings WHERE key = ?').run(key);
    return;
  }
  db.prepare(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
    .run(key, JSON.stringify({ problem, login: row.db_user, env }));
}

export function certProblems({ db = getDb() } = {}) {
  const rows = db.prepare(
    `SELECT m.id, m.app_id, a.slug AS app_slug, m.tenant, m.engine, m.db_user, s.value, s.updated_at
       FROM settings s
       JOIN managed_databases m ON s.key = '${NOTE_PREFIX}' || m.id
       LEFT JOIN apps a ON a.id = m.app_id
      WHERE m.client_cert_required = 1
      ORDER BY a.slug, m.engine, m.tenant`
  ).all();
  const out = [];
  for (const r of rows) {
    let v;
    try { v = JSON.parse(r.value); } catch (_) { continue; }
    if (v?.login !== r.db_user || !CERT_PROBLEM_LABEL[v.problem]) continue;
    out.push({
      database_id: r.id,
      app_id: r.app_id,
      app_slug: r.app_slug || null,
      env: v.env || envForTenant(r.tenant) || r.tenant,
      engine: r.engine,
      login: r.db_user,
      problem: v.problem,
      label: CERT_PROBLEM_LABEL[v.problem],
      checked_at: r.updated_at,
    });
  }
  return out;
}

/**
 * One run: the list, plus the engine-side check and the pg_hba sync for a
 * RUNNING Postgres (managedDb.syncPgHba never starts a server from here).
 * A warning, not a failure: nothing is broken, a login is just weaker than
 * the rest.
 */
export async function runManagedDbLoginsCheck({ sync = null } = {}) {
  const logins = passwordOnlyLogins();
  const tlsLogins = tlsOnlyLogins();
  let pg = null;
  try {
    const syncPgHba = sync || (await import('./managedDb.js')).syncPgHba;
    pg = await syncPgHba({ startServer: false });
  } catch (e) {
    pg = { error: e.message };
  }
  const extra = (pg?.engineRoles || []).filter((r) => !logins.some((l) => l.engine === 'postgres' && l.login === r));
  const problems = certProblems();
  const n = logins.length + extra.length;
  const problemText = problems.length
    ? `${problems.length} certificate login(s) need attention: `
      + problems.map((p) => `${p.app_slug || `app ${p.app_id}`} ${p.env || ''} ${p.engine} ${p.login}: ${p.label}`.replace(/\s+/g, ' ')).join('; ') + '.'
    : '';
  const tlsText = tlsLogins.length
    ? `${tlsLogins.length} login(s) require TLS and the password but no client certificate: `
      + tlsLogins.map((l) => `${l.app_slug || `app ${l.app_id}`} ${l.env || ''} ${l.engine} ${l.login}`.replace(/\s+/g, ' ')).join('; ') + '.'
    : '';
  const detail = {
    logins,
    tls_logins: tlsLogins,
    postgres_engine_roles_without_certificate: extra,
    cert_problems: problems,
    postgres_strict: pg?.strict ?? null,
    ...(n || problems.length || pg?.error ? { severity: 'warning' } : {}),
    message: [n
      ? `${n} managed database login(s) can still sign in with a password alone: `
        + [...logins.map((l) => `${l.app_slug || `app ${l.app_id}`} ${l.env || ''} ${l.engine} ${l.login}`.replace(/\s+/g, ' ')),
          ...extra.map((r) => `postgres role ${r} (not an AppCrane login)`)].join('; ')
        + '. Platform admin: Managed databases, Require certificate.'
      : problems.length || tlsLogins.length ? '' : 'Every managed database login requires TLS and its own client certificate.'
        + (pg?.strict ? ' Postgres refuses every TCP login without one (strict pg_hba).' : ''),
    !n && tlsLogins.length ? 'No managed database login signs in with a password alone.' : '',
    tlsText,
    problemText].filter(Boolean).join(' '),
    ...(pg?.error ? { postgres_error: pg.error } : {}),
  };
  setJobDetail(JOB_ID, detail);
  return detail;
}

export function startManagedDbLoginsCheck() {
  if (timer) return;
  jobStarted(JOB_ID, { cadenceMs: CHECK_MS });
  const tick = () => trackJob(JOB_ID, () => runManagedDbLoginsCheck()).catch((e) => log.warn(`[managed-db-logins] ${e.message}`));
  setTimeout(tick, 30_000).unref?.();
  timer = setInterval(tick, CHECK_MS);
  timer.unref?.();
}
