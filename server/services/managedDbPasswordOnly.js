// Managed database logins that can still authenticate WITHOUT a client
// certificate, and the Job Health check that reports them.
//
// A login is password-only while its row has client_cert_required = 0:
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

export const JOB_ID = 'managed-db-logins';
const CHECK_MS = 60 * 60_000;
let timer = null;

const CONVERT_NOTE = {
  postgres: 'Joins the certificate group: TLS, its own client certificate and the password.',
  mariadb: 'REQUIRE SUBJECT/ISSUER: TLS, its own client certificate and the password.',
  mongo: 'Becomes an x509 login: TLS and its own client certificate, no password.',
  redis: 'The instance is recreated with TLS and its own CA (the Redis container restarts once).',
};

export function passwordOnlyLogins({ engine = null, db = getDb() } = {}) {
  const rows = db.prepare(
    `SELECT m.id, m.app_id, a.slug AS app_slug, m.tenant, m.engine, m.db_name, m.db_user,
            m.app_user, m.app_password_enc IS NOT NULL AS app_enabled
       FROM managed_databases m LEFT JOIN apps a ON a.id = m.app_id
      WHERE m.client_cert_required IS NOT 1 ${engine ? 'AND m.engine = ?' : ''}
      ORDER BY a.slug, m.engine, m.tenant`
  ).all(...(engine ? [engine] : []));
  const out = [];
  for (const r of rows) {
    const base = {
      database_id: r.id,
      app_id: r.app_id,
      app_slug: r.app_slug || null,
      env: envForTenant(r.tenant) || r.tenant,
      engine: r.engine,
      convert_note: CONVERT_NOTE[r.engine] || null,
    };
    out.push({ ...base, login: r.db_user, kind: 'owner' });
    if (r.app_user && r.app_enabled) out.push({ ...base, login: r.app_user, kind: 'app' });
  }
  return out;
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
  const detail = {
    logins,
    postgres_engine_roles_without_certificate: extra,
    cert_problems: problems,
    postgres_strict: pg?.strict ?? null,
    ...(n || problems.length || pg?.error ? { severity: 'warning' } : {}),
    message: [n
      ? `${n} managed database login(s) can still sign in with a password alone: `
        + [...logins.map((l) => `${l.app_slug || `app ${l.app_id}`} ${l.env || ''} ${l.engine} ${l.login}`.replace(/\s+/g, ' ')),
          ...extra.map((r) => `postgres role ${r} (not an AppCrane login)`)].join('; ')
        + '. Platform admin: Managed databases, Require certificate.'
      : problems.length ? '' : 'Every managed database login requires TLS and its own client certificate.'
        + (pg?.strict ? ' Postgres refuses every TCP login without one (strict pg_hba).' : ''),
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
