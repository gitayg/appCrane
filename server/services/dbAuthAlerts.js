/**
 * Failed-login alerts for the managed databases.
 *
 * Every few minutes this reads the shared servers' own logs (`docker logs
 * --since`), extracts authentication failures — login, target database, time,
 * and a short reason; never the raw line — and when one login fails more than
 * the platform threshold (default 5) inside ten minutes, writes an audit_log
 * row and e-mails the platform admins, at most once per login per hour.
 *
 * WHAT IS REPORTED, AND WHY IT IS THE LOGIN AND NOT THE ADDRESS. Every
 * connection to a managed server arrives from the bridge gateway (measured;
 * docker-proxy rewrites the source), so the client address in the engine's
 * log identifies nothing and is not stored. The LOGIN and the DATABASE do: a
 * login belongs to exactly one app (managed_databases.db_user), so
 * "crane_a7_u failed 40 times against crane_a14" names app 7 as the one
 * probing app 14's database. Both owners are resolved and put in the alert.
 *
 * WHAT IS NEVER STORED: the password. No engine logs it — Postgres, MariaDB
 * and Mongo log the user, never the credential — and the raw line is
 * discarded after the regex extracts its fields, so a future log format that
 * did include something sensitive could still not reach SQLite, the audit log
 * or an e-mail through this file. Login and database names are clamped to a
 * safe alphabet because they are attacker-controlled strings (a client picks
 * the user name it sends).
 *
 * WHAT IS PARSED, per engine (the server flags that make each line exist are
 * in managedDbTls.js):
 *   postgres  log_line_prefix 'user=%u db=%d ' + the FATAL auth messages
 *             (wrong password, pg_hba reject = TLS required, missing or wrong
 *             client certificate, database permission denied)
 *   mariadb   log_warnings=2: "Access denied for user 'x'@'host'" — the
 *             database is named only when the denial was for a database
 *   mongo     the structured "Failed to authenticate" event (id 5286307 on
 *             mongo:8.0, measured; "Authentication failed" id 20249 before)
 *   redis     NOT covered: a failed AUTH is not logged by redis-server (it is
 *             kept in the in-memory ACL LOG only), and reading N per-app
 *             containers' ACL LOG over redis-cli is not the cheap thing the
 *             other three are.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { logAudit } from '../middleware/audit.js';
import { enqueueEmail } from './emailQueue.js';
import { getManagedDbSettings } from './managedDbSettings.js';

const execFileAsync = promisify(execFile);

export const WINDOW_MINUTES = 10;
export const RATE_LIMIT_MINUTES = 60;
export const SCAN_INTERVAL_MS = 3 * 60 * 1000;

const SAFE_NAME = /[^A-Za-z0-9_.$@-]/g;
function clamp(s) {
  if (s == null) return null;
  const v = String(s).replace(SAFE_NAME, '?').slice(0, 64);
  return v || null;
}

// docker logs --timestamps: RFC3339Nano, then one space, then the line.
const TS = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s(.*)$/;

const PG_PREFIX = /user=(\S*) db=(\S*) (?:FATAL|ERROR):\s+(.*)$/;
const PG_REASONS = [
  [/password authentication failed/, 'bad-password'],
  [/pg_hba\.conf rejects connection.*no encryption/, 'tls-required'],
  [/pg_hba\.conf rejects connection/, 'rejected'],
  [/no pg_hba\.conf entry/, 'no-hba-entry'],
  [/certificate|clientcert/, 'client-certificate'],
  [/permission denied for database/, 'database-denied'],
  [/role ".*" does not exist/, 'unknown-login'],
];

const MARIA_DB_DENIED = /Access denied for user '([^']*)'@'[^']*' to database '([^']*)'/;
const MARIA_DENIED = /Access denied for user '([^']*)'@'[^']*'/;

/**
 * Parse one engine's `docker logs --timestamps` output.
 * @returns {Array<{ login: string, database: string|null, reason: string, at: string }>}
 */
export function parseAuthFailures(engine, text) {
  const out = [];
  for (const raw of String(text || '').split('\n')) {
    const m = TS.exec(raw.trim());
    if (!m) continue;
    const at = new Date(m[1]).toISOString();
    const line = m[2];

    if (engine === 'postgres') {
      const p = PG_PREFIX.exec(line);
      if (!p || !p[1]) continue;
      const reason = PG_REASONS.find(([re]) => re.test(p[3]))?.[1];
      if (!reason) continue;
      out.push({ login: clamp(p[1]), database: clamp(p[2]), reason, at });
    } else if (engine === 'mariadb') {
      const d = MARIA_DB_DENIED.exec(line);
      if (d) { out.push({ login: clamp(d[1]), database: clamp(d[2]), reason: 'database-denied', at }); continue; }
      const a = MARIA_DENIED.exec(line);
      if (a && a[1]) out.push({ login: clamp(a[1]), database: null, reason: 'access-denied', at });
    } else if (engine === 'mongo') {
      // mongo:8.0 logs "Failed to authenticate" (id 5286307, attr.user /
      // attr.db) — measured; older servers said "Authentication failed"
      // (id 20249, attr.principalName / attr.authenticationDatabase).
      if (!line.includes('"Failed to authenticate"') && !line.includes('"Authentication failed"')) continue;
      let ev;
      try { ev = JSON.parse(line.slice(line.indexOf('{'))); } catch (_) { continue; }
      const user = ev?.attr?.user || ev?.attr?.principalName;
      if (!user) continue;
      out.push({
        login: clamp(user),
        database: clamp(ev?.attr?.db || ev?.attr?.authenticationDatabase),
        reason: String(ev?.attr?.mechanism || 'auth').toLowerCase().includes('x509') ? 'client-certificate' : 'bad-password',
        at,
      });
    }
  }
  return out.filter(f => f.login && !IGNORED_LOGINS.has(f.login));
}

// AppCrane's own readiness probe deliberately logs in as a user that does not
// exist (managedDb.waitReady: "Access denied" proves the server is up without
// putting a credential in argv), dozens of times per server start. Counting it
// would page the admins on every recreate.
const IGNORED_LOGINS = new Set(['appcrane_readiness_probe']);

/** Store parsed failures, skipping exact repeats (overlapping log reads). */
export function recordFailures(db, engine, failures) {
  const exists = db.prepare(
    'SELECT 1 FROM managed_db_auth_failures WHERE engine = ? AND login = ? AND IFNULL(database_name, \'\') = IFNULL(?, \'\') AND reason = ? AND occurred_at = ?',
  );
  const ins = db.prepare(
    'INSERT INTO managed_db_auth_failures (engine, login, database_name, reason, occurred_at) VALUES (?, ?, ?, ?, ?)',
  );
  let n = 0;
  for (const f of failures) {
    if (exists.get(engine, f.login, f.database, f.reason, f.at)) continue;
    ins.run(engine, f.login, f.database, f.reason, f.at);
    n++;
  }
  return n;
}

function appForLogin(db, login) {
  return db.prepare(`SELECT a.id, a.slug FROM managed_databases m JOIN apps a ON a.id = m.app_id WHERE m.db_user = ? LIMIT 1`).get(login) || null;
}

function appForDatabase(db, name) {
  if (!name) return null;
  return db.prepare(`SELECT a.id, a.slug FROM managed_databases m JOIN apps a ON a.id = m.app_id WHERE m.db_name = ? LIMIT 1`).get(name) || null;
}

/**
 * Raise the alerts the stored failures call for. Pure over SQLite plus the
 * two side-effect seams, so the threshold and the rate limit are testable.
 *
 * "More than N in ten minutes": with the default 5, the sixth failure inside
 * the window alerts. One alert per (engine, login) per hour, tracked in
 * managed_db_auth_alerts so a restart of AppCrane does not reset it.
 */
export function evaluateAlerts(db, {
  now = new Date(),
  threshold = getManagedDbSettings(db).auth_alert_threshold,
  audit = logAudit,
  sendMail = enqueueEmail,
} = {}) {
  const windowStart = new Date(now.getTime() - WINDOW_MINUTES * 60 * 1000).toISOString();
  const rateStart = new Date(now.getTime() - RATE_LIMIT_MINUTES * 60 * 1000).toISOString();
  const groups = db.prepare(`
    SELECT engine, login, COUNT(*) AS failures,
           GROUP_CONCAT(DISTINCT IFNULL(database_name, '')) AS dbs,
           GROUP_CONCAT(DISTINCT reason) AS reasons,
           MIN(occurred_at) AS first_at, MAX(occurred_at) AS last_at
    FROM managed_db_auth_failures
    WHERE occurred_at >= ?
    GROUP BY engine, login
  `).all(windowStart);

  const raised = [];
  for (const g of groups) {
    if (!(g.failures > threshold)) continue;
    const last = db.prepare('SELECT alerted_at FROM managed_db_auth_alerts WHERE engine = ? AND login = ?').get(g.engine, g.login);
    if (last && last.alerted_at >= rateStart) continue;

    const databases = String(g.dbs || '').split(',').filter(Boolean);
    const owner = appForLogin(db, g.login);
    const targets = databases.map(d => ({ database: d, app: appForDatabase(db, d)?.slug || null }));
    const foreign = owner ? targets.filter(t => t.app && t.app !== owner.slug) : [];
    const detail = {
      engine: g.engine,
      login: g.login,
      login_app: owner?.slug || null,
      databases: targets,
      cross_app: foreign.length > 0,
      failures: g.failures,
      threshold,
      window_minutes: WINDOW_MINUTES,
      reasons: String(g.reasons || '').split(',').filter(Boolean),
      first_at: g.first_at,
      last_at: g.last_at,
    };

    db.prepare(`INSERT INTO managed_db_auth_alerts (engine, login, alerted_at) VALUES (?, ?, ?)
      ON CONFLICT(engine, login) DO UPDATE SET alerted_at = excluded.alerted_at`).run(g.engine, g.login, now.toISOString());
    try { audit(null, owner?.id ?? null, 'managed-db-auth-alert', detail, 'system'); }
    catch (e) { log.warn(`[db-auth-alerts] audit write failed: ${e.message}`); }

    const admins = db.prepare(
      "SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL",
    ).all();
    const subject = `[AppCrane] Repeated failed ${g.engine} logins for ${g.login}`;
    const text = [
      `The managed ${g.engine} server refused login "${g.login}" ${g.failures} times in the last ${WINDOW_MINUTES} minutes (alert threshold: more than ${threshold}).`,
      '',
      `Login belongs to: ${owner ? owner.slug : 'no app on this platform (an unknown login name)'}`,
      `Target database(s): ${targets.length ? targets.map(t => `${t.database}${t.app ? ` (app ${t.app})` : ''}`).join(', ') : 'not named by the engine'}`,
      `Reasons: ${detail.reasons.join(', ')}`,
      `First: ${g.first_at}   Last: ${g.last_at}`,
      '',
      foreign.length
        ? `This login targeted a database it does not own. The app it belongs to (${owner.slug}) is the likely source.`
        : 'The source address is not reported: every connection to a managed database arrives from the Docker bridge gateway, so the login and the database are what identify the caller.',
      '',
      'Passwords are never logged by the database engines and are not part of this alert. You will get at most one of these per login per hour.',
    ].join('\n');
    const hour = now.toISOString().slice(0, 13);
    for (const a of admins) {
      try {
        sendMail({ to: a.email, subject, text, appId: null, idempotencyKey: `db-auth-alert:${g.engine}:${g.login}:${hour}:${String(a.email).toLowerCase()}`, source: 'db-auth-alert' });
      } catch (e) {
        log.warn(`[db-auth-alerts] mail to a platform admin skipped: ${e.message}`);
      }
    }
    raised.push(detail);
  }
  return raised;
}

// ---------------------------------------------------------------------------
// The job
// ---------------------------------------------------------------------------

// Per container, the newest log timestamp already read. In memory: after a
// restart the first scan reads the last window again, and recordFailures()
// drops the exact repeats.
const cursors = new Map();

/**
 * One pass: read each shared server's new log lines, store failures, alert.
 * `exec` is a test seam for `docker logs`.
 */
export async function scanOnce({ db = getDb(), now = new Date(), exec = execFileAsync } = {}) {
  const servers = db.prepare('SELECT engine, container_name FROM managed_db_servers').all();
  let stored = 0;
  for (const s of servers) {
    if (!['postgres', 'mariadb', 'mongo'].includes(s.engine)) continue;
    const since = cursors.get(s.container_name)
      || new Date(now.getTime() - WINDOW_MINUTES * 60 * 1000).toISOString();
    let text = '';
    try {
      const { stdout, stderr } = await exec('docker', ['logs', '--timestamps', '--since', since, s.container_name], { timeout: 30000, maxBuffer: 32 * 1024 * 1024 });
      text = `${stdout || ''}\n${stderr || ''}`;
    } catch (e) {
      log.debug(`[db-auth-alerts] could not read ${s.container_name} logs: ${e.message}`);
      continue;
    }
    const failures = parseAuthFailures(s.engine, text).filter(f => f.at > since || !cursors.has(s.container_name));
    stored += recordFailures(db, s.engine, failures);
    const newest = failures.reduce((m, f) => (f.at > m ? f.at : m), since);
    cursors.set(s.container_name, newest);
  }
  // Keep the table bounded: nothing older than a day is ever consulted.
  db.prepare("DELETE FROM managed_db_auth_failures WHERE occurred_at < ?").run(new Date(now.getTime() - 24 * 3600 * 1000).toISOString());
  const raised = evaluateAlerts(db, { now });
  return { stored, raised };
}

export function __resetCursorsForTests() { cursors.clear(); }

let timer = null;
export function startDbAuthAlertScheduler() {
  if (timer) return;
  timer = setInterval(() => {
    scanOnce().catch(e => log.warn(`[db-auth-alerts] scan failed: ${e.message}`));
  }, SCAN_INTERVAL_MS);
  timer.unref?.();
}
