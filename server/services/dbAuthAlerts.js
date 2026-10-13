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
 *   redis     a failed AUTH is not logged by redis-server at all; it is
 *             kept in the in-memory ACL LOG. So each per-scope instance's
 *             `ACL LOG 128` is read with redis-cli INSIDE its own container
 *             (managedRedis.aclLogArgs), authenticated by the REDISCLI_AUTH
 *             the container already has — no password on any argv, and none
 *             passed in with `docker exec -e` either, since nothing needs to
 *             cross. Entries with reason "auth" are counted.
 *
 * REDIS IS READ BY ENTRY, NOT BY LINE. The ACL LOG groups repeats: a burst of
 * failures for one username is ONE entry whose count grows (measured on
 * redis:8.10-alpine: three wrong passwords -> one entry, count 3). An entry is
 * identified by (entry-id, timestamp-created) — ids restart at 0 with the
 * instance — and managed_db_redis_acl_seen (migration 110) records the count
 * already turned into failure rows, so each scan stores only the DELTA, and a
 * restart of AppCrane does not count the log twice. The log is never reset:
 * it stays as evidence for whoever investigates the alert.
 *
 * A failure row's time is the entry's timestamp-last-updated, so the up to
 * SCAN_INTERVAL_MS of failures a delta covers are all dated at the newest of
 * them. That can only move failures LATER, i.e. into the window, never out.
 *
 * For Redis the login stored is the username the client sent, and `default`
 * (what a password-only `AUTH <pw>` resolves to on every instance) is stored
 * as default@<instance>, so failures against six different apps' instances do
 * not add up to one alert. The client address in the entry is never read: as
 * for the shared servers, it is the Docker bridge gateway for every
 * connection (measured), so the username and the TARGET INSTANCE are what
 * identify the caller. A connection refused for a missing or wrong client
 * certificate never reaches AUTH, so it is not in the ACL LOG and not counted.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { logAudit } from '../middleware/audit.js';
import { enqueueEmail } from './emailQueue.js';
import { getManagedDbSettings } from './managedDbSettings.js';
import * as redis from './managedRedis.js';

const execFileAsync = promisify(execFile);

export const WINDOW_MINUTES = 10;
export const RATE_LIMIT_MINUTES = 60;
export const SCAN_INTERVAL_MS = 3 * 60 * 1000;
// Bounds an attacker cannot push past (security review: amplification). Login
// names in these logs are whatever the caller typed, so a rogue app can invent
// thousands; each distinct name used to get its own rows, audit entry and e-mail.
// Logins that belong to an app are bounded by the number of managed databases,
// so they are never folded or capped: hiding them is the attack. Only invented
// names are bounded here.
export const MAX_UNKNOWN_GROUPS_PER_SCAN = 200; // distinct invented-login groups kept per engine scan
export const DIGEST_OVER = 3;                    // more alerts than this in one pass -> one digest e-mail
export const UNKNOWN_LOGINS = '(logins not belonging to any app)';

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

/**
 * Parse `redis-cli --json ACL LOG 128` (redis:8.10 output, measured). Keeps
 * only reason "auth" and only the fields counted; `client-info` is dropped
 * unread, and the username is clamped like every other attacker-chosen name.
 * @returns {Array<{ entryId: number, createdMs: number, updatedMs: number, count: number, username: string }>}
 */
export function parseRedisAclLog(text) {
  let entries;
  try { entries = JSON.parse(String(text || '').trim() || '[]'); } catch (_) { return []; }
  if (!Array.isArray(entries)) return [];
  const out = [];
  for (const e of entries) {
    if (!e || e.reason !== 'auth') continue;
    const entryId = Number(e['entry-id']);
    const createdMs = Number(e['timestamp-created']);
    const updatedMs = Number(e['timestamp-last-updated'] ?? e['timestamp-created']);
    const count = Number(e.count);
    const username = clamp(e.username);
    if (!Number.isInteger(entryId) || !Number.isFinite(createdMs) || !Number.isFinite(updatedMs)) continue;
    if (!Number.isInteger(count) || count < 1 || !username) continue;
    out.push({ entryId, createdMs, updatedMs, count, username });
  }
  return out;
}

/** The login a Redis failure is stored under (see the header on `default`). */
export function redisLogin(username, dbName) {
  return username === 'default' ? clamp(`default@${dbName}`) : username;
}

/**
 * Turn ACL LOG entries into failure rows: for each entry, only the count not
 * already recorded. One transaction, so the rows and the seen-count move
 * together — a crash between them can neither lose nor double failures.
 */
export function recordRedisAclEntries(db, { container, dbName }, entries, { now = new Date() } = {}) {
  const seen = db.prepare('SELECT seen_count FROM managed_db_redis_acl_seen WHERE container_name = ? AND entry_id = ? AND created_ms = ?');
  const upsert = db.prepare(`INSERT INTO managed_db_redis_acl_seen (container_name, entry_id, created_ms, seen_count, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(container_name, entry_id, created_ms) DO UPDATE SET seen_count = excluded.seen_count, updated_at = excluded.updated_at`);
  const ins = db.prepare(
    "INSERT INTO managed_db_auth_failures (engine, login, database_name, reason, occurred_at, count) VALUES ('redis', ?, ?, 'auth-failed', ?, ?)",
  );
  let n = 0;
  const owner = ownerCache(db);
  // Usernames are the caller's to invent: every one that belongs to no app is
  // folded into ONE row per instance per scan, the same bound recordFailures
  // applies to the other engines. Real logins keep their own row.
  const folded = { count: 0, at: null };
  db.transaction(() => {
    for (const e of entries) {
      const prev = seen.get(container, e.entryId, e.createdMs)?.seen_count || 0;
      const login = redisLogin(e.username, dbName);
      if (!IGNORED_LOGINS.has(login)) {
        const at = new Date(e.updatedMs).toISOString();
        const delta = e.count - prev;
        // ONE row carrying the delta, never one row per failure: the count is
        // the attacker's to inflate.
        if (delta > 0) {
          if (owner(login)) ins.run(login, dbName, at, delta);
          else { folded.count += delta; if (!folded.at || at > folded.at) folded.at = at; }
          n += delta;
        }
      }
      // Touched on every scan, delta or not: a row is pruned only once its
      // entry has not been in the log for a day.
      upsert.run(container, e.entryId, e.createdMs, Math.max(prev, e.count), now.toISOString());
    }
    if (folded.count > 0) ins.run(UNKNOWN_LOGINS, dbName, folded.at, folded.count);
  })();
  return n;
}

/** appForLogin, memoised for one batch: one lookup per distinct name, not per failure. */
function ownerCache(db) {
  const memo = new Map();
  return (login) => {
    if (!memo.has(login)) memo.set(login, appForLogin(db, login));
    return memo.get(login);
  };
}

// A log read is capped at 32 MiB, but a parse of it could still yield hundreds
// of thousands of failures; only this many are grouped per scan, the rest are
// counted into the folded row without being examined one by one.
export const MAX_FAILURES_PER_SCAN = 100000;

// AppCrane's own readiness probe deliberately logs in as a user that does not
// exist (managedDb.waitReady: "Access denied" proves the server is up without
// putting a credential in argv), dozens of times per server start. Counting it
// would page the admins on every recreate.
const IGNORED_LOGINS = new Set(['appcrane_readiness_probe']);

/**
 * Store parsed failures as one counted row per (login, database, reason) in this
 * batch, skipping a group already stored at the same time (overlapping log
 * reads). Groups for logins that belong to an app are always kept; at most
 * MAX_UNKNOWN_GROUPS_PER_SCAN invented-login groups are, the rest folded into one
 * UNKNOWN_LOGINS row, so invented names cannot grow the table.
 */
export function recordFailures(db, engine, failures) {
  const groups = new Map();
  const overflow = failures.length > MAX_FAILURES_PER_SCAN ? failures.length - MAX_FAILURES_PER_SCAN : 0;
  if (overflow) failures = failures.slice(0, MAX_FAILURES_PER_SCAN);
  for (const f of failures) {
    const k = `${f.login}\u0000${f.database ?? ''}\u0000${f.reason}`;
    const g = groups.get(k);
    if (g) { g.count++; if (f.at > g.at) g.at = f.at; }
    else groups.set(k, { login: f.login, database: f.database, reason: f.reason, at: f.at, count: 1 });
  }
  // Real logins are kept whole, always; only invented names are folded, so an
  // attacker flooding invented names cannot push a real login's failures out.
  const all = [...groups.values()];
  const owner = ownerCache(db);
  const known = all.filter(g => owner(g.login));
  const unknownGroups = all.filter(g => !owner(g.login)).sort((a, b) => b.count - a.count);
  let list = known;
  if (overflow) {
    const last = failures[failures.length - 1];
    unknownGroups.push({ login: UNKNOWN_LOGINS, database: null, reason: 'many-logins', at: last?.at, count: overflow });
  }
  if (unknownGroups.length <= MAX_UNKNOWN_GROUPS_PER_SCAN) list = list.concat(unknownGroups);
  else {
    const rest = unknownGroups.slice(MAX_UNKNOWN_GROUPS_PER_SCAN - 1);
    list = list.concat(unknownGroups.slice(0, MAX_UNKNOWN_GROUPS_PER_SCAN - 1));
    list.push({
      login: UNKNOWN_LOGINS, database: null, reason: 'many-logins',
      at: rest.reduce((m, g) => (g.at > m ? g.at : m), rest[0].at),
      count: rest.reduce((n, g) => n + g.count, 0),
    });
  }
  const exists = db.prepare(
    'SELECT 1 FROM managed_db_auth_failures WHERE engine = ? AND login = ? AND IFNULL(database_name, \'\') = IFNULL(?, \'\') AND reason = ? AND occurred_at = ?',
  );
  const ins = db.prepare(
    'INSERT INTO managed_db_auth_failures (engine, login, database_name, reason, occurred_at, count) VALUES (?, ?, ?, ?, ?, ?)',
  );
  let n = 0;
  db.transaction(() => {
    for (const g of list) {
      if (exists.get(engine, g.login, g.database, g.reason, g.at)) continue;
      ins.run(engine, g.login, g.database, g.reason, g.at, g.count);
      n += g.count;
    }
  })();
  return n;
}

function appForLogin(db, login) {
  // A Redis instance's built-in `default` user is recorded as default@<db>, and
  // belongs to that instance's app.
  const m = /^default@(.+)$/.exec(login || '');
  if (m) return appForDatabase(db, m[1]);
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
  const rawGroups = db.prepare(`
    SELECT engine, login, SUM(count) AS failures,
           GROUP_CONCAT(DISTINCT IFNULL(database_name, '')) AS dbs,
           GROUP_CONCAT(DISTINCT reason) AS reasons,
           MIN(occurred_at) AS first_at, MAX(occurred_at) AS last_at
    FROM managed_db_auth_failures
    WHERE occurred_at >= ?
    GROUP BY engine, login
  `).all(windowStart);

  // Logins that belong to no app (invented names, typos) share ONE alert per
  // engine instead of one each: their names are the attacker's to multiply.
  const groups = [];
  const unknown = new Map();
  for (const g of rawGroups) {
    if (g.login === UNKNOWN_LOGINS || !appForLogin(db, g.login)) {
      const u = unknown.get(g.engine) || { engine: g.engine, login: UNKNOWN_LOGINS, failures: 0, dbs: new Set(), reasons: new Set(), first_at: g.first_at, last_at: g.last_at, samples: [] };
      u.failures += g.failures;
      for (const d of String(g.dbs || '').split(',').filter(Boolean)) u.dbs.add(d);
      for (const r of String(g.reasons || '').split(',').filter(Boolean)) u.reasons.add(r);
      if (g.first_at < u.first_at) u.first_at = g.first_at;
      if (g.last_at > u.last_at) u.last_at = g.last_at;
      if (g.login !== UNKNOWN_LOGINS && u.samples.length < 10) u.samples.push(g.login);
      unknown.set(g.engine, u);
    } else groups.push(g);
  }
  for (const u of unknown.values()) {
    groups.push({ ...u, dbs: [...u.dbs].slice(0, 20).join(','), reasons: [...u.reasons].join(',') });
  }

  const raised = [];
  const pending = [];
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

    const subject = `[AppCrane] Repeated failed ${g.engine} logins for ${g.login}`;
    const text = [
      `The managed ${g.engine} server refused login "${g.login}" ${g.failures} times in the last ${WINDOW_MINUTES} minutes (alert threshold: more than ${threshold}).`,
      '',
      `Login belongs to: ${owner ? owner.slug : 'no app on this platform (an unknown login name)'}`,
      ...(g.samples?.length ? [`Login names tried (up to 10): ${g.samples.join(', ')}`] : []),
      `Target database(s): ${targets.length ? targets.map(t => `${t.database}${t.app ? ` (app ${t.app})` : ''}`).join(', ') : 'not named by the engine'}`,
      `Reasons: ${detail.reasons.join(', ')}`,
      `First: ${g.first_at}   Last: ${g.last_at}`,
      '',
      foreign.length
        ? `This login targeted a database it does not own. The app it belongs to (${owner.slug}) is the likely source.`
        : g.engine === 'redis'
          ? 'The source address is not reported: Redis records every connection to a managed instance as coming from the Docker bridge gateway, so the username and the target instance are what identify the caller. Connections refused for a missing or wrong client certificate never reach AUTH and are not counted here.'
          : 'The source address is not reported: every connection to a managed database arrives from the Docker bridge gateway, so the login and the database are what identify the caller.',
      '',
      'Passwords are never logged by the database engines and are not part of this alert. You will get at most one of these per login per hour; when several logins cross the threshold at once they arrive as one digest.',
    ].join('\n');
    pending.push({ subject, text, key: `${g.engine}:${g.login}` });
    raised.push(detail);
  }

  // Never suppressed, only batched: every alert above is audited; the e-mail is
  // one per alert, or ONE digest listing all of them when many fire at once.
  if (pending.length) {
    const admins = db.prepare(
      "SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL",
    ).all();
    const hour = now.toISOString().slice(0, 13);
    const mails = pending.length > DIGEST_OVER
      ? [{
        subject: `[AppCrane] Repeated failed database logins for ${pending.length} logins`,
        text: [`${pending.length} logins crossed the failed-login alert threshold in this pass:`, '', ...pending.map(p => `----\n${p.subject}\n\n${p.text}`)].join('\n'),
        key: `digest:${pending.map(p => p.key).sort().join('|').slice(0, 200)}`,
      }]
      : pending;
    for (const m of mails) {
      for (const a of admins) {
        try {
          sendMail({ to: a.email, subject: m.subject, text: m.text, appId: null, idempotencyKey: `db-auth-alert:${m.key}:${hour}:${String(a.email).toLowerCase()}`, source: 'db-auth-alert' });
        } catch (e) {
          log.warn(`[db-auth-alerts] mail to a platform admin skipped: ${e.message}`);
        }
      }
    }
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
  stored += await scanRedisInstances({ db, now, exec });
  // Keep the tables bounded: nothing older than a day is ever consulted.
  const dayAgo = new Date(now.getTime() - 24 * 3600 * 1000).toISOString();
  db.prepare("DELETE FROM managed_db_auth_failures WHERE occurred_at < ?").run(dayAgo);
  db.prepare('DELETE FROM managed_db_redis_acl_seen WHERE updated_at < ?').run(dayAgo);
  const raised = evaluateAlerts(db, { now });
  return { stored, raised };
}

/**
 * Every per-scope Redis: read its ACL LOG and record the new failures. One
 * unreachable instance (stopped, mid-recreate) is skipped, not fatal.
 */
async function scanRedisInstances({ db, now, exec }) {
  const rows = db.prepare(
    "SELECT db_name, container_name, client_cert_required FROM managed_databases WHERE engine = 'redis' AND container_name IS NOT NULL",
  ).all();
  let stored = 0;
  for (const r of rows) {
    let stdout = '';
    try {
      ({ stdout } = await exec('docker', redis.aclLogArgs(r.container_name, { tls: r.client_cert_required === 1 }), { timeout: 30000, maxBuffer: 4 * 1024 * 1024 }));
    } catch (e) {
      log.debug(`[db-auth-alerts] could not read ${r.container_name} ACL LOG: ${e.message}`);
      continue;
    }
    stored += recordRedisAclEntries(db, { container: r.container_name, dbName: r.db_name }, parseRedisAclLog(stdout), { now });
  }
  return stored;
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
