import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Failed-login alerts (services/dbAuthAlerts.js). The log lines below are the
// engines' real output, copied from postgres:16-alpine, mariadb:11.4 and
// mongo:8.0 running with the flags managedDbTls.js sets.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mdbalert-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const alerts = await import('../server/services/dbAuthAlerts.js');
const { setManagedDbSettings } = await import('../server/services/managedDbSettings.js');

let APP_7, APP_14;
before(() => {
  initDb(process.env.DATA_DIR);
  const db = getDb();
  const ins = db.prepare('INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)');
  APP_7 = Number(ins.run('Seven', 'seven', 1).lastInsertRowid);
  APP_14 = Number(ins.run('Supply', 'supply', 2).lastInsertRowid);
  const md = db.prepare("INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc) VALUES (?, '', 'postgres', ?, ?, 'x')");
  md.run(APP_7, 'crane_a7', 'crane_a7_u');
  md.run(APP_14, 'crane_a14', 'crane_a14_u');
  db.prepare("INSERT INTO users (name, email, role, active, api_key_hash) VALUES ('Admin', 'admin@example.test', 'platform_admin', 1, 'h-admin')").run();
});
after(() => { try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {} });
beforeEach(() => {
  const db = getDb();
  db.prepare('DELETE FROM managed_db_auth_failures').run();
  db.prepare('DELETE FROM managed_db_auth_alerts').run();
  db.prepare("DELETE FROM audit_log WHERE action = 'managed-db-auth-alert'").run();
});

const T0 = new Date('2026-10-12T12:00:00Z');
const at = (s) => new Date(T0.getTime() + s * 1000).toISOString().replace('.000Z', '.123456789Z');

function pgLines(n, { user = 'crane_a7_u', db = 'crane_a14', startS = 0 } = {}) {
  return Array.from({ length: n }, (_, i) =>
    `${at(startS + i)} 2026-10-12 12:00:0${i % 10}.123 UTC [${100 + i}] user=${user} db=${db} FATAL:  password authentication failed for user "${user}"`).join('\n');
}

test('postgres: wrong password, TLS-required reject, missing cert and database denial are all parsed with login + database', () => {
  const text = [
    `${at(1)} 2026-10-12 12:00:01.001 UTC [11] user=crane_a7_u db=crane_a14 FATAL:  password authentication failed for user "crane_a7_u"`,
    `${at(1)} 2026-10-12 12:00:01.001 UTC [11] user=crane_a7_u db=crane_a14 DETAIL:  Connection matched file "/tmp/appcrane-tls/pg_hba.conf" line 3`,
    `${at(2)} 2026-10-12 12:00:02.001 UTC [12] user=crane_a14_u db=crane_a14 FATAL:  pg_hba.conf rejects connection for host "172.17.0.1", user "crane_a14_u", database "crane_a14", no encryption`,
    `${at(3)} 2026-10-12 12:00:03.001 UTC [13] user=crane_a14_u db=crane_a14 FATAL:  connection requires a valid client certificate`,
    `${at(4)} 2026-10-12 12:00:04.001 UTC [14] user=crane_a7_u db=crane_a14 FATAL:  permission denied for database "crane_a14"`,
    `${at(5)} 2026-10-12 12:00:05.001 UTC [15] user=crane_a7_u db=crane_a7 LOG:  connection authorized: user=crane_a7_u database=crane_a7 SSL enabled`,
    `${at(6)} 2026-10-12 12:00:06.001 UTC [16] user=crane_a7_u db=crane_a7 FATAL:  too many connections for role "crane_a7_u"`,
  ].join('\n');
  assert.deepEqual(alerts.parseAuthFailures('postgres', text).map((f) => [f.login, f.database, f.reason]), [
    ['crane_a7_u', 'crane_a14', 'bad-password'],
    ['crane_a14_u', 'crane_a14', 'tls-required'],
    ['crane_a14_u', 'crane_a14', 'client-certificate'],
    ['crane_a7_u', 'crane_a14', 'database-denied'],
  ], 'successful connections and connection-limit refusals are not auth failures');
});

test('mariadb: access denied (with and without a database), readiness probe ignored', () => {
  const text = [
    `${at(1)} 2026-10-12 12:00:01 5 [Warning] Access denied for user 'crane_a7_u'@'172.17.0.1' (using password: YES)`,
    `${at(2)} 2026-10-12 12:00:02 6 [Warning] Access denied for user 'crane_a7_u'@'%' to database 'crane_a14'`,
    `${at(3)} 2026-10-12 12:00:03 7 [Warning] Access denied for user 'appcrane_readiness_probe'@'localhost' (using password: NO)`,
  ].join('\n');
  assert.deepEqual(alerts.parseAuthFailures('mariadb', text).map((f) => [f.login, f.database, f.reason]), [
    ['crane_a7_u', null, 'access-denied'],
    ['crane_a7_u', 'crane_a14', 'database-denied'],
  ]);
});

test('mongo: the 8.0 "Failed to authenticate" event', () => {
  const ev = { t: { $date: '2026-10-12T12:00:01.000+00:00' }, s: 'I', c: 'ACCESS', id: 5286307, ctx: 'conn113', msg: 'Failed to authenticate',
    attr: { client: '172.17.0.1:59266', mechanism: 'SCRAM-SHA-256', user: 'crane_a7_u', db: 'crane_a14', error: 'AuthenticationFailed: SCRAM authentication failed, storedKey mismatch' } };
  assert.deepEqual(alerts.parseAuthFailures('mongo', `${at(1)} ${JSON.stringify(ev)}`).map((f) => [f.login, f.database, f.reason]),
    [['crane_a7_u', 'crane_a14', 'bad-password']]);
});

test('attacker-controlled names are clamped to a safe alphabet', () => {
  const [f] = alerts.parseAuthFailures('mariadb', `${at(1)} x [Warning] Access denied for user '<script>x</script>'@'h' (using password: YES)`);
  assert.equal(f.login, '?script?x?/script?'.replace('/', '?'));
});

test('THRESHOLD: 5 failures in 10 minutes do not alert, the 6th does — audit row + one mail per admin', () => {
  const db = getDb();
  const mails = [];
  const sendMail = (m) => mails.push(m);
  alerts.recordFailures(db, 'postgres', alerts.parseAuthFailures('postgres', pgLines(5)));
  assert.deepEqual(alerts.evaluateAlerts(db, { now: new Date(T0.getTime() + 60e3), sendMail }), []);
  assert.equal(mails.length, 0);

  alerts.recordFailures(db, 'postgres', alerts.parseAuthFailures('postgres', pgLines(1, { startS: 30 })));
  const raised = alerts.evaluateAlerts(db, { now: new Date(T0.getTime() + 60e3), sendMail });
  assert.equal(raised.length, 1);
  assert.equal(raised[0].failures, 6);
  assert.equal(raised[0].login_app, 'seven');
  assert.deepEqual(raised[0].databases, [{ database: 'crane_a14', app: 'supply' }]);
  assert.equal(raised[0].cross_app, true, 'app 7\'s login against app 14\'s database is flagged as cross-app');

  const row = db.prepare("SELECT app_id, detail FROM audit_log WHERE action = 'managed-db-auth-alert'").get();
  assert.ok(row, 'an audit_log row');
  assert.equal(row.app_id, APP_7, 'attributed to the app the login belongs to');
  assert.equal(mails.length, 1);
  assert.equal(mails[0].to, 'admin@example.test');
  assert.match(mails[0].subject, /Repeated failed postgres logins for crane_a7_u/);
  assert.match(mails[0].text, /does not own/);
});

test('failures outside the 10-minute window do not count', () => {
  const db = getDb();
  alerts.recordFailures(db, 'postgres', alerts.parseAuthFailures('postgres', pgLines(6, { startS: 0 })));
  const raised = alerts.evaluateAlerts(db, { now: new Date(T0.getTime() + 11 * 60e3), sendMail: () => {} });
  assert.deepEqual(raised, []);
});

test('RATE LIMIT: at most one alert per login per hour, then again after the hour', () => {
  const db = getDb();
  const mails = [];
  const sendMail = (m) => mails.push(m);
  alerts.recordFailures(db, 'postgres', alerts.parseAuthFailures('postgres', pgLines(8)));
  assert.equal(alerts.evaluateAlerts(db, { now: new Date(T0.getTime() + 60e3), sendMail }).length, 1);
  alerts.recordFailures(db, 'postgres', alerts.parseAuthFailures('postgres', pgLines(8, { startS: 300 })));
  assert.equal(alerts.evaluateAlerts(db, { now: new Date(T0.getTime() + 6 * 60e3), sendMail }).length, 0, 'still inside the hour');
  alerts.recordFailures(db, 'postgres', alerts.parseAuthFailures('postgres', pgLines(8, { startS: 3700 })));
  assert.equal(alerts.evaluateAlerts(db, { now: new Date(T0.getTime() + 3710e3), sendMail }).length, 1, 'a new hour, a new alert');
  assert.equal(mails.length, 2);
});

test('the threshold is the platform setting', () => {
  const db = getDb();
  setManagedDbSettings(db, { auth_alert_threshold: 10 });
  try {
    alerts.recordFailures(db, 'postgres', alerts.parseAuthFailures('postgres', pgLines(8)));
    assert.equal(alerts.evaluateAlerts(db, { now: new Date(T0.getTime() + 60e3), sendMail: () => {} }).length, 0);
  } finally {
    setManagedDbSettings(db, { auth_alert_threshold: 5 });
  }
});

test('NO PASSWORD anywhere: not in stored failures, the audit row or the e-mail', () => {
  const db = getDb();
  const secret = 'Sup3rS3cretPassw0rd';
  // A hostile line carrying a password-shaped value in the message text. No
  // engine logs the password; this proves that even if one did, only the
  // regex-extracted fields survive.
  const lines = Array.from({ length: 7 }, (_, i) =>
    `${at(i)} 2026-10-12 12:00:0${i}.1 UTC [${i}] user=crane_a7_u db=crane_a14 FATAL:  password authentication failed for user "crane_a7_u" password=${secret}`).join('\n');
  alerts.recordFailures(db, 'postgres', alerts.parseAuthFailures('postgres', lines));
  const mails = [];
  alerts.evaluateAlerts(db, { now: new Date(T0.getTime() + 60e3), sendMail: (m) => mails.push(m) });
  const stored = JSON.stringify(db.prepare('SELECT * FROM managed_db_auth_failures').all());
  const audit = JSON.stringify(db.prepare("SELECT * FROM audit_log WHERE action = 'managed-db-auth-alert'").all());
  assert.ok(audit.length > 2 && mails.length === 1, 'the alert fired, so there is something to inspect');
  for (const [where, s] of [['failures table', stored], ['audit_log', audit], ['email', JSON.stringify(mails)]]) {
    assert.ok(!s.includes(secret), `the password reached ${where}`);
  }
});

test('scanOnce reads each server with docker logs --timestamps --since, and does not double-count an overlap', async () => {
  const db = getDb();
  db.prepare("INSERT OR IGNORE INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc) VALUES ('postgres', 'x-pg', 'img', 1, 'x')").run();
  alerts.__resetCursorsForTests();
  const calls = [];
  const exec = async (cmd, args) => { calls.push([cmd, ...args]); return { stdout: '', stderr: pgLines(4, { startS: 0 }) }; };
  const now = new Date(T0.getTime() + 120e3);
  await alerts.scanOnce({ db, now, exec });
  await alerts.scanOnce({ db, now, exec }); // the same lines again
  assert.equal(db.prepare('SELECT COUNT(*) n FROM managed_db_auth_failures').get().n, 4);
  assert.deepEqual(calls[0].slice(0, 4), ['docker', 'logs', '--timestamps', '--since']);
  assert.equal(calls[0].at(-1), 'x-pg');
});
