import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Every managed login under TLS + its own client certificate, without a
// daemon: the strict pg_hba builder, passwordOnlyLogins(), syncPgHba() with
// its engine calls recorded, the admin conversion (requireCertificate and its
// routes), the Job Health check, and the deployer for a catalogue login and
// for an app that declares no database. What Postgres then does with these
// files is test/managed-db-strict-real.test.js.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mdbstrict-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const tls = await import('../server/services/managedDbTls.js');
const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const po = await import('../server/services/managedDbPasswordOnly.js');
const deployer = await import('../server/services/deployer.js');
const certs = await import('../server/services/dbCerts.js');
const { encrypt, generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { SANDBOX_TENANT } = await import('../server/services/sandboxDb.js');
const jobHealth = await import('../server/services/jobHealth.js');

let A; let B; let CAT; let IMG;
before(() => {
  initDb(process.env.DATA_DIR);
  const ins = getDb().prepare('INSERT INTO apps (name, slug, slot, catalog_slug) VALUES (?, ?, ?, ?)');
  A = Number(ins.run('A', 'strict-a', 1, null).lastInsertRowid);
  B = Number(ins.run('B', 'strict-b', 2, null).lastInsertRowid);
  CAT = Number(ins.run('Cat', 'strict-cat', 3, 'metabase').lastInsertRowid);
  IMG = Number(ins.run('Img', 'strict-img', 4, null).lastInsertRowid);
  getDb().prepare(`INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc)
    VALUES ('postgres', 'x-postgres', 'img', 45432, ?)`).run(encrypt('a'.repeat(32)));
});
after(() => {
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

function seedRow(appId, tenant, engine, { cert = 0, appLogin = null } = {}) {
  const { database, username } = mdb.namesForScope({ appId, tenant });
  const r = getDb().prepare(`INSERT INTO managed_databases
      (app_id, tenant, engine, db_name, db_user, password_enc, client_cert_required, app_user, app_password_enc)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    appId, tenant || '', engine, database, username, encrypt('p'.repeat(32)), cert,
    appLogin ? `${username}_app` : null, appLogin === 'enabled' ? encrypt('q'.repeat(32)) : null,
  );
  return { id: Number(r.lastInsertRowid), database, username };
}
const clear = () => getDb().prepare('DELETE FROM managed_databases').run();

/** syncPgHba's engine calls, recorded. `roles` is what the engine reports. */
function pgOps({ state = 'running', roles = '', hbaErrors = '' } = {}) {
  const calls = [];
  return {
    calls,
    ops: {
      containerState: async () => state,
      exec: async (args) => { calls.push(['exec', args.join(' '), hbaOnDisk()]); return ''; },
      runAdminSql: async (_engine, sql) => {
        calls.push(['sql', sql]);
        if (/pg_has_role/.test(sql)) return roles;
        if (/pg_hba_file_rules/.test(sql)) return hbaErrors;
        return '';
      },
    },
  };
}
const reloads = (calls) => calls.filter((c) => c[0] === 'sql' && /pg_reload_conf/.test(c[1])).length;
const hbaOnDisk = () => certs.readServerFile('postgres', 'pg_hba.conf');

/** Engine calls of secureLogin/requireCertificate, recorded; syncPgHba goes through `sync`. */
function loginOps(sync) {
  const calls = [];
  return {
    calls,
    ops: {
      ensureServer: async (e) => { calls.push(['ensureServer', e]); },
      runAdminSql: async (e, sql) => { calls.push(['sql', e, sql]); },
      runAdminMongo: async (s) => { calls.push(['mongo', s]); },
      ensureRedisInstance: async (o) => { calls.push(['redis', o]); },
      ...(sync ? { syncPgHba: sync } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// pg_hba
// ---------------------------------------------------------------------------

test('pg_hba strict: only the last line changes, to reject; local trust and the cert-group lines stay', () => {
  const lines = (o) => tls.pgHbaConf(o).split('\n').filter((l) => l && !l.startsWith('#')).map((l) => l.split(/\s+/));
  const loose = lines();
  const strict = lines({ strict: true });
  assert.deepEqual(loose[3], ['host', 'all', 'all', 'all', 'scram-sha-256']);
  assert.deepEqual(strict[3], ['host', 'all', 'all', 'all', 'reject']);
  assert.deepEqual(strict.slice(0, 3), loose.slice(0, 3));
  assert.deepEqual(strict[0], ['local', 'all', 'all', 'trust'], "AppCrane's own docker exec admin path keeps working");
  assert.equal(strict.length, 4);
  assert.equal(tls.isStrictPgHba(tls.pgHbaConf({ strict: true })), true);
  assert.equal(tls.isStrictPgHba(tls.pgHbaConf()), false);
  assert.equal(tls.isStrictPgHba(null), false);
});

test('the engine-side query lists login roles outside the cert group, superuser aside, one per line', () => {
  const sql = tls.pgPasswordOnlyRolesSql();
  assert.match(sql, /^COPY \(SELECT rolname FROM pg_roles/);
  assert.match(sql, /rolcanlogin AND NOT rolsuper/);
  assert.match(sql, new RegExp(`NOT pg_has_role\\(r\\.oid, '${tls.PG_CERT_GROUP}', 'MEMBER'\\)`));
  assert.match(sql, /TO STDOUT;$/);
});

// ---------------------------------------------------------------------------
// passwordOnlyLogins
// ---------------------------------------------------------------------------

test('passwordOnlyLogins: every engine, owner and enabled _app logins, sandbox scopes; certificate logins and disabled _app logins left out', () => {
  clear();
  seedRow(A, null, 'postgres', { cert: 1, appLogin: 'enabled' });
  seedRow(A, SANDBOX_TENANT, 'postgres', { cert: 0 });
  seedRow(B, null, 'mariadb', { cert: 0, appLogin: 'enabled' });
  seedRow(B, SANDBOX_TENANT, 'mariadb', { cert: 0, appLogin: 'disabled' });
  seedRow(CAT, null, 'mongo', { cert: 0 });
  seedRow(CAT, null, 'redis', { cert: 0 });
  seedRow(IMG, null, 'mongo', { cert: 1 });
  const got = po.passwordOnlyLogins().map((l) => `${l.app_slug}|${l.env}|${l.engine}|${l.kind}|${l.login}`).sort();
  const n = (id, t) => mdb.namesForScope({ appId: id, tenant: t }).username;
  assert.deepEqual(got, [
    `strict-a|sandbox|postgres|owner|${n(A, SANDBOX_TENANT)}`,
    `strict-b|production|mariadb|app|${n(B)}_app`,
    `strict-b|production|mariadb|owner|${n(B)}`,
    `strict-b|sandbox|mariadb|owner|${n(B, SANDBOX_TENANT)}`,
    `strict-cat|production|mongo|owner|${n(CAT)}`,
    `strict-cat|production|redis|owner|${n(CAT)}`,
  ].sort());
  assert.deepEqual(po.passwordOnlyLogins({ engine: 'postgres' }).map((l) => l.login), [n(A, SANDBOX_TENANT)]);
  const one = po.passwordOnlyLogins({ engine: 'postgres' })[0];
  assert.ok(Number.isInteger(one.database_id) && one.app_id === A && one.convert_note);
  assert.ok(!JSON.stringify(po.passwordOnlyLogins()).includes('p'.repeat(32)), 'no password in the list');
});

// ---------------------------------------------------------------------------
// syncPgHba
// ---------------------------------------------------------------------------

test('syncPgHba: strict only when NO postgres login is password-only, flips back when one appears, reloads without a restart', async () => {
  clear();
  const one = seedRow(A, null, 'postgres', { cert: 0 });
  const two = seedRow(B, null, 'postgres', { cert: 0 });
  seedRow(CAT, null, 'mariadb', { cert: 0 });

  let r = pgOps();
  let out = await mdb.syncPgHba({ ops: r.ops });
  assert.equal(out.strict, false);
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), false);

  // Converting one of two: still not strict, nothing rewritten.
  getDb().prepare('UPDATE managed_databases SET client_cert_required = 1 WHERE id = ?').run(one.id);
  r = pgOps();
  out = await mdb.syncPgHba({ ops: r.ops });
  assert.equal(out.strict, false);
  assert.equal(out.changed, false);
  assert.equal(reloads(r.calls), 0);

  // The last one: strict, copied into the container, checked, reloaded.
  getDb().prepare('UPDATE managed_databases SET client_cert_required = 1 WHERE id = ?').run(two.id);
  r = pgOps();
  out = await mdb.syncPgHba({ ops: r.ops });
  assert.equal(out.strict, true, 'a password-only MariaDB login does not keep Postgres loose');
  assert.equal(out.changed, true);
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), true);
  const execs = r.calls.filter((c) => c[0] === 'exec').map((c) => c[1]);
  assert.equal(execs.length, 1);
  assert.match(execs[0], /^exec \S+ sh -c /);
  assert.ok(execs[0].endsWith(`sh -c ${tls.installSnippet('postgres')}`), 'the file is re-copied into the running container');
  assert.ok(!r.calls.some((c) => c[0] === 'exec' && /\b(restart|rm|run|stop)\b/.test(c[1].split(' ')[0])), 'never a restart');
  const order = r.calls.map((c) => (c[0] === 'exec' ? 'copy' : /pg_hba_file_rules/.test(c[1]) ? 'check' : /pg_reload_conf/.test(c[1]) ? 'reload' : 'roles'));
  assert.deepEqual(order, ['roles', 'copy', 'check', 'reload']);

  // Idempotent.
  r = pgOps();
  out = await mdb.syncPgHba({ ops: r.ops });
  assert.equal(out.changed, false);
  assert.equal(reloads(r.calls), 0);

  // A new password-only login: back to scram-sha-256, reloaded.
  seedRow(IMG, null, 'postgres', { cert: 0 });
  r = pgOps();
  out = await mdb.syncPgHba({ ops: r.ops });
  assert.equal(out.strict, false);
  assert.equal(out.changed, true);
  assert.equal(reloads(r.calls), 1);
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), false);
});

test('syncPgHba: a login role the ENGINE has outside the cert group keeps the server loose', async () => {
  clear();
  seedRow(A, null, 'postgres', { cert: 1 });
  const r = pgOps({ roles: 'crane_a1_u\n' });
  const out = await mdb.syncPgHba({ ops: r.ops });
  assert.equal(out.strict, false);
  assert.deepEqual(out.engineRoles, ['crane_a1_u']);
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), false);
});

test('syncPgHba: an unparsable file is not reloaded and the old file is put back; a stopped server is left alone', async () => {
  clear();
  seedRow(A, null, 'postgres', { cert: 1 });
  const before = hbaOnDisk();
  const bad = pgOps({ hbaErrors: '5: invalid authentication method' });
  await assert.rejects(mdb.syncPgHba({ ops: bad.ops }), /does not parse/);
  assert.equal(reloads(bad.calls), 0);
  assert.equal(hbaOnDisk(), before);
  // The container's private copy is put back too: the last copy made carries the old file.
  const copies = bad.calls.filter((c) => c[0] === 'exec');
  assert.equal(copies.length, 2, 'copied in, then the old file copied back');
  assert.notEqual(copies[0][2], before);
  assert.equal(copies[1][2], before);

  const stopped = pgOps({ state: 'exited' });
  const out = await mdb.syncPgHba({ ops: stopped.ops });
  assert.equal(out.running, false);
  assert.deepEqual(stopped.calls, []);
  assert.equal(hbaOnDisk(), before);
});

// ---------------------------------------------------------------------------
// requireCertificate (the admin action) and secureLogin's re-evaluation
// ---------------------------------------------------------------------------

test('requireCertificate: converts the owner AND its enabled _app login, marks the row, re-evaluates strict; strict flips only on the last', async () => {
  clear();
  const cat = seedRow(CAT, null, 'postgres', { cert: 0 });
  const img = seedRow(IMG, null, 'postgres', { cert: 0, appLogin: 'enabled' });
  const syncs = [];
  const sync = async () => { const r = pgOps(); const o = await mdb.syncPgHba({ ops: r.ops }); syncs.push(o.strict); return o; };
  await sync();
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), false);

  const first = loginOps(sync);
  const res1 = await mdb.requireCertificate(cat.id, { ops: first.ops });
  assert.deepEqual(res1, { converted: true, engine: 'postgres', app_id: CAT, logins: [cat.username], redeploy_required: true });
  assert.equal(getDb().prepare('SELECT client_cert_required FROM managed_databases WHERE id = ?').get(cat.id).client_cert_required, 1);
  assert.match(first.calls.map((c) => c[2] || '').join('\n'), new RegExp(`GRANT ${tls.PG_CERT_GROUP} TO "${cat.username}";`));
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), false, 'another password-only login remains');

  const second = loginOps(sync);
  const res2 = await mdb.requireCertificate(img.id, { ops: second.ops });
  assert.deepEqual(res2.logins, [img.username, `${img.username}_app`]);
  const sql = second.calls.map((c) => c[2] || '').join('\n');
  assert.match(sql, new RegExp(`GRANT ${tls.PG_CERT_GROUP} TO "${img.username}";`));
  assert.match(sql, new RegExp(`GRANT ${tls.PG_CERT_GROUP} TO "${img.username}_app";`), 'the _app login gets the requirement at once');
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), true, 'the last conversion makes pg_hba strict');
  assert.equal(po.passwordOnlyLogins({ engine: 'postgres' }).length, 0);

  // Again: nothing new, still strict.
  const again = await mdb.requireCertificate(img.id, { ops: loginOps(sync).ops });
  assert.equal(again.converted, false);
  assert.equal(await mdb.requireCertificate(999999, { ops: loginOps(sync).ops }), null);
});

test('requireCertificate on MariaDB: REQUIRE SUBJECT for the owner and the _app login, each its own CN', async () => {
  clear();
  const m = seedRow(B, null, 'mariadb', { cert: 0, appLogin: 'enabled' });
  const r = loginOps();
  await mdb.requireCertificate(m.id, { ops: r.ops });
  const sql = r.calls.filter((c) => c[0] === 'sql').map((c) => c[2]).join('\n');
  assert.match(sql, new RegExp(`ALTER USER '${m.username}'@'%' REQUIRE SUBJECT '/CN=${m.username}' AND ISSUER`));
  assert.match(sql, new RegExp(`ALTER USER '${m.username}_app'@'%' REQUIRE SUBJECT '/CN=${m.username}_app' AND ISSUER`));
});

// ---------------------------------------------------------------------------
// Job Health
// ---------------------------------------------------------------------------

test("Job Health 'managed-db-logins': warning listing the logins, ok when none", async () => {
  jobHealth._resetJobHealthForTests();
  jobHealth.jobStarted(po.JOB_ID);
  clear();
  seedRow(CAT, null, 'postgres', { cert: 0 });
  const sync = async () => ({ strict: false, engineRoles: ['handmade'] });
  const warn = await jobHealth.trackJob(po.JOB_ID, () => po.runManagedDbLoginsCheck({ sync }));
  assert.equal(warn.severity, 'warning');
  assert.match(warn.message, /2 managed database login\(s\)/);
  assert.match(warn.message, /strict-cat production postgres crane_a\d+_u/);
  assert.match(warn.message, /postgres role handmade/);
  let job = jobHealth.getJobHealth().find((j) => j.id === po.JOB_ID);
  assert.equal(job.status, 'warning');

  clear();
  const ok = await jobHealth.trackJob(po.JOB_ID, () => po.runManagedDbLoginsCheck({ sync: async () => ({ strict: true, engineRoles: [] }) }));
  assert.equal(ok.severity, undefined);
  assert.match(ok.message, /strict pg_hba/);
  job = jobHealth.getJobHealth().find((j) => j.id === po.JOB_ID);
  assert.equal(job.status, 'ok');
  jobHealth._resetJobHealthForTests();
});

// ---------------------------------------------------------------------------
// Deployer
// ---------------------------------------------------------------------------

test('catalogue login made certificate-required: deploy mounts the cert and injects the TLS URL; a failed cert step fails the deploy', async () => {
  clear();
  seedRow(CAT, null, 'postgres', { cert: 1 });
  const app = getDb().prepare('SELECT * FROM apps WHERE id = ?').get(CAT);
  const mount = { host: '/h', container: certs.CLIENT_MOUNT_PATH, readOnly: true };
  const calls = [];
  const env = {};
  const out = await deployer.injectManagedDbForEnv({
    app, env: 'production', runtimeEnvVars: env,
    secureLogin: async (scope, engine, o) => { calls.push(o.certRequired); return { applied: true, certRequired: true, mounts: [mount], tls: { required: true } }; },
  });
  assert.deepEqual(calls, [false], 'never forced by the deployer for a catalogue login');
  assert.deepEqual(out.mounts, [mount]);
  assert.match(env.MB_DB_CONNECTION_URI, /sslmode=verify-full&sslrootcert=/);
  assert.equal(env.DB_CERT_FILE, `${certs.CLIENT_MOUNT_PATH}/client.crt`);

  await assert.rejects(deployer.injectManagedDbForEnv({
    app, env: 'production', runtimeEnvVars: {},
    secureLogin: async () => { throw new Error('server down'); },
  }), /Securing the managed postgres database login failed: server down/);

  // Still best-effort for a catalogue login that is password-only.
  getDb().prepare('UPDATE managed_databases SET client_cert_required = 0').run();
  const lines = [];
  await deployer.injectManagedDbForEnv({
    app, env: 'production', runtimeEnvVars: {}, appendLog: (l) => lines.push(l),
    secureLogin: async () => { throw new Error('server down'); },
  });
  assert.ok(lines.some((l) => /could not apply the per-login limits/.test(l)));
});

test('an app that declares no database, row certificate-required: never secureLogin; mounted + DB_*_FILE only when the engine enforces it; warnings + card entries otherwise', async () => {
  clear();
  const row = seedRow(IMG, null, 'postgres', { cert: 1 });
  const app = getDb().prepare('SELECT * FROM apps WHERE id = ?').get(IMG);
  const mount = { host: '/h', container: certs.CLIENT_MOUNT_PATH, readOnly: true };
  const files = certs.clientFilePaths('');
  const noSecureLogin = async () => { throw new Error('secureLogin must not run for an undeclared app'); };
  const enforced = async () => ({ required: true, enforced: true, mounts: [mount], tls: { required: true, x509: false, ...files } });
  const run = (runtimeEnvVars, certMountIfEnforced, lines = []) => deployer.injectManagedDbForEnv({
    app, env: 'production', runtimeEnvVars, appendLog: (l) => lines.push(l), secureLogin: noSecureLogin, certMountIfEnforced,
  });

  // 1. Enforced, and the app's own URL points at the mounted files: mounted, no problem.
  const url = `postgresql://u:p@h:1/d?sslmode=verify-full&sslrootcert=${files.ca}&sslcert=${files.cert}&sslkey=${files.key}`;
  const env = { DATABASE_URL: url, DB_CA_FILE: '/mine' };
  let lines = [];
  const out = await run(env, enforced, lines);
  assert.deepEqual(out.mounts, [mount]);
  assert.equal(env.DATABASE_URL, url, 'the app\'s own URL is not touched');
  assert.equal(env.DB_CA_FILE, '/mine', 'a variable the app set wins');
  assert.equal(env.DB_CERT_FILE, files.cert);
  assert.ok(lines.some((l) => l.includes('sslmode=verify-full') && l.includes(files.key)));
  assert.ok(!lines.some((l) => /^WARNING/.test(l)));
  assert.deepEqual(po.certProblems(), []);

  // 2. Enforced, but the app's URL sends no certificate: still mounted, a warning, listed on the card.
  lines = [];
  const plain = { DATABASE_URL: 'postgresql://u:p@h:1/d' };
  const out2 = await run(plain, enforced, lines);
  assert.deepEqual(out2.mounts, [mount]);
  assert.ok(lines.some((l) => /^WARNING: .*certificate required but the app is not configured to send it/.test(l)), lines.join('\n'));
  assert.deepEqual(po.certProblems().map((p) => [p.database_id, p.problem, p.label, p.env]),
    [[row.id, 'not_sent', 'certificate required but the app is not configured to send it', 'production']]);

  // 3. The row says certificate, the engine does not enforce it: nothing mounted, nothing injected, a warning, listed.
  lines = [];
  const loose = { DATABASE_URL: 'postgresql://u:p@h:1/d' };
  const out3 = await run(loose, async () => ({ required: true, enforced: false, mounts: [], tls: null }), lines);
  assert.deepEqual(out3.mounts, []);
  assert.equal(loose.DB_CERT_FILE, undefined);
  assert.ok(lines.some((l) => /^WARNING: .*does not enforce it.*left the login unchanged/.test(l)), lines.join('\n'));
  assert.deepEqual(po.certProblems().map((p) => p.problem), ['not_enforced']);

  // Fixed on the next deploy: the entry goes.
  await run({ DATABASE_URL: url }, enforced);
  assert.deepEqual(po.certProblems(), []);

  // 4. The check itself failing fails the deploy (before the container is touched).
  await assert.rejects(run({}, async () => { throw new Error('down'); }),
    /Checking the managed postgres database login's certificate requirement failed: down/);

  // 5. Password-only row: nothing called.
  getDb().prepare('UPDATE managed_databases SET client_cert_required = 0').run();
  let called = false;
  const none = await run({}, async () => { called = true; return {}; });
  assert.deepEqual(none.mounts, []);
  assert.equal(called, false);
});

test('certMountIfEnforced: read only (no GRANT/ALTER/REQUIRE, no Redis ensure); files only when the engine enforces the certificate', async () => {
  clear();
  const pg = seedRow(A, null, 'postgres', { cert: 1 });
  const my = seedRow(A, null, 'mariadb', { cert: 1 });
  const mg = seedRow(A, null, 'mongo', { cert: 1 });
  getDb().prepare(`INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc)
    VALUES ('mongo', 'x-mongo', 'img', 47017, ?) ON CONFLICT DO NOTHING`).run(encrypt('m'.repeat(32)));
  const rd = seedRow(B, null, 'redis', { cert: 1 });
  getDb().prepare('UPDATE managed_databases SET container_name = ? WHERE id = ?').run('x-redis-b', rd.id);
  const scopeA = { appId: A };
  const calls = [];
  const ops = (answers) => ({
    ensureServer: async (e) => { calls.push(['ensureServer', e]); },
    runAdminSql: async (e, sql) => { calls.push(['sql', e, sql]); return answers[e]; },
    runAdminMongo: async (sc) => { calls.push(['mongo', sc]); return answers.mongo; },
    containerFacts: async (n) => { calls.push(['facts', n]); return answers.redis; },
  });
  const files = (u) => join(process.env.DATA_DIR, 'managed-db', '_tls', 'client', u, 'client.crt');
  const opts = (answers) => ({ resolveOwner: async () => null, ops: ops(answers) });

  // Not enforced anywhere: nothing written, nothing mounted.
  const off = { postgres: 'f\n', mariadb: 'CONCAT(...)\nCERT::\n', mongo: 'MONGO_CERT_NOT_ENFORCED\n', redis: { state: 'running', owner: 'redis', config: '' } };
  for (const e of ['postgres', 'mariadb', 'mongo']) {
    const r = await mdb.certMountIfEnforced(scopeA, e, opts(off));
    assert.equal(r.required, true);
    assert.equal(r.enforced, false, e);
    assert.deepEqual(r.mounts, []);
  }
  const rOff = await mdb.certMountIfEnforced({ appId: B }, 'redis', opts(off));
  assert.equal(rOff.enforced, false);
  assert.equal(existsSync(files(pg.username)), false, 'no certificate written while the engine does not enforce it');

  // Enforced: mounted, TLS paths, still nothing that changes a login.
  const on = { postgres: 't\n', mariadb: `CONCAT(...)\nCERT:SPECIFIED:/CN=${my.username}\n`, mongo: 'MONGO_CERT_ENFORCED\n', redis: { state: 'running', owner: 'redis', config: (await import('../server/services/managedRedis.js')).REDIS_TLS_CONFIG_VERSION } };
  for (const e of ['postgres', 'mariadb', 'mongo']) {
    const r = await mdb.certMountIfEnforced(scopeA, e, opts(on));
    assert.equal(r.enforced, true, e);
    assert.deepEqual(r.mounts.map((m) => m.container), [certs.CLIENT_MOUNT_PATH]);
    assert.equal(r.tls.cert, certs.clientFilePaths('').cert);
  }
  assert.equal((await mdb.certMountIfEnforced({ appId: B }, 'redis', opts(on))).enforced, true);
  assert.ok(existsSync(files(pg.username)));

  const sql = calls.filter((c) => c[0] === 'sql').map((c) => c[2]).join('\n');
  assert.match(sql, /pg_has_role/);
  assert.match(sql, /FROM mysql\.user/);
  assert.doesNotMatch(sql, /\b(GRANT|ALTER|REVOKE|CREATE|DROP)\b/, 'read only');
  assert.ok(!calls.some((c) => c[0] === 'mongo' && /createUser|dropUser/.test(c[1])), 'mongo: read only');
  assert.ok(calls.filter((c) => c[0] === 'facts').every((c) => c[1] === 'x-redis-b'));

  // A password-only row: not required, no engine call.
  getDb().prepare('UPDATE managed_databases SET client_cert_required = 0 WHERE id = ?').run(pg.id);
  calls.length = 0;
  assert.equal((await mdb.certMountIfEnforced(scopeA, 'postgres', opts(on))).required, false);
  assert.deepEqual(calls, []);
});

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

test('routes: platform admin only; list from SQLite; conversion through the engine with a redeploy note; 404 for an unknown id', async () => {
  clear();
  const cat = seedRow(CAT, null, 'postgres', { cert: 0 });
  const mkUser = (role) => {
    const key = generateApiKey('dhk_user');
    getDb().prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
      .run(`u-${role}-${Math.random()}`, `${role}${Math.random()}@t.test`, role, hashApiKey(key), 'human');
    return key;
  };
  const PLATFORM = mkUser('platform_admin');
  const USER = mkUser('user');
  getDb().prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) SELECT ?, id, ? FROM users WHERE api_key_hash = ?')
    .run(CAT, 'owner', hashApiKey(USER));

  const routes = await import('../server/routes/managedDb.js');
  const { errorHandler } = await import('../server/utils/errors.js');
  const engineCalls = [];
  routes.__setEngineForTests({ requireCertificate: async (id) => { engineCalls.push(id); return id === cat.id ? { converted: true, engine: 'postgres', app_id: CAT, logins: [cat.username], redeploy_required: true } : null; } });
  const api = express();
  api.use(express.json());
  api.use('/api/managed-db', routes.serversRouter);
  api.use(errorHandler);
  const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}/api/managed-db`;
  const call = (method, path, key, body = { confirm: true }, auth = 'key') => fetch(base + path, {
    method,
    headers: key ? { ...(auth === 'key' ? { 'X-API-Key': key } : { Authorization: `Bearer ${key}` }), 'Content-Type': 'application/json' } : {},
    body: method === 'POST' ? JSON.stringify(body) : undefined,
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
  const adminId = getDb().prepare('SELECT id FROM users WHERE api_key_hash = ?').get(hashApiKey(PLATFORM)).id;
  const session = (ageMin) => {
    const token = generateApiKey('sess');
    getDb().prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(adminId, hashApiKey(token));
    getDb().prepare(`UPDATE identity_sessions SET created_at = datetime('now', '-${ageMin} minutes') WHERE token_hash = ?`).run(hashApiKey(token));
    return token;
  };
  try {
    assert.equal((await call('GET', '/logins/password-only', null)).status, 401);
    assert.equal((await call('GET', '/logins/password-only', USER)).status, 403, 'even the app owner');
    assert.equal((await call('POST', `/logins/${cat.id}/require-certificate`, USER)).status, 403);
    assert.deepEqual(engineCalls, []);

    const list = await call('GET', '/logins/password-only', PLATFORM);
    assert.equal(list.status, 200);
    assert.deepEqual(list.body.logins.map((l) => l.login), [cat.username]);
    assert.ok(!JSON.stringify(list.body).includes('p'.repeat(32)));

    // No explicit confirm: refused before the engine is touched.
    for (const body of [{}, { confirm: 'true' }, { confirm: 1 }]) {
      const r = await call('POST', `/logins/${cat.id}/require-certificate`, PLATFORM, body);
      assert.equal(r.status, 400, JSON.stringify(body));
      assert.equal(r.body?.error?.code, 'CONFIRMATION_REQUIRED');
    }
    // A dashboard session signed in outside the step-up window: refused until it steps up.
    const stale = await call('POST', `/logins/${cat.id}/require-certificate`, session(30), { confirm: true }, 'session');
    assert.equal(stale.status, 401, JSON.stringify(stale.body));
    assert.equal(stale.body?.error?.code, 'STEP_UP_REQUIRED');
    assert.deepEqual(engineCalls, []);
    const fresh = await call('POST', `/logins/${cat.id}/require-certificate`, session(0), { confirm: true }, 'session');
    assert.equal(fresh.status, 200, JSON.stringify(fresh.body));
    engineCalls.length = 0;

    const conv = await call('POST', `/logins/${cat.id}/require-certificate`, PLATFORM);
    assert.equal(conv.status, 200);
    assert.equal(conv.body.app_slug, 'strict-cat');
    assert.match(conv.body.note, /Redeploy or restart strict-cat/);
    const audit = getDb().prepare("SELECT app_id, detail FROM audit_log WHERE action = 'managed-db-require-certificate'").get();
    assert.equal(audit.app_id, CAT);

    assert.equal((await call('POST', '/logins/424242/require-certificate', PLATFORM)).status, 404);
    assert.equal((await call('POST', '/logins/abc/require-certificate', PLATFORM)).status, 404);
  } finally {
    routes.__setEngineForTests(null);
    server.closeAllConnections?.();
    server.close();
  }
  assert.equal(typeof mdb.requireCertificate, 'function', 'the real engine exports what the route calls');
});

test('provision of a new login and secureLogin re-evaluate pg_hba (hooks present)', async () => {
  clear();
  const row = seedRow(A, null, 'postgres', { cert: 0 });
  const sync = async () => { const r = pgOps(); return mdb.syncPgHba({ ops: r.ops }); };
  await sync();
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), false);
  await mdb.secureLogin({ appId: A }, 'postgres', { certRequired: true, resolveOwner: async () => null, ops: loginOps(sync).ops });
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), true, 'secureLogin converting the last login makes it strict');
  assert.ok(existsSync(join(process.env.DATA_DIR, 'managed-db', '_tls', 'client', row.username, 'client.crt')));
  assert.ok(readFileSync(join(process.env.DATA_DIR, 'managed-db', '_tls', 'server', 'postgres', 'pg_hba.conf'), 'utf8').includes('reject'));
});

test('provision while strict: pg_hba is loosened BEFORE CREATE ROLE, a failed loosen fails the provision, a failed CREATE re-tightens', async () => {
  clear();
  seedRow(A, null, 'postgres', { cert: 1 });
  await mdb.syncPgHba({ ops: pgOps().ops });
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), true, 'precondition: strict');

  const order = [];
  const mk = ({ hbaErrors = '', createFails = false } = {}) => ({
    ensureServer: async () => ({ port: 45432 }),
    createInEngine: async (_e, _db, user) => {
      order.push(['create', tls.isStrictPgHba(hbaOnDisk())]);
      if (createFails) throw new Error('boom');
      return user;
    },
    dropInEngine: async () => {},
    syncPgHba: (o = {}) => { order.push(['sync', o.loosen ? 'loosen' : 'decide']); return mdb.syncPgHba({ ...o, ops: pgOps({ hbaErrors }).ops }); },
  });

  // A failed loosen: refused, no role created, no row left, still strict.
  order.length = 0;
  await assert.rejects(mdb.provision({ appId: CAT }, 'postgres', { ops: mk({ hbaErrors: '5: bad' }) }),
    /provisioning postgres database refused: pg_hba\.conf could not fall back/);
  assert.ok(!order.some((c) => c[0] === 'create'), 'no CREATE ROLE');
  assert.equal(getDb().prepare('SELECT COUNT(*) AS n FROM managed_databases WHERE app_id = ?').get(CAT).n, 0);
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), true);

  // A failed CREATE: loosened first, then strict again once the row is gone.
  order.length = 0;
  await assert.rejects(mdb.provision({ appId: CAT }, 'postgres', { ops: mk({ createFails: true }) }), /provisioning postgres database failed: boom/);
  assert.deepEqual(order, [['sync', 'loosen'], ['create', false], ['sync', 'decide']]);
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), true, 're-tightened');

  // Success: the role is created on a loose server and the server stays loose for it.
  order.length = 0;
  const conn = await mdb.provision({ appId: CAT }, 'postgres', { ops: mk() });
  assert.ok(conn.username);
  assert.deepEqual(order, [['sync', 'loosen'], ['create', false], ['sync', 'decide']]);
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), false, 'loose while the catalogue login is password-only');
});
