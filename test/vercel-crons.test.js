import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'fs';
import http from 'http';
import { tmpdir } from 'os';
import { join } from 'path';

// vercel.json `crons` become AppCrane cron jobs: validated, synced per
// app+env touching only the rows AppCrane created from vercel.json, and run as
// a GET of the path on the app's own loopback port with
// Authorization: Bearer <CRON_SECRET> when the app sets one.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-vercel-cron-'));
process.env.DATA_DIR = join(ROOT, 'data');
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(ROOT, 'bin');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), `#!/bin/sh
if [ "$1" = "inspect" ]; then echo 'true|running'; exit 0; fi
echo "unexpected docker $*" >&2; exit 9
`, { mode: 0o755 });
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { parseVercelCrons, syncVercelCrons, syncVercelCronsForRelease, MAX_VERCEL_CRONS } = await import('../server/services/vercelCrons.js');
const { syncCronJobsFromManifest, runCronJob } = await import('../server/services/cronScheduler.js');
const { encrypt } = await import('../server/services/encryption.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');


async function portFree(port) {
  return new Promise((res) => {
    const s = http.createServer();
    s.once('error', () => res(false));
    s.listen(port, '127.0.0.1', () => s.close(() => res(true)));
  });
}
let SLOT = 2401;
while (!(await portFree(getPortsForSlot(SLOT).sand_be))) SLOT++;
db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('Vercel App', 'vercelapp', ?)").run(SLOT);
const app = db.prepare("SELECT * FROM apps WHERE slug = 'vercelapp'").get();
const rows = (env = 'sandbox') => db.prepare('SELECT name, kind, origin, schedule, http_path, command FROM app_cron_jobs WHERE app_id = ? AND env = ? ORDER BY name').all(app.id, env).map((r) => ({ ...r }));
const job = (name) => db.prepare('SELECT * FROM app_cron_jobs WHERE app_id = ? AND name = ?').get(app.id, name);

const SECRET = 'k'.repeat(40) + 'SECRETVALUE';
const seen = [];
let reply = (req, res) => res.writeHead(204).end();
const server = http.createServer((req, res) => {
  seen.push({ method: req.method, url: req.url, headers: req.headers, local: req.socket.localAddress });
  reply(req, res);
});
await new Promise((r) => server.listen(getPortsForSlot(SLOT).sand_be, '127.0.0.1', r));

after(() => { server.close(); try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

const SIGNUDOC = { crons: [{ path: '/api/internal/retention', schedule: '0 9 * * *' }, { path: '/api/internal/backup', schedule: '0 8 * * *' }] };

test('a valid crons array parses into named http jobs', () => {
  assert.deepEqual(parseVercelCrons(SIGNUDOC), [
    { path: '/api/internal/retention', schedule: '0 9 * * *', name: 'vercel:/api/internal/retention' },
    { path: '/api/internal/backup', schedule: '0 8 * * *', name: 'vercel:/api/internal/backup' },
  ]);
  assert.deepEqual(parseVercelCrons({ buildCommand: 'x' }), [], 'no crons key is no jobs');
  const twice = parseVercelCrons({ crons: [{ path: '/api/sync', schedule: '*/5 * * * *' }, { path: '/api/sync', schedule: '0 0 * * *' }] });
  assert.deepEqual(twice.map((c) => c.name), ['vercel:/api/sync [*/5 * * * *]', 'vercel:/api/sync [0 0 * * *]'], 'one path on two schedules is two jobs');
  assert.equal(parseVercelCrons({ crons: [{ path: '/api/x?full=1', schedule: '5 4 * * 1-5' }] })[0].path, '/api/x?full=1', 'a query string is kept');
});

test('a path that is not a plain rooted path on the app is refused', () => {
  assert.throws(() => parseVercelCrons({ crons: [{ path: '//evil.example.com/x', schedule: '0 9 * * *' }] }), /must not start with "\/\/"/);
  const bad = ['api/x', '//evil.example.com/x', 'http://evil.example.com/x', 'https://evil.example.com/', '/api/../admin',
    '/api/%2e%2e/admin', '/api/./x', '/a\\b', '/a b', '/a#frag', '', null, 42, `/${'a'.repeat(600)}`];
  for (const path of bad) {
    assert.throws(() => parseVercelCrons({ crons: [{ path, schedule: '0 9 * * *' }] }), /crons\[0\]/, `refuses ${JSON.stringify(path)}`);
  }
});

test('a schedule Vercel would refuse is refused', () => {
  const bad = ['0 9 * * MON', '@daily', '0 9 * *', '0 9 * * * *', '60 9 * * *', '0 24 * * *', '0 9 1 * 1', '0 9 * JAN *', '5MON 9 * * *', ''];
  for (const schedule of bad) {
    assert.throws(() => parseVercelCrons({ crons: [{ path: '/api/x', schedule }] }), /crons\[0\]/, `refuses ${JSON.stringify(schedule)}`);
  }
});

test('the count is capped and duplicates and non-arrays are refused', () => {
  const many = Array.from({ length: MAX_VERCEL_CRONS + 1 }, (_, i) => ({ path: `/api/j${i}`, schedule: '0 9 * * *' }));
  assert.throws(() => parseVercelCrons({ crons: many }), /limit is 100/);
  assert.equal(parseVercelCrons({ crons: many.slice(0, MAX_VERCEL_CRONS) }).length, MAX_VERCEL_CRONS);
  assert.throws(() => parseVercelCrons({ crons: [SIGNUDOC.crons[0], SIGNUDOC.crons[0]] }), /twice/);
  assert.throws(() => parseVercelCrons({ crons: {} }), /must be an array/);
  assert.throws(() => parseVercelCrons([]), /JSON object/);
});

test('sync creates, updates and removes only vercel.json jobs, and never a job somebody declared', () => {
  syncCronJobsFromManifest(app.id, 'sandbox', [{ name: 'nightly', schedule: '0 0 * * *', command: 'echo hi' }]);
  let r = syncVercelCrons(app.id, 'sandbox', parseVercelCrons(SIGNUDOC));
  assert.deepEqual(r.created, ['vercel:/api/internal/retention', 'vercel:/api/internal/backup']);
  assert.deepEqual(rows(), [
    { name: 'nightly', kind: 'exec', origin: 'manifest', schedule: '0 0 * * *', http_path: null, command: 'echo hi' },
    { name: 'vercel:/api/internal/backup', kind: 'http', origin: 'vercel', schedule: '0 8 * * *', http_path: '/api/internal/backup', command: 'GET /api/internal/backup' },
    { name: 'vercel:/api/internal/retention', kind: 'http', origin: 'vercel', schedule: '0 9 * * *', http_path: '/api/internal/retention', command: 'GET /api/internal/retention' },
  ]);
  assert.deepEqual(rows('production'), [], 'the other environment is untouched');

  r = syncVercelCrons(app.id, 'sandbox', parseVercelCrons({ crons: [{ path: '/api/internal/retention', schedule: '30 9 * * *' }] }));
  assert.deepEqual(r, { created: [], updated: ['vercel:/api/internal/retention'], removed: ['vercel:/api/internal/backup'], skipped: [] });
  assert.equal(job('vercel:/api/internal/retention').schedule, '30 9 * * *');
  assert.ok(job('nightly'), 'the deployhub.json job survives a vercel.json removal');

  syncCronJobsFromManifest(app.id, 'sandbox', []);
  assert.equal(job('nightly'), undefined, 'the manifest sync still removes its own job');
  assert.ok(job('vercel:/api/internal/retention'), 'and no longer removes the vercel.json one');

  syncCronJobsFromManifest(app.id, 'sandbox', [{ name: 'vercel:/api/x', schedule: '1 1 * * *', command: 'echo mine' }]);
  r = syncVercelCrons(app.id, 'sandbox', parseVercelCrons({ crons: [{ path: '/api/x', schedule: '2 2 * * *' }, { path: '/api/internal/retention', schedule: '30 9 * * *' }] }));
  assert.deepEqual(r.skipped, ['vercel:/api/x']);
  assert.equal(job('vercel:/api/x').command, 'echo mine', 'a name a person holds is not overwritten');
  assert.equal(job('vercel:/api/x').origin, 'manifest');
  r = syncVercelCrons(app.id, 'sandbox', []);
  assert.deepEqual(r.removed, ['vercel:/api/internal/retention']);
  assert.ok(job('vercel:/api/x'), 'emptying vercel.json does not remove a person\'s job');
  syncCronJobsFromManifest(app.id, 'sandbox', []);
});

test('a malformed vercel.json is reported, changes nothing and does not throw', () => {
  const dir = mkdtempSync(join(ROOT, 'rel-'));
  writeFileSync(join(dir, 'vercel.json'), JSON.stringify(SIGNUDOC));
  assert.deepEqual(syncVercelCronsForRelease(app.id, 'sandbox', dir), ['vercel.json crons: 2 declared, 2 created, 0 updated, 0 removed']);
  const before = rows();

  writeFileSync(join(dir, 'vercel.json'), '{ "crons": [ ');
  let lines = syncVercelCronsForRelease(app.id, 'sandbox', dir);
  assert.match(lines[0], /^WARNING: vercel\.json crons NOT synced .*not valid JSON/);
  writeFileSync(join(dir, 'vercel.json'), JSON.stringify({ crons: [{ path: 'https://evil.example.com/', schedule: '0 9 * * *' }] }));
  lines = syncVercelCronsForRelease(app.id, 'sandbox', dir);
  assert.match(lines[0], /NOT synced .*crons\[0\].*must start with "\/"/);
  assert.deepEqual(rows(), before, 'existing vercel.json jobs left as they were');

  rmSync(join(dir, 'vercel.json'));
  symlinkSync('/etc/hosts', join(dir, 'vercel.json'));
  assert.match(syncVercelCronsForRelease(app.id, 'sandbox', dir)[0], /symbolic link/);
  assert.deepEqual(rows(), before);

  rmSync(join(dir, 'vercel.json'));
  assert.deepEqual(syncVercelCronsForRelease(app.id, 'sandbox', dir), ['vercel.json crons: none declared, 2 removed'], 'a removed file removes its jobs');
  assert.deepEqual(rows(), []);
});

// ── running an http job ───────────────────────────────────────────────────


function vercelJob(path = '/api/internal/retention', timeout = 5) {
  syncVercelCrons(app.id, 'sandbox', parseVercelCrons({ crons: [{ path, schedule: '0 9 * * *' }] }));
  db.prepare('UPDATE app_cron_jobs SET timeout_seconds = ? WHERE app_id = ?').run(timeout, app.id);
  return job(`vercel:${path}`);
}

test('an http job GETs the path on the app\'s loopback port and records the status', async () => {
  seen.length = 0;
  const r = await runCronJob(vercelJob());
  assert.equal(r.ran, true);
  assert.equal(r.exitCode, 0);
  assert.equal(r.httpStatus, 204);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].method, 'GET');
  assert.equal(seen[0].url, '/api/internal/retention');
  assert.equal(seen[0].local, '127.0.0.1', 'reached over loopback, not through the proxy');
  assert.equal(seen[0].headers.authorization, undefined, 'no CRON_SECRET, no Authorization header');
  assert.match(seen[0].headers['user-agent'], /^vercel-cron\/1\.0/);
  assert.equal(seen[0].headers['x-vercel-cron-schedule'], '0 9 * * *');
  const row = job('vercel:/api/internal/retention');
  assert.equal(row.last_exit_code, 0);
  assert.equal(row.last_http_status, 204);
  assert.match(row.last_log, /GET \/api\/internal\/retention without Authorization .* -> HTTP 204/);
});

test('with CRON_SECRET set it is sent as a Bearer token and never written to the row', async () => {
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'production', 'CRON_SECRET', ?)").run(app.id, encrypt('production-only'));
  seen.length = 0;
  await runCronJob(vercelJob());
  assert.equal(seen[0].headers.authorization, undefined, 'production\'s CRON_SECRET is not sent to the sandbox');
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'sandbox', 'CRON_SECRET', ?)").run(app.id, encrypt(SECRET));
  seen.length = 0;
  reply = (req, res) => {
    const ok = req.headers.authorization === `Bearer ${SECRET}`;
    res.writeHead(ok ? 200 : 401, { 'content-type': 'application/json' }).end(JSON.stringify({ echoed: req.headers.authorization }));
  };
  const r = await runCronJob(vercelJob());
  assert.equal(seen[0].headers.authorization, `Bearer ${SECRET}`, 'the sandbox value, not production\'s');
  assert.equal(r.httpStatus, 200);
  assert.equal(r.exitCode, 0);
  const row = job('vercel:/api/internal/retention');
  assert.ok(!row.last_log.includes(SECRET), 'the secret an app echoes back is removed from the stored log');
  assert.match(row.last_log, /with Authorization: Bearer CRON_SECRET -> HTTP 200/);
  assert.match(row.last_log, /\[CRON_SECRET\]/);
});

test('a non-2xx answer is a failure, and a redirect is not followed', async () => {
  reply = (req, res) => res.writeHead(401).end('Unauthorized.');
  let r = await runCronJob(vercelJob());
  assert.equal(r.exitCode, 1);
  assert.equal(r.httpStatus, 401);
  assert.equal(job('vercel:/api/internal/retention').last_exit_code, 1);

  seen.length = 0;
  reply = (req, res) => (req.url === '/elsewhere' ? res.writeHead(200).end() : res.writeHead(302, { location: '/elsewhere' }).end());
  r = await runCronJob(vercelJob());
  assert.equal(r.httpStatus, 302);
  assert.equal(r.exitCode, 1);
  assert.deepEqual(seen.map((s) => s.url), ['/api/internal/retention'], 'only the cron path was requested');
});

test('a route that does not answer within the timeout fails with that reason', async () => {
  reply = () => {};
  const r = await runCronJob(vercelJob('/api/slow', 1));
  assert.equal(r.exitCode, 1);
  assert.equal(r.httpStatus, null);
  assert.match(job('vercel:/api/slow').last_log, /no answer within 1s/);
});
