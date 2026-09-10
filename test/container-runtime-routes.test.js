import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// container_command / volume_paths on the WRITE path (v2.70.0).
//
// The columns, the validators and the deploy-path plumbing all landed before
// this file existed, and every one of them was tested — but nothing could SET
// either column, because `ALLOWED_APP_COLS` in routes/apps.js did not list
// them. The whole feature was unreachable from the API: a caller sending a
// command got `Invalid field: container_command` and the deploy path read NULL
// forever. So the thing under test here is reachability, and it is asserted
// over a real socket into the REAL apps router rather than against the
// validators, which already had their own tests and passed the whole time.
//
// The second property is that validation happens HERE, on the way in. Both
// columns are re-validated on the way out (parseContainerCommand /
// parseVolumePaths degrade a bad row to the old default instead of making an
// app undeployable), and that fallback is only a safety net if bad values
// cannot be stored in the first place. If the write path stopped validating,
// every one of these would still "work" — the row would be written and the
// degrade path would quietly swallow it at deploy time. That is exactly the
// failure this file exists to catch, so each refusal below asserts the 400 AND
// that the column was not written.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-runtime-routes-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, role };
}

const admin = mkUser('rtadmin', 'platform_admin');

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use(errorHandler);

const server = await new Promise((resolve) => {
  const s = api.listen(0, '127.0.0.1', () => resolve(s));
});
const BASE = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.unref();
  server.close();
});

async function req(as, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': as.key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await res.json() };
}

const rowFor = (slug) => db.prepare(
  'SELECT container_command, volume_paths FROM apps WHERE slug = ?'
).get(slug);

let n = 0;
async function mkApp(label) {
  const slug = `rt-${label}-${++n}`;
  const r = await req(admin, 'POST', '/api/apps', {
    name: `RT ${label}`, slug, source_type: 'image', image_ref: 'nginx:1.27',
  });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  return slug;
}

// ---------------------------------------------------------------------------
// Accept
// ---------------------------------------------------------------------------

test('a command array is accepted and stored as JSON', async () => {
  const slug = await mkApp('cmd');
  const r = await req(admin, 'PUT', `/api/apps/${slug}`, { container_command: ['start-dev'] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(rowFor(slug).container_command, '["start-dev"]',
    'the column must hold JSON the deploy path can parse, not a JS array coerced to a string');
});

test('a multi-argument command keeps its arguments separate', async () => {
  // The argv-vs-string distinction is the entire safety property: separate
  // arguments cannot be re-split by a shell, so nothing in a stored command can
  // become a second token.
  const slug = await mkApp('argv');
  const r = await req(admin, 'PUT', `/api/apps/${slug}`, {
    container_command: ['server', '--http-port', '8080'],
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(JSON.parse(rowFor(slug).container_command), ['server', '--http-port', '8080']);
});

test('volume paths are accepted and stored as JSON', async () => {
  const slug = await mkApp('vol');
  const r = await req(admin, 'PUT', `/api/apps/${slug}`, { volume_paths: ['/config', '/var/lib/odoo'] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(JSON.parse(rowFor(slug).volume_paths), ['/config', '/var/lib/odoo']);
});

test('null clears a previously stored command', async () => {
  const slug = await mkApp('clear');
  await req(admin, 'PUT', `/api/apps/${slug}`, { container_command: ['start-dev'] });
  assert.equal(rowFor(slug).container_command, '["start-dev"]');

  const r = await req(admin, 'PUT', `/api/apps/${slug}`, { container_command: null });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(rowFor(slug).container_command, null,
    'clearing must write NULL — the deploy path reads NULL as "the image entrypoint decides"');
});

// ---------------------------------------------------------------------------
// Refuse, and store nothing
// ---------------------------------------------------------------------------

test('a shell string is refused, and nothing is written', async () => {
  const slug = await mkApp('shell');
  const r = await req(admin, 'PUT', `/api/apps/${slug}`, { container_command: 'sh -c "rm -rf /"' });
  assert.equal(r.status, 400, JSON.stringify(r.body));
  assert.equal(rowFor(slug).container_command, null,
    'a refused command must leave the column untouched, or the degrade path becomes the real path');
});

test('a colon in a volume path is refused, and nothing is written', async () => {
  // ':' is the -v field separator. '/config:ro' is not a broken mount, it is a
  // different valid one, and a colon on the host side can name a source
  // AppCrane never chose.
  const slug = await mkApp('colon');
  const r = await req(admin, 'PUT', `/api/apps/${slug}`, { volume_paths: ['/config:ro'] });
  assert.equal(r.status, 400, JSON.stringify(r.body));
  assert.equal(rowFor(slug).volume_paths, null);
});

test('traversal and kernel mount points are refused', async () => {
  const slug = await mkApp('escape');
  for (const bad of [['/a/../../etc'], ['/proc'], ['/sys'], ['/dev'], ['/'], ['relative']]) {
    const r = await req(admin, 'PUT', `/api/apps/${slug}`, { volume_paths: bad });
    assert.equal(r.status, 400, `${JSON.stringify(bad)} was accepted: ${JSON.stringify(r.body)}`);
  }
  assert.equal(rowFor(slug).volume_paths, null);
});

test('the refusal explains itself rather than answering a bare 400', async () => {
  // An operator setting a command from the API sees only this string.
  const slug = await mkApp('msg');
  const r = await req(admin, 'PUT', `/api/apps/${slug}`, { container_command: 'start-dev' });
  assert.equal(r.status, 400);
  const text = JSON.stringify(r.body);
  assert.match(text, /array/i,
    `the message must say what shape is expected; got ${text}`);
});
