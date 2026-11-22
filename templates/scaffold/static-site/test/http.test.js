import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { signedHeaders } from './helpers.js';
import { createHandler } from '../server/app.js';

const publicDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'public');
let server;
let port;
before(async () => {
  server = createServer(createHandler({ version: '0.1.0', publicDir })).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  port = server.address().port;
});
after(() => { server.closeAllConnections?.(); server.close(); });

// node:http rather than fetch, so a path like /../ reaches the server as sent.
function get(path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, headers }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, type: res.headers['content-type'], body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('/api/health answers with no identity: 200, status and version', async () => {
  const r = await get('/api/health');
  assert.equal(r.status, 200);
  assert.deepEqual(JSON.parse(r.body), { status: 'ok', version: '0.1.0' });
});

test('pages are refused without a signed identity', async () => {
  const r = await get('/', { 'x-appcrane-user-id': '1', 'x-appcrane-app-role': 'owner' });
  assert.equal(r.status, 401);
  assert.equal(JSON.parse(r.body).error.code, 'IDENTITY_UNSIGNED');
});

test('pages are refused with a forged signature', async () => {
  const r = await get('/', signedHeaders({ secret: randomBytes(32).toString('base64url') }));
  assert.equal(r.status, 401);
  assert.equal(JSON.parse(r.body).error.code, 'IDENTITY_FORGED');
});

test('a signed visitor gets the page and their identity', async () => {
  const page = await get('/', signedHeaders());
  assert.equal(page.status, 200);
  assert.match(page.type, /text\/html/);
  assert.match(page.body, /<main>/);
  const me = await get('/api/me', signedHeaders({ appRole: 'viewer' }));
  assert.equal(JSON.parse(me.body).user.appRole, 'viewer');
});

test('public/admin/ needs admin or owner, however the path is spelled', async () => {
  for (const p of ['/admin/', '/admin', '/admin/index.html', '/%61dmin/', '/ADMIN/', '/./admin/']) {
    assert.equal((await get(p, signedHeaders({ appRole: 'user' }))).status, 403, `${p} let a user in`);
  }
  assert.equal((await get('/admin/', signedHeaders({ appRole: 'admin' }))).status, 200);
  assert.equal((await get('/admin/', signedHeaders({ appRole: 'owner' }))).status, 200);
});

test('paths that climb out of public/ are refused', async () => {
  for (const p of ['/../package.json', '/%2e%2e/package.json', '/..%2fpackage.json', '/%00']) {
    const r = await get(p, signedHeaders());
    assert.ok([400, 404].includes(r.status), `${p} -> ${r.status}`);
    assert.doesNotMatch(r.body, /"scripts"/, `${p} leaked package.json`);
  }
});
