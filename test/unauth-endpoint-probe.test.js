import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { crawlServed } from '../server/services/servedOutputScan.js';
import { probeUnauthEndpoints, describeRecords, PROBE_HEADER } from '../server/services/unauthEndpointProbe.js';
import { collectRoutes, emptyRoutes, skipReason } from '../server/services/unauthRouteDiscovery.js';
import { appServer, identityHeaderNames, VALUES, BUNDLE } from './unauth-endpoint-fixtures.js';

// The unauthenticated-endpoint probe against a real HTTP app: routes found in
// the served bundle and an OpenAPI document, records flagged by shape, writes
// only when asked, and nothing that identifies anyone on any request.

const servers = [];
after(() => { for (const s of servers) { s.closeAllConnections?.(); s.close(); } });
const start = async (o) => { const a = await appServer(o); servers.push(a.server); return a; };
const noValueIn = (obj) => { const s = JSON.stringify(obj); for (const v of Object.values(VALUES)) assert.ok(!s.includes(v), `${v} leaked`); };
const read = (r, p) => r.reads.find((x) => x.path === p);

test('bundle + OpenAPI discovery: unauthenticated records are flagged by key names, 401 and health are not; no write without the flag', async () => {
  const app = await start();
  const crawl = await crawlServed({ baseUrl: app.url });
  assert.equal(crawl.ok, true, crawl.error);
  assert.deepEqual([...crawl.routes.keys()].sort(), ['/api/health', '/api/invoices', '/api/items', '/api/logout', '/api/me', '/api/reset', '/api/users']);
  const r = await probeUnauthEndpoints({ baseUrl: app.url, routes: crawl.routes });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.openapi, '/openapi.json');
  assert.deepEqual(read(r, '/api/users'), { method: 'GET', path: '/api/users', status: 200, verdict: 'records', shape: 'array[1] of {id, email, name}' });
  assert.equal(read(r, '/api/invoices').verdict, 'records', 'a route only the bundle names is discovered and probed');
  assert.equal(read(r, '/api/me').verdict, 'protected');
  assert.equal(read(r, '/api/reports').verdict, 'records', 'a route only the OpenAPI document names is discovered and probed');
  assert.equal(read(r, '/api/reports').shape, '{reports: array[1] of {id, title}}');
  assert.equal(read(r, '/api/items').verdict, 'protected');
  for (const p of ['/api/health', '/api/reset', '/api/logout', '/api/users/{id}']) {
    assert.ok(!app.requests.some((q) => q.path === p), `${p} must not be requested`);
  }
  assert.ok(r.skipped.health >= 1 && r.skipped['side-effect'] >= 2 && r.skipped.templated >= 1, JSON.stringify(r.skipped));
  assert.equal(app.requests.filter((q) => !['GET', 'OPTIONS'].includes(q.method)).length, 0, 'write probing is off: only GET and OPTIONS');
  assert.deepEqual(r.writes, [{ method: 'POST', path: '/api/items', status: null, verdict: 'not_probed', allow: 'GET, POST' }]);
  noValueIn(r);
});

test('write probing on: one POST with {} and the marker header; 2xx is "accepts unauthenticated writes"', async () => {
  const app = await start();
  const crawl = await crawlServed({ baseUrl: app.url });
  const r = await probeUnauthEndpoints({ baseUrl: app.url, routes: crawl.routes, probeWrites: true });
  const posts = app.requests.filter((q) => q.method === 'POST');
  assert.equal(posts.length, 1, JSON.stringify(posts.map((p) => p.path)));
  assert.equal(posts[0].path, '/api/items');
  assert.equal(posts[0].body, '{}');
  assert.match(posts[0].headers[PROBE_HEADER.toLowerCase()], /^[A-Za-z0-9_-]{16}$/);
  assert.deepEqual(r.writes.map((w) => [w.path, w.status, w.verdict]), [['/api/items', 201, 'accepted']]);
  noValueIn(r);
});

test('no request carries Cookie, Authorization, an API key or any X-AppCrane-* header', async () => {
  const app = await start();
  const crawl = await crawlServed({ baseUrl: app.url });
  await probeUnauthEndpoints({ baseUrl: app.url, routes: crawl.routes, probeWrites: true });
  assert.ok(app.requests.length >= 10);
  const names = new Set();
  for (const q of app.requests) {
    assert.deepEqual(identityHeaderNames(q.headers), [], `${q.method} ${q.path}`);
    for (let i = 0; i < q.rawHeaders.length; i += 2) names.add(q.rawHeaders[i].toLowerCase());
  }
  const allowed = new Set(['host', 'connection', 'accept', 'accept-language', 'accept-encoding', 'sec-fetch-mode', 'user-agent', 'content-type', 'content-length', PROBE_HEADER.toLowerCase()]);
  assert.deepEqual([...names].filter((n) => !allowed.has(n)), [], `unexpected header names: ${[...names].join(', ')}`);
});

test('caps: at most maxRoutes GETs, a hung route times out per request, the deadline bounds the whole probe', async () => {
  const app = await start({ extraPaths: 80 });
  const r = await probeUnauthEndpoints({ baseUrl: app.url, maxRoutes: 50 });
  const gets = app.requests.filter((q) => q.method === 'GET' && q.path.startsWith('/api/'));
  assert.equal(r.reads.length, 50);
  assert.ok(gets.length <= 50, `${gets.length} GETs`);
  assert.equal(r.truncated, true);

  const hung = await start({ hang: ['/api/users', '/api/admin'] });
  const t0 = Date.now();
  const h = await probeUnauthEndpoints({ baseUrl: hung.url, timeoutMs: 300 });
  assert.ok(Date.now() - t0 < 5000);
  assert.equal(read(h, '/api/users').verdict, 'error');
  assert.equal(read(h, '/api/users').error, 'timed out');

  const all = await start({ hang: ['/openapi.json', '/swagger.json', '/api/openapi.json', '/api/swagger.json', '/api-docs', '/api/docs', '/v3/api-docs', '/docs/openapi.json', '/api', '/api/users', '/api/user', '/api/admin', '/api/admin/users', '/api/accounts', '/api/customers', '/api/orders', '/api/items', '/api/data', '/users', '/graphql'] });
  const t1 = Date.now();
  const d = await probeUnauthEndpoints({ baseUrl: all.url, timeoutMs: 4000, deadlineMs: 1000 });
  assert.ok(Date.now() - t1 < 2500, `${Date.now() - t1}ms`);
  assert.equal(d.truncated, true);
});

test('only a loopback http origin is probed; an unreachable sandbox is a failed probe, not a clean one', async () => {
  await assert.rejects(probeUnauthEndpoints({ baseUrl: 'http://example.com' }), /loopback/);
  await assert.rejects(probeUnauthEndpoints({ baseUrl: 'https://localhost:1' }), /loopback/);
  const app = await start();
  const port = Number(new URL(app.url).port);
  await new Promise((res) => { app.server.closeAllConnections?.(); app.server.close(res); });
  servers.splice(servers.indexOf(app.server), 1);
  const r = await probeUnauthEndpoints({ baseUrl: `http://localhost:${port}`, timeoutMs: 1000 });
  assert.equal(r.ok, false);
  assert.match(r.error, /could not reach the sandbox \(ECONNREFUSED\)/);
});

test('nothing is logged: no body value reaches console or the logger', async () => {
  const logger = (await import('../server/utils/logger.js')).default;
  const seen = [];
  const saved = {};
  for (const k of ['log', 'info', 'warn', 'error', 'debug']) { saved[`c.${k}`] = console[k]; console[k] = (...a) => seen.push(a); }
  for (const k of ['info', 'warn', 'error', 'debug']) { saved[`l.${k}`] = logger[k]; logger[k] = (...a) => seen.push(a); }
  try {
    const app = await start();
    const crawl = await crawlServed({ baseUrl: app.url });
    await probeUnauthEndpoints({ baseUrl: app.url, routes: crawl.routes, probeWrites: true });
  } finally {
    for (const k of ['log', 'info', 'warn', 'error', 'debug']) console[k] = saved[`c.${k}`];
    for (const k of ['info', 'warn', 'error', 'debug']) logger[k] = saved[`l.${k}`];
  }
  const text = JSON.stringify(seen);
  for (const v of Object.values(VALUES)) assert.ok(!text.includes(v), `${v} logged`);
});

test('shape descriptions: key names only, never values; identity-free answers are not records', () => {
  assert.deepEqual(describeRecords([{ id: 1, email: 'a@b.test' }]), { records: true, empty: false, shape: 'array[1] of {id, email}' });
  assert.equal(describeRecords({ 'bob@corp.test': { id: 1 }, total: 1 }).shape, 'object {total, +1 more}', 'an e-mail used as a key is not shown');
  assert.equal(describeRecords({ user: null, authenticated: false }).records, false);
  assert.equal(describeRecords({ status: 'ok', version: '1.2.3' }).records, false);
  assert.equal(describeRecords({ name: 'my api', version: '1' }).records, false);
  assert.equal(describeRecords({ id: 'u1', email: 'x@y.test' }).records, true);
  assert.deepEqual(describeRecords({ data: [] }), { records: false, empty: true, shape: 'object {data}' });
  assert.equal(describeRecords([]).empty, true);
  const routes = collectRoutes('fetch("/shop-sandbox/api/orders");axios.post("/api/cart");x="https://other.test/api/users"', emptyRoutes(), '/shop-sandbox');
  assert.deepEqual([...routes.keys()], ['/api/orders', '/api/cart']);
  assert.deepEqual([...routes.get('/api/cart').methods], ['POST']);
  assert.equal(skipReason('/api/version'), 'health');
  assert.equal(skipReason('/api/admin/delete-all'), 'side-effect');
  assert.equal(skipReason('/api/users'), null);
  assert.ok(BUNDLE.includes('/api/users'));
});
