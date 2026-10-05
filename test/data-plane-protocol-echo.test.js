import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import express from 'express';

// Two review findings on the UDP data plane (PR #14):
//   1. Older reads reported data_plane_protocol='tcp' for every app, so a client that
//      sends back what it read must not be refused for echoing it.
//   2. A UDP data plane's firewall advice must say UDP: an operator who copies
//      a `-p tcp` DOCKER-USER rule leaves the UDP port open.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-dpproto-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const KEY = generateApiKey('dhk_user');
const ADMIN_ID = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active) VALUES ('p','p@t.test','platform_admin',?,1)")
  .run(hashApiKey(KEY)).lastInsertRowid;
const ADMIN = db.prepare('SELECT * FROM users WHERE id = ?').get(ADMIN_ID);
db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('Plain','plain',1,'managed','main')").run();
db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('Relay','relay',2,'managed','main')").run();

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const app = express();
  app.use(express.json());
  app.use('/api/apps', appsRoutes);
  app.use(errorHandler);
  const s = app.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const base = `http://127.0.0.1:${server.address().port}`;
const put = async (slug, body) => {
  const r = await fetch(`${base}/api/apps/${slug}`, {
    method: 'PUT', headers: { 'content-type': 'application/json', 'x-api-key': KEY }, body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json() };
};

const { callTool } = await import('../server/services/mcpTools.js');
const tool = async (name, args) => JSON.parse((await callTool(ADMIN, name, args)).content[0].text);

test('REST: echoing the reported tcp is accepted, alone or alongside an ingress change', async () => {
  const r1 = await put('plain', { description: 'renamed', data_plane_protocol: 'tcp' });
  assert.equal(r1.status, 200, `refused for echoing the value GET returned: ${JSON.stringify(r1.body)}`);
  // The review's case: a client reads the app, switches it to tcp, sends the object back.
  const r2 = await put('plain', { ingress_type: 'tcp', data_plane_protocol: 'tcp' });
  assert.equal(r2.status, 200, `an ingress change was refused for echoing tcp: ${JSON.stringify(r2.body)}`);
  const r3 = await put('plain', { ingress_type: 'http', data_plane_protocol: 'tcp' });
  assert.equal(r3.status, 200, `switching back was refused for echoing tcp: ${JSON.stringify(r3.body)}`);
});

test('REST: asking for udp on a non-dual app is still refused', async () => {
  const r = await put('plain', { data_plane_protocol: 'udp' });
  assert.equal(r.status, 400);
});

test('MCP: setting a non-dual ingress while echoing tcp is accepted, udp is not', async () => {
  const ok = await tool('appcrane_set_app_ingress', { slug: 'plain', ingress_type: 'http', data_plane_protocol: 'tcp' });
  assert.equal(ok.ingress_type, 'http');
  await assert.rejects(tool('appcrane_set_app_ingress', { slug: 'plain', ingress_type: 'http', data_plane_protocol: 'udp' }));
});

test('MCP: a UDP data plane is told to filter UDP, not TCP', async () => {
  const out = await tool('appcrane_set_app_ingress', {
    slug: 'relay', ingress_type: 'dual', public_port: 8090, data_plane_port: 51820, data_plane_protocol: 'udp',
  });
  assert.equal(out.data_plane_protocol, 'udp');
  assert.match(out.warning, /-p udp/, 'the warning gives no UDP filter, so a copied TCP rule leaves the port open');
  assert.doesNotMatch(out.warning, /-p tcp/);
});

// Third finding: reads reported the EFFECTIVE protocol, 'tcp', on every non-dual
// app even while the column still held 'udp'. A client that flipped a UDP app
// away from dual and back, sending what it read, wrote 'tcp' and silently lost
// the UDP data plane. Reads now report null outside dual, and null is "keep".
const get = async (slug) => (await (await fetch(`${base}/api/apps/${slug}`, { headers: { 'x-api-key': KEY } })).json()).app;
const stored = (slug) => db.prepare('SELECT data_plane_protocol FROM apps WHERE slug = ?').get(slug).data_plane_protocol;

test('REST: a read-modify-write flip away from dual and back keeps udp', async () => {
  db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('Wg','wg-rmw',3,'managed','main')").run();
  assert.equal((await put('wg-rmw', { ingress_type: 'dual', public_port: 8091, data_plane_port: 51820, data_plane_protocol: 'udp' })).status, 200);

  const asDual = await get('wg-rmw');
  assert.equal(asDual.data_plane_protocol, 'udp');
  assert.equal((await put('wg-rmw', { ingress_type: 'http', data_plane_protocol: asDual.data_plane_protocol, data_plane_port: null })).status, 200);

  const asHttp = await get('wg-rmw');
  assert.equal(asHttp.data_plane_protocol, null, 'outside dual the protocol reads null, like data_plane_port');
  assert.equal(stored('wg-rmw'), 'udp', 'the stored value survives the flip');

  const back = await put('wg-rmw', { ingress_type: 'dual', data_plane_port: 51820, data_plane_protocol: asHttp.data_plane_protocol });
  assert.equal(back.status, 200, JSON.stringify(back.body));
  assert.equal(stored('wg-rmw'), 'udp', 'echoing the null it read wrote tcp over the stored udp');
  assert.equal((await get('wg-rmw')).data_plane_protocol, 'udp');
});

test('MCP: echoing null from get-ingress on the flip back keeps udp; an explicit tcp still switches', async () => {
  db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('Wg2','wg-mcp',4,'managed','main')").run();
  await tool('appcrane_set_app_ingress', { slug: 'wg-mcp', ingress_type: 'dual', public_port: 8092, data_plane_port: 51821, data_plane_protocol: 'udp' });
  const away = await tool('appcrane_set_app_ingress', { slug: 'wg-mcp', ingress_type: 'http', data_plane_port: null });
  assert.equal(away.data_plane_protocol, null);
  const read = await tool('appcrane_get_app_ingress', { slug: 'wg-mcp' });
  assert.equal(read.data_plane_protocol, null);
  const back = await tool('appcrane_set_app_ingress', { slug: 'wg-mcp', ingress_type: 'dual', data_plane_port: 51821, data_plane_protocol: read.data_plane_protocol });
  assert.equal(back.data_plane_protocol, 'udp');
  const tcp = await tool('appcrane_set_app_ingress', { slug: 'wg-mcp', ingress_type: 'dual', data_plane_port: 51821, data_plane_protocol: 'tcp' });
  assert.equal(tcp.data_plane_protocol, 'tcp', 'an explicit value on a dual app is still honoured');
});
