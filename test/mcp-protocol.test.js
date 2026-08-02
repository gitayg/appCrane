import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// MCP protocol negotiation (v2.28.1). The contract: a client speaking ANY
// supported revision keeps working. That matters more than usual here — people
// running AppCrane point long-lived agents at this endpoint, so a hard cutover
// to 2026-07-28 would cut off work already in flight.
//
// Mounts the MCP router alone rather than booting server/index.js: the full
// boot starts the email worker, health checker and credential checker, which
// hold the event loop open and have nothing to do with protocol negotiation.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mcp-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const KEY = generateApiKey('dhk_admin');
getDb()
  .prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@x.io','platform_admin',?,1,'human')")
  .run(hashApiKey(KEY));

const mcpRouter = (await import('../server/routes/mcp.js')).default;
const app = express();
app.use(express.json());
app.use('/api/mcp', mcpRouter);

const server = await new Promise((resolve) => {
  const s = app.listen(0, () => resolve(s));
});
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => server.close());

async function rpc(method, params, headers = {}) {
  const res = await fetch(`${BASE}/api/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': KEY, ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return { status: res.status, header: res.headers.get('mcp-protocol-version'), body: await res.json() };
}

test('legacy initialize is unchanged by default', async () => {
  const r = await rpc('initialize', {});
  assert.equal(r.body.result.protocolVersion, '2024-11-05',
    'a client that states no version must get exactly what it got before');
  assert.equal(r.body.result.serverInfo.name, 'appcrane');
});

test('initialize echoes any requested supported revision', async () => {
  for (const v of ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28']) {
    const r = await rpc('initialize', { protocolVersion: v });
    assert.equal(r.body.result.protocolVersion, v, `should negotiate ${v}`);
  }
});

test('server/discover answers for 2026-07-28 clients', async () => {
  const r = await rpc('server/discover', {
    _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' },
  });
  assert.equal(r.body.error, undefined, JSON.stringify(r.body.error));
  assert.equal(r.body.result.protocolVersion, '2026-07-28');
  assert.ok(r.body.result.capabilities.tools, 'advertises tools capability');
  assert.equal(r.header, '2026-07-28', 'negotiated version echoed in the header');
});

test('version may arrive via _meta or header, not just params', async () => {
  const viaMeta = await rpc('tools/list', { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } });
  assert.equal(viaMeta.header, '2026-07-28');

  const viaHeader = await rpc('tools/list', {}, { 'MCP-Protocol-Version': '2025-11-25' });
  assert.equal(viaHeader.header, '2025-11-25');
});

test('an unknown future revision degrades to our newest, not an error', async () => {
  const r = await rpc('initialize', { protocolVersion: '2099-01-01' });
  assert.equal(r.body.result.protocolVersion, '2026-07-28');
});

test('tools list and dispatch across revisions', async () => {
  for (const v of ['2024-11-05', '2026-07-28']) {
    const r = await rpc('tools/list', { _meta: { 'io.modelcontextprotocol/protocolVersion': v } });
    assert.ok(Array.isArray(r.body.result?.tools), `tools/list broken on ${v}`);
    assert.ok(r.body.result.tools.length > 0, `no tools returned on ${v}`);
  }
});

test('ping still answers though the new revision drops it', async () => {
  assert.deepEqual((await rpc('ping', {})).body.result, {});
});

test('unknown methods still error cleanly', async () => {
  assert.equal((await rpc('does/notExist', {})).body.error.code, -32601);
});
