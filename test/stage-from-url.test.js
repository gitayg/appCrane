import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Getting bytes in without paying for them by the character (v2.55.0).
//
// appcrane_stage_chunk makes the MODEL the data pipe: every byte is emitted as
// base64 inside a tool call, so a 600KB bundle is ~800KB of characters the
// model has to reproduce exactly. That costs output tokens per character and
// fails the whole upload on a single wrong one. It is fine for a config file
// and wrong for an artifact.
//
// appcrane_stage_from_url costs the same few dozen tokens whatever the file
// size, because AppCrane does the download. The hazard that buys is SSRF: this
// server sits next to Docker's socket, Caddy's admin API on 2019, its own API
// on 5001, and on a cloud host the metadata service on 169.254.169.254.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-url-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { isBlockedAddress, assertFetchable } = await import('../server/services/remoteFetch.js');

let user;
before(() => {
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@x.io','platform_admin','h',1,'human')"
  ).run().lastInsertRowid;
  user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
});

test('the addresses AppCrane must never be talked into fetching', () => {
  for (const ip of [
    '127.0.0.1',        // itself — API on 5001, Caddy admin on 2019
    '169.254.169.254',  // cloud metadata: instance credentials
    '10.1.2.3', '172.16.0.1', '192.168.1.1', '100.64.0.1',
    '::1', 'fd00::1', 'fe80::1',
    '::ffff:127.0.0.1', // IPv4 loopback wearing an IPv6 hat
  ]) {
    assert.equal(isBlockedAddress(ip), true, `${ip} must be blocked`);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '140.82.121.4', '2606:4700::1111']) {
    assert.equal(isBlockedAddress(ip), false, `${ip} is a normal public address`);
  }
});

test('plain http is refused — the bytes and any token in the URL would be in the clear', async () => {
  await assert.rejects(() => assertFetchable('http://example.com/x.zip'), /only https/);
});

test('a hostname resolving to a private address is refused', async () => {
  // localhost resolves to 127.0.0.1 / ::1 on every machine this runs on, so it
  // exercises the resolve-then-check path rather than a string match on the URL.
  await assert.rejects(() => assertFetchable('https://localhost/x.zip'),
    /private or link-local/);
});

test('a garbage URL is refused before any lookup', async () => {
  await assert.rejects(() => assertFetchable('not-a-url'), /not a valid URL/);
});

test('stage_chunk refuses to be used as a bulk pipe, and names the cheap paths', async () => {
  await assert.rejects(
    () => callTool(user, 'appcrane_stage_chunk', {
      session: 'big', part: 1, of: 40, content: 'aGk=', encoding: 'base64',
    }),
    (e) => {
      assert.match(e.message, /too many for this tool/);
      assert.match(e.message, /appcrane_stage_from_url/, 'the error must name the zero-cost alternative');
      assert.match(e.message, /api\/files\/staged/, 'and the curl path, which accepts MCP keys');
      return true;
    },
  );
});

test('a small file still goes through — the guardrail must not break the real use', async () => {
  const r = await callTool(user, 'appcrane_stage_chunk', {
    session: 'small', part: 1, of: 2, content: Buffer.from('hello').toString('base64'), encoding: 'base64',
  });
  const out = typeof r === 'string' ? JSON.parse(r) : (r.content ? JSON.parse(r.content[0].text) : r);
  assert.deepEqual(out.missing_parts, [2]);
});
