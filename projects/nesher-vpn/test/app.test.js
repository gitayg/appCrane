import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createPublicKey, createPrivateKey } from 'crypto';
import { createApp } from '../server.js';
import { generateKeyPair, isWgKey } from '../lib/wg.js';
import { allocateAddress, desiredPeers, purgeOld } from '../lib/passes.js';

const TOKEN = 'a'.repeat(40);
const USER = { 'X-AppCrane-Auth-Mode': 'authenticated', 'X-AppCrane-User-Id': '7', 'X-AppCrane-User-Email': 'u@x.io', 'X-AppCrane-App-Role': 'user', 'X-AppCrane-Is-Admin': '0' };
const OTHER = { ...USER, 'X-AppCrane-User-Id': '8', 'X-AppCrane-User-Email': 'o@x.io' };

async function boot(env = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), 'nvpn-'));
  const server = createApp({ AGENT_TOKEN: TOKEN, DATA_DIR: dataDir, VPN_ENDPOINT: 'nesher.example:51820', ...env }).listen(0);
  await new Promise(r => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, { headers = {}, body } = {}) => {
    const r = await fetch(base + path, { method, headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers }, body: body && JSON.stringify(body) });
    return { status: r.status, body: await r.json().catch(() => null) };
  };
  return { server, call, dataDir };
}
const agent = { Authorization: `Bearer ${TOKEN}` };
const serverKey = generateKeyPair().publicKey;

test('generated keys are valid WireGuard keys and the public half matches the private', () => {
  const { privateKey, publicKey } = generateKeyPair();
  assert.ok(isWgKey(privateKey) && isWgKey(publicKey));
  const d = Buffer.from(privateKey, 'base64').toString('base64url');
  const x = Buffer.from(publicKey, 'base64').toString('base64url');
  const derived = createPublicKey(createPrivateKey({ key: { kty: 'OKP', crv: 'X25519', d, x }, format: 'jwk' })).export({ format: 'jwk' }).x;
  assert.equal(derived, x);
});

test('allocation skips live passes and reuses expired/revoked addresses', () => {
  const now = Date.now(), future = new Date(now + 1e6).toISOString(), past = new Date(now - 1e6).toISOString();
  const passes = [
    { address: '10.77.0.2', expiresAt: future },
    { address: '10.77.0.3', expiresAt: past },
    { address: '10.77.0.4', expiresAt: future, revokedAt: past },
  ];
  assert.equal(allocateAddress(passes, now), '10.77.0.3');
  assert.deepEqual(desiredPeers(passes, now).map(p => p.allowedIps), ['10.77.0.2/32']);
  assert.equal(purgeOld([{ expiresAt: new Date(now - 8 * 86400e3).toISOString() }], now).length, 0);
});

test('end to end: agent check-in, issue, agent sees peer, revoke removes it', async () => {
  const { server, call, dataDir } = await boot();
  try {
    assert.equal((await call('GET', '/api/me')).status, 401);
    assert.equal((await call('POST', '/api/passes', { headers: USER, body: { name: 'phone', ttlHours: 8 } })).status, 409, 'no device yet');

    assert.equal((await call('GET', '/agent/peers', { headers: { Authorization: 'Bearer nope' } })).status, 401);
    assert.equal((await call('POST', '/agent/status', { headers: agent, body: { publicKey: serverKey, peers: [] } })).status, 200);

    assert.equal((await call('POST', '/api/passes', { headers: USER, body: { name: 'phone', ttlHours: 5 } })).status, 400, 'ttl must be a listed choice');
    const made = await call('POST', '/api/passes', { headers: USER, body: { name: 'phone', ttlHours: 8 } });
    assert.equal(made.status, 201);
    assert.match(made.body.config, /Endpoint = nesher\.example:51820/);
    assert.match(made.body.config, new RegExp(`PublicKey = ${serverKey.replace(/[+/]/g, '\\$&')}`));
    assert.match(made.body.config, /Address = 10\.77\.0\.2\/32/);
    assert.match(made.body.qrSvg, /^<svg/);

    const priv = made.body.config.match(/PrivateKey = (\S+)/)[1];
    assert.ok(!readFileSync(join(dataDir, 'state.json'), 'utf8').includes(priv), 'private key must never be stored');

    const peers = (await call('GET', '/agent/peers', { headers: agent })).body.peers;
    assert.equal(peers.length, 1);
    assert.equal(peers[0].allowedIps, '10.77.0.2/32');
    assert.ok(!('privateKey' in peers[0]));

    await call('POST', '/agent/status', { headers: agent, body: { publicKey: serverKey, peers: [{ publicKey: peers[0].publicKey, latestHandshake: 1700000000, rx: 5, tx: 6 }] } });
    const mine = (await call('GET', '/api/passes', { headers: USER })).body.passes[0];
    assert.equal(mine.lastHandshake, new Date(1700000000e3).toISOString());
    assert.equal(mine.txBytes, 6);

    assert.equal((await call('DELETE', `/api/passes/${made.body.pass.id}`, { headers: OTHER })).status, 404, "can't revoke someone else's");
    assert.equal((await call('GET', '/api/passes', { headers: OTHER })).body.passes.length, 0);
    assert.equal((await call('DELETE', `/api/passes/${made.body.pass.id}`, { headers: USER })).status, 200);
    assert.equal((await call('GET', '/agent/peers', { headers: agent })).body.peers.length, 0);
  } finally { server.close(); }
});

test('viewers cannot issue, non-JSON writes are refused, per-user cap holds', async () => {
  const { server, call } = await boot({ MAX_PASSES_PER_USER: '1' });
  try {
    await call('POST', '/agent/status', { headers: agent, body: { publicKey: serverKey } });
    assert.equal((await call('POST', '/api/passes', { headers: { ...USER, 'X-AppCrane-App-Role': 'viewer' }, body: { ttlHours: 1 } })).status, 403);
    const r = await fetch(`http://127.0.0.1:${server.address().port}/api/passes`, { method: 'POST', headers: { ...USER, 'Content-Type': 'text/plain' }, body: 'ttlHours=1' });
    assert.equal(r.status, 415);
    assert.equal((await call('POST', '/api/passes', { headers: USER, body: { ttlHours: 1 } })).status, 201);
    assert.equal((await call('POST', '/api/passes', { headers: USER, body: { ttlHours: 1 } })).status, 429);
  } finally { server.close(); }
});

test('agent endpoints refuse to run without a strong token configured', async () => {
  const { server, call } = await boot({ AGENT_TOKEN: 'short' });
  try { assert.equal((await call('GET', '/agent/peers', { headers: { Authorization: 'Bearer short' } })).status, 503); }
  finally { server.close(); }
});
