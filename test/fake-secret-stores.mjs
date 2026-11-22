// In-process fakes of the four outside secret stores, on 127.0.0.1 only:
// Vault (KV v2 read, AppRole login), Infisical (universal auth + v3 raw secret),
// 1Password Connect (vault/item lookup by filter, item read) and SSM
// GetParameter (JSON 1.1), whose SigV4 signature is checked against the
// AWS SDK's own signer (@smithy/signature-v4), not against the code under test.
// Each records every request it saw in `calls`.
import http from 'node:http';
import crypto from 'node:crypto';
import { SignatureV4 } from '@smithy/signature-v4';

function listen(handler) {
  const calls = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', async () => {
      const url = new URL(req.url, 'http://x');
      calls.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), headers: req.headers, body });
      const send = (status, obj, type = 'application/json') => { res.writeHead(status, { 'content-type': type }); res.end(JSON.stringify(obj)); };
      try { await handler({ req, url, body, send }); } catch (e) { send(500, { error: String(e.message) }); }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    server, calls, url: `http://127.0.0.1:${server.address().port}`,
    close: () => { server.closeAllConnections?.(); server.close(); },
  })));
}

export async function startFakeVault() {
  const state = { tokens: new Set(), approles: new Map(), kv: new Map(), loginToken: 'approle-issued-token' };
  const fake = await listen(({ req, url, body, send }) => {
    if (req.method === 'POST' && url.pathname === '/v1/auth/approle/login') {
      const { role_id: r, secret_id: s } = JSON.parse(body || '{}');
      if (state.approles.get(r) !== s) return send(400, { errors: ['invalid role or secret ID'] });
      state.tokens.add(state.loginToken);
      return send(200, { auth: { client_token: state.loginToken } });
    }
    const m = /^\/v1\/([^/]+)\/data\/(.+)$/.exec(url.pathname);
    if (req.method !== 'GET' || !m) return send(404, { errors: [] });
    if (!state.tokens.has(req.headers['x-vault-token'])) return send(403, { errors: ['permission denied'] });
    const key = `${decodeURIComponent(m[1])}/${m[2].split('/').map(decodeURIComponent).join('/')}`;
    if (!state.kv.has(key)) return send(404, { errors: [] });
    return send(200, { data: { data: state.kv.get(key), metadata: { version: 1 } } });
  });
  return { ...fake, state };
}

export async function startFakeInfisical() {
  const state = { clients: new Map(), issued: new Set(), secrets: new Map() };
  const fake = await listen(({ req, url, body, send }) => {
    if (req.method === 'POST' && url.pathname === '/api/v1/auth/universal-auth/login') {
      const { clientId, clientSecret } = JSON.parse(body || '{}');
      if (state.clients.get(clientId) !== clientSecret) return send(401, { message: 'invalid credentials' });
      const t = `inf-token-${crypto.randomBytes(4).toString('hex')}`;
      state.issued.add(t);
      return send(200, { accessToken: t, expiresIn: 7200, tokenType: 'Bearer' });
    }
    const m = /^\/api\/v3\/secrets\/raw\/([^/]+)$/.exec(url.pathname);
    if (req.method !== 'GET' || !m) return send(404, { message: 'not found' });
    if (!state.issued.has(String(req.headers.authorization || '').replace(/^Bearer /, ''))) return send(401, { message: 'unauthorized' });
    const q = url.searchParams;
    const k = [q.get('workspaceId'), q.get('environment'), q.get('secretPath'), decodeURIComponent(m[1])].join('|');
    if (!state.secrets.has(k)) return send(404, { message: 'Secret not found' });
    return send(200, { secret: { secretKey: decodeURIComponent(m[1]), secretValue: state.secrets.get(k) } });
  });
  return { ...fake, state };
}

export async function startFakeOnePasswordConnect() {
  const state = { token: 'connect-token', vaults: [] };
  const filterValue = (q) => /^(?:name|title) eq "(.*)"$/.exec(q.get('filter') || '')?.[1];
  const fake = await listen(({ req, url, send }) => {
    if (req.headers.authorization !== `Bearer ${state.token}`) return send(401, { status: 401, message: 'Invalid token' });
    const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    if (parts[0] !== 'v1' || parts[1] !== 'vaults') return send(404, {});
    if (parts.length === 2) {
      const want = filterValue(url.searchParams);
      return send(200, state.vaults.filter((v) => want === undefined || v.name === want).map(({ id, name }) => ({ id, name })));
    }
    const vault = state.vaults.find((v) => v.id === parts[2]);
    if (!vault) return send(404, { status: 404, message: 'vault not found' });
    if (parts.length === 4 && parts[3] === 'items') {
      const want = filterValue(url.searchParams);
      return send(200, vault.items.filter((i) => want === undefined || i.title === want).map(({ id, title }) => ({ id, title })));
    }
    if (parts.length === 5 && parts[3] === 'items') {
      const item = vault.items.find((i) => i.id === parts[4]);
      return item ? send(200, item) : send(404, { status: 404, message: 'item not found' });
    }
    return send(404, {});
  });
  return { ...fake, state };
}

class NodeSha256 {
  constructor(secret) { this.h = secret ? crypto.createHmac('sha256', secret) : crypto.createHash('sha256'); }
  update(d) { this.h.update(typeof d === 'string' ? Buffer.from(d, 'utf8') : Buffer.from(d)); }
  async digest() { return new Uint8Array(this.h.digest()); }
}

export async function startFakeSsm({ accessKeyId, secretAccessKey, region = 'us-east-1' }) {
  const state = { params: new Map(), signatureFailures: 0 };
  const signer = new SignatureV4({ service: 'ssm', region, sha256: NodeSha256, credentials: { accessKeyId, secretAccessKey }, applyChecksum: false });
  const fake = await listen(async ({ req, url, body, send }) => {
    const auth = String(req.headers.authorization || '');
    const signedNames = /SignedHeaders=([a-z0-9;-]+)/.exec(auth)?.[1]?.split(';') || [];
    const amzDate = String(req.headers['x-amz-date'] || '');
    const signingDate = new Date(`${amzDate.slice(0, 4)}-${amzDate.slice(4, 6)}-${amzDate.slice(6, 8)}T${amzDate.slice(9, 11)}:${amzDate.slice(11, 13)}:${amzDate.slice(13, 15)}Z`);
    const headers = Object.fromEntries(signedNames.map((n) => [n, String(req.headers[n])]));
    const expected = await signer.sign({
      method: req.method, protocol: 'http:', hostname: '127.0.0.1', port: Number(req.headers.host.split(':')[1]), path: url.pathname, query: {}, headers, body,
    }, { signingDate });
    const type = 'application/x-amz-json-1.1';
    if (!signedNames.includes('host') || !signedNames.includes('x-amz-target') || expected.headers.authorization !== auth) {
      state.signatureFailures++;
      return send(403, { __type: 'InvalidSignatureException', message: 'signature mismatch' }, type);
    }
    if (req.headers['x-amz-target'] !== 'AmazonSSM.GetParameter') return send(400, { __type: 'InvalidAction' }, type);
    const input = JSON.parse(body || '{}');
    if (input.WithDecryption !== true) return send(400, { __type: 'ValidationException', message: 'expected WithDecryption' }, type);
    if (!state.params.has(input.Name)) return send(400, { __type: 'ParameterNotFound' }, type);
    return send(200, { Parameter: { Name: input.Name, Type: 'SecureString', Value: state.params.get(input.Name), Version: 1 } }, type);
  });
  return { ...fake, state };
}
