import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import https from 'https';
import { execFileSync } from 'child_process';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The S3 export behind SIEM sinks and owner audit streams (siem/s3Export.js):
// a custom endpoint is dialled through the SIEM network guard (the address
// checked is the address dialled) and a redirect is never followed, so an
// endpoint that answers 307 cannot bounce the signed upload, with the audit
// events in it, to another host.

const dir = mkdtempSync(join(tmpdir(), 'crane-s3-guard-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=127.0.0.1',
  '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem')], { stdio: 'ignore' });
const tls = { key: readFileSync(join(dir, 'k.pem')), cert: readFileSync(join(dir, 'c.pem')) };
// The pre-fix client was plain fetch with no CA option; trusting the test
// certificate process-wide lets both clients reach the endpoint.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const { sendS3 } = await import('../server/services/siem/s3Export.js');
const { s3GetObject } = await import('../server/services/s3.js');

let endpoint, elsewhere, endpointBase, elsewhereBase;
const hits = { endpoint: [], elsewhere: [] };

function serve(name, handler) {
  return new Promise((resolve) => {
    const s = https.createServer(tls, (req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => { hits[name].push({ method: req.method, url: req.url, body: Buffer.concat(chunks).toString() }); handler(req, res); });
    });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}

before(async () => {
  elsewhere = await serve('elsewhere', (req, res) => { res.writeHead(200, { ETag: '"x"' }); res.end(); });
  elsewhereBase = `https://127.0.0.1:${elsewhere.address().port}`;
  endpoint = await serve('endpoint', (req, res) => {
    if (req.url.includes('/redirect-bucket/')) { res.writeHead(307, { Location: `${elsewhereBase}/stolen${req.url}` }); return res.end(); }
    res.writeHead(200, { ETag: '"ok"' });
    res.end();
  });
  endpointBase = `https://127.0.0.1:${endpoint.address().port}`;
});

after(() => {
  endpoint?.close(); elsewhere?.close();
  rmSync(dir, { recursive: true, force: true });
});

const docs = [{ '@timestamp': '2026-11-22T10:00:00.000Z', appcrane: { event_id: 7 }, message: 'audit event' }];
const sink = (bucket) => ({ config: { endpoint: endpointBase, bucket, region: 'us-east-1', access_key_id: 'AKIDEXAMPLE' }, ca_pem: tls.cert.toString() });

test('an allow-listed endpoint receives the upload', async () => {
  await sendS3(docs, sink('ok-bucket'), { secret_access_key: 'secret' }, ['127.0.0.1']);
  assert.equal(hits.endpoint.at(-1).method, 'PUT');
  assert.match(hits.endpoint.at(-1).body, /audit event/);
});

test('a 307 from the endpoint is not followed', async () => {
  const err = await sendS3(docs, sink('redirect-bucket'), { secret_access_key: 'secret' }, ['127.0.0.1']).then(() => null, (e) => e);
  assert.equal(hits.elsewhere.length, 0, `the signed upload followed the redirect to another host: ${JSON.stringify(hits.elsewhere)}`);
  assert.match(String(err?.message), /307/);
});

test('an endpoint off the allowlist is refused before connecting', async () => {
  const before = hits.endpoint.length;
  await assert.rejects(sendS3(docs, sink('ok-bucket'), { secret_access_key: 'secret' }, []), { code: 'EBLOCKEDADDRESS' });
  assert.equal(hits.endpoint.length, before);
});

test('a GET (backup restore) does not follow a redirect to another host', async () => {
  const conn = { endpoint: endpointBase, bucket: 'redirect-bucket', region: 'us-east-1', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'secret' };
  const err = await s3GetObject(conn, 'manifest.json').then(() => null, (e) => e);
  assert.equal(hits.elsewhere.length, 0, `the GET followed the redirect: ${JSON.stringify(hits.elsewhere)}`);
  assert.ok(err, 'the redirect was treated as the object');
});
