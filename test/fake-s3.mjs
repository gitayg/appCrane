// An in-process S3 for tests: path-style, verifies every request's SigV4
// signature and payload hash with its own implementation (not s3.js's), and
// implements PUT/GET/DELETE, multipart create/upload-part/complete/abort,
// ListObjectsV2 (paged) and DeleteObjects. No network beyond 127.0.0.1.
import http from 'http';
import crypto from 'crypto';

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const md5hex = (b) => crypto.createHash('md5').update(b).digest('hex');
const hmac = (k, s) => crypto.createHmac('sha256', k).update(s, 'utf8').digest();
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const unesc = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

function errXml(code, message) {
  return `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${esc(message)}</Message></Error>`;
}

export async function startFakeS3({ bucket = 'test-bucket', region = 'us-east-1', accessKeyId = 'AKIDFAKE', secretAccessKey = 'fake-secret-key', pageSize = 1000 } = {}) {
  const objects = new Map();
  const uploads = new Map();
  const log = [];
  const state = { failOn: null, pageSize, requireMd5: false };

  function verify(req, body, rawPath, rawQuery) {
    const auth = req.headers.authorization || '';
    const m = /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/s3\/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$/.exec(auth);
    if (!m) return 'malformed Authorization';
    const [, ak, date, reg, signed, sig] = m;
    if (ak !== accessKeyId) return 'InvalidAccessKeyId';
    if (reg !== region) return 'wrong region';
    const payloadHash = req.headers['x-amz-content-sha256'];
    if (payloadHash !== sha256(body)) return 'XAmzContentSHA256Mismatch';
    const names = signed.split(';');
    if (!names.includes('host') || !names.includes('x-amz-date') || !names.includes('x-amz-content-sha256')) return 'required header not signed';
    for (const h of Object.keys(req.headers)) if (h.startsWith('x-amz-') && !names.includes(h)) return `unsigned ${h}`;
    const canonHeaders = names.map((n) => `${n}:${String(req.headers[n] ?? '').trim()}\n`).join('');
    const pairs = rawQuery ? rawQuery.split('&').map((p) => { const i = p.indexOf('='); return i < 0 ? [p, ''] : [p.slice(0, i), p.slice(i + 1)]; }) : [];
    const canonQuery = pairs.map(([k, v]) => [enc(decodeURIComponent(k)), enc(decodeURIComponent(v))])
      .sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : (a[0] < b[0] ? -1 : 1))).map(([k, v]) => `${k}=${v}`).join('&');
    const canonical = [req.method, rawPath, canonQuery, canonHeaders, signed, payloadHash].join('\n');
    const amzDate = req.headers['x-amz-date'];
    const scope = `${date}/${reg}/s3/aws4_request`;
    const sts = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonical)].join('\n');
    let k = hmac('AWS4' + secretAccessKey, date);
    k = hmac(k, reg); k = hmac(k, 's3'); k = hmac(k, 'aws4_request');
    const expect = crypto.createHmac('sha256', k).update(sts).digest('hex');
    return expect === sig ? null : 'SignatureDoesNotMatch';
  }

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const [rawPath, rawQuery = ''] = req.url.split('?');
      const q = new URLSearchParams(rawQuery);
      const send = (status, xml, headers = {}) => { res.writeHead(status, { 'content-type': 'application/xml', ...headers }); res.end(xml); };
      const bad = verify(req, body, rawPath, rawQuery);
      const segs = rawPath.split('/').slice(1);
      const b = decodeURIComponent(segs[0] || '');
      const key = segs.length > 1 ? segs.slice(1).map(decodeURIComponent).join('/') : null;
      let op;
      if (req.method === 'PUT' && q.has('partNumber')) op = 'UPLOAD-PART';
      else if (req.method === 'PUT') op = 'PUT';
      else if (req.method === 'POST' && q.has('uploads')) op = 'CREATE-MULTIPART';
      else if (req.method === 'POST' && q.has('uploadId')) op = 'COMPLETE-MULTIPART';
      else if (req.method === 'POST' && q.has('delete')) op = 'DELETE-OBJECTS';
      else if (req.method === 'DELETE' && q.has('uploadId')) op = 'ABORT-MULTIPART';
      else if (req.method === 'DELETE') op = 'DELETE';
      else if (req.method === 'GET' && key == null) op = 'LIST';
      else op = 'GET';
      const entry = { op, key, bytes: body.length, sse: req.headers['x-amz-server-side-encryption'] || null, partNumber: q.get('partNumber') };
      log.push(entry);
      if (bad) { entry.rejected = bad; return send(403, errXml(bad === 'InvalidAccessKeyId' ? bad : 'SignatureDoesNotMatch', bad)); }
      if (b !== bucket) return send(404, errXml('NoSuchBucket', 'The specified bucket does not exist'));
      if (state.failOn && state.failOn(entry, log)) { entry.injected = true; return send(500, errXml('InternalError', 'injected failure')); }

      if (op === 'PUT') {
        objects.set(key, { body, last_modified: new Date().toISOString(), sse: entry.sse });
        return send(200, '', { etag: `"${md5hex(body)}"` });
      }
      if (op === 'GET') {
        const o = objects.get(key);
        if (!o) return send(404, errXml('NoSuchKey', 'The specified key does not exist.'));
        res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': o.body.length });
        return res.end(o.body);
      }
      if (op === 'DELETE') { objects.delete(key); return send(204, ''); }
      if (op === 'CREATE-MULTIPART') {
        const id = crypto.randomBytes(12).toString('hex');
        uploads.set(id, { key, parts: new Map(), sse: entry.sse });
        return send(200, `<InitiateMultipartUploadResult><Bucket>${bucket}</Bucket><Key>${esc(key)}</Key><UploadId>${id}</UploadId></InitiateMultipartUploadResult>`);
      }
      if (op === 'UPLOAD-PART') {
        const u = uploads.get(q.get('uploadId'));
        if (!u || u.key !== key) return send(404, errXml('NoSuchUpload', 'no such upload'));
        u.parts.set(Number(q.get('partNumber')), body);
        return send(200, '', { etag: `"${md5hex(body)}"` });
      }
      if (op === 'COMPLETE-MULTIPART') {
        const u = uploads.get(q.get('uploadId'));
        if (!u || u.key !== key) return send(404, errXml('NoSuchUpload', 'no such upload'));
        const listed = [...body.toString().matchAll(/<Part><PartNumber>(\d+)<\/PartNumber><ETag>([^<]+)<\/ETag><\/Part>/g)].map((m) => [Number(m[1]), unesc(m[2])]);
        const bufs = [];
        for (const [n, etag] of listed) {
          const p = u.parts.get(n);
          if (!p || etag !== `"${md5hex(p)}"`) return send(400, errXml('InvalidPart', `part ${n} etag mismatch`));
          bufs.push(p);
        }
        if (listed.length !== u.parts.size) return send(400, errXml('InvalidPart', 'not every uploaded part was listed'));
        const all = Buffer.concat(bufs);
        const etag = `"${md5hex(Buffer.concat(bufs.map((p) => crypto.createHash('md5').update(p).digest())))}-${bufs.length}"`;
        objects.set(key, { body: all, last_modified: new Date().toISOString(), sse: u.sse, etag });
        uploads.delete(q.get('uploadId'));
        return send(200, `<CompleteMultipartUploadResult><Key>${esc(key)}</Key><ETag>${esc(etag)}</ETag></CompleteMultipartUploadResult>`);
      }
      if (op === 'ABORT-MULTIPART') { uploads.delete(q.get('uploadId')); return send(204, ''); }
      if (op === 'LIST') {
        if (q.get('list-type') !== '2') return send(400, errXml('InvalidArgument', 'list-type=2 only'));
        const prefix = q.get('prefix') || '';
        const keys = [...objects.keys()].filter((k) => k.startsWith(prefix)).sort();
        const start = q.get('continuation-token') ? Number(Buffer.from(q.get('continuation-token'), 'base64').toString()) : 0;
        const page = keys.slice(start, start + state.pageSize);
        const more = start + state.pageSize < keys.length;
        const contents = page.map((k) => `<Contents><Key>${esc(k)}</Key><Size>${objects.get(k).body.length}</Size><LastModified>${objects.get(k).last_modified}</LastModified></Contents>`).join('');
        return send(200, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>${bucket}</Name><Prefix>${esc(prefix)}</Prefix><KeyCount>${page.length}</KeyCount><IsTruncated>${more}</IsTruncated>${more ? `<NextContinuationToken>${Buffer.from(String(start + state.pageSize)).toString('base64')}</NextContinuationToken>` : ''}${contents}</ListBucketResult>`);
      }
      if (op === 'DELETE-OBJECTS') {
        const sum = req.headers['x-amz-checksum-sha256'];
        const md5 = req.headers['content-md5'];
        entry.checksum = sum ? 'sha256' : (md5 ? 'md5' : null);
        if (state.requireMd5 && !md5) return send(400, errXml('InvalidRequest', 'Missing required header for this request: Content-MD5'));
        if (!sum && !md5) return send(400, errXml('InvalidRequest', 'Missing required header for this request: Content-MD5'));
        if (sum && (sum !== crypto.createHash('sha256').update(body).digest('base64') || req.headers['x-amz-sdk-checksum-algorithm'] !== 'SHA256')) return send(400, errXml('BadDigest', 'x-amz-checksum-sha256 mismatch'));
        if (md5 && md5 !== crypto.createHash('md5').update(body).digest('base64')) return send(400, errXml('InvalidDigest', 'Content-MD5 mismatch'));
        const keys = [...body.toString().matchAll(/<Key>([^<]*)<\/Key>/g)].map((m) => unesc(m[1]));
        entry.keys = keys;
        for (const k of keys) objects.delete(k);
        return send(200, `<DeleteResult>${keys.map((k) => `<Deleted><Key>${esc(k)}</Key></Deleted>`).join('')}</DeleteResult>`);
      }
      return send(400, errXml('NotImplemented', op));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  return {
    endpoint, bucket, region, accessKeyId, secretAccessKey, objects, uploads, log, state,
    conn: { bucket, region, endpoint, accessKeyId, secretAccessKey },
    close: () => new Promise((r) => server.close(r)),
  };
}
