/**
 * Minimal AWS Signature V4 S3 client — no SDK, no dependencies.
 *
 * Used by the scheduled off-site backup (v2.21.9). Supports AWS S3
 * (virtual-hosted style) and S3-compatible endpoints like Cloudflare R2 and
 * MinIO (path style, pass `endpoint`).
 *
 * Operations: PutObject, GetObject (streamed to a file), DeleteObject,
 * ListObjectsV2, DeleteObjects, and multipart upload (create / upload-part /
 * complete / abort) driven from a stream, so an archive of any size is sent
 * one part at a time and never held whole in memory.
 *
 * Every request carries the SHA-256 of its payload in x-amz-content-sha256 and
 * signs it. Errors carry the S3 status, Code and Message only — never the URL,
 * a header, or the request S3 echoes back in a SignatureDoesNotMatch body.
 *
 * `conn` everywhere is { bucket, region, endpoint?, accessKeyId, secretAccessKey }.
 */
import crypto from 'crypto';
import { createWriteStream } from 'fs';
import { rm } from 'fs/promises';
import { Readable, Transform } from 'stream';
import { pipeline } from 'stream/promises';

export const MIN_PART_SIZE = 5 * 1024 * 1024;
export const DEFAULT_PART_SIZE = 16 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 10 * 60 * 1000;
const DOWNLOAD_TIMEOUT_MS = 6 * 60 * 60 * 1000;

function hmac(key, str) { return crypto.createHmac('sha256', key).update(str, 'utf8').digest(); }
function sha256hex(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
const EMPTY_SHA256 = sha256hex(Buffer.alloc(0));

// AWS SigV4 signing key: HMAC chain over date → region → service → aws4_request.
export function signingKey(secret, dateStamp, region, service) {
  const kDate = hmac('AWS4' + secret, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

// RFC 3986 encoding as SigV4 requires: encodeURIComponent leaves !'()* alone.
export function uriEncode(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function encodeKey(key) {
  return key.split('/').map(uriEncode).join('/');
}

function target(conn, key) {
  const { bucket, region, endpoint } = conn;
  if (endpoint) {
    const u = new URL(endpoint);
    const base = `${u.protocol}//${u.host}`;
    const path = key == null ? `/${bucket}` : `/${bucket}/${encodeKey(key)}`;
    return { host: u.host, canonicalUri: path, url: base + path };
  }
  const host = `${bucket}.s3.${region}.amazonaws.com`;
  const path = key == null ? '/' : `/${encodeKey(key)}`;
  return { host, canonicalUri: path, url: `https://${host}${path}` };
}

function canonicalQuery(query) {
  return Object.entries(query)
    .map(([k, v]) => [uriEncode(k), uriEncode(v == null ? '' : String(v))])
    .sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : (a[0] < b[0] ? -1 : 1)))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
}

/** Build the signed headers for one request. Exported for the signature test. */
export function signRequest({ conn, method, key = null, query = {}, headers = {}, payloadHash, now = new Date() }) {
  const { host, canonicalUri, url } = target(conn, key);
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const h = { host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  for (const [k, v] of Object.entries(headers)) if (v != null && v !== '') h[k.toLowerCase()] = String(v).trim();
  const names = Object.keys(h).sort();
  const canonicalHeaders = names.map((n) => `${n}:${h[n]}\n`).join('');
  const signedHeaders = names.join(';');
  const qs = canonicalQuery(query);
  const canonicalRequest = [method, canonicalUri, qs, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${dateStamp}/${conn.region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(Buffer.from(canonicalRequest))].join('\n');
  const signature = crypto.createHmac('sha256', signingKey(conn.secretAccessKey, dateStamp, conn.region, 's3'))
    .update(stringToSign, 'utf8').digest('hex');
  const out = { ...h };
  delete out.host;
  out.authorization = `AWS4-HMAC-SHA256 Credential=${conn.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { url: qs ? `${url}?${qs}` : url, headers: out };
}

const xmlDecode = (s) => s.replace(/&(lt|gt|quot|apos|amp|#\d+|#x[0-9a-f]+);/gi, (m, e) => {
  const map = { lt: '<', gt: '>', quot: '"', apos: "'", amp: '&' };
  if (map[e.toLowerCase()]) return map[e.toLowerCase()];
  return String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
});
const xmlEscape = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const tag = (xml, name) => { const m = new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(xml); return m ? xmlDecode(m[1]) : null; };

function s3Error(op, status, body) {
  const code = tag(body || '', 'Code');
  const message = tag(body || '', 'Message');
  const detail = code ? `${code}${message ? `: ${message}` : ''}` : (status === 403 ? 'access denied' : 'no error body');
  return Object.assign(new Error(`S3 ${op} failed (${status}): ${detail.slice(0, 300)}`), { status, s3Code: code });
}

async function request(conn, { op, method, key = null, query = {}, headers = {}, body = null, timeoutMs = REQUEST_TIMEOUT_MS }) {
  const payload = body == null ? null : (Buffer.isBuffer(body) ? body : Buffer.from(body));
  const payloadHash = payload ? sha256hex(payload) : EMPTY_SHA256;
  const signed = signRequest({ conn, method, key, query, headers, payloadHash });
  let res;
  try {
    res = await fetch(signed.url, { method, headers: signed.headers, body: payload, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    throw new Error(`S3 ${op} failed: ${e.cause?.code || e.name || 'network error'}`);
  }
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw s3Error(op, res.status, txt);
  }
  return res;
}

function sseHeaders(sse) {
  if (!sse || !sse.mode) return {};
  if (sse.mode === 'AES256') return { 'x-amz-server-side-encryption': 'AES256' };
  if (sse.mode === 'aws:kms') {
    return { 'x-amz-server-side-encryption': 'aws:kms', ...(sse.kmsKeyId ? { 'x-amz-server-side-encryption-aws-kms-key-id': sse.kmsKeyId } : {}) };
  }
  return {};
}

/**
 * PUT one object. `body` is a Buffer or string. Accepts the connection fields
 * inline (the v2.21.9 shape) plus optional `sse`.
 */
export async function s3PutObject(o) {
  const { key, body, contentType = 'application/octet-stream', sse } = o;
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const res = await request(o, {
    op: 'PUT', method: 'PUT', key, body: payload,
    headers: { 'content-type': contentType, ...sseHeaders(sse) },
  });
  return { key, size: payload.length, etag: res.headers.get('etag') || null };
}

/** GET an object and stream it to `dest`, hashing as it goes. */
export async function s3GetObjectToFile(conn, key, dest) {
  const res = await request(conn, { op: 'GET', method: 'GET', key, timeoutMs: DOWNLOAD_TIMEOUT_MS });
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  const tap = new Transform({ transform(c, _e, cb) { hash.update(c); bytes += c.length; cb(null, c); } });
  try {
    await pipeline(Readable.fromWeb(res.body), tap, createWriteStream(dest, { mode: 0o600 }));
  } catch (e) {
    await rm(dest, { force: true });
    throw new Error(`S3 GET failed while reading the body: ${e.code || e.message}`);
  }
  return { bytes, sha256: hash.digest('hex') };
}

/** GET a small object into memory (manifests, the connection probe). */
export async function s3GetObject(conn, key, { maxBytes = 16 * 1024 * 1024 } = {}) {
  const res = await request(conn, { op: 'GET', method: 'GET', key });
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxBytes) throw new Error(`S3 object ${key} is larger than ${maxBytes} bytes`);
  return buf;
}

export async function s3DeleteObject(conn, key) {
  await request(conn, { op: 'DELETE', method: 'DELETE', key });
}

/**
 * ListObjectsV2 under `prefix`, following continuation tokens up to maxPages.
 * `truncated: true` means the listing is INCOMPLETE — callers that delete
 * based on a listing must refuse to act on one.
 */
export async function s3ListObjects(conn, prefix = '', { maxPages = 50 } = {}) {
  const objects = [];
  let token = null;
  for (let page = 0; page < maxPages; page++) {
    const query = { 'list-type': '2', prefix, ...(token ? { 'continuation-token': token } : {}) };
    const res = await request(conn, { op: 'LIST', method: 'GET', query });
    const xml = await res.text();
    if (!/<ListBucketResult[\s>]/.test(xml)) throw new Error('S3 LIST returned something that is not a ListBucketResult');
    for (const m of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
      const key = tag(m[1], 'Key');
      if (key == null) continue;
      objects.push({ key, size: Number(tag(m[1], 'Size') || 0), last_modified: tag(m[1], 'LastModified') });
    }
    const truncated = tag(xml, 'IsTruncated') === 'true';
    token = tag(xml, 'NextContinuationToken');
    if (!truncated) return { objects, truncated: false };
    if (!token) throw new Error('S3 LIST is truncated but returned no continuation token');
  }
  return { objects, truncated: true };
}

// DeleteObjects needs a body checksum. Content-MD5 is MD5, which a FIPS
// provider refuses, so the request carries the SHA-256 checksum instead
// (x-amz-checksum-sha256, base64, with x-amz-sdk-checksum-algorithm naming
// it); both are x-amz-* headers and so are signed. An S3-compatible server
// that still insists on Content-MD5 gets it on a retry when MD5 is available,
// and per-key DeleteObject calls when it is not.
export function deleteObjectsChecksumHeaders(body) {
  return {
    'x-amz-checksum-sha256': crypto.createHash('sha256').update(body).digest('base64'),
    'x-amz-sdk-checksum-algorithm': 'SHA256',
  };
}

function wantsContentMd5(e) {
  return e?.status === 400 && /content-md5/i.test(e.message || '');
}

function contentMd5(body) {
  try {
    return crypto.createHash('md5').update(body).digest('base64');
  } catch {
    return null;
  }
}

/** DeleteObjects in batches of 1000. Returns what S3 reports deleted and failed. */
export async function s3DeleteObjects(conn, keys) {
  const deleted = [];
  const errors = [];
  for (let i = 0; i < keys.length; i += 1000) {
    const batch = keys.slice(i, i + 1000);
    const body = Buffer.from(`<?xml version="1.0" encoding="UTF-8"?><Delete><Quiet>false</Quiet>${batch.map((k) => `<Object><Key>${xmlEscape(k)}</Key></Object>`).join('')}</Delete>`);
    let res;
    try {
      res = await request(conn, {
        op: 'DELETE-OBJECTS', method: 'POST', query: { delete: '' }, body,
        headers: { ...deleteObjectsChecksumHeaders(body), 'content-type': 'application/xml' },
      });
    } catch (e) {
      if (!wantsContentMd5(e)) throw e;
      const md5 = contentMd5(body);
      if (!md5) {
        for (const k of batch) {
          try { await s3DeleteObject(conn, k); deleted.push(k); } catch (err) { errors.push({ key: k, code: err.s3Code || 'DeleteFailed' }); }
        }
        continue;
      }
      res = await request(conn, {
        op: 'DELETE-OBJECTS', method: 'POST', query: { delete: '' }, body,
        headers: { 'content-md5': md5, 'content-type': 'application/xml' },
      });
    }
    const xml = await res.text();
    for (const m of xml.matchAll(/<Deleted>([\s\S]*?)<\/Deleted>/g)) deleted.push(tag(m[1], 'Key'));
    for (const m of xml.matchAll(/<Error>([\s\S]*?)<\/Error>/g)) errors.push({ key: tag(m[1], 'Key'), code: tag(m[1], 'Code') });
  }
  return { deleted, errors };
}

/**
 * Upload a stream. Below one part it is a single PUT; at or above it, a
 * multipart upload whose parts are partSize bytes (the last may be shorter —
 * R2 requires every other part to be the same size). Any failure after the
 * multipart upload exists aborts it, so no orphaned parts are left billed.
 *
 * Returns { key, bytes, sha256, etag, parts, multipart }.
 */
export async function s3UploadStream(conn, key, readable, { partSize = DEFAULT_PART_SIZE, contentType = 'application/octet-stream', sse } = {}) {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  let pending = [];
  let pendingLen = 0;
  let uploadId = null;
  const parts = [];

  const uploadPart = async (buf) => {
    if (!uploadId) {
      const res = await request(conn, {
        op: 'CREATE-MULTIPART', method: 'POST', key, query: { uploads: '' },
        headers: { 'content-type': contentType, ...sseHeaders(sse) },
      });
      uploadId = tag(await res.text(), 'UploadId');
      if (!uploadId) throw new Error('S3 CREATE-MULTIPART returned no UploadId');
    }
    const partNumber = parts.length + 1;
    const res = await request(conn, { op: `UPLOAD-PART ${partNumber}`, method: 'PUT', key, query: { partNumber: String(partNumber), uploadId }, body: buf });
    const etag = res.headers.get('etag');
    if (!etag) throw new Error(`S3 UPLOAD-PART ${partNumber} returned no ETag`);
    parts.push({ partNumber, etag, bytes: buf.length });
  };

  try {
    for await (const chunk of readable) {
      const c = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      hash.update(c);
      bytes += c.length;
      pending.push(c);
      pendingLen += c.length;
      while (pendingLen >= partSize) {
        const all = Buffer.concat(pending, pendingLen);
        await uploadPart(all.subarray(0, partSize));
        const rest = all.subarray(partSize);
        pending = rest.length ? [rest] : [];
        pendingLen = rest.length;
      }
    }
    const tail = Buffer.concat(pending, pendingLen);
    if (!uploadId) {
      const r = await s3PutObject({ ...conn, key, body: tail, contentType, sse });
      return { key, bytes, sha256: hash.digest('hex'), etag: r.etag, parts: 1, multipart: false };
    }
    if (tail.length) await uploadPart(tail);
    const body = `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload>${parts.map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${xmlEscape(p.etag)}</ETag></Part>`).join('')}</CompleteMultipartUpload>`;
    const res = await request(conn, { op: 'COMPLETE-MULTIPART', method: 'POST', key, query: { uploadId }, body, headers: { 'content-type': 'application/xml' } });
    // S3 can answer 200 and still fail the completion in the body.
    const xml = await res.text();
    if (/<Error>/.test(xml)) throw s3Error('COMPLETE-MULTIPART', 200, xml);
    return { key, bytes, sha256: hash.digest('hex'), etag: tag(xml, 'ETag'), parts: parts.length, multipart: true };
  } catch (e) {
    if (uploadId) {
      await request(conn, { op: 'ABORT-MULTIPART', method: 'DELETE', key, query: { uploadId } }).catch(() => {});
    }
    if (typeof readable.destroy === 'function') readable.destroy();
    throw e;
  }
}
