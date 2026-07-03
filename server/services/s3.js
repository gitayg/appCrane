/**
 * Minimal AWS Signature V4 S3 PutObject — no SDK, no dependencies.
 *
 * Used by the scheduled off-site backup (v2.21.9). Supports AWS S3
 * (virtual-hosted style) and S3-compatible endpoints like Cloudflare R2
 * (path style, pass `endpoint`).
 *
 * The signing-key derivation is verified against AWS's documented test vector
 * in the s3.test — see scripts/verify-sigv4 or the inline check.
 */
import crypto from 'crypto';

function hmac(key, str) { return crypto.createHmac('sha256', key).update(str, 'utf8').digest(); }
function sha256hex(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

// AWS SigV4 signing key: HMAC chain over date → region → service → aws4_request.
export function signingKey(secret, dateStamp, region, service) {
  const kDate = hmac('AWS4' + secret, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

function encodeKey(key) {
  return key.split('/').map(s => encodeURIComponent(s)).join('/');
}

/**
 * PUT one object. `body` is a Buffer or string.
 * @param {{bucket,region,accessKeyId,secretAccessKey,key,body,contentType?,endpoint?}} o
 */
export async function s3PutObject(o) {
  const { bucket, region, accessKeyId, secretAccessKey, key, body,
          contentType = 'application/octet-stream', endpoint } = o;
  const service = 's3';
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const payloadHash = sha256hex(payload);

  // Path-style for custom endpoints (R2, MinIO), virtual-hosted for AWS.
  const host = endpoint ? new URL(endpoint).host : `${bucket}.s3.${region}.amazonaws.com`;
  const canonicalUri = endpoint ? `/${bucket}/${encodeKey(key)}` : `/${encodeKey(key)}`;
  const base = endpoint ? endpoint.replace(/\/$/, '') : `https://${host}`;
  const url = endpoint ? `${base}/${bucket}/${encodeKey(key)}` : `${base}${canonicalUri}`;

  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''); // YYYYMMDDTHHMMSSZ
  const dateStamp = amzDate.slice(0, 8);

  const canonicalHeaders =
    `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = ['PUT', canonicalUri, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');

  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(Buffer.from(canonicalRequest))].join('\n');
  const signature = crypto.createHmac('sha256', signingKey(secretAccessKey, dateStamp, region, service))
    .update(stringToSign, 'utf8').digest('hex');

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      'X-Amz-Date': amzDate,
      'X-Amz-Content-Sha256': payloadHash,
      'Authorization': authorization,
      'Content-Type': contentType,
      'Content-Length': String(payload.length),
    },
    body: payload,
    signal: AbortSignal.timeout(120000),
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(`S3 PUT failed (${res.status}): ${txt.slice(0, 300)}`);
  }
  return { key, size: payload.length, etag: res.headers.get('etag') || null };
}
