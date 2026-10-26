import zlib from 'zlib';
import { promisify } from 'util';
import { s3PutObject } from '../s3.js';
import { assertResolvable } from './netGuard.js';

// Object export: each delivered batch becomes one JSONL object under a daily
// prefix, <prefix>dt=YYYY-MM-DD/appcrane-events-<firstId>-<lastId>.jsonl[.gz].
// S3 has no append, so "daily JSONL" is a day's prefix of batch objects. The
// key is derived from the event ids, so a retried batch overwrites the same
// object instead of duplicating it.

const gzip = promisify(zlib.gzip);

export function exportKey(prefix, day, firstId, lastId, gz) {
  const p = prefix ? `${String(prefix).replace(/^\/+|\/+$/g, '')}/` : '';
  return `${p}dt=${day}/appcrane-events-${firstId}-${lastId}.jsonl${gz ? '.gz' : ''}`;
}

export async function sendS3(docs, sink, secrets, allowlist, { put = s3PutObject } = {}) {
  if (!docs.length) return;
  const c = sink.config;
  if (c.endpoint) {
    let host;
    try { const u = new URL(c.endpoint); if (u.protocol !== 'https:') throw new Error('x'); host = u.hostname; } catch { throw new Error('S3 endpoint must be an https:// URL'); }
    await assertResolvable(host, allowlist);
  }
  const byDay = new Map();
  for (const d of docs) {
    const day = d['@timestamp'].slice(0, 10);
    if (!byDay.has(day)) byDay.set(day, []);
    byDay.get(day).push(d);
  }
  for (const [day, list] of byDay) {
    const ids = list.map(d => d.appcrane.event_id);
    const body = list.map(d => JSON.stringify(d)).join('\n') + '\n';
    const gz = !!c.gzip;
    await put({
      bucket: c.bucket, region: c.region || 'us-east-1', endpoint: c.endpoint || undefined,
      accessKeyId: c.access_key_id, secretAccessKey: secrets.secret_access_key || '',
      key: exportKey(c.prefix, day, Math.min(...ids), Math.max(...ids), gz),
      body: gz ? await gzip(Buffer.from(body)) : body,
      contentType: gz ? 'application/gzip' : 'application/x-ndjson',
    });
  }
}
