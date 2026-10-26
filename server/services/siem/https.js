import https from 'https';
import zlib from 'zlib';
import { promisify } from 'util';
import { toCef } from './mapping.js';
import { guardFor } from './netGuard.js';
import { scrubText } from '../eventScrub.js';

// HTTPS JSON sinks. One request builder per preset; all of them go through
// postHttps(), which pins the guarded DNS lookup, verifies TLS (system roots or
// the sink's custom CA), never follows redirects and caps the response it reads.

const gzip = promisify(zlib.gzip);
const TIMEOUT_MS = 20_000;
const MAX_RESPONSE = 64 * 1024;
const DEFAULT_MAX_BYTES = 1024 * 1024;

export const HTTPS_PRESETS = {
  generic:  { label: 'Generic HTTPS JSON (webhook)', secrets: ['auth_value'] },
  splunk:   { label: 'Splunk HTTP Event Collector', secrets: ['token'] },
  datadog:  { label: 'Datadog logs intake', secrets: ['api_key'] },
  elastic:  { label: 'Elastic / OpenSearch _bulk', secrets: ['api_key', 'password'] },
  sumo:     { label: 'Sumo Logic HTTP source', secrets: ['url'] },
  sentinel: { label: 'Microsoft Sentinel (Logs Ingestion API)', secrets: ['client_secret'] },
};

function httpError(status, text) {
  const snippet = scrubText(String(text || '').slice(0, 300)).slice(0, 200);
  return Object.assign(new Error(`HTTP ${status}${snippet ? `: ${snippet}` : ''}`), { status });
}

/** POST over TLS with the SIEM network policy. Resolves { status, text }; never follows a redirect. */
export function postHttps(rawUrl, { headers = {}, body, sink, allowlist, method = 'POST' }) {
  let url;
  try { url = new URL(rawUrl); } catch { return Promise.reject(new Error('destination is not a valid URL')); }
  if (url.protocol !== 'https:') return Promise.reject(new Error('only https:// destinations are allowed'));
  let guard;
  try { guard = guardFor(url.hostname, allowlist); } catch (e) { return Promise.reject(e); }
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body ?? '', 'utf8');
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method,
      lookup: guard.lookup,
      ca: sink.ca_pem ? [sink.ca_pem] : undefined,
      rejectUnauthorized: !sink.tls_skip_verify,
      minVersion: 'TLSv1.2',
      headers: { 'content-length': payload.length, 'user-agent': 'AppCrane-SIEM', ...headers },
      timeout: TIMEOUT_MS,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => { if (size < MAX_RESPONSE) { chunks.push(c); size += c.length; } });
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8').slice(0, MAX_RESPONSE) }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error(`request to ${url.hostname} timed out`)));
    req.on('error', reject);
    req.end(payload);
  });
}

function ndjson(lines) {
  return lines.join('\n') + '\n';
}

function line(doc, sink) {
  return sink.format === 'cef' ? toCef(doc) : JSON.stringify(doc);
}

function sentinelRow(d) {
  return {
    TimeGenerated: d['@timestamp'],
    EventId: d.event.id,
    Kind: d.appcrane.kind,
    Severity: d.appcrane.severity,
    Outcome: d.event.outcome,
    Category: d.event.category.join(','),
    Message: d.message,
    UserId: d.user?.id ?? null,
    UserName: d.user?.name ?? null,
    AppSlug: d.appcrane.app?.slug ?? null,
    SourceIp: d.source?.ip ?? null,
    Data: d.appcrane.data ?? null,
  };
}

const sentinelTokens = new Map();

async function sentinelToken(sink, secrets, allowlist) {
  const c = sink.config;
  const cacheKey = `${sink.id}:${c.tenant_id}:${c.client_id}`;
  const hit = sentinelTokens.get(cacheKey);
  if (hit && hit.exp > Date.now()) return hit.token;
  const authority = (c.authority || 'https://login.microsoftonline.com').replace(/\/+$/, '');
  const form = new URLSearchParams({
    client_id: c.client_id, client_secret: secrets.client_secret || '',
    grant_type: 'client_credentials', scope: 'https://monitor.azure.com//.default',
  }).toString();
  const res = await postHttps(`${authority}/${encodeURIComponent(c.tenant_id)}/oauth2/v2.0/token`, {
    headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form, sink, allowlist,
  });
  if (res.status !== 200) throw httpError(res.status, 'token request refused');
  let j;
  try { j = JSON.parse(res.text); } catch { throw new Error('token endpoint returned no JSON'); }
  if (!j.access_token) throw new Error('token endpoint returned no access_token');
  sentinelTokens.set(cacheKey, { token: j.access_token, exp: Date.now() + Math.max(60, Number(j.expires_in || 3600) - 120) * 1000 });
  return j.access_token;
}

export function _clearSentinelTokens() { sentinelTokens.clear(); }

/** Build { url, headers, body, check? } for one chunk of documents. */
export async function buildHttpsRequest(docs, sink, secrets, allowlist) {
  const c = sink.config;
  switch (sink.preset) {
    case 'splunk': {
      const base = String(c.url || '').replace(/\/+$/, '');
      const url = /\/services\/collector(\/event)?$/.test(base) ? base : `${base}/services/collector/event`;
      const body = docs.map(d => JSON.stringify({
        time: Date.parse(d['@timestamp']) / 1000, host: d.observer.hostname, source: 'appcrane',
        sourcetype: c.sourcetype || (sink.format === 'cef' ? 'cef' : '_json'), ...(c.index ? { index: c.index } : {}),
        event: sink.format === 'cef' ? toCef(d) : d,
      })).join('\n');
      return { url, headers: { authorization: `Splunk ${secrets.token || ''}`, 'content-type': 'application/json' }, body };
    }
    case 'datadog': {
      const url = c.url || `https://http-intake.logs.${c.site || 'datadoghq.com'}/api/v2/logs`;
      const body = JSON.stringify(docs.map(d => ({
        ...(sink.format === 'cef' ? { message: toCef(d) } : d),
        ddsource: 'appcrane', service: c.service || 'appcrane', hostname: d.observer.hostname,
        ...(c.tags ? { ddtags: c.tags } : {}),
      })));
      return { url, headers: { 'dd-api-key': secrets.api_key || '', 'content-type': 'application/json' }, body };
    }
    case 'elastic': {
      const base = String(c.url || '').replace(/\/+$/, '');
      const index = c.index || 'appcrane-events';
      const lines = [];
      for (const d of docs) {
        lines.push(JSON.stringify({ create: { _index: index, _id: d.event.id } }));
        lines.push(JSON.stringify(d));
      }
      const auth = secrets.api_key ? `ApiKey ${secrets.api_key}`
        : c.username ? `Basic ${Buffer.from(`${c.username}:${secrets.password || ''}`).toString('base64')}` : null;
      return {
        url: `${base}/_bulk`, body: ndjson(lines),
        headers: { 'content-type': 'application/x-ndjson', ...(auth ? { authorization: auth } : {}) },
        check: (text) => {
          let j;
          try { j = JSON.parse(text); } catch { throw new Error('_bulk returned no JSON'); }
          if (!j.errors) return;
          const bad = (j.items || []).map(i => i.create || i.index || {}).find(i => i.status && i.status !== 409 && (i.status < 200 || i.status >= 300));
          if (bad) throw new Error(`_bulk item refused: HTTP ${bad.status} ${scrubText(bad.error?.type || '')}`);
        },
      };
    }
    case 'sumo': {
      return {
        url: secrets.url || '', body: ndjson(docs.map(d => line(d, sink))),
        headers: { 'content-type': 'text/plain', ...(c.category ? { 'x-sumo-category': c.category } : {}), 'x-sumo-name': 'appcrane' },
      };
    }
    case 'sentinel': {
      const token = await sentinelToken(sink, secrets, allowlist);
      const base = String(c.dce_url || '').replace(/\/+$/, '');
      const url = `${base}/dataCollectionRules/${encodeURIComponent(c.dcr_id || '')}/streams/${encodeURIComponent(c.stream || '')}?api-version=2023-01-01`;
      return { url, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(docs.map(sentinelRow)) };
    }
    default: {
      const headers = { 'content-type': sink.format === 'cef' ? 'text/plain' : 'application/json' };
      if (c.auth_header && secrets.auth_value) headers[String(c.auth_header).toLowerCase()] = secrets.auth_value;
      const body = sink.format === 'cef' ? ndjson(docs.map(d => toCef(d))) : JSON.stringify(docs);
      return { url: c.url || '', headers, body };
    }
  }
}

function maxBytesFor(sink) {
  if (sink.preset === 'datadog') return 4 * 1024 * 1024;
  return Math.min(Number(sink.config.max_bytes) || DEFAULT_MAX_BYTES, 10 * 1024 * 1024);
}

async function sendChunk(docs, sink, secrets, allowlist) {
  const r = await buildHttpsRequest(docs, sink, secrets, allowlist);
  if (docs.length > 1 && Buffer.byteLength(r.body) > maxBytesFor(sink)) {
    const mid = Math.ceil(docs.length / 2);
    await sendChunk(docs.slice(0, mid), sink, secrets, allowlist);
    await sendChunk(docs.slice(mid), sink, secrets, allowlist);
    return;
  }
  let body = r.body;
  const headers = { ...r.headers };
  if (sink.config.gzip) { body = await gzip(Buffer.from(body)); headers['content-encoding'] = 'gzip'; }
  const res = await postHttps(r.url, { headers, body, sink, allowlist });
  if (res.status === 401 && sink.preset === 'sentinel') _clearSentinelTokens();
  if (res.status < 200 || res.status >= 300) throw httpError(res.status, res.text);
  r.check?.(res.text);
}

export async function sendHttps(docs, sink, secrets, allowlist) {
  if (!docs.length) return;
  const per = sink.preset === 'datadog' ? 1000 : docs.length;
  for (let i = 0; i < docs.length; i += per) await sendChunk(docs.slice(i, i + per), sink, secrets, allowlist);
}
