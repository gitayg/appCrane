// Does the app hand out data, or take writes, from a caller with no identity?
//
// AppCrane fronts every app with the SSO gate, but the gate is Caddy in front
// of the public URL. The container's own port is reachable without it (another
// app on the host, a misconfigured ingress, a published port, a headless or
// public mode), and an app that never verifies the signed X-AppCrane-* headers
// serves whoever reaches it. This probe is that caller: it goes straight to the
// sandbox's loopback port, the way health checks and the served-output crawl
// do, and sends no Cookie, no Authorization, no API key and no X-AppCrane-*
// header, so what it measures is the app's own auth.
//
// Reads are GET only. Writes are opt-in (policy probe_unauth_writes): a POST
// with an empty JSON body is not harmless (an insert of {} succeeds on many
// stacks, and a route may act on any POST), so by default a write route is
// only asked OPTIONS. Bodies are read capped and dropped: a finding is the
// route, the method, the status and the key names of what came back.

import { randomBytes } from 'crypto';
import { fetchAppProbe } from './appProbeFetch.js';
import { MAX_ROUTES, OPENAPI_PATHS, emptyRoutes, addCommon, collectOpenApi, skipReason } from './unauthRouteDiscovery.js';

const BODY_MAX_BYTES = 256 * 1024;
const OPENAPI_MAX_BYTES = 2 * 1024 * 1024;
const MAX_WRITES = 10;
const CONCURRENCY = 4;
export const PROBE_HEADER = 'X-Release-Check-Probe';
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
const SAFE_KEY_RE = /^[A-Za-z_$][A-Za-z0-9_$-]{0,39}$/;
const RECORD_KEY_RE = /^(?:_?id|uuid|email|e_?mail|user_?id|userid|user|users|username|user_?name|phone|phone_?number|password|password_?hash|ssn|address|customer_?id|account_?id|owner_?id)$/i;

/** The headers every probe request carries: nothing that identifies anyone. */
export function probeHeaders(extra = {}) {
  return { accept: 'application/json, */*;q=0.5', ...extra };
}

async function readCapped(res, max) {
  if (!res.body) return { text: '', capped: false };
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > max) { await reader.cancel().catch(() => {}); return { text: Buffer.concat(chunks).toString('utf8'), capped: true }; }
    chunks.push(value);
  }
  return { text: Buffer.concat(chunks).toString('utf8'), capped: false };
}

function keysOf(obj) {
  const all = Object.keys(obj);
  const safe = all.filter((k) => SAFE_KEY_RE.test(k)).slice(0, 8);
  const more = all.length - safe.length;
  return `{${safe.join(', ')}${more > 0 ? `${safe.length ? ', ' : ''}+${more} more` : ''}}`;
}
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Whether a JSON body looks like records, and its shape by key names only. */
export function describeRecords(json) {
  if (Array.isArray(json)) {
    const first = json.find(isObj);
    if (first) return { records: true, empty: false, shape: `array[${json.length}] of ${keysOf(first)}` };
    return { records: false, empty: json.length === 0, shape: `array[${json.length}]` };
  }
  if (!isObj(json)) return { records: false, empty: false, shape: typeof json };
  for (const [k, v] of Object.entries(json)) {
    if (!Array.isArray(v) || !v.some(isObj)) continue;
    const name = SAFE_KEY_RE.test(k) ? k : '<key>';
    return { records: true, empty: false, shape: `{${name}: array[${v.length}] of ${keysOf(v.find(isObj))}}` };
  }
  if (Object.entries(json).some(([k, v]) => RECORD_KEY_RE.test(k) && v !== null && v !== '' && v !== false)) {
    return { records: true, empty: false, shape: `object ${keysOf(json)}` };
  }
  const emptyList = Object.values(json).some((v) => Array.isArray(v) && v.length === 0);
  return { records: false, empty: emptyList, shape: `object ${keysOf(json)}` };
}

function readVerdict(status, type, text, capped) {
  if (status === 401 || status === 403) return { verdict: 'protected' };
  if (status === 404 || status === 405) return { verdict: 'absent' };
  if (status < 200 || status >= 300 || status === 204) return { verdict: 'other' };
  const t = text.trimStart();
  if (/html/i.test(type) || t.startsWith('<')) return { verdict: 'not_data' };
  if (capped) return /^\[\s*\{/.test(t) ? { verdict: 'records', shape: 'array (over 256 KB) of objects' } : { verdict: 'not_data' };
  let json;
  try { json = JSON.parse(t); } catch { return { verdict: 'not_data' }; }
  const d = describeRecords(json);
  return { verdict: d.records ? 'records' : d.empty ? 'empty_list' : 'not_data', shape: d.shape };
}

function writeVerdict(status) {
  if (status >= 200 && status < 300) return 'accepted';
  if (status === 401 || status === 403) return 'protected';
  if (status === 404 || status === 405) return 'absent';
  if (status === 400 || status === 422) return 'rejected_input';
  return 'other';
}

async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) await fn(items[i++]);
  }));
}

/**
 * @param {{ baseUrl: string, routes?: Map, probeWrites?: boolean, fetchImpl?: Function,
 *   timeoutMs?: number, deadlineMs?: number, maxRoutes?: number }} opts
 *   baseUrl is the sandbox's loopback origin; anything else is refused.
 */
export async function probeUnauthEndpoints({ baseUrl, routes, probeWrites = false, fetchImpl = fetchAppProbe, timeoutMs = 4000, deadlineMs = 30000, maxRoutes = MAX_ROUTES }) {
  const origin = new URL(baseUrl);
  if (!LOOPBACK.has(origin.hostname) || origin.protocol !== 'http:') throw new Error('probeUnauthEndpoints only probes an app over its loopback port');
  const deadline = Date.now() + deadlineMs;
  const marker = randomBytes(12).toString('base64url');
  const out = {
    ok: true, error: null, openapi: null, requests: 0, truncated: false, writes_probed: !!probeWrites,
    discovered: { bundle: 0, openapi: 0, common: 0 }, skipped: {}, reads: [], writes: [], write_candidates: [],
  };

  const send = async (method, path, { max = BODY_MAX_BYTES, headers, body } = {}) => {
    const left = deadline - Date.now();
    if (left <= 0) { out.truncated = true; throw Object.assign(new Error('probe deadline reached'), { deadline: true }); }
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), Math.min(timeoutMs, left));
    out.requests++;
    // A write is never re-sent through a redirect: only GET follows one.
    const doFetch = method === 'GET' ? fetchImpl : (u, o) => fetch(u, { ...o, redirect: 'manual' });
    try {
      const res = await doFetch(`${origin.origin}${path}`, { method, signal: ctrl.signal, headers: probeHeaders(headers), ...(body !== undefined ? { body } : {}) });
      const { text, capped } = await readCapped(res, max);
      return { status: res.status, type: res.headers.get('content-type') || '', allow: res.headers.get('allow') || '', text, capped };
    } finally {
      clearTimeout(t);
    }
  };
  const why = (e) => (e.name === 'AbortError' ? 'timed out' : (e.cause?.code || e.message));

  const all = new Map();
  for (const [p, r] of routes || emptyRoutes()) all.set(p, { path: p, methods: new Set(r.methods), sources: new Set(r.sources) });
  let reachable = false;
  for (const p of OPENAPI_PATHS) {
    let r;
    try { r = await send('GET', p, { max: OPENAPI_MAX_BYTES }); } catch (e) {
      if (e.deadline) break;
      if (!reachable && /ECONNREFUSED|ECONNRESET|EHOSTUNREACH/.test(why(e))) return { ...out, ok: false, error: `could not reach the sandbox (${why(e)})` };
      continue;
    }
    reachable = true;
    if (r.status !== 200 || r.capped) continue;
    let spec;
    try { spec = JSON.parse(r.text); } catch { continue; }
    if (collectOpenApi(spec, all)) { out.openapi = p; break; }
  }
  addCommon(all);

  const reads = [];
  for (const r of all.values()) {
    for (const s of r.sources) out.discovered[s] = (out.discovered[s] || 0) + 1;
    const skip = skipReason(r.path);
    if (skip) { out.skipped[skip] = (out.skipped[skip] || 0) + 1; continue; }
    if (r.methods.has('GET')) reads.push(r);
    if (r.methods.has('POST') || r.methods.has('PUT') || r.methods.has('PATCH')) out.write_candidates.push({ path: r.path, methods: [...r.methods].filter((m) => m !== 'GET' && m !== 'DELETE').sort() });
  }
  const rank = (r) => (r.sources.has('bundle') || r.sources.has('openapi') ? 0 : 1);
  reads.sort((a, b) => rank(a) - rank(b));
  if (reads.length > maxRoutes) out.truncated = true;

  await pool(reads.slice(0, maxRoutes), CONCURRENCY, async (r) => {
    if (Date.now() >= deadline) { out.truncated = true; return; }
    try {
      const res = await send('GET', r.path);
      const v = readVerdict(res.status, res.type, res.text, res.capped);
      out.reads.push({ method: 'GET', path: r.path, status: res.status, verdict: v.verdict, ...(v.shape ? { shape: v.shape } : {}) });
    } catch (e) {
      if (!e.deadline) out.reads.push({ method: 'GET', path: r.path, status: null, verdict: 'error', error: why(e) });
    }
  });

  const writes = out.write_candidates.filter((w) => w.methods.includes('POST')).slice(0, MAX_WRITES);
  if (out.write_candidates.length > MAX_WRITES) out.truncated = true;
  for (const w of writes) {
    if (Date.now() >= deadline) { out.truncated = true; break; }
    const entry = { method: 'POST', path: w.path, status: null, verdict: 'not_probed' };
    try {
      const o = await send('OPTIONS', w.path);
      entry.allow = o.allow.slice(0, 80) || null;
      if (probeWrites) {
        const res = await send('POST', w.path, { body: '{}', headers: { 'content-type': 'application/json', [PROBE_HEADER]: marker } });
        entry.status = res.status;
        entry.verdict = writeVerdict(res.status);
      }
    } catch (e) {
      if (!e.deadline) { entry.verdict = 'error'; entry.error = why(e); }
    }
    out.writes.push(entry);
  }
  out.reads.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}
