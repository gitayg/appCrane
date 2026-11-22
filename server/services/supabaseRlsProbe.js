// Can an anonymous visitor read this Supabase project's tables?
//
// The app's own anon key is in every browser that loads it, so anyone can ask
// PostgREST what this asks: list the tables (the OpenAPI root, /rest/v1/) and
// GET one row of each. A table that answers with a row has RLS off or a policy
// that lets anon read. Read-only by construction: GET only, the anon or
// publishable key only (anything else is refused before a request is made),
// redirects not followed, short timeouts, bodies capped and never kept: a
// table is reported by name and whether a row came back, never by content.

import { isPublicByDesign } from './releaseSecretScan.js';

const MAX_TABLES = 40;
const OPENAPI_MAX_BYTES = 4 * 1024 * 1024;
const ROW_MAX_BYTES = 256 * 1024;
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_$-]{0,62}$/;

/** https://<ref>.supabase.co, the only hosts the release check probes. */
export function supabaseUrlForRef(ref) {
  if (!/^[a-z0-9]{20}$/.test(String(ref || ''))) return null;
  return `https://${ref}.supabase.co`;
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
    if (size > max) { await reader.cancel().catch(() => {}); return { text: '', capped: true }; }
    chunks.push(value);
  }
  return { text: Buffer.concat(chunks).toString('utf8'), capped: false };
}

/**
 * @param {{ baseUrl: string, anonKey: string, tables?: string[], fetchImpl?: Function, timeoutMs?: number, deadlineMs?: number }} opts
 * @returns {Promise<{ ok: boolean, error: string|null, openapi_status: number|null, listed_from: string[],
 *   tables: Array<{ name: string, status: 'readable'|'no_rows'|'not_readable'|'error', http: number|null }> }>}
 */
export async function probeSupabaseRls({ baseUrl, anonKey, tables = [], fetchImpl = fetch, timeoutMs = 4000, deadlineMs = 20000 }) {
  if (!isPublicByDesign(anonKey)) throw new Error('probeSupabaseRls takes an anon or publishable key only');
  const base = String(baseUrl).replace(/\/+$/, '');
  const deadline = Date.now() + deadlineMs;
  const headers = { apikey: anonKey, Authorization: `Bearer ${anonKey}` };
  const out = { ok: true, error: null, openapi_status: null, listed_from: [], tables: [] };

  const get = async (url, accept, max) => {
    const left = deadline - Date.now();
    if (left <= 0) throw new Error('probe deadline reached');
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), Math.min(timeoutMs, left));
    try {
      const res = await fetchImpl(url, { method: 'GET', redirect: 'manual', signal: ctrl.signal, headers: { ...headers, Accept: accept } });
      const { text, capped } = await readCapped(res, max);
      return { status: res.status, text, capped };
    } finally {
      clearTimeout(t);
    }
  };
  const why = (e) => (e.name === 'AbortError' ? 'timed out' : (e.cause?.code || e.message));

  const names = new Set();
  try {
    const r = await get(`${base}/rest/v1/`, 'application/openapi+json, application/json', OPENAPI_MAX_BYTES);
    out.openapi_status = r.status;
    if (r.status === 200 && !r.capped) {
      const spec = JSON.parse(r.text);
      for (const p of Object.keys(spec?.paths || {})) {
        const n = p.replace(/^\//, '');
        if (n && !n.startsWith('rpc/') && NAME_RE.test(n)) names.add(n);
      }
      for (const n of Object.keys(spec?.definitions || {})) if (NAME_RE.test(n)) names.add(n);
      if (names.size) out.listed_from.push('openapi');
    }
  } catch (e) {
    out.openapi_error = why(e);
  }
  const before = names.size;
  for (const n of tables) if (NAME_RE.test(n)) names.add(n);
  if (names.size > before) out.listed_from.push('bundle');
  if (!names.size) {
    out.ok = false;
    out.error = out.openapi_error
      ? `could not list tables (${out.openapi_error})`
      : `no table to probe (the OpenAPI root answered ${out.openapi_status ?? 'nothing'} and the bundle names none)`;
    return out;
  }

  for (const name of [...names].slice(0, MAX_TABLES)) {
    try {
      const r = await get(`${base}/rest/v1/${encodeURIComponent(name)}?select=*&limit=1`, 'application/json', ROW_MAX_BYTES);
      let status = 'error';
      if (r.status === 200) {
        let rows = null;
        try { rows = r.capped ? null : JSON.parse(r.text); } catch { rows = null; }
        status = r.capped || (Array.isArray(rows) && rows.length > 0) ? 'readable' : Array.isArray(rows) ? 'no_rows' : 'error';
      } else if ([401, 403, 404].includes(r.status)) {
        status = 'not_readable';
      }
      out.tables.push({ name, status, http: r.status });
    } catch (e) {
      out.tables.push({ name, status: 'error', http: null, error: why(e) });
    }
  }
  if (names.size > MAX_TABLES) out.truncated = true;
  return out;
}
