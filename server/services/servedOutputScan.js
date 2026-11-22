// Secrets in what an app serves to browsers, for the release check.
//
// The source-tree check (releaseSecretScan.js) reads the commit. This reads the
// output: the HTML at the app's root, every same-origin script, stylesheet and
// source map it references or imports, a `.map` beside each script, and the
// .env paths a static server hands out by accident. Two sources, one matcher:
//
//   crawlServed    HTTP against a running release on its loopback port, which
//                  is exactly what a browser is sent (the SSO gate sits in
//                  front of the public URL, not this port)
//   scanBuiltDir   built output committed to the release tree (dist/, build/)
//
// A Supabase anon or publishable key is public by design and is never a
// finding; it is collected, with the project URL and the table names the
// bundle queries, as the input to the RLS probe. Values never leave this file:
// a finding carries the rule, the place and redact()'s prefix and length.

import { readdirSync, readFileSync, lstatSync, existsSync } from 'fs';
import { join, relative, extname } from 'path';
import { fetchAppProbe } from './appProbeFetch.js';
import { secretMatches } from './releaseSecretScan.js';
import { jwtPayload } from './adopt/secrets.js';
import { emptyRoutes, collectRoutes } from './unauthRouteDiscovery.js';

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_RESOURCES = 80;
const MAX_FINDINGS = 25;
const MAX_TABLES = 50;
const TEXT_EXT = new Set(['.js', '.mjs', '.cjs', '.css', '.html', '.htm', '.map', '.json', '.txt']);
const ASSET_EXT = /\.(?:m?js|cjs|css|map)$/i;
export const ENV_PROBE_PATHS = Object.freeze(['/.env', '/.env.local', '/.env.production', '/.env.production.local', '/.env.development']);
export const BUILT_DIRS = Object.freeze(['dist', 'build', 'out', 'public', '.next/static', 'client/dist', 'frontend/dist', 'web/dist', 'app/dist', 'apps/web/dist']);

const SUPABASE_URL_RE = /https:\/\/([a-z0-9]{20})\.supabase\.(?:co|in)\b/g;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const PUBLISHABLE_RE = /\bsb_publishable_[A-Za-z0-9_-]{16,}/g;
const FROM_TABLE_RE = /\.from\(\s*["'`]([A-Za-z_][A-Za-z0-9_]{0,62})["'`]\s*\)/g;

/** What may be shown of a secret: a short prefix and its length. */
export function redact(value) {
  const v = String(value ?? '');
  return `${v.slice(0, 6)}... (${v.length} chars)`;
}

export function emptySupabase() {
  return { refs: new Set(), anonKeys: new Map(), tables: new Set() };
}

function lineAt(text, index) {
  let n = 1;
  for (let i = text.indexOf('\n'); i !== -1 && i < index; i = text.indexOf('\n', i + 1)) n++;
  return n;
}

function collectSupabase(text, into) {
  for (const m of text.matchAll(SUPABASE_URL_RE)) into.refs.add(m[1]);
  for (const m of text.matchAll(JWT_RE)) {
    const p = jwtPayload(m[0]);
    if (p?.role === 'anon') into.anonKeys.set(m[0], typeof p.ref === 'string' ? p.ref : null);
  }
  for (const m of text.matchAll(PUBLISHABLE_RE)) into.anonKeys.set(m[0], null);
  for (const m of text.matchAll(FROM_TABLE_RE)) if (into.tables.size < MAX_TABLES) into.tables.add(m[1]);
}

/** Findings in one served file, values redacted. */
export function scanServedText(file, text, supabase = emptySupabase()) {
  collectSupabase(text, supabase);
  const seen = new Set();
  const findings = [];
  for (const m of secretMatches(text)) {
    const k = `${m.rule}:${m.value}`;
    if (seen.has(k)) continue;
    seen.add(k);
    findings.push({ file, line: lineAt(text, m.index), rule: m.rule, preview: redact(m.value) });
  }
  return findings;
}

function looksLikeEnvFile(text) {
  const t = text.trimStart();
  if (t.startsWith('<')) return 0;
  return (t.match(/^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/gm) || []).length;
}

function result() {
  return { ok: true, error: null, findings: [], scanned: [], truncated: false, html: false, supabase: emptySupabase(), routes: emptyRoutes() };
}

function addFindings(out, list) {
  for (const f of list) {
    if (out.findings.length >= MAX_FINDINGS) { out.truncated = true; return; }
    out.findings.push(f);
  }
}

async function readCapped(res) {
  if (!res.body) return { text: '', capped: false };
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  let capped = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_BYTES) { capped = true; await reader.cancel().catch(() => {}); break; }
    chunks.push(value);
  }
  return { text: Buffer.concat(chunks).toString('utf8'), capped };
}

/**
 * Fetch and scan what a running release serves.
 * @param {{ baseUrl: string, basePath?: string, fetchImpl?: Function, timeoutMs?: number, deadlineMs?: number }} opts
 *   baseUrl is the loopback origin (http://localhost:<port>); basePath is the
 *   public mount Caddy strips (/<slug>-sandbox/), removed from asset URLs.
 */
export async function crawlServed({ baseUrl, basePath = '/', fetchImpl = fetchAppProbe, timeoutMs = 5000, deadlineMs = 30000 }) {
  const out = result();
  const origin = new URL(baseUrl).origin;
  const mount = `/${String(basePath || '').replace(/^\/+|\/+$/g, '')}`;
  const deadline = Date.now() + deadlineMs;
  const queued = new Set();
  const queue = [];

  const toPath = (ref, from) => {
    if (!ref || /^(?:data|blob|javascript|mailto):/i.test(ref)) return null;
    let u;
    try { u = new URL(ref, `${origin}${from}`); } catch { return null; }
    if (u.origin !== origin) return null;
    let p = u.pathname;
    if (mount !== '/' && (p === mount || p.startsWith(`${mount}/`))) p = p.slice(mount.length) || '/';
    return p;
  };
  const enqueue = (p, kind) => {
    if (!p || queued.has(p)) return;
    if (queued.size >= MAX_RESOURCES) { out.truncated = true; return; }
    queued.add(p);
    queue.push({ path: p, kind });
  };

  const get = async (path) => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), Math.max(1, Math.min(timeoutMs, deadline - Date.now())));
    try {
      const res = await fetchImpl(`${origin}${path}`, { signal: ctrl.signal, headers: { accept: '*/*' } });
      const { text, capped } = await readCapped(res);
      return { status: res.status, type: res.headers.get('content-type') || '', text, capped };
    } finally {
      clearTimeout(t);
    }
  };

  let root;
  try {
    root = await get('/');
  } catch (e) {
    const why = e.name === 'AbortError' ? 'timed out' : (e.cause?.code || e.message);
    return { ...out, ok: false, error: `could not fetch / (${why})` };
  }
  queued.add('/');
  out.scanned.push({ path: '/', status: root.status, bytes: root.text.length });
  if (root.capped) out.truncated = true;
  const rootIsHtml = /html/i.test(root.type) || /^\s*<(?:!doctype|html)/i.test(root.text);
  if (root.status === 200) {
    addFindings(out, scanServedText('/', root.text, out.supabase));
    collectRoutes(root.text, out.routes, mount);
    if (rootIsHtml) {
      out.html = true;
      for (const m of root.text.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
        const p = toPath(m[1], '/');
        if (p && ASSET_EXT.test(p)) enqueue(p, 'asset');
      }
    }
  }
  for (const p of ENV_PROBE_PATHS) enqueue(p, 'env');

  while (queue.length) {
    if (Date.now() > deadline) { out.truncated = true; break; }
    const item = queue.shift();
    let r;
    try { r = await get(item.path); } catch { continue; }
    if (r.status !== 200) continue;
    const htmlFallback = /html/i.test(r.type) || /^\s*<(?:!doctype|html)/i.test(r.text);
    if (htmlFallback) continue;
    out.scanned.push({ path: item.path, status: r.status, bytes: r.text.length });
    if (r.capped) out.truncated = true;
    if (item.kind === 'env') {
      const vars = looksLikeEnvFile(r.text);
      if (!vars) continue;
      addFindings(out, [{ file: item.path, line: 1, rule: 'served-env-file', preview: `${vars} variable(s), values not shown` }]);
    }
    addFindings(out, scanServedText(item.path, r.text, out.supabase));
    if (/\.(?:m?js|cjs)$/i.test(item.path)) {
      collectRoutes(r.text, out.routes, mount);
      const map = /[#@]\s*sourceMappingURL=([^\s'"*]+)/.exec(r.text);
      if (map && !/^data:/i.test(map[1])) enqueue(toPath(map[1], item.path), 'asset');
      enqueue(`${item.path}.map`, 'asset');
      for (const m of r.text.matchAll(/(?:import\(|from|import)\s*["'](\.{1,2}\/[^"'\s]+?\.m?js)["']/g)) enqueue(toPath(m[1], item.path), 'asset');
      for (const m of r.text.matchAll(/["'](\/?(?:assets|static|_next\/static|js)\/[^"'\s]+?\.(?:m?js|css))["']/g)) {
        enqueue(toPath(m[1].startsWith('/') ? m[1] : `/${m[1]}`, '/'), 'asset');
      }
    }
  }
  return out;
}

/** The built-output directories present in a release tree. */
export function builtDirsIn(releaseDir) {
  if (!releaseDir) return [];
  return BUILT_DIRS.map((d) => join(releaseDir, d)).filter((p) => {
    try { return lstatSync(p).isDirectory(); } catch { return false; }
  });
}

/** Scan built output on disk: every text asset, source maps and .env files included. */
export function scanBuiltDir(root, dirs = [root], { deadline = Infinity } = {}) {
  const out = result();
  let files = 0;
  const walk = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const d of entries) {
      if (out.truncated) return;
      if (files >= 5000 || Date.now() > deadline) { out.truncated = true; return; }
      const p = join(dir, d.name);
      if (d.isSymbolicLink()) continue;
      if (d.isDirectory()) { if (d.name !== 'node_modules' && d.name !== '.git') walk(p); continue; }
      const isEnv = /^\.env(?:\..+)?$/.test(d.name);
      if (!d.isFile() || (!isEnv && !TEXT_EXT.has(extname(d.name).toLowerCase()))) continue;
      let st;
      try { st = lstatSync(p); } catch { continue; }
      if (st.size > MAX_BYTES) { out.truncated = true; continue; }
      let text;
      try { text = readFileSync(p, 'utf8'); } catch { continue; }
      files++;
      const rel = relative(root, p);
      out.scanned.push({ path: rel, bytes: text.length });
      if (isEnv) {
        const vars = looksLikeEnvFile(text);
        if (vars) addFindings(out, [{ file: rel, line: 1, rule: 'served-env-file', preview: `${vars} variable(s), values not shown` }]);
      }
      addFindings(out, scanServedText(rel, text, out.supabase));
    }
  };
  for (const d of dirs) if (existsSync(d)) walk(d);
  return out;
}
