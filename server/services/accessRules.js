// Path role rules enforced at the gate (/api/identity/verify).
//
// A hosted app is meant to stay unaware of auth: AppCrane's forward_auth is the
// only check most of them have, and until now it only answered "may this person
// enter the app at all". A pentest of one hosted app found 27 routes with no
// check of their own, so any signed-in member could call the admin ones. These
// rules let the app declare, in deployhub.json or from the dashboard, which
// paths need which per-app role, and the gate refuses everyone else.
//
// Semantics, chosen to fail closed:
//   - Every rule that matches the request applies, and the strictest one wins.
//     Order does not matter, and a broad rule can never open up a narrower one.
//   - A listed role admits that role and every role above it
//     (viewer < user < admin < owner), so ["admin"] never locks the owner out.
//   - A path no rule matches behaves as before: anyone with access to the app.
//   - Matching is case-insensitive and runs on a canonical path (decoded until
//     stable, dot segments resolved, empty segments and ;params dropped,
//     backslashes read as slashes), so the many ways an app framework may read
//     a path all hit the same rule. A path that cannot be decoded is refused.
//   - Framework aliases of a path are matched too (pathReadings below): a rule
//     for /admin also covers /admin.json, /admin.html, /admin/, the Next.js
//     data route /_next/data/<buildId>/admin.json (and .../admin/index.json),
//     SvelteKit's /admin/__data.json and Nuxt's /admin/_payload.json. Prefix
//     rules likewise. Not covered: i18n locale prefixes (/en/admin), routes an
//     app maps to a handler under an unrelated path.
//   - Method override: a request is decided for its own method AND for every
//     method named by X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override
//     or a `_method` query parameter, and the strictest result applies. So a
//     DELETE-only rule holds against `POST` + `X-HTTP-Method-Override: DELETE`.
//     A `_method` field in a form BODY cannot be seen at the gate: for an app
//     whose framework honours one (Rails, Laravel, Express method-override on
//     req.body), a method-scoped rule is not a boundary. Omit `methods` there.

import { getDb } from '../db.js';

export const RULE_ROLES = ['viewer', 'user', 'admin', 'owner'];
export const RULE_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
export const MAX_RULES = 200;
const MAX_PATH_LEN = 256;
const PATH_CHARS_RE = /^[A-Za-z0-9._~!$&'()+,=:@/*-]+$/;
const RULE_KEYS = ['path', 'methods', 'roles'];
const ACCESS_KEYS = ['rules'];

export class AccessRulesError extends Error {}

function fail(where, field, why) {
  throw new AccessRulesError(`${where}${field}: ${why}`);
}

function checkPattern(where, field, path) {
  if (typeof path !== 'string' || !path.startsWith('/')) fail(where, field, `must be a string starting with "/" (got ${JSON.stringify(path)})`);
  if (path.length > MAX_PATH_LEN) fail(where, field, `must be at most ${MAX_PATH_LEN} characters`);
  if (path === '/') return;
  if (!PATH_CHARS_RE.test(path)) fail(where, field, `"${path}" has a character that is not allowed (no %, ;, spaces, ? or #; write the path decoded)`);
  if (path.endsWith('/')) fail(where, field, `"${path}" must not end with "/" (use "${path}*" for everything under it, or drop the slash)`);
  const segs = path.slice(1).split('/');
  for (const s of segs) {
    if (s === '') fail(where, field, `"${path}" has an empty segment ("//")`);
    if (s === '.' || s === '..') fail(where, field, `"${path}" has a "${s}" segment`);
    if (s.includes('*') && s !== '*') fail(where, field, `"${path}": "*" must be a whole segment ("/a/*/b" or a trailing "/*"), not part of one`);
  }
}

/**
 * Validate an `access` block (the deployhub.json shape, also what the dashboard
 * sends) and return the normalised rule list, or null when no block is given.
 * Throws AccessRulesError naming the offending field.
 */
export function parseAccessRules(block, where = 'deployhub.json ') {
  if (block === undefined || block === null) return null;
  if (typeof block !== 'object' || Array.isArray(block)) fail(where, 'access', 'must be an object like { "rules": [ ... ] }');
  for (const k of Object.keys(block)) {
    if (!ACCESS_KEYS.includes(k)) fail(where, `access.${k}`, `unknown key (allowed: ${ACCESS_KEYS.join(', ')})`);
  }
  const rules = block.rules === undefined ? [] : block.rules;
  if (!Array.isArray(rules)) fail(where, 'access.rules', 'must be an array');
  if (rules.length > MAX_RULES) fail(where, 'access.rules', `at most ${MAX_RULES} rules`);
  return rules.map((r, i) => {
    const f = `access.rules[${i}]`;
    if (!r || typeof r !== 'object' || Array.isArray(r)) fail(where, f, 'must be an object like { "path": "/admin/*", "roles": ["admin"] }');
    for (const k of Object.keys(r)) {
      if (!RULE_KEYS.includes(k)) fail(where, `${f}.${k}`, `unknown key (allowed: ${RULE_KEYS.join(', ')})`);
    }
    checkPattern(where, `${f}.path`, r.path);
    if (!Array.isArray(r.roles) || r.roles.length === 0) fail(where, `${f}.roles`, `must be a non-empty array of: ${RULE_ROLES.join(', ')}`);
    for (const role of r.roles) {
      if (!RULE_ROLES.includes(role)) fail(where, `${f}.roles`, `unknown role ${JSON.stringify(role)} (allowed: ${RULE_ROLES.join(', ')})`);
    }
    const out = { path: r.path, roles: [...new Set(r.roles)] };
    if (r.methods !== undefined) {
      if (!Array.isArray(r.methods) || r.methods.length === 0) fail(where, `${f}.methods`, `must be a non-empty array of: ${RULE_METHODS.join(', ')} (omit it to match every method)`);
      const methods = r.methods.map((m) => (typeof m === 'string' ? m.toUpperCase() : m));
      for (const m of methods) {
        if (!RULE_METHODS.includes(m)) fail(where, `${f}.methods`, `unknown method ${JSON.stringify(m)} (allowed: ${RULE_METHODS.join(', ')})`);
      }
      out.methods = [...new Set(methods)];
    }
    return out;
  });
}

/**
 * The canonical, lower-cased segment list for a request URI, or null when the
 * URI cannot be read unambiguously (malformed escapes, control characters, or
 * still-encoded after three decodes).
 */
export function canonicalSegments(uri) {
  let p = String(uri ?? '');
  const cut = p.search(/[?#]/);
  if (cut !== -1) p = p.slice(0, cut);
  for (let i = 0; i < 3 && /%[0-9a-fA-F]{2}/.test(p); i++) {
    try { p = decodeURIComponent(p); } catch { return null; }
  }
  if (/%[0-9a-fA-F]{2}/.test(p)) return null;
  if (/[\u0000-\u001f\u007f]/.test(p)) return null;
  const out = [];
  for (let seg of p.replace(/\\/g, '/').split('/')) {
    const semi = seg.indexOf(';');
    if (semi !== -1) seg = seg.slice(0, semi);
    seg = seg.trim().toLowerCase();
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(seg);
  }
  return out;
}

function compile(rule) {
  const lower = rule.path.toLowerCase();
  const segs = lower === '/' ? [] : lower.slice(1).split('/');
  const prefix = segs.length > 0 && segs[segs.length - 1] === '*';
  return {
    rule,
    segs: prefix ? segs.slice(0, -1) : segs,
    prefix,
    methods: rule.methods ? new Set(rule.methods) : null,
    rank: Math.min(...rule.roles.map((r) => RULE_ROLES.indexOf(r))),
  };
}

const OVERRIDE_HEADERS = ['x-http-method-override', 'x-http-method', 'x-method-override'];
const METHOD_TOKEN_RE = /^[A-Za-z]{1,16}$/;

/** The methods a request must be decided for: its own, plus any override it carries. */
export function effectiveMethods(method, headers = {}, uri = '') {
  const out = new Set();
  const add = (v) => { const m = String(v).trim(); if (METHOD_TOKEN_RE.test(m)) out.add(m.toUpperCase()); };
  if (method) add(method);
  for (const h of OVERRIDE_HEADERS) {
    const v = headers[h];
    for (const part of (Array.isArray(v) ? v : [v])) if (typeof part === 'string') part.split(',').forEach(add);
  }
  const q = String(uri ?? '').indexOf('?');
  if (q !== -1) {
    const query = String(uri).slice(q + 1).split('#')[0];
    for (const pair of query.split('&')) {
      const [k, v = ''] = pair.split('=');
      let key = k;
      let val = v;
      try { key = decodeURIComponent(k.replace(/\+/g, ' ')); val = decodeURIComponent(v.replace(/\+/g, ' ')); } catch { /* keep raw */ }
      if (key.trim().toLowerCase() === '_method') add(val);
    }
  }
  const list = [...out];
  if (!method) list.push(null);
  return list;
}

/**
 * Every reading of a canonical segment list a framework may route to the same
 * handler: the path itself, the path without a format suffix on its last
 * segment, and the page a data route stands for. The alias set is in the header.
 */
export function pathReadings(segs) {
  const out = [segs];
  const push = (p) => { if (!out.some((x) => x.length === p.length && x.every((s, i) => s === p[i]))) out.push(p); };
  const stripExt = (p) => {
    const last = p[p.length - 1];
    const dot = last ? last.indexOf('.') : -1;
    return dot > 0 ? [...p.slice(0, -1), last.slice(0, dot)] : null;
  };
  const base = [segs];
  if (segs[0] === '_next' && segs[1] === 'data' && segs.length >= 4) {
    let page = segs.slice(3);
    const s = stripExt(page);
    if (s) page = s;
    if (page[page.length - 1] === 'index') page = page.slice(0, -1);
    base.push(page);
  }
  const last = segs[segs.length - 1];
  if (last === '__data.json' || last === '_payload.json') base.push(segs.slice(0, -1));
  for (const p of base) {
    push(p);
    const s = stripExt(p);
    if (s) push(s);
  }
  return out;
}

function pathMatches(c, path) {
  if (c.prefix ? path.length < c.segs.length : path.length !== c.segs.length) return false;
  return c.segs.every((s, i) => s === '*' || s === path[i]);
}

function methodMatches(c, method) {
  if (!c.methods) return true;
  // Unknown method: method-scoped rules apply, rather than none of them.
  if (!method) return true;
  if (c.methods.has(method)) return true;
  return method === 'HEAD' && c.methods.has('GET');
}

/**
 * The strictest rule matching this request, or null when none does.
 * `paths` is every canonical reading of the request path; a rule matching any
 * of them applies.
 */
export function strictestRule(rules, method, paths) {
  let best = null;
  for (const c of rules.map(compile)) {
    if (!methodMatches(c, method)) continue;
    if (!paths.some((p) => pathMatches(c, p))) continue;
    if (!best || c.rank > best.rank) best = c;
  }
  return best ? { rule: best.rule, role: RULE_ROLES[best.rank] } : null;
}

/** Does `appRole` reach `requiredRole` in viewer < user < admin < owner? */
export function roleSatisfies(appRole, requiredRole) {
  const have = RULE_ROLES.indexOf(appRole);
  return have !== -1 && have >= RULE_ROLES.indexOf(requiredRole);
}

/**
 * Decide a gate request. Returns { ok: true } when no rule stands in the way,
 * { ok: false, reason: 'malformed' } for an unreadable path on an app that has
 * rules, or { ok: false, reason: 'role', role } naming the role needed.
 *
 * `uri` is the X-Forwarded-Uri Caddy sends; `mountPrefix` is the app's /<slug>
 * (or /<slug>-sandbox). Caddy normally strips the mount before forward_auth,
 * but the uri is read both with and without it, so a mount that slipped through
 * (an encoded or differently-cased prefix) cannot shift a path past a rule.
 */
export function decideAccess(rules, { method, uri, mountPrefix, appRole, headers = {} }) {
  if (!rules || rules.length === 0) return { ok: true };
  const segs = canonicalSegments(uri);
  if (!segs) return { ok: false, reason: 'malformed' };
  const bases = [segs];
  const mount = mountPrefix ? canonicalSegments(mountPrefix) : null;
  if (mount && mount.length && mount.every((s, i) => segs[i] === s)) bases.push(segs.slice(mount.length));
  const paths = bases.flatMap(pathReadings);
  let hit = null;
  for (const m of effectiveMethods(method, headers, uri)) {
    const h = strictestRule(rules, m, paths);
    if (h && (!hit || RULE_ROLES.indexOf(h.role) > RULE_ROLES.indexOf(hit.role))) hit = h;
  }
  if (!hit || roleSatisfies(appRole, hit.role)) return { ok: true };
  return { ok: false, reason: 'role', role: hit.role, rule: hit.rule };
}

// --- storage -------------------------------------------------------------

export function getRules(db, appId, env, source) {
  const row = db.prepare('SELECT rules_json, updated_at FROM app_access_rules WHERE app_id = ? AND env = ? AND source = ?')
    .get(appId, env, source);
  return row ? { rules: JSON.parse(row.rules_json), updated_at: row.updated_at } : null;
}

/** Manifest and dashboard rules together: both apply, the strictest wins. */
export function effectiveRules(db, appId, env) {
  return db.prepare('SELECT rules_json FROM app_access_rules WHERE app_id = ? AND env = ?')
    .all(appId, env)
    .flatMap((r) => JSON.parse(r.rules_json));
}

export function setRules(db, appId, env, source, rules, userId = null) {
  if (!rules || rules.length === 0) {
    db.prepare('DELETE FROM app_access_rules WHERE app_id = ? AND env = ? AND source = ?').run(appId, env, source);
    return;
  }
  db.prepare(`
    INSERT INTO app_access_rules (app_id, env, source, rules_json, updated_by, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(app_id, env, source) DO UPDATE SET
      rules_json = excluded.rules_json, updated_by = excluded.updated_by, updated_at = excluded.updated_at
  `).run(appId, env, source, JSON.stringify(rules), userId);
}

/**
 * Deploy hook: the release's deployhub.json rules replace the previous
 * release's for that environment. No `access` block clears them. Dashboard
 * rules are a separate set and are never touched by a deploy.
 */
export function storeManifestRules(appId, env, rules) {
  setRules(getDb(), appId, env, 'manifest', rules || []);
}

/**
 * Before the new release takes traffic: the gate enforces the previous
 * release's manifest rules AND the new release's, so a route the new release
 * adds is protected from its first request, and nothing the old release
 * protected opens early. Every rule applies and the strictest wins, so the
 * union is never looser than either set. Returns what to hand
 * revertStagedManifestRules if the new release does not go live; on success
 * storeManifestRules then leaves exactly the new release's rules.
 */
export function stageManifestRules(appId, env, rules) {
  const db = getDb();
  const previous = getRules(db, appId, env, 'manifest')?.rules || [];
  const seen = new Set(previous.map((r) => JSON.stringify(r)));
  const union = [...previous, ...(rules || []).filter((r) => !seen.has(JSON.stringify(r)))];
  setRules(db, appId, env, 'manifest', union);
  return { appId, env, previous };
}

/** The new release did not go live and the previous one serves again: its rules, exactly. */
export function revertStagedManifestRules(staged) {
  if (!staged) return;
  setRules(getDb(), staged.appId, staged.env, 'manifest', staged.previous);
}
