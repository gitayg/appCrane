// Which API routes an app exposes, for the unauthenticated-endpoint probe.
//
// Three sources, all bounded: string literals in the bundle the browser is
// sent ("/api/...", "/graphql", with the method when a fetch/axios call names
// one), an OpenAPI or Swagger document if the app serves one, and a short list
// of common paths. Templated paths ({id}, :id, ${...}) cannot be filled and are
// skipped; paths whose name suggests a side effect even on GET are never probed.

export const MAX_ROUTES = 50;
export const COMMON_PATHS = Object.freeze([
  '/api', '/api/users', '/api/user', '/api/admin', '/api/admin/users', '/api/accounts',
  '/api/customers', '/api/orders', '/api/items', '/api/data', '/users', '/graphql',
]);
export const OPENAPI_PATHS = Object.freeze([
  '/openapi.json', '/swagger.json', '/api/openapi.json', '/api/swagger.json', '/api-docs', '/api/docs', '/v3/api-docs', '/docs/openapi.json',
]);

const ROUTE_LITERAL_RE = /(\.(?:get|post|put|patch|delete)\s*\(\s*)?["'`]((?:\/[A-Za-z0-9_-]+)*\/(?:api|graphql)(?:\/[A-Za-z0-9_.~%-]+)*\/?)(?=["'`?#]|\$\{)/g;
const METHOD_NEAR_RE = /^[^;]{0,160}?\bmethod\s*:\s*["'`](POST|PUT|PATCH|DELETE)["'`]/i;
const EXCLUDED_RE = /(?:^|\/)(?:health|healthz|healthcheck|ready|readyz|live|livez|ping|status|version|metrics|favicon\.ico)$/i;
const STATIC_RE = /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|html?|txt|webp)$/i;
const SIDE_EFFECT_RE = /(?:^|[/_-])(?:delete|remove|reset|destroy|purge|drop|clear|wipe|truncate|seed|migrate|logout|signout|sign-out|send|email|invite|pay|charge|checkout|webhook|cron|run|exec|import|sync|refresh|revoke)(?:$|[/_-])/i;

/** The path the container sees: the public mount Caddy strips is removed, the trailing slash too. */
export function normalizeRoute(p, mount = '/') {
  let s = String(p || '').split(/[?#]/)[0];
  if (!s.startsWith('/')) s = `/${s}`;
  if (mount !== '/' && (s === mount || s.startsWith(`${mount}/`))) s = s.slice(mount.length) || '/';
  if (s.length > 1) s = s.replace(/\/+$/, '');
  return s.length <= 200 ? s : null;
}

/** Why a route is not probed, or null when it may be. */
export function skipReason(p) {
  if (!p || /[{}:$*]/.test(p)) return 'templated';
  if (EXCLUDED_RE.test(p)) return 'health';
  if (STATIC_RE.test(p)) return 'static';
  if (SIDE_EFFECT_RE.test(p)) return 'side-effect';
  return null;
}

export function emptyRoutes() {
  return new Map();
}

function add(into, path, method, source) {
  if (!path) return;
  let r = into.get(path);
  if (!r) {
    if (into.size >= MAX_ROUTES * 4) return;
    r = { path, methods: new Set(), sources: new Set() };
    into.set(path, r);
  }
  r.sources.add(source);
  if (method) r.methods.add(method);
}

/** API route literals in one served text, with a write method when the call names one. */
export function collectRoutes(text, into, mount = '/') {
  for (const m of String(text).matchAll(ROUTE_LITERAL_RE)) {
    const path = normalizeRoute(m[2], mount);
    let method = null;
    if (m[1]) method = m[1].replace(/[\s.(]/g, '').toUpperCase();
    else {
      const near = METHOD_NEAR_RE.exec(text.slice(m.index + m[0].length, m.index + m[0].length + 200));
      if (near) method = near[1].toUpperCase();
    }
    add(into, path, method && method !== 'GET' ? method : 'GET', 'bundle');
  }
  return into;
}

/** Routes and their methods from a parsed OpenAPI 3 / Swagger 2 document. */
export function collectOpenApi(spec, into, mount = '/') {
  if (!spec || typeof spec !== 'object' || !(spec.openapi || spec.swagger) || !spec.paths || typeof spec.paths !== 'object') return false;
  let prefix = '';
  if (typeof spec.basePath === 'string') prefix = spec.basePath;
  else if (Array.isArray(spec.servers) && typeof spec.servers[0]?.url === 'string' && spec.servers[0].url.startsWith('/')) prefix = spec.servers[0].url;
  prefix = prefix.replace(/\/+$/, '');
  for (const [p, ops] of Object.entries(spec.paths).slice(0, MAX_ROUTES * 4)) {
    const path = normalizeRoute(`${prefix}${p}`, mount);
    const methods = Object.keys(ops || {}).map((k) => k.toUpperCase()).filter((k) => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(k));
    if (!methods.length) add(into, path, 'GET', 'openapi');
    for (const m of methods) add(into, path, m, 'openapi');
  }
  return true;
}

export function addCommon(into) {
  for (const p of COMMON_PATHS) add(into, p, 'GET', 'common');
  return into;
}
