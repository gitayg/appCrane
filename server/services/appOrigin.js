// Per-app origins. Every app on one host under /<slug> shares one browser
// origin with every other app and with the dashboard: any app's script can
// call another app as the visitor, and read the dashboard's session from
// localStorage. Paths do not separate origins; hosts do.
//
// When the platform setting app_isolation_domain is set (e.g. apps.example.com),
// each app is served on its own host:
//   production  <slug>.<domain>
//   sandbox     <slug>-sandbox.<domain>     (slugs never end in -sandbox: slugPolicy.js)
// and the visitor is signed in there by a one-time handoff from the platform
// host into a host-only cookie (APP_SESSION_COOKIE) that holds an 'app'-scope
// session valid for that one app and environment only.
//
// Off (setting empty) everything stays exactly as before.

export const APP_SESSION_COOKIE = '__Host-cc_app';
// With isolation on, the platform session moves to a __Host- cookie: an app
// host under the platform's own domain can set a cookie for that domain, but
// never one with the __Host- prefix.
export const PLATFORM_SESSION_COOKIE_ISOLATED = '__Host-cc_token';
export const PLATFORM_SESSION_COOKIE_LEGACY = 'cc_token';
// Paths on an app host that AppCrane answers itself (sign-in handoff, sign-out).
export const RESERVED_APP_PATH = '/__appcrane';
export const HANDOFF_CODE_TTL_SECONDS = 60;
// Ties a sign-in code to the browser that started the sign-in: the app host
// sets a random value here before sending the visitor to the platform, the
// code carries its hash, and only a browser holding the value can use the
// code. Without it, someone could send a victim a link with a code issued to
// their own account and sign the victim in to the app as themselves.
export const HANDOFF_STATE_COOKIE = '__Host-cc_handoff';
export const HANDOFF_STATE_MAX_AGE_SECONDS = 600;

const ENVS = new Set(['sandbox', 'production']);

function setting(db, key) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value || '';
}

export function normalizeDomain(raw) {
  const d = String(raw || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/.]+$/, '');
  if (!d) return null;
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d)) return null;
  return d;
}

/** The isolation base domain, or null when isolation is off. */
export function isolationDomain(db) {
  return normalizeDomain(setting(db, 'app_isolation_domain'));
}

export function isolationEnabled(db) {
  return isolationDomain(db) !== null;
}

/** Wildcard certificate for the isolation domain, or null (Caddy on-demand TLS). */
export function isolationTls(db) {
  const cert = setting(db, 'app_isolation_tls_cert_file');
  const key = setting(db, 'app_isolation_tls_key_file');
  return cert && key ? { cert, key } : null;
}

/**
 * The dashboard frames apps in its app tabs. Its CSP allows frames from
 * 'self' only, which was every app while apps lived under /<slug>; on their
 * own hosts they need the isolation domain added, or the browser refuses the
 * frame ("This content is blocked"). Off, the policy is returned unchanged.
 */
export function withAppFrames(db, csp) {
  const base = isolationDomain(db);
  return base ? csp.replace("frame-src 'self'", `frame-src 'self' https://*.${base}`) : csp;
}

export function appHost(db, slug, env) {
  const base = isolationDomain(db);
  if (!base || !ENVS.has(env)) return null;
  return `${env === 'sandbox' ? `${slug}-sandbox` : slug}.${base}`;
}

export function appOrigin(db, slug, env) {
  const host = appHost(db, slug, env);
  return host ? `https://${host}` : null;
}

/**
 * The URL a person should open for an app. Isolated: its own host. Otherwise
 * the path on the platform host, as before (craneBase = 'https://<platform>'
 * or '' for a same-host relative link).
 */
export function appUrl(db, slug, env, { craneBase = '' } = {}) {
  const origin = appOrigin(db, slug, env);
  if (origin) return `${origin}/`;
  return `${craneBase}/${env === 'sandbox' ? `${slug}-sandbox` : slug}`;
}

/** { slug, env } for an app host under the isolation domain, else null. Does not check the app exists. */
export function parseAppHost(db, host) {
  const base = isolationDomain(db);
  if (!base || !host) return null;
  const h = String(host).toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
  if (!h.endsWith(`.${base}`)) return null;
  const label = h.slice(0, -(base.length + 1));
  if (!label || label.includes('.')) return null;
  if (label.endsWith('-sandbox')) return { slug: label.slice(0, -'-sandbox'.length), env: 'sandbox' };
  return { slug: label, env: 'production' };
}
