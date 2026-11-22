import https from 'https';
import { X509Certificate } from 'crypto';
import { makeGuardedLookup, assertHostNotBlocked } from '../remoteFetch.js';

// The connection test the IT setup page runs before a staged SSO change may be
// confirmed. Someone without an AppCrane account chooses these URLs, so the
// fetch is https only, refuses private, loopback and link-local destinations
// (checked on the address actually dialled), follows no redirects, and is
// bounded in time and size.

const TIMEOUT_MS = 8000;
const MAX_BYTES = 1024 * 1024;

let seams = {};

/** Tests: point names at chosen addresses, trust a test CA, relax the address check, shorten the deadline. */
export function configureConnectionTestFetch(opts = {}) {
  seams = { ...opts };
}

function guardedJson(rawUrl) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(rawUrl); } catch { return reject(new Error('not a valid URL')); }
    if (url.protocol !== 'https:') return reject(new Error('the URL must start with https://'));
    const isBlocked = seams.isBlocked;
    try { assertHostNotBlocked(url, isBlocked); } catch (e) { return reject(e); }
    const lookup = makeGuardedLookup({ ...(isBlocked && { isBlocked }), ...(seams.resolve && { resolve: seams.resolve }) });
    const req = https.get(url, { lookup, timeout: TIMEOUT_MS, headers: { Accept: 'application/json' }, ...(seams.ca && { ca: seams.ca }) }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`${url.host} answered HTTP ${res.statusCode}${res.statusCode >= 300 && res.statusCode < 400 ? ' (redirects are not followed)' : ''}`)); }
      let size = 0; const chunks = [];
      res.on('data', (c) => { size += c.length; if (size > MAX_BYTES) { req.destroy(new Error('response too large')); } else chunks.push(c); });
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error(`${url.host} did not answer with JSON`)); } });
    });
    req.on('timeout', () => req.destroy(new Error(`${url.host} did not answer within ${TIMEOUT_MS / 1000}s`)));
    // The idle timeout above restarts on every byte; this bounds the whole request.
    const deadlineMs = seams.deadlineMs || TIMEOUT_MS;
    const deadline = setTimeout(() => req.destroy(new Error(`${url.host} did not answer within ${deadlineMs / 1000}s`)), deadlineMs);
    req.on('close', () => clearTimeout(deadline));
    req.on('error', reject);
  });
}

const deps = { fetchJson: guardedJson };
export function _setConnectionTestDeps(d) { Object.assign(deps, d); }
export function _resetConnectionTestDeps() { deps.fetchJson = guardedJson; }

function discoveryUrl(base) {
  return base.endsWith('/.well-known/openid-configuration') ? base : base.replace(/\/$/, '') + '/.well-known/openid-configuration';
}

/** { ok, steps: [{ step, ok, detail }] } for an OIDC discovery URL. */
export async function testOidc({ discovery_url, client_id }) {
  const steps = [];
  const step = (name, ok, detail) => { steps.push({ step: name, ok, detail }); return ok; };
  if (!step('client_id', !!String(client_id || '').trim(), client_id ? 'set' : 'enter the client ID')) return { ok: false, steps };
  let doc;
  try {
    doc = await deps.fetchJson(discoveryUrl(String(discovery_url || '')));
    step('discovery', true, 'discovery document fetched');
  } catch (e) {
    step('discovery', false, String(e.message).slice(0, 200));
    return { ok: false, steps };
  }
  const missing = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'].filter((k) => !doc?.[k]);
  if (!step('metadata', !missing.length, missing.length ? `missing ${missing.join(', ')}` : `issuer ${doc.issuer}`)) return { ok: false, steps };
  try {
    const jwks = await deps.fetchJson(doc.jwks_uri);
    const n = Array.isArray(jwks?.keys) ? jwks.keys.length : 0;
    step('jwks', n > 0, n ? `${n} signing key(s)` : 'the key set is empty');
  } catch (e) {
    step('jwks', false, String(e.message).slice(0, 200));
  }
  return { ok: steps.every((s) => s.ok), steps, issuer: doc.issuer };
}

/** { ok, steps } for a SAML IdP: sign-in URL and signing certificate. */
export function testSaml({ idp_sso_url, idp_cert }) {
  const steps = [];
  let urlOk = false;
  try { urlOk = new URL(String(idp_sso_url || '')).protocol === 'https:'; } catch { /* stays false */ }
  steps.push({ step: 'sso_url', ok: urlOk, detail: urlOk ? 'https URL' : 'the IdP sign-in URL must start with https://' });
  if (!idp_cert) {
    steps.push({ step: 'certificate', ok: false, detail: 'paste the IdP signing certificate' });
  } else {
    try {
      const pem = String(idp_cert).includes('BEGIN CERTIFICATE') ? String(idp_cert) : `-----BEGIN CERTIFICATE-----\n${String(idp_cert).replace(/\s+/g, '')}\n-----END CERTIFICATE-----`;
      const cert = new X509Certificate(pem);
      const live = Date.parse(cert.validTo) > Date.now() && Date.parse(cert.validFrom) <= Date.now();
      steps.push({ step: 'certificate', ok: live, detail: live ? `valid until ${cert.validTo}, SHA-256 ${cert.fingerprint256}` : `not valid now (${cert.validFrom} to ${cert.validTo})` });
    } catch {
      steps.push({ step: 'certificate', ok: false, detail: 'not a readable X.509 certificate' });
    }
  }
  return { ok: steps.every((s) => s.ok), steps };
}
