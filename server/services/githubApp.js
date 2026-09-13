/**
 * Per-instance GitHub App authentication (v2.75.0).
 *
 * WHY THIS EXISTS
 * ---------------
 * A connected app (source_type='github') is cloned and cross-checked with a
 * long-lived personal access token stored on the app row. That token is valid
 * until someone revokes it and reaches everything its owner can reach. This
 * module is the alternative: THIS AppCrane instance registers its OWN GitHub
 * App (never a shared one -- a shared App would make one private key the
 * credential for every install), app builders install it on only the
 * repositories they pick, and AppCrane authenticates with installation access
 * tokens that GitHub expires after an hour.
 *
 * WHAT GITHUB'S DOCS PIN DOWN (quoted, because the design is built on them)
 * ------------------------------------------------------------------------
 *   - App manifest flow: "You must complete all three steps in the GitHub App
 *     Manifest flow within one hour." The form POSTs to
 *     https://github.com/settings/apps/new (or
 *     https://github.com/organizations/ORGANIZATION/settings/apps/new), and
 *     `state` is "An unguessable random string. It is used to protect against
 *     cross-site request forgery attacks."
 *   - Conversion: "POST /app-manifests/{code}/conversions" returns `id`,
 *     `slug`, `client_id`, `client_secret`, `webhook_secret`, `pem`, `owner`,
 *     `html_url`.
 *   - JWT: "This should be RS256 since your JWT must be signed using the RS256
 *     algorithm", iat "60 seconds in the past" to survive clock drift, and exp
 *     "no more than 10 minutes into the future".
 *   - Installation token: POST /app/installations/INSTALLATION_ID/access_tokens,
 *     "The installation access token will expire after 1 hour", narrowable with
 *     `repositories` / `repository_ids` and `permissions`.
 *   - Setup URL: "Bad actors can hit this URL with a spoofed `installation_id`.
 *     Therefore, you should not rely on the validity of the `installation_id`
 *     parameter." So AppCrane never takes installation_id from a redirect; it
 *     asks GET /repos/{owner}/{repo}/installation with its own JWT instead.
 *
 * WHAT IS NEVER PERSISTED
 * -----------------------
 * Installation access tokens. They are cached in this process only, keyed by
 * installation + repository, and dropped 5 minutes before GitHub expires them.
 * Nothing writes one to the database, a log line, a git config or argv.
 */

import crypto from 'crypto';
import { getDb } from '../db.js';
import { encrypt, decrypt, hashApiKey } from './encryption.js';

const DEFAULT_API_BASE = 'https://api.github.com';
const DEFAULT_WEB_BASE = 'https://github.com';

/** GitHub REST base. Overridable so tests never touch the real api.github.com. */
export function githubApiBase() {
  return (process.env.APPCRANE_GITHUB_API_BASE || DEFAULT_API_BASE).replace(/\/+$/, '');
}

/** github.com itself (manifest form + install links). Same override rationale. */
export function githubWebBase() {
  return (process.env.APPCRANE_GITHUB_WEB_BASE || DEFAULT_WEB_BASE).replace(/\/+$/, '');
}

// JWT lifetime. GitHub's ceiling is 10 minutes; 9 leaves room for the 60s
// backdated iat without ever presenting a token GitHub will reject outright.
const JWT_BACKDATE_S = 60;
const JWT_TTL_S = 9 * 60;

// A cached installation token is reused only while it has more than this left.
// GitHub issues them for an hour; a deploy that clones, pins and then verifies
// must not have the token die between steps.
const TOKEN_REFRESH_MARGIN_MS = 5 * 60_000;

const FETCH_TIMEOUT_MS = 10_000;

// installationId|repo -> { token, expiresAtMs }. Process memory only.
const _tokenCache = new Map();

// Manifest-flow state values (hashed), created by the start route and consumed
// exactly once by the exchange route.
const MANIFEST_STATE_TTL_MS = 30 * 60_000;
const _manifestStates = new Map();

// ---------------------------------------------------------------------------
// Config storage
// ---------------------------------------------------------------------------

/** The App this instance registered, without any secret. null when unconfigured. */
export function getAppConfig() {
  let row;
  try {
    row = getDb().prepare('SELECT * FROM github_app_config WHERE id = 1').get();
  } catch (_) {
    return null;
  }
  if (!row) return null;
  return {
    configured: true,
    github_app_id: row.github_app_id,
    slug: row.slug,
    name: row.name,
    owner_login: row.owner_login,
    html_url: row.html_url,
    client_id: row.client_id,
    created_at: row.created_at,
    install_url: row.html_url ? `${row.html_url.replace(/\/+$/, '')}/installations/new` : null,
  };
}

/** The App's private key, decrypted. Throws when there is no App configured. */
export function getPrivateKey() {
  const row = getDb().prepare('SELECT private_key_enc FROM github_app_config WHERE id = 1').get();
  if (!row) throw new Error('No GitHub App is configured on this AppCrane instance.');
  return decrypt(row.private_key_enc);
}

/** The webhook secret GitHub generated for the App, decrypted, or null. */
export function getWebhookSecret() {
  const row = getDb().prepare('SELECT webhook_secret_enc FROM github_app_config WHERE id = 1').get();
  if (!row?.webhook_secret_enc) return null;
  return decrypt(row.webhook_secret_enc);
}

/**
 * Persist a manifest conversion response. Every secret in it (pem, webhook
 * secret, client secret) is encrypted before it reaches the database.
 */
export function saveAppConfig(conversion, userId = null) {
  if (!conversion?.id || !conversion?.pem) {
    throw new Error('GitHub returned no app id / private key for this manifest code.');
  }
  const db = getDb();
  db.prepare(`
    INSERT INTO github_app_config
      (id, github_app_id, slug, name, owner_login, html_url, client_id,
       client_secret_enc, webhook_secret_enc, private_key_enc, created_by)
    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      github_app_id = excluded.github_app_id, slug = excluded.slug, name = excluded.name,
      owner_login = excluded.owner_login, html_url = excluded.html_url,
      client_id = excluded.client_id, client_secret_enc = excluded.client_secret_enc,
      webhook_secret_enc = excluded.webhook_secret_enc,
      private_key_enc = excluded.private_key_enc, created_by = excluded.created_by
  `).run(
    conversion.id,
    conversion.slug || '',
    conversion.name || null,
    conversion.owner?.login || null,
    conversion.html_url || null,
    conversion.client_id || null,
    conversion.client_secret ? encrypt(conversion.client_secret) : null,
    conversion.webhook_secret ? encrypt(conversion.webhook_secret) : null,
    encrypt(conversion.pem),
    userId,
  );
  clearTokenCache();
  return getAppConfig();
}

/**
 * Forget the App locally. GitHub has no REST endpoint that deletes an App, so
 * this cannot revoke anything on GitHub's side -- the caller is told to delete
 * it there too.
 */
export function deleteAppConfig() {
  getDb().prepare('DELETE FROM github_app_config WHERE id = 1').run();
  clearTokenCache();
}

/** Drop every cached installation token (config change, tests). */
export function clearTokenCache() {
  _tokenCache.clear();
}

// ---------------------------------------------------------------------------
// App authentication
// ---------------------------------------------------------------------------

const b64url = (buf) => Buffer.from(buf).toString('base64url');

/**
 * A JWT for the App itself, RS256, iat backdated 60s, exp 9 minutes out.
 * `nowMs` is injectable so a test can prove the exp bound rather than believe it.
 */
export function createAppJwt({ nowMs = Date.now(), privateKey, appId } = {}) {
  const key = privateKey || getPrivateKey();
  const iss = appId || getAppConfig()?.github_app_id;
  if (!iss) throw new Error('No GitHub App is configured on this AppCrane instance.');
  const nowS = Math.floor(nowMs / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = { iat: nowS - JWT_BACKDATE_S, exp: nowS + JWT_TTL_S, iss: String(iss) };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${b64url(signer.sign(key))}`;
}

async function githubJson(path, { method = 'GET', auth, body, accept = 'application/vnd.github+json' } = {}) {
  const headers = {
    Accept: accept,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'appcrane-github-app',
  };
  if (auth) headers.Authorization = auth;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${githubApiBase()}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  const text = await res.text().catch(() => '');
  let parsed = null;
  try { parsed = text ? JSON.parse(text) : null; } catch (_) { parsed = null; }
  if (!res.ok) {
    const err = new Error(`GitHub ${method} ${path} returned ${res.status}${parsed?.message ? ` — ${parsed.message}` : ''}`);
    err.status = res.status;
    throw err;
  }
  return parsed;
}

/** Exchange a manifest `code` for the App's credentials (one hour to do it). */
export async function exchangeManifestCode(code) {
  if (!code || !/^[A-Za-z0-9_-]{1,255}$/.test(code)) throw new Error('Invalid manifest code.');
  return githubJson(`/app-manifests/${encodeURIComponent(code)}/conversions`, { method: 'POST' });
}

/**
 * Which installation of this App covers owner/repo. Authoritative, unlike the
 * installation_id GitHub appends to the setup URL (which the docs say not to
 * trust). 404 => the App is not installed on that repository.
 */
export async function findInstallationForRepo(owner, repo) {
  const data = await githubJson(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/installation`,
    { auth: `Bearer ${createAppJwt()}` },
  );
  if (!data?.id) throw new Error('GitHub returned no installation id for this repository.');
  return { installationId: data.id, account: data.account?.login || null };
}

/**
 * A short-lived installation access token, narrowed to `repositories` when
 * given. Cached in memory and re-issued once it is within 5 minutes of expiry;
 * never written anywhere durable.
 */
export async function getInstallationToken(installationId, { repositories, nowMs = Date.now() } = {}) {
  const id = Number(installationId);
  if (!Number.isInteger(id) || id <= 0) throw new Error(`Invalid installation id '${installationId}'.`);
  const repos = Array.isArray(repositories) ? [...repositories].sort() : null;
  const cacheKey = `${id}|${repos ? repos.join(',') : '*'}`;

  const hit = _tokenCache.get(cacheKey);
  if (hit && hit.expiresAtMs - nowMs > TOKEN_REFRESH_MARGIN_MS) return hit.token;

  const body = repos ? { repositories: repos } : undefined;
  const data = await githubJson(`/app/installations/${id}/access_tokens`, {
    method: 'POST',
    auth: `Bearer ${createAppJwt({ nowMs })}`,
    body,
  });
  if (!data?.token) throw new Error('GitHub returned no installation access token.');
  const expiresAtMs = data.expires_at ? Date.parse(data.expires_at) : nowMs + 60 * 60_000;
  _tokenCache.set(cacheKey, { token: data.token, expiresAtMs });
  return data.token;
}

/** Health probe: can this instance still authenticate as its App? */
export async function probeGitHubApp() {
  if (!getAppConfig()) return { ok: true, skipped: true };
  try {
    const app = await githubJson('/app', { auth: `Bearer ${createAppJwt()}` });
    return { ok: true, slug: app?.slug || null };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ---------------------------------------------------------------------------
// Manifest flow state
// ---------------------------------------------------------------------------

/**
 * The manifest AppCrane asks GitHub to register. MINIMUM permissions:
 *   contents: read  -- clone the repository (git over HTTPS needs Contents)
 *   metadata: read  -- mandatory companion of any repository permission
 *   pull_requests: read -- the PR poller reads GET /repos/{o}/{r}/pulls, which
 *     GitHub's permissions reference lists under "Repository permissions for
 *     Pull requests" at read. Without it the enhancement-request lifecycle
 *     (PR opened -> in_progress, merged -> shipped) stops working for every
 *     App-backed app. Nothing writes with it.
 * Deliberately NOT requested: webhooks (write) -- so "Register on GitHub" stays
 * a PAT-only action -- issues, and anything write-shaped. A read-only App
 * cannot push, open a PR, or change repository settings.
 */
export function buildManifest({ baseUrl, name }) {
  const base = baseUrl.replace(/\/+$/, '');
  return {
    name,
    url: base,
    hook_attributes: { url: `${base}/api/github-app/webhook`, active: false },
    redirect_url: `${base}/settings`,
    setup_url: `${base}/settings`,
    public: false,
    default_permissions: { contents: 'read', metadata: 'read', pull_requests: 'read' },
    default_events: [],
  };
}

/** Where the manifest form is POSTed: a user account, or an organization. */
export function manifestFormUrl(org) {
  return org
    ? `${githubWebBase()}/organizations/${encodeURIComponent(org)}/settings/apps/new`
    : `${githubWebBase()}/settings/apps/new`;
}

/**
 * An opaque, single-use, session-bound state value. Only the hash is kept, so
 * the value itself exists in the admin's browser and nowhere else on the box.
 */
export function createManifestState(userId, sessionFingerprint) {
  const state = crypto.randomBytes(16).toString('base64url');
  _manifestStates.set(hashApiKey(state), {
    userId,
    sessionFingerprint,
    expiresAtMs: Date.now() + MANIFEST_STATE_TTL_MS,
  });
  return state;
}

/**
 * Consume a state value. Single use: the entry is removed on the FIRST lookup,
 * match or not, so a guessed value cannot be retried and a replay of a real one
 * fails. Returns true only when it was live, unexpired, and belongs to this
 * admin's session.
 */
export function consumeManifestState(state, userId, sessionFingerprint) {
  if (!state || typeof state !== 'string') return false;
  const key = hashApiKey(state);
  const rec = _manifestStates.get(key);
  _manifestStates.delete(key);
  for (const [k, v] of _manifestStates) if (v.expiresAtMs < Date.now()) _manifestStates.delete(k);
  if (!rec) return false;
  if (rec.expiresAtMs < Date.now()) return false;
  return rec.userId === userId && rec.sessionFingerprint === sessionFingerprint;
}

/** Test seam: forget every pending manifest state. */
export function clearManifestStates() {
  _manifestStates.clear();
}
