/**
 * GitHub service-account helper (v2.2.15+).
 *
 * AppCrane optionally fronts a single GitHub org/user that owns every
 * per-app repository — the end user never authenticates against GitHub,
 * AppCrane does it on their behalf with a stored PAT.
 *
 * Phase 1 (this module): config get/set with encrypted-at-rest token,
 * plus a tiny REST helper that hits the GitHub API on the service
 * account's behalf. Phase 2 will layer in repo creation, push helpers,
 * and PR plumbing on top of `apiFetch`.
 *
 * The token is stored in `settings.github_service_token_enc` using the
 * same AES-256-GCM envelope as oidc_client_secret_enc — never returned
 * to any client and never logged.
 */

import { getDb } from '../db.js';
import { encrypt, decrypt } from './encryption.js';
import log from '../utils/logger.js';

const KEYS = {
  owner:      'github_service_owner',
  tokenEnc:   'github_service_token_enc',
  visibility: 'github_service_visibility',
  enabled:    'github_service_enabled',
};

const VALID_VISIBILITIES = new Set(['private', 'internal', 'public']);

function readRow(db, key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row?.value ?? '';
}

function writeRow(db, key, value, userId) {
  db.prepare(`
    INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')
  `).run(key, String(value ?? ''), userId ?? null);
}

/**
 * Sanitized public view of the config — never includes the token.
 * Returns { owner, visibility, enabled, configured } where `configured`
 * means a non-empty token is present at rest (so the UI can render
 * "service account active" without round-tripping through decrypt).
 */
export function getServiceConfig() {
  const db = getDb();
  const tokenEnc = readRow(db, KEYS.tokenEnc);
  return {
    owner:      readRow(db, KEYS.owner),
    visibility: readRow(db, KEYS.visibility) || 'private',
    enabled:    readRow(db, KEYS.enabled) === '1',
    configured: !!tokenEnc,
  };
}

/**
 * Replace one or more fields. Pass `token` (plaintext) to rotate; omit it
 * to leave the existing token untouched. Pass `token: null` (explicit) to
 * clear the token and disable the integration.
 */
export function setServiceConfig({ owner, token, visibility, enabled }, userId) {
  const db = getDb();

  if (visibility !== undefined && !VALID_VISIBILITIES.has(visibility)) {
    throw new Error(`visibility must be one of: ${[...VALID_VISIBILITIES].join(', ')}`);
  }

  db.transaction(() => {
    if (owner !== undefined)      writeRow(db, KEYS.owner,      String(owner).trim(), userId);
    if (visibility !== undefined) writeRow(db, KEYS.visibility, visibility,           userId);
    if (enabled !== undefined)    writeRow(db, KEYS.enabled,    enabled ? '1' : '0', userId);

    if (token === null) {
      writeRow(db, KEYS.tokenEnc, '', userId);
      writeRow(db, KEYS.enabled,  '0', userId);
    } else if (typeof token === 'string' && token.length > 0) {
      writeRow(db, KEYS.tokenEnc, encrypt(token), userId);
    }
  })();

  return getServiceConfig();
}

/**
 * Server-internal: returns the decrypted PAT or null if unconfigured.
 * NEVER expose the return value to any HTTP response or log line.
 */
export function getServiceTokenInternal() {
  const db = getDb();
  const enc = readRow(db, KEYS.tokenEnc);
  if (!enc) return null;
  try {
    return decrypt(enc);
  } catch (e) {
    log.error(`[github-service] failed to decrypt service token: ${e.message}`);
    return null;
  }
}

/**
 * Thin GitHub REST wrapper. Returns parsed JSON or throws on non-2xx.
 * Callers should never hand the request body to user input verbatim —
 * this helper does no payload validation.
 */
export async function apiFetch(path, { method = 'GET', body, headers = {} } = {}) {
  const cfg = getServiceConfig();
  if (!cfg.enabled) throw new Error('github service is disabled');
  const token = getServiceTokenInternal();
  if (!token) throw new Error('github service token is not configured');

  const url = path.startsWith('http') ? path : `https://api.github.com${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept:        'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent':  'appcrane-service',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_) { /* keep raw */ }

  if (!res.ok) {
    const msg = data?.message || text || res.statusText;
    const err = new Error(`github ${method} ${path} → ${res.status}: ${msg}`);
    err.status = res.status;
    err.body = data;
    throw err;
  }
  return data;
}

/**
 * Naming convention for AppCrane-managed repos (v2.6.11+).
 *
 * Every repo created via the service account is prefixed `AMC_` so the
 * service-account's repo list is easy to identify, audit, and scope
 * fine-grained PAT access to. The slug stays the AppCrane-internal
 * identifier; the GitHub repo name is `AMC_<slug>`.
 *
 * Example: AppCrane app slug `castle` → GitHub repo `AMC_castle`.
 *
 * Exposed so the audit / cleanup tooling can match against the same
 * prefix without duplicating it.
 */
export const MANAGED_REPO_PREFIX = 'AMC_';
export function managedRepoNameForSlug(slug) {
  return `${MANAGED_REPO_PREFIX}${slug}`;
}

/**
 * Create a repository under the configured service account/org.
 *
 * v2.6.11 changes:
 *   - Repo name is `AMC_<slug>` (not just `<slug>`). Lets the operator
 *     scope a fine-grained PAT to "AMC_*" repos and trust the rest of
 *     the service account's namespace is untouched
 *   - Pre-flight existence check via GET /repos/{owner}/{name}. If the
 *     repo already exists, throw a clear "REPO_EXISTS" error before
 *     POSTing — the previous behavior leaked GitHub's 422 verbatim
 *     ("name already exists on this account"), which was confusing in
 *     the deploy log
 *
 * Returns the GitHub API response (cherry-picked).
 */
export async function createAppRepo(slug, { description = '', autoInit = true } = {}) {
  if (!slug || typeof slug !== 'string') throw new Error('slug is required');
  const cfg = getServiceConfig();
  if (!cfg.owner) throw new Error('github_service_owner is not configured');

  const repoName = managedRepoNameForSlug(slug);

  // Org repos go through /orgs/{owner}/repos; user repos through /user/repos.
  // We don't know which the owner is up front, so probe /users/{owner} once
  // and cache the type implicitly via the body.type — the service-account
  // user is unlikely to switch between org and personal mid-session.
  const owner = await apiFetch(`/users/${encodeURIComponent(cfg.owner)}`);
  const isOrg = owner?.type === 'Organization';

  // Pre-flight: does the repo already exist on the service account?
  // A 404 here = clean to create; a 200 = name taken, fail with a
  // diagnostic rather than letting POST blow up with a generic 422.
  // Anything else (403, 500, network) = let the create attempt surface
  // it; this check is best-effort.
  try {
    const existing = await apiFetch(
      `/repos/${encodeURIComponent(cfg.owner)}/${encodeURIComponent(repoName)}`
    );
    if (existing?.full_name) {
      const err = new Error(
        `REPO_EXISTS: ${existing.full_name} already exists on the service account. ` +
        `Pick a different app slug, or delete the existing repo if it's safe to do so.`
      );
      err.status = 409;
      err.body = { code: 'REPO_EXISTS', existing: existing.full_name };
      throw err;
    }
  } catch (e) {
    if (e?.status === 409) throw e;          // re-throw our own collision
    if (e?.status === 404) { /* expected — proceed to create */ }
    // any other status: log-and-continue; the POST will surface real errors
  }

  const path = isOrg ? `/orgs/${encodeURIComponent(cfg.owner)}/repos` : '/user/repos';
  const body = {
    name:        repoName,
    description: description || `AppCrane-managed app: ${slug}`,
    private:     cfg.visibility !== 'public',
    visibility:  cfg.visibility,
    auto_init:   !!autoInit,
    has_issues:  true,
    has_wiki:    false,
    has_projects: false,
  };

  const repo = await apiFetch(path, { method: 'POST', body });

  return {
    full_name:      repo.full_name,
    html_url:       repo.html_url,
    clone_url:      repo.clone_url,
    ssh_url:        repo.ssh_url,
    default_branch: repo.default_branch,
    private:        repo.private,
    visibility:     repo.visibility,
    owner_type:     isOrg ? 'org' : 'user',
  };
}

/**
 * Push a batch of files to a managed AMC_<slug> repo as a single commit
 * (v2.6.13).
 *
 * The end-user agent's `github_push_files` MCP tool authenticates with
 * the user's own X-Github-Token header — which has zero permissions on
 * the AppCrane service account's repos. So managed-app scaffolding has
 * to go through the SERVER-side service-account credential we already
 * hold encrypted. That's this helper.
 *
 * Uses the Trees + Commits + Refs API rather than per-file Contents API
 * so N files = 1 commit (not N commits). Cheaper, cleaner history.
 *
 *   files: [{ path, content, encoding? }]
 *   encoding: 'utf-8' (default) or 'base64' (for binaries like icons)
 *
 * Returns { commit: { sha, html_url }, branch, files: [paths] }.
 *
 * Throws REPO_NOT_FOUND if the AMC_<slug> repo doesn't exist on the
 * service account; the caller probably forgot to call
 * appcrane_create_managed_app first.
 */
export async function pushFilesToManagedRepo(slug, files, opts = {}) {
  if (!slug || typeof slug !== 'string') throw new Error('slug is required');
  if (!Array.isArray(files) || files.length === 0) throw new Error('files must be a non-empty array');
  for (const f of files) {
    if (!f || typeof f.path !== 'string' || typeof f.content !== 'string') {
      throw new Error('each file needs { path: string, content: string }');
    }
    if (f.path.includes('..') || f.path.startsWith('/')) {
      throw new Error(`invalid file path '${f.path}': must be repo-relative, no ".." or leading slash`);
    }
    if (f.encoding && !['utf-8', 'base64'].includes(f.encoding)) {
      throw new Error(`invalid encoding '${f.encoding}': must be 'utf-8' or 'base64'`);
    }
  }

  const cfg = getServiceConfig();
  if (!cfg.owner) throw new Error('github_service_owner is not configured');
  const repoName = managedRepoNameForSlug(slug);
  const ownerRepo = `${encodeURIComponent(cfg.owner)}/${encodeURIComponent(repoName)}`;

  // Repo must exist. Fast-fail with a clearer error than the GitHub 404.
  let repo;
  try {
    repo = await apiFetch(`/repos/${ownerRepo}`);
  } catch (e) {
    if (e?.status === 404) {
      const err = new Error(`REPO_NOT_FOUND: ${cfg.owner}/${repoName} doesn't exist on the service account. Did you call appcrane_create_managed_app first?`);
      err.status = 404;
      throw err;
    }
    throw e;
  }

  const branch = opts.branch || repo.default_branch || 'main';
  const message = opts.message || `chore: scaffolding for ${slug}`;

  // 1. Current branch tip
  const ref = await apiFetch(`/repos/${ownerRepo}/git/ref/heads/${encodeURIComponent(branch)}`);
  const parentCommitSha = ref.object.sha;

  // 2. Parent commit's tree
  const parentCommit = await apiFetch(`/repos/${ownerRepo}/git/commits/${parentCommitSha}`);
  const parentTreeSha = parentCommit.tree.sha;

  // 3. Create blobs for every file. Done in parallel — GitHub rate-limits
  // separately from REST endpoints (5000/h for authenticated). For a
  // ~20-file scaffold that's fine.
  const blobs = await Promise.all(files.map(async (f) => {
    const blob = await apiFetch(`/repos/${ownerRepo}/git/blobs`, {
      method: 'POST',
      body: { content: f.content, encoding: f.encoding || 'utf-8' },
    });
    return { path: f.path, sha: blob.sha, mode: '100644', type: 'blob' };
  }));

  // 4. New tree based on parent, with our blobs grafted in.
  const newTree = await apiFetch(`/repos/${ownerRepo}/git/trees`, {
    method: 'POST',
    body: { base_tree: parentTreeSha, tree: blobs },
  });

  // 5. Commit pointing at the new tree.
  const newCommit = await apiFetch(`/repos/${ownerRepo}/git/commits`, {
    method: 'POST',
    body: { message, tree: newTree.sha, parents: [parentCommitSha] },
  });

  // 6. Move the branch ref forward. Not force — if someone else pushed
  // in the meantime we'd want a clear error rather than silent overwrite.
  await apiFetch(`/repos/${ownerRepo}/git/refs/heads/${encodeURIComponent(branch)}`, {
    method: 'PATCH',
    body: { sha: newCommit.sha, force: false },
  });

  return {
    commit: { sha: newCommit.sha, html_url: `${repo.html_url}/commit/${newCommit.sha}` },
    branch,
    files: files.map(f => f.path),
    message,
  };
}
