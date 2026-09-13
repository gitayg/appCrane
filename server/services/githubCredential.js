/**
 * ONE place decides which credential a CONNECTED (source_type='github') app
 * authenticates to GitHub with (v2.75.0).
 *
 * Order, and why there is no fallback between the two:
 *
 *   1. The app has a GitHub App installation attached -> a short-lived
 *      installation access token, narrowed to that one repository. If issuing
 *      it fails, the operation FAILS. It does NOT quietly fall back to a PAT.
 *      An operator who attached an installation is retiring that PAT; silently
 *      using it again would mean the token they are trying to stop relying on
 *      keeps being used, at the exact moment something is wrong, and they would
 *      never see it. A clear error is recoverable; an invisible fallback is not.
 *
 *   2. No installation -> the stored PAT, decrypted exactly as before. This
 *      path is byte-for-byte the pre-v2.75.0 behaviour, including the two
 *      different reactions to an undecryptable blob: deploys throw (they always
 *      did), read-only pollers treat it as "no token" (they always did). That
 *      is what `patErrors` selects; it is a description of existing callers,
 *      not a new policy.
 *
 * Managed apps (source_type='managed') never come through here: they use the
 * platform service account, or their repository lives on this host.
 */

import { getDb } from '../db.js';
import { decrypt } from './encryption.js';
import {
  getAppConfig, getInstallationToken, findInstallationForRepo, githubWebBase,
} from './githubApp.js';
import {
  installationBlockedReason, getInstallationStatus, setInstallationStatus, clearReposRemoved,
} from './githubAppWebhookState.js';

/**
 * owner/repo from a github_url. Host-checked against the configured GitHub web
 * base so a URL pointing somewhere else cannot be treated as a GitHub repo.
 */
export function parseGithubRepo(url) {
  if (!url) return null;
  let host;
  try { host = new URL(githubWebBase()).hostname; } catch (_) { host = 'github.com'; }
  try {
    const u = new URL(url);
    if (u.hostname !== host && !(host === 'github.com' && /(?:^|\.)github\.com$/.test(u.hostname))) return null;
    const parts = u.pathname.replace(/^\/+|\/+$/g, '').replace(/\.git$/, '').split('/');
    if (parts.length < 2 || !parts[0] || !parts[1]) return null;
    return { owner: parts[0], repo: parts[1], fullName: `${parts[0]}/${parts[1]}` };
  } catch (_) {
    return null;
  }
}

/** The installation attached to an app, or null. */
export function getInstallation(appId) {
  try {
    return getDb().prepare('SELECT * FROM app_github_installations WHERE app_id = ?').get(appId) || null;
  } catch (_) {
    return null;
  }
}

/**
 * Attach an app to the installation that covers its repository. The
 * installation id is resolved from GitHub with this instance's App JWT -- never
 * taken from a redirect parameter, because GitHub's own docs say a spoofed
 * `installation_id` can be handed to the setup URL.
 */
export async function attachInstallation(app, userId = null) {
  if (!getAppConfig()) {
    throw new Error('No GitHub App is configured on this AppCrane instance. A platform admin creates one at Settings → GitHub.');
  }
  if (app.source_type !== 'github') {
    throw new Error(`App '${app.slug}' is source_type='${app.source_type || '(unset)'}'. GitHub App authentication is for connected GitHub repositories only.`);
  }
  const parsed = parseGithubRepo(app.github_url);
  if (!parsed) throw new Error(`App '${app.slug}' has no parseable GitHub repository URL.`);

  const { installationId, account } = await findInstallationForRepo(parsed.owner, parsed.repo);
  getDb().prepare(`
    INSERT INTO app_github_installations (app_id, slug, installation_id, repo_full_name, attached_by)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(app_id) DO UPDATE SET
      slug = excluded.slug, installation_id = excluded.installation_id,
      repo_full_name = excluded.repo_full_name, attached_by = excluded.attached_by,
      attached_at = datetime('now')
  `).run(app.id, app.slug, installationId, parsed.fullName, userId);
  // GitHub just confirmed this installation covers this repository, so an
  // earlier "uninstalled" / "repository removed" report no longer applies.
  // A suspension is left alone: a suspended installation can still be listed.
  if (getInstallationStatus(installationId)?.status === 'deleted') setInstallationStatus(installationId, null);
  clearReposRemoved(installationId, [parsed.fullName]);
  return { installation_id: installationId, repo_full_name: parsed.fullName, account };
}

/** Stop using the GitHub App for this app. Whatever PAT it has applies again. */
export function detachInstallation(appId) {
  getDb().prepare('DELETE FROM app_github_installations WHERE app_id = ?').run(appId);
}

/** Every app currently attached to an installation (admin views, delete guard). */
export function listAttachedApps() {
  try {
    return getDb().prepare('SELECT app_id, slug, installation_id, repo_full_name, attached_at FROM app_github_installations ORDER BY slug').all();
  } catch (_) {
    return [];
  }
}

/**
 * Why an app may NOT use the installation row it is attached to: its github_url
 * no longer parses, or names a different repository than the one attached.
 * null when they match (owner/repo compared case-insensitively).
 */
export function installationRepoMismatch(app, inst) {
  const parsed = parseGithubRepo(app?.github_url);
  if (!parsed) {
    return `App '${app?.slug}' is attached to a GitHub App installation but its github_url is not a GitHub repository URL.`;
  }
  if (parsed.fullName.toLowerCase() !== String(inst.repo_full_name).toLowerCase()) {
    return `App '${app.slug}' now points at ${parsed.fullName}, but its GitHub App installation was attached to ${inst.repo_full_name}. ` +
      'Re-attach the installation for the new repository (Applications → GitHub App) before deploying.';
  }
  return null;
}

/**
 * The credential for one connected app.
 *
 * Returns { source: 'installation' | 'pat' | 'none', token, installationId?,
 * repoFullName? }. Throws only on the installation path.
 *
 * patErrors: 'null' (default) matches the read-only callers, which have always
 * treated an undecryptable token as no token; 'throw' matches the deployer,
 * which has always let the decrypt error out.
 */
export async function resolveGitHubCredential(app, { patErrors = 'null', nowMs } = {}) {
  const inst = app?.id ? getInstallation(app.id) : null;

  if (!inst) {
    if (!app?.github_token_encrypted) return { source: 'none', token: null };
    if (patErrors === 'throw') return { source: 'pat', token: decrypt(app.github_token_encrypted) };
    try { return { source: 'pat', token: decrypt(app.github_token_encrypted) }; }
    catch (_) { return { source: 'pat', token: null }; }
  }

  if (!getAppConfig()) {
    throw new Error(
      `App '${app.slug}' is attached to GitHub App installation ${inst.installation_id}, but no GitHub App is configured on this instance. ` +
      'Refusing to fall back to a stored personal access token: re-create the App at Settings → GitHub, or detach the installation from this app first.',
    );
  }

  const mismatch = installationRepoMismatch(app, inst);
  if (mismatch) throw new Error(mismatch);
  const parsed = parseGithubRepo(app.github_url);

  const blocked = installationBlockedReason(app.slug, inst.installation_id, inst.repo_full_name);
  if (blocked) throw new Error(blocked);

  const token = await getInstallationToken(inst.installation_id, { repositories: [parsed.repo], nowMs });
  return {
    source: 'installation',
    token,
    installationId: inst.installation_id,
    repoFullName: inst.repo_full_name,
  };
}
