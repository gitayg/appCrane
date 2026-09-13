/**
 * Where an app's code comes from, as ONE label the app list shows per app.
 *
 *   crane_hosted    managed, repo_backend='local'   (git repo on this host)
 *   managed_github  managed, repo_backend NULL      (service-account repo on GitHub)
 *   github_app      github, installation attached   (short-lived installation tokens)
 *   github_token    github, stored PAT, no installation
 *   github_public   github, no credential at all
 *   null            every other source_type, or a repo_backend value managedRepo.js refuses
 *
 * Installation before PAT mirrors services/githubCredential.js: an attached
 * installation is what deploys authenticate with, even if a PAT is still stored.
 */

import { getDb } from '../db.js';

export function codeSourceOf(app, githubAppAttached) {
  if (app.source_type === 'managed') {
    if (app.repo_backend === null || app.repo_backend === undefined) return 'managed_github';
    if (app.repo_backend === 'local') return 'crane_hosted';
    return null;
  }
  if (app.source_type === 'github') {
    if (githubAppAttached) return 'github_app';
    if (app.github_token_encrypted) return 'github_token';
    return 'github_public';
  }
  return null;
}

/** app ids with a GitHub App installation attached, in one query. */
export function attachedInstallationIds(appIds) {
  if (!appIds.length) return new Set();
  try {
    const rows = getDb().prepare(
      `SELECT app_id FROM app_github_installations WHERE app_id IN (${appIds.map(() => '?').join(',')})`
    ).all(...appIds);
    return new Set(rows.map(r => r.app_id));
  } catch (_) {
    return new Set();
  }
}

export function codeSourceFields(app, attachedIds) {
  const github_app_attached = attachedIds.has(app.id);
  return {
    repo_backend: app.repo_backend ?? null,
    github_app_attached,
    code_source: codeSourceOf(app, github_app_attached),
  };
}
