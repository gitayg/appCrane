/**
 * State kept for the GitHub App webhook receiver: delivery dedupe, and what
 * GitHub has told us about installations and repositories being removed.
 *
 * Kept separate from githubCredential.js so the credential resolver can ask
 * "is this installation still usable?" without importing the HTTP receiver.
 */

import { getDb } from '../db.js';

// GitHub: redeliveries keep the same X-GitHub-Delivery and are possible for
// deliveries from the past 3 days. 7 days covers that with margin.
export const DELIVERY_RETENTION_DAYS = 7;

/**
 * Claim a delivery id. Returns true the first time an id is seen, false for a
 * redelivery / replay. Claimed BEFORE acting, so two concurrent arrivals of the
 * same id cannot both act.
 */
export function claimDelivery(deliveryId, event, action) {
  const db = getDb();
  db.prepare(`DELETE FROM github_app_webhook_deliveries WHERE received_at < datetime('now', ?)`)
    .run(`-${DELIVERY_RETENTION_DAYS} days`);
  const r = db.prepare('INSERT OR IGNORE INTO github_app_webhook_deliveries (delivery_id, event, action) VALUES (?, ?, ?)')
    .run(deliveryId, event, action || null);
  return r.changes === 1;
}

export function recordDeliveryResult(deliveryId, result) {
  getDb().prepare('UPDATE github_app_webhook_deliveries SET result = ? WHERE delivery_id = ?').run(result, deliveryId);
}

export function lastDeliveryAt() {
  try {
    return getDb().prepare('SELECT MAX(received_at) AS t FROM github_app_webhook_deliveries').get()?.t || null;
  } catch (_) {
    return null;
  }
}

export function setInstallationStatus(installationId, status) {
  const db = getDb();
  if (status === null) {
    db.prepare('DELETE FROM github_app_installation_state WHERE installation_id = ?').run(installationId);
    return;
  }
  db.prepare(`
    INSERT INTO github_app_installation_state (installation_id, status) VALUES (?, ?)
    ON CONFLICT(installation_id) DO UPDATE SET status = excluded.status, changed_at = datetime('now')
  `).run(installationId, status);
}

export function getInstallationStatus(installationId) {
  try {
    return getDb().prepare('SELECT status, changed_at FROM github_app_installation_state WHERE installation_id = ?').get(installationId) || null;
  } catch (_) {
    return null;
  }
}

export function markReposRemoved(installationId, fullNames) {
  const stmt = getDb().prepare('INSERT OR IGNORE INTO github_app_removed_repos (installation_id, repo_full_name) VALUES (?, ?)');
  for (const n of fullNames) stmt.run(installationId, String(n).toLowerCase());
}

export function clearReposRemoved(installationId, fullNames) {
  const stmt = getDb().prepare('DELETE FROM github_app_removed_repos WHERE installation_id = ? AND repo_full_name = ?');
  for (const n of fullNames) stmt.run(installationId, String(n).toLowerCase());
}

export function isRepoRemoved(installationId, fullName) {
  try {
    return !!getDb().prepare('SELECT 1 FROM github_app_removed_repos WHERE installation_id = ? AND repo_full_name = ?')
      .get(installationId, String(fullName).toLowerCase());
  } catch (_) {
    return false;
  }
}

/**
 * Why an attached installation can no longer be used for `repoFullName`, as a
 * message an operator can act on, or null when nothing GitHub reported blocks it.
 */
export function installationBlockedReason(slug, installationId, repoFullName) {
  const st = getInstallationStatus(installationId);
  if (st?.status === 'deleted') {
    return `App '${slug}' is attached to GitHub App installation ${installationId}, which was uninstalled on GitHub (${st.changed_at} UTC). `
      + 'Install the App on the repository again, then re-attach it (Applications → gh app), or detach to use a personal access token.';
  }
  if (st?.status === 'suspended') {
    return `App '${slug}' is attached to GitHub App installation ${installationId}, which is suspended on GitHub (${st.changed_at} UTC). `
      + 'Unsuspend the installation on GitHub, or detach to use a personal access token.';
  }
  if (repoFullName && isRepoRemoved(installationId, repoFullName)) {
    return `Repository ${repoFullName} was removed from GitHub App installation ${installationId} on GitHub. `
      + `Add it back to the installation, then re-attach '${slug}' (Applications → gh app), or detach to use a personal access token.`;
  }
  return null;
}
