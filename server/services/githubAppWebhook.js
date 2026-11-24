/**
 * What a verified delivery to this instance's GitHub App webhook does.
 * routes/githubAppWebhook.js has already checked the signature and claimed the
 * delivery id before anything here runs.
 *
 * Apps are NEVER chosen from payload data alone. A push reaches an app only when
 *   - app_github_installations has a row for (installation.id, repository.full_name)
 *     -- repo compared case-insensitively, as GitHub treats owner/repo --
 *   - the app's github_url still names that repository (the same rule the
 *     credential resolver enforces), and
 *   - GitHub has not reported the installation / repository as removed.
 * Then the push goes through the same gate and trigger as the per-app webhook:
 * evaluatePush (branch filter, auto-deploy flags) and triggerAutoDeploys.
 *
 * A `repository` renamed / transferred delivery is matched on GitHub's numeric
 * repository id (app_github_installations.repo_id, migration 291), which a
 * verified push or installation_repositories delivery records while the row
 * still matches by installation and name. It changes the row's repo_full_name
 * and the app's github_url, and nothing else.
 */

import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';
import {
  evaluatePush, recordDelivery, triggerAutoDeploys, pushConfigForApp, GITHUB_APP_PUSH_SOURCE,
} from './deployTrigger.js';
import { installationRepoMismatch } from './githubCredential.js';
import { githubWebBase } from './githubApp.js';
import {
  installationBlockedReason, setInstallationStatus, getInstallationStatus,
  markReposRemoved, clearReposRemoved,
} from './githubAppWebhookState.js';

function validInstallationId(payload) {
  const id = Number(payload?.installation?.id);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function validRepoId(repo) {
  const id = Number(repo?.id);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function recordRepoId(db, appIds, repoId) {
  if (!repoId || !appIds.length) return;
  db.prepare(`UPDATE app_github_installations SET repo_id = ? WHERE app_id IN (${appIds.map(() => '?').join(',')}) AND repo_id IS NOT ?`)
    .run(repoId, ...appIds, repoId);
}

function attachedRows(installationId) {
  return getDb().prepare('SELECT * FROM app_github_installations WHERE installation_id = ? ORDER BY app_id').all(installationId);
}

async function handlePush({ deliveryId, payload, payloadHash, deps }) {
  if (payload?.deleted === true) return { result: 'ignored_deleted_ref' };
  const ref = typeof payload?.ref === 'string' ? payload.ref : '';
  if (!ref.startsWith('refs/heads/')) return { result: 'ignored_non_branch_ref' };
  const branch = ref.slice('refs/heads/'.length);

  const installationId = validInstallationId(payload);
  const repoFullName = payload?.repository?.full_name;
  if (!installationId || typeof repoFullName !== 'string' || !repoFullName) {
    return { result: 'ignored_no_installation' };
  }

  const db = getDb();
  const rows = db.prepare(`
    SELECT * FROM app_github_installations
    WHERE installation_id = ? AND lower(repo_full_name) = lower(?)
    ORDER BY app_id
  `).all(installationId, repoFullName);
  if (!rows.length) return { result: 'ignored_unattached' };
  recordRepoId(db, rows.map((r) => r.app_id), validRepoId(payload.repository));

  const commitSha = typeof payload.after === 'string' ? payload.after.slice(0, 8) : null;
  const commitMessage = typeof payload.head_commit?.message === 'string' ? payload.head_commit.message.slice(0, 200) : undefined;
  const apps = [];

  for (const inst of rows) {
    const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(inst.app_id);
    if (!app) continue;
    const logDelivery = (d) => recordDelivery({
      appId: app.id, event: 'github-app-push', deliveryId, payloadHash, sigValid: true, ...d,
    });

    if (app.source_type !== 'github' || installationRepoMismatch(app, inst)) {
      logDelivery({ actionTaken: 'skipped_repo_mismatch', branch, commitSha });
      apps.push({ slug: app.slug, action: 'skipped_repo_mismatch' });
      continue;
    }
    if (installationBlockedReason(app.slug, installationId, inst.repo_full_name)) {
      logDelivery({ actionTaken: 'skipped_installation_removed', branch, commitSha });
      apps.push({ slug: app.slug, action: 'skipped_installation_removed' });
      continue;
    }
    const config = pushConfigForApp(app.id);
    if (!config) {
      logDelivery({ actionTaken: 'skipped_no_config', branch, commitSha });
      apps.push({ slug: app.slug, action: 'skipped_no_config' });
      continue;
    }
    const gate = evaluatePush(config, branch);
    if (gate.action !== 'deploy') {
      logDelivery({ actionTaken: gate.action, branch, commitSha });
      apps.push({ slug: app.slug, action: gate.action, branch_filter: gate.filterBranch });
      continue;
    }
    const triggered = await triggerAutoDeploys({
      config, branch, commitSha, commitMessage, logDelivery, source: GITHUB_APP_PUSH_SOURCE, deps,
    });
    const allQueued = triggered.length > 0 && triggered.every((t) => t.status === 'queued');
    apps.push({ slug: app.slug, action: allQueued ? 'deploy_queued' : 'deploy_triggered', triggered });
  }

  const result = apps.some((a) => a.action === 'deploy_triggered') ? 'deploy_triggered'
    : apps.some((a) => a.action === 'deploy_queued') ? 'deploy_queued' : 'no_deploy';
  return { result, apps };
}

function handleInstallation({ payload }) {
  const installationId = validInstallationId(payload);
  if (!installationId) return { result: 'ignored_no_installation' };
  const action = payload.action;
  if (!['deleted', 'suspend', 'unsuspend'].includes(action)) return { status: 202, result: 'ignored_action' };

  const rows = attachedRows(installationId);
  if (!rows.length) return { result: 'ignored_unattached' };

  if (action === 'deleted') setInstallationStatus(installationId, 'deleted');
  if (action === 'suspend') setInstallationStatus(installationId, 'suspended');
  if (action === 'unsuspend' && getInstallationStatus(installationId)?.status === 'suspended') {
    setInstallationStatus(installationId, null);
  }
  for (const r of rows) {
    logAudit(null, r.app_id, `github-app-installation-${action}`, { installation_id: installationId, repo: r.repo_full_name });
  }
  log.info(`[github-app-webhook] installation ${installationId} ${action}: ${rows.map((r) => r.slug).join(', ')}`);
  return { result: `installation_${action}`, apps: rows.map((r) => r.slug) };
}

function handleInstallationRepositories({ payload }) {
  const installationId = validInstallationId(payload);
  if (!installationId) return { result: 'ignored_no_installation' };
  const action = payload.action;
  const list = action === 'removed' ? payload.repositories_removed : action === 'added' ? payload.repositories_added : null;
  if (!list) return { status: 202, result: 'ignored_action' };

  const names = new Set((Array.isArray(list) ? list : [])
    .map((r) => r?.full_name).filter((n) => typeof n === 'string' && n).map((n) => n.toLowerCase()));
  const affected = attachedRows(installationId).filter((r) => names.has(String(r.repo_full_name).toLowerCase()));
  if (!affected.length) return { result: 'ignored_unattached' };

  const repos = affected.map((r) => r.repo_full_name);
  if (action === 'removed') markReposRemoved(installationId, repos);
  else {
    clearReposRemoved(installationId, repos);
    const idByName = new Map(list.filter((r) => typeof r?.full_name === 'string').map((r) => [r.full_name.toLowerCase(), validRepoId(r)]));
    for (const r of affected) recordRepoId(getDb(), [r.app_id], idByName.get(String(r.repo_full_name).toLowerCase()));
  }
  for (const r of affected) {
    logAudit(null, r.app_id, `github-app-repository-${action}`, { installation_id: installationId, repo: r.repo_full_name });
  }
  log.info(`[github-app-webhook] installation ${installationId} repositories ${action}: ${affected.map((r) => r.slug).join(', ')}`);
  return { result: `repositories_${action}`, apps: affected.map((r) => r.slug) };
}

const FULL_NAME_RE = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;

/**
 * The repository's name before this change, from the payload's `changes`:
 * renamed carries changes.repository.name.from (the old name), transferred
 * changes.owner.from.user (or .organization) (the old owner).
 */
function previousFullName(action, payload) {
  const repo = payload.repository;
  if (action === 'renamed') {
    const from = payload.changes?.repository?.name?.from;
    return typeof from === 'string' && typeof repo?.owner?.login === 'string' ? `${repo.owner.login}/${from}` : null;
  }
  const owner = payload.changes?.owner?.from?.user?.login || payload.changes?.owner?.from?.organization?.login;
  return typeof owner === 'string' && typeof repo?.name === 'string' ? `${owner}/${repo.name}` : null;
}

function handleRepository({ payload }) {
  const action = payload?.action;
  if (action !== 'renamed' && action !== 'transferred') return { status: 202, result: 'ignored_action' };
  const repoId = validRepoId(payload.repository);
  const newName = payload.repository?.full_name;
  if (!repoId || typeof newName !== 'string' || !FULL_NAME_RE.test(newName)) return { status: 400, result: 'ignored_malformed' };

  const db = getDb();
  const rows = db.prepare('SELECT * FROM app_github_installations WHERE repo_id = ? ORDER BY app_id').all(repoId);
  if (!rows.length) return { result: 'ignored_unattached' };

  const before = previousFullName(action, payload);
  const apps = [];
  for (const inst of rows) {
    const app = db.prepare('SELECT id, slug, github_url FROM apps WHERE id = ?').get(inst.app_id);
    if (!app) continue;
    // The id is the match. The row must also still name the repository as it
    // was before this change: a row re-attached to another repository since
    // the id was recorded keeps a stale id, and is not rewritten from it.
    if (!before || String(inst.repo_full_name).toLowerCase() !== before.toLowerCase()) {
      apps.push({ slug: app.slug, action: 'skipped_stale_attachment' });
      logAudit(null, app.id, `github-app-repository-${action}-skipped`, { repo_id: repoId, attached_repo: inst.repo_full_name, previous: before, now: newName });
      continue;
    }
    // github_url follows only when it named the attached repository; a URL
    // someone pointed elsewhere is theirs, and the reconciler flags it.
    const urlFollows = !installationRepoMismatch(app, inst);
    const url = `${githubWebBase().replace(/\/+$/, '')}/${newName}`;
    db.transaction(() => {
      db.prepare('UPDATE app_github_installations SET repo_full_name = ? WHERE app_id = ?').run(newName, app.id);
      if (urlFollows) db.prepare('UPDATE apps SET github_url = ? WHERE id = ?').run(url, app.id);
    })();
    logAudit(null, app.id, `github-app-repository-${action}`, {
      repo_id: repoId, from: inst.repo_full_name, to: newName,
      github_url: urlFollows ? { from: app.github_url, to: url } : { unchanged: app.github_url },
      installation_id: inst.installation_id, delivery_installation_id: validInstallationId(payload),
    });
    apps.push({ slug: app.slug, action: urlFollows ? 'updated' : 'updated_installation_only' });
  }
  log.info(`[github-app-webhook] repository ${repoId} ${action} to ${newName}: ${apps.map((a) => `${a.slug} ${a.action}`).join(', ')}`);
  return { result: `repository_${action}`, apps };
}

// Test seam, same purpose as triggerAutoDeploys' `deps`: lets a test observe
// deployApp over HTTP without building anything. Never set in production.
let _testDeployDeps = null;
export function setDeployDepsForTests(deps) {
  _testDeployDeps = deps;
}

/** Returns { status?, result, apps? }. */
export async function handleGithubAppEvent({ event, deliveryId, payload, payloadHash = null, deps = _testDeployDeps }) {
  switch (event) {
    case 'ping':
      return { result: 'pong' };
    case 'push':
      return handlePush({ deliveryId, payload, payloadHash, deps });
    case 'installation':
      return handleInstallation({ payload });
    case 'installation_repositories':
      return handleInstallationRepositories({ payload });
    case 'repository':
      return handleRepository({ payload });
    default:
      log.debug(`[github-app-webhook] ignored event '${event}' (delivery ${deliveryId})`);
      return { status: 202, result: 'ignored_event' };
  }
}
