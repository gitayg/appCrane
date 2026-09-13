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
 */

import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';
import {
  evaluatePush, recordDelivery, triggerAutoDeploys, pushConfigForApp, GITHUB_APP_PUSH_SOURCE,
} from './deployTrigger.js';
import { installationRepoMismatch } from './githubCredential.js';
import {
  installationBlockedReason, setInstallationStatus, getInstallationStatus,
  markReposRemoved, clearReposRemoved,
} from './githubAppWebhookState.js';

function validInstallationId(payload) {
  const id = Number(payload?.installation?.id);
  return Number.isInteger(id) && id > 0 ? id : null;
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
    apps.push({ slug: app.slug, action: 'deploy_triggered', triggered });
  }

  return { result: apps.some((a) => a.action === 'deploy_triggered') ? 'deploy_triggered' : 'no_deploy', apps };
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
  else clearReposRemoved(installationId, repos);
  for (const r of affected) {
    logAudit(null, r.app_id, `github-app-repository-${action}`, { installation_id: installationId, repo: r.repo_full_name });
  }
  log.info(`[github-app-webhook] installation ${installationId} repositories ${action}: ${affected.map((r) => r.slug).join(', ')}`);
  return { result: `repositories_${action}`, apps: affected.map((r) => r.slug) };
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
    default:
      log.debug(`[github-app-webhook] ignored event '${event}' (delivery ${deliveryId})`);
      return { status: 202, result: 'ignored_event' };
  }
}
