/**
 * Deploy-on-push: the ONE implementation of "a commit landed on the watched
 * branch, so start the deploys this app is marked for".
 *
 * Two pushes reach it:
 *   - a GitHub push, through the signed webhook (routes/webhooks.js)
 *   - a commit to a local managed repo on this host (services/managedRepo.js)
 *
 * "Marked" is the app's webhook_configs row, which every app gets at creation:
 * auto_deploy_sandbox (default 1), auto_deploy_prod (default 0), branch_filter
 * (default 'main'). The same row governs both sources, so the switches an
 * operator already sees for the GitHub webhook are the switches for a local
 * push too.
 *
 * The webhook used to inline the trigger once per environment. It was moved
 * here unchanged — same SQL, same audit action and detail, same log lines, same
 * order of writes — and routes/webhooks.js now calls it. A local push passes a
 * different `source` (its own deployment note, audit action and actor) and
 * nothing else differs.
 */

import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';

/** What the GitHub webhook has always written and logged. */
export const WEBHOOK_SOURCE = Object.freeze({
  deploymentLog: 'Triggered by webhook',
  auditAction: 'webhook-deploy',
  triggeredMsg: (env, slug) => `Webhook triggered ${env} deploy for ${slug}`,
  failedMsg: (env) => (env === 'production' ? 'Webhook prod deploy failed' : 'Webhook deploy failed'),
  unavailableMsg: (env) => (env === 'production'
    ? 'Deploy service not available for webhook prod trigger'
    : 'Deploy service not available for webhook trigger'),
});

/** A commit to a local managed repo (appcrane_push_to_managed_app & co). */
export const LOCAL_PUSH_SOURCE = Object.freeze({
  deploymentLog: 'Triggered by push to the managed repository',
  auditAction: 'push-deploy',
  triggeredMsg: (env, slug) => `Push triggered ${env} deploy for ${slug}`,
  failedMsg: (env) => `Push-triggered ${env} deploy failed`,
  unavailableMsg: (env) => `Deploy service not available for push-triggered ${env} deploy`,
});

const ENVIRONMENTS = [
  { env: 'sandbox', flag: 'auto_deploy_sandbox' },
  { env: 'production', flag: 'auto_deploy_prod' },
];

/** The webhook_configs row joined the way the webhook route reads it. */
export function pushConfigForApp(appId) {
  return getDb().prepare(`
    SELECT wc.*, a.id as app_id, a.slug, a.name as app_name, a.branch as app_branch
    FROM webhook_configs wc
    JOIN apps a ON a.id = wc.app_id
    WHERE wc.app_id = ?
  `).get(appId);
}

/**
 * Should a push to `branch` deploy? Returns the delivery action name the
 * webhook has always recorded: 'skipped_branch', 'skipped_no_auto' or 'deploy'.
 */
export function evaluatePush(config, branch) {
  const filterBranch = config.branch_filter || config.app_branch || 'main';
  if (branch !== filterBranch) return { action: 'skipped_branch', filterBranch };
  if (!config.auto_deploy_sandbox && !config.auto_deploy_prod) return { action: 'skipped_no_auto', filterBranch };
  return { action: 'deploy', filterBranch };
}

/** One webhook_deliveries row, trimmed to the last 100 per app. Never throws. */
export function recordDelivery({ appId, event, deliveryId, payloadHash, sigValid, actionTaken, branch = null, commitSha = null, deployId = null }) {
  const db = getDb();
  try {
    db.prepare(`
      INSERT INTO webhook_deliveries
        (app_id, event, delivery_id, payload_hash, branch, commit_hash,
         sig_valid, action_taken, deploy_id, result)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      appId, event, deliveryId, payloadHash,
      branch, commitSha, sigValid ? 1 : 0, actionTaken, deployId ?? null,
      actionTaken, // keep legacy `result` column in sync
    );
    // Trim to last 100 per app (runs fast — table is tiny)
    db.prepare(`
      DELETE FROM webhook_deliveries
      WHERE app_id = ? AND id NOT IN (
        SELECT id FROM webhook_deliveries WHERE app_id = ? ORDER BY id DESC LIMIT 100
      )
    `).run(appId, appId);
  } catch (e) {
    log.warn(`Webhook delivery log failed: ${e.message}`);
  }
}

/**
 * Start the deploys `config` is marked for: sandbox first, then production.
 * Per environment: insert the pending deployments row, record the delivery,
 * audit, then hand the row to deployApp without waiting for the build.
 *
 * The caller has already passed evaluatePush. Returns
 * [{ env, deployment_id }] in trigger order.
 *
 * `deps` exists for tests that must observe deployApp without building
 * anything; production callers never pass it.
 */
export async function triggerAutoDeploys({
  config, branch, commitSha, commitMessage, logDelivery,
  source = WEBHOOK_SOURCE, actorId = null, deps = null,
}) {
  const db = getDb();
  const triggered = [];

  for (const { env, flag } of ENVIRONMENTS) {
    if (!config[flag]) continue;

    const deployResult = db.prepare(`
      INSERT INTO deployments (app_id, env, status, commit_hash, commit_message, log)
      VALUES (?, ?, 'pending', ?, ?, ?)
    `).run(config.app_id, env, commitSha, commitMessage, source.deploymentLog);

    logDelivery({ actionTaken: 'deploy_triggered', branch, commitSha, deployId: deployResult.lastInsertRowid });
    logAudit(actorId, config.app_id, source.auditAction, { env, commit: commitSha });
    triggered.push({ env, deployment_id: deployResult.lastInsertRowid });
    log.info(source.triggeredMsg(env, config.slug));

    try {
      const { deployApp } = deps || await import('./deployer.js');
      const { getPortsForSlot } = deps || await import('./portAllocator.js');
      const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(config.app_id);
      const ports = getPortsForSlot(app.slot);
      deployApp(deployResult.lastInsertRowid, app, env, ports).catch(err => {
        log.error(`${source.failedMsg(env)}: ${err.message}`);
      });
    } catch (e) {
      log.warn(source.unavailableMsg(env));
    }
  }

  return triggered;
}

/**
 * Deploy-on-push for a commit that just landed in a LOCAL managed repo.
 * Called by managedRepo.pushFilesToManagedRepo after the ref update, once per
 * committed push (a staged chunk commits nothing and never gets here).
 *
 * A race-displaced push must not deploy: under "newest wins" the push that
 * displaced this one owns the branch tip and runs this same function for it.
 * So the tip is re-read here, and a push whose commit is no longer the tip is
 * recorded as 'skipped_superseded' instead of starting a second deploy of
 * someone else's commit under this push's name.
 *
 * Never throws — the commit has landed; a deploy that could not be started is
 * reported in the return value and the delivery log, not as a failed push.
 * Returns { action, branch, commit?, triggered: [{ env, deployment_id }], error? }.
 */
export async function deployAfterLocalPush(app, pushResult, { actorId = null, deps = null } = {}) {
  const branch = pushResult?.branch;
  const pushed = pushResult?.commit?.sha || null;
  const out = { action: null, branch, triggered: [] };
  const logDelivery = (d) => recordDelivery({
    appId: app.id, event: 'managed-push', deliveryId: null, payloadHash: null, sigValid: true, ...d,
  });

  try {
    const config = pushConfigForApp(app.id);
    if (!config) {
      out.action = 'skipped_no_config';
      return out;
    }

    const { localBranchHeadSha } = await import('./managedRepo.js');
    const tip = await localBranchHeadSha(app, branch);
    const commitSha = tip.slice(0, 8);
    out.commit = commitSha;

    const gate = evaluatePush(config, branch);
    if (gate.action !== 'deploy') {
      out.action = gate.action;
      out.branch_filter = gate.filterBranch;
      logDelivery({ actionTaken: gate.action, branch, commitSha });
      return out;
    }

    if (tip !== pushed) {
      out.action = 'skipped_superseded';
      logDelivery({ actionTaken: 'skipped_superseded', branch, commitSha });
      return out;
    }

    out.action = 'deploy_triggered';
    out.triggered = await triggerAutoDeploys({
      config, branch, commitSha,
      commitMessage: pushResult?.message?.slice(0, 200),
      logDelivery, source: LOCAL_PUSH_SOURCE, actorId, deps,
    });
    return out;
  } catch (e) {
    log.warn(`Deploy-on-push for ${app.slug} could not start: ${e.message}`);
    out.action = 'error';
    out.error = e.message;
    return out;
  }
}

/**
 * The `auto_deploy` + `next` part of a push tool's response. A push with no
 * `auto_deploy` (a GitHub-backed app) gets exactly `{ next: defaultNext }`.
 * When deploys started, `next` tells the agent NOT to deploy again — a second
 * appcrane_deploy for the same commit would queue a duplicate build.
 */
export function pushDeployView(slug, result, defaultNext) {
  const ad = result?.auto_deploy;
  if (!ad) return { next: defaultNext };
  if (ad.triggered?.length) {
    const started = ad.triggered.map((t) => `${t.env} deployment ${t.deployment_id}`).join(', ');
    return {
      auto_deploy: ad,
      next: `Pushed. Deploy on push started ${started} for commit ${ad.commit} — do not call appcrane_deploy for this commit. ` +
        `Follow it with appcrane_wait_deploy deployment_id=${ad.triggered[0].deployment_id}.`,
    };
  }
  const why = {
    skipped_branch: `branch '${ad.branch}' is not the deploy-on-push branch '${ad.branch_filter}'`,
    skipped_no_auto: 'deploy on push is off for both environments',
    skipped_superseded: 'a newer push replaced this commit as the branch tip and deploys it instead',
    skipped_no_config: 'this app has no deploy-on-push settings',
    error: `it could not be started: ${ad.error}`,
  }[ad.action] || ad.action;
  return { auto_deploy: ad, next: `${defaultNext} (No automatic deploy: ${why}.)` };
}
