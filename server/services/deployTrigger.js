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
 *
 * One deploy per app+env at a time: a push that lands while a fresh deploy of
 * that env is in flight starts nothing. It is queued (services/pushCoalescer.js)
 * as that env's single follow-up, newest push wins, and AppCrane deploys it
 * once when the in-flight deploy ends. A local push's follow-up re-reads the
 * branch tip then, so every file pushed meanwhile ships in that one build.
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

/** A push delivered to this instance's GitHub App webhook (routes/githubAppWebhook.js). */
export const GITHUB_APP_PUSH_SOURCE = Object.freeze({
  deploymentLog: 'Triggered by GitHub App push webhook',
  auditAction: 'github-app-push-deploy',
  triggeredMsg: (env, slug) => `GitHub App push triggered ${env} deploy for ${slug}`,
  failedMsg: (env) => `GitHub App push-triggered ${env} deploy failed`,
  unavailableMsg: (env) => `Deploy service not available for GitHub App push-triggered ${env} deploy`,
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
 * An env with a fresh deploy already in flight gets no row and no deployApp:
 * the push is queued behind it (see the header) and reported as
 * { env, status: 'queued', queued_behind: <in-flight deployment id> }.
 *
 * The caller has already passed evaluatePush. Returns
 * [{ env, deployment_id } | { env, status: 'queued', queued_behind }] in
 * trigger order.
 *
 * `envs` limits the run to those environments (a queued follow-up runs for its
 * own env only). `refreshCommit`, when given, returns the commit a queued
 * follow-up deploys, read at follow-up time (a local push passes the branch
 * tip). `deps` exists for tests that must observe deployApp without building
 * anything; production callers never pass it.
 */
export async function triggerAutoDeploys({
  config, branch, commitSha, commitMessage, logDelivery,
  source = WEBHOOK_SOURCE, actorId = null, deps = null,
  envs = null, refreshCommit = null,
}) {
  const db = getDb();
  const triggered = [];

  for (const { env, flag } of ENVIRONMENTS) {
    if (!config[flag]) continue;
    if (envs && !envs.includes(env)) continue;
    const { restoreInProgress } = await import('./managedDbRestoreGuard.js');
    if (restoreInProgress(config.slug, env)) {
      log.warn(`[deploy-trigger] ${config.slug}/${env}: not deployed, a database restore is running`);
      logDelivery({ actionTaken: 'skipped_restore', branch, commitSha });
      continue;
    }

    const queued = await queueBehindInflight({
      config, env, flag, branch, commitSha, commitMessage, logDelivery, source, actorId, deps, refreshCommit,
    });
    if (queued) {
      triggered.push(queued);
      continue;
    }

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
 * When a fresh deploy of config's app+env is in flight, park this push as that
 * env's follow-up and return its queued entry; otherwise null. Never throws:
 * if the check itself fails, the push deploys as it always has.
 */
async function queueBehindInflight({
  config, env, flag, branch, commitSha, commitMessage, logDelivery, source, actorId, deps, refreshCommit,
}) {
  try {
    const { freshInflightDeploy } = await import('./deployer.js');
    const inflight = freshInflightDeploy(getDb(), config.app_id, env);
    if (!inflight) return null;

    const { queueFollowUp } = await import('./pushCoalescer.js');
    queueFollowUp({
      appId: config.app_id, env, slug: config.slug, behind: inflight.id,
      run: async () => {
        const current = pushConfigForApp(config.app_id);
        const gate = current ? evaluatePush(current, branch).action : 'skipped_no_config';
        if (gate !== 'deploy' || !current[flag]) {
          log.info(`[push-coalesce] ${config.slug}/${env}: queued push not deployed (${gate !== 'deploy' ? gate : 'skipped_no_auto'})`);
          logDelivery({ actionTaken: gate !== 'deploy' ? gate : 'skipped_no_auto', branch, commitSha });
          return;
        }
        const sha = refreshCommit ? await refreshCommit() : commitSha;
        await triggerAutoDeploys({
          config: current, branch, commitSha: sha, commitMessage, logDelivery,
          source, actorId, deps, envs: [env], refreshCommit,
        });
      },
    });
    logDelivery({ actionTaken: 'deploy_queued', branch, commitSha, deployId: inflight.id });
    return { env, status: 'queued', queued_behind: inflight.id };
  } catch (e) {
    log.warn(`[push-coalesce] ${config.slug}/${env}: could not queue behind the running deploy, deploying now: ${e.message}`);
    return null;
  }
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
 * Returns { action, branch, commit?, triggered: [...], error? }; action is
 * 'deploy_queued' when every env was queued behind a running deploy.
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

    out.triggered = await triggerAutoDeploys({
      config, branch, commitSha,
      commitMessage: pushResult?.message?.slice(0, 200),
      logDelivery, source: LOCAL_PUSH_SOURCE, actorId, deps,
      refreshCommit: async () => (await localBranchHeadSha(app, branch)).slice(0, 8),
    });
    const allQueued = out.triggered.length > 0 && out.triggered.every((t) => t.status === 'queued');
    out.action = allQueued ? 'deploy_queued' : 'deploy_triggered';
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
  if (ad.action === 'deploy_queued' && ad.triggered?.length) {
    const behind = [...new Set(ad.triggered.map((t) => t.queued_behind))].join(', ');
    return {
      auto_deploy: ad,
      next: `Pushed. A deploy of this app (deployment ${behind}) is still running; this commit is queued and AppCrane will ` +
        'deploy the branch tip once, when it finishes, including any files you push meanwhile. Do not call appcrane_deploy. ' +
        'Push the rest of the change now, ideally all files in ONE appcrane_push_to_managed_app call.',
    };
  }
  if (ad.triggered?.length) {
    const startedRows = ad.triggered.filter((t) => t.status !== 'queued');
    const queuedRows = ad.triggered.filter((t) => t.status === 'queued');
    const started = startedRows.map((t) => `${t.env} deployment ${t.deployment_id}`).join(', ');
    const queuedNote = queuedRows.length
      ? ` ${queuedRows.map((t) => `${t.env} is queued behind deployment ${t.queued_behind}`).join(', ')}; it deploys once that finishes.`
      : '';
    return {
      auto_deploy: ad,
      next: `Pushed. Deploy on push started ${started} for commit ${ad.commit} — do not call appcrane_deploy for this commit. ` +
        `Follow it with appcrane_wait_deploy deployment_id=${startedRows[0].deployment_id}.${queuedNote}`,
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
