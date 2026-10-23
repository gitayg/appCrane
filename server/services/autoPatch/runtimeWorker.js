// Runtime auto-patch: when an app's running language runtime (PHP today) is
// affected by a remote-code-execution advisory and its base image tag has a
// newer image, rebuild the SAME commit on a freshly pulled base, sandbox
// first, then production, under the RCE auto-patch policy (auto_approve_rce_fixes,
// the per-app opt-out). No repository write: the production commit is rebuilt
// as it is, so the new deployments record the same commit on a new base.
//
// In scope: apps whose repository AppCrane hosts and GitHub-backed apps. Both
// deploy from a repository AppCrane clones and pin to an exact commit, so a
// rebuild needs no write to it. The guard that keeps a rebuild from shipping
// something nobody promoted is commit equality: for a hosted repository the
// branch tip must equal production's commit (exact 40-hex, commits.js); for a
// GitHub app, whose tip AppCrane does not read without its token, the live
// sandbox must run exactly production's commit, which is what is about to be
// rebuilt over it. Image-source apps (prebuilt images) and uploads are never
// rebuilt: they are listed for a person.
//
// Every guardrail must hold; the first that does not hands the app to a person
// with the reason, and nothing further happens. One run per app at a time
// (partial unique index), and one run per (app, advisories, production image),
// so a person who redeploys production gets a fresh look.

import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { logAudit } from '../../middleware/audit.js';
import { trackJob, jobStarted, setJobDetail } from '../jobHealth.js';
import { effectiveForApp, POLICY_NAME } from './policy.js';
import { deploymentCommit, isFullSha } from './commits.js';
import { compareVersions, branchOf, RUNTIMES } from './runtimeAdvisories.js';
import { UnsupportedRegistry } from './runtimeRegistry.js';
import { sendRuntimePatchMail, notifyAdminsOfAdvisories } from './runtimeMail.js';

export const ACTOR = 'AppCrane runtime patch';
export const SWEEP_MS = 60 * 60 * 1000;
const RETRY_SOON_MS = 60 * 60 * 1000;
const WAIT_FOR_BASE_MS = 6 * 60 * 60 * 1000;
const MAX_PER_SWEEP = 5;
const RT_SUFFIX = /-rt[0-9a-z]+$/;

const defaults = {
  now: () => Date.now(),
  pollMs: 5000,
  deployTimeoutMs: 30 * 60 * 1000,
  healthSettleMs: 5 * 60 * 1000,
  inspect: async (slug, env, probe) => (await import('./runtimeInspect.js')).inspectContainerRuntime(slug, env, { probe }),
  imageVersion: async (ref, runtime) => (await import('./runtimeInspect.js')).imageRuntimeVersion(ref, runtime),
  advisories: async (runtime, version) => (await import('./runtimeAdvisories.js')).runtimeAdvisories(runtime, version),
  currentDigest: async (ref) => (await import('./runtimeRegistry.js')).currentDigest(ref),
  containerImage: async (slug, env) => (await import('../docker.js')).getContainerImage(slug, env),
  imageBase: async (ref) => (await import('../docker.js')).imageBaseInfo(ref),
  retag: async (from, to) => (await import('../docker.js')).tagImage(from, to),
  branchHead: async (app, branch) => (await import('../managedRepo.js')).localBranchHeadSha(app, branch),
  usesLocalRepo: async (app) => (await import('../managedRepo.js')).usesLocalRepo(app),
  resolveCommit: async (slug, hash) => (await import('./commits.js')).resolveCommitExact(slug, hash),
  deployApp: async (...a) => (await import('../deployer.js')).deployApp(...a),
  promoteApp: async (...a) => (await import('../deployer.js')).promoteApp(...a),
  rollbackApp: async (...a) => (await import('../deployer.js')).rollbackApp(...a),
  runReleaseCheck: async (ctx) => (await import('../releaseCheck.js')).runReleaseCheck(ctx),
  refuseDeployForMemory: async (ctx) => (await import('../deployer.js')).refuseDeployForMemory(ctx),
  assessRisk: async (ctx) => (await import('../redeployRisk.js')).assessRedeployRisk(ctx),
  restoreInProgress: async (slug) => (await import('../managedDbRestoreGuard.js')).restoreInProgress(slug),
  coderState: async (slug) => {
    const { getContainer } = await import('../builder/appContainer.js');
    const c = getContainer(slug);
    if (!c) return { live: false };
    if (c.busy) return { live: true, busy: true };
    const { listWorkspaceChanges } = await import('../builder/gitOps.js');
    return { live: true, dirty: listWorkspaceChanges(c.workspaceDir).length > 0 };
  },
  ports: async (slot) => (await import('../portAllocator.js')).getPortsForSlot(slot),
};

let testDeps = null;
/** Test seam: replaces any of the defaults above. */
export function _setRuntimePatchDepsForTests(d) { testDeps = d; }
const dep = () => ({ ...defaults, ...(testDeps || {}) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sqlTime = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
const exactCommit = (a, b) => isFullSha(a) && a === b;
const rtLabel = (rt) => RUNTIMES[rt]?.label || rt;

class Outcome extends Error {
  constructor(status, reason, extra = {}) { super(reason); this.status = status; this.reason = reason; this.extra = extra; }
}
const fallback = (reason) => new Outcome('fallback', reason);
const defer = (reason, retryAfterMs = RETRY_SOON_MS) => new Outcome('deferred', reason, { retryAfterMs });

function liveDeployment(db, appId, env) {
  return db.prepare(`SELECT * FROM deployments WHERE app_id = ? AND env = ? AND status = 'live' ORDER BY id DESC LIMIT 1`).get(appId, env) || null;
}

function sourceKind(app, local) {
  if (app.source_type === 'image') return 'image';
  if (local) return 'local';
  if ((app.source_type === 'github' || app.source_type === 'managed') && app.github_url) return 'github';
  return 'other';
}

/** The base this deployment was built on: image labels, then the deployment row, then the generated PHP base. */
function baseOf(info, deployment) {
  if (info?.base_image) return { image: info.base_image, digest: info.base_digest || null };
  if (deployment?.base_image) return { image: deployment.base_image, digest: deployment.base_digest || null };
  if (deployment?.php_version) return { image: `php:${deployment.php_version}-apache`, digest: null };
  return null;
}

async function transientBlock(db, app, d) {
  if (await d.restoreInProgress(app.slug)) return 'a database restore is running';
  const inflight = db.prepare(`SELECT id, env FROM deployments WHERE app_id = ? AND status IN ('pending','building','deploying')
    AND started_at > datetime('now', '-30 minutes') LIMIT 1`).get(app.id);
  if (inflight) return `deployment #${inflight.id} (${inflight.env}) is in progress`;
  if (db.prepare("SELECT 1 FROM auto_patch_runs WHERE app_id = ? AND status = 'running'").get(app.id)) return 'a dependency auto-patch is running on this app';
  let coder;
  try { coder = await d.coderState(app.slug); } catch (e) { return `could not read the coder workspace (${e.message})`; }
  if (coder?.busy) return 'a coder session is working on this app';
  if (coder?.dirty) return 'a coder session has uncommitted work on this app';
  return null;
}

async function stillAllowed(db, app, d) {
  const eff = effectiveForApp(db, app);
  if (!eff.enabled) return `auto-patch was turned off while this run was in progress (${eff.reason})`;
  if (await d.restoreInProgress(app.slug)) return 'a database restore started while this run was in progress';
  return null;
}

/** Why a person must act for this production row, or null when the policy may rebuild it. */
function personReason(db, app, row, kind) {
  if (kind === 'image') return 'deployed from a prebuilt image: rebuild that image on a patched base and redeploy it';
  if (kind === 'other') return `a ${app.source_type || 'unknown'} app is not rebuilt automatically: redeploy it on a patched base`;
  if (row.unsupported_branch) return `${rtLabel(row.runtime)} ${branchOf(row.version)} gets no fix for this flaw: move the app to a supported ${rtLabel(row.runtime)} branch`;
  if (!row.fixed_version) return 'no fixed version is known';
  if (!row.base_image) return 'AppCrane does not know which base image this release was built on: redeploy it so the base is recorded';
  const eff = effectiveForApp(db, app);
  if (!eff.enabled) return `auto-patch is off: ${eff.reason}`;
  return null;
}

/**
 * Every running container whose runtime is affected by a known RCE advisory.
 * Rows: { app_id, slug, env, source, runtime, version, advisories, fixed_version,
 *   unsupported_branch, base_image, base_digest, image_id, handling: 'auto'|'person', why }.
 */
export async function surveyRuntimes(db = getDb(), d = dep()) {
  const rows = [];
  const cache = new Map();
  const apps = db.prepare('SELECT * FROM apps ORDER BY id').all();
  for (const app of apps) {
    let local = false;
    try { local = await d.usesLocalRepo(app); } catch (_) { local = false; }
    const kind = sourceKind(app, local);
    const envRows = {};
    for (const env of ['production', 'sandbox']) {
      const dep_ = liveDeployment(db, app.id, env);
      if (!dep_) continue;
      const probe = dep_.php_version || /php/i.test(dep_.base_image || '') ? ['php'] : [];
      let info;
      try { info = await d.inspect(app.slug, env, probe); } catch (_) { info = null; }
      if (!info?.runtime || !info.version) continue;
      const key = `${info.runtime}@${info.version}`;
      if (!cache.has(key)) {
        try { cache.set(key, await d.advisories(info.runtime, info.version)); } catch (e) { cache.set(key, null); log.warn(`[runtime-patch] advisories for ${key}: ${e.message}`); }
      }
      const adv = cache.get(key);
      if (!adv?.affected) continue;
      const base = baseOf(info, dep_);
      envRows[env] = {
        app_id: app.id, slug: app.slug, env, source: kind, runtime: info.runtime, version: info.version,
        advisories: adv.advisories.map((a) => a.id), advisory_details: adv.advisories,
        fixed_version: adv.fixedVersion, unsupported_branch: adv.unsupportedBranch,
        base_image: base?.image || null, base_digest: base?.digest || null, image_id: info.image_id, deployment_id: dep_.id,
      };
    }
    if (envRows.production) {
      const why = personReason(db, app, envRows.production, kind);
      rows.push({ ...envRows.production, handling: why ? 'person' : 'auto', why: why || 'AppCrane rebuilds sandbox and production on the patched base' });
    }
    if (envRows.sandbox) {
      const why = envRows.production ? rows[rows.length - 1].why : 'only sandbox runs the affected runtime: rebuild sandbox on a patched base';
      rows.push({ ...envRows.sandbox, handling: envRows.production ? rows[rows.length - 1].handling : 'person', why });
    }
  }
  return rows;
}

function update(db, run, fields) {
  const cols = Object.keys(fields);
  if (!cols.length) return run;
  db.prepare(`UPDATE runtime_patch_runs SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`).run(...cols.map((c) => fields[c]), run.id);
  Object.assign(run, fields);
  return run;
}

function beginRun(db, app, row, now) {
  const key = row.advisories.join(', ');
  const existing = db.prepare('SELECT * FROM runtime_patch_runs WHERE app_id = ? AND advisory_key = ? AND prod_image_id = ?').get(app.id, key, row.image_id);
  try {
    if (existing) {
      if (existing.status !== 'deferred' || (existing.retry_after && existing.retry_after > sqlTime(now))) return null;
      const r = db.prepare(`UPDATE runtime_patch_runs SET status = 'running', started_at = datetime('now'), finished_at = NULL, retry_after = NULL
        WHERE id = ? AND status = 'deferred'`).run(existing.id);
      return r.changes ? db.prepare('SELECT * FROM runtime_patch_runs WHERE id = ?').get(existing.id) : null;
    }
    const id = db.prepare(`INSERT INTO runtime_patch_runs (app_id, advisory_key, runtime, from_version, fixed_version, base_image, from_digest, prod_image_id, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running')`).run(app.id, key, row.runtime, row.version, row.fixed_version, row.base_image, row.base_digest, row.image_id).lastInsertRowid;
    return db.prepare('SELECT * FROM runtime_patch_runs WHERE id = ?').get(id);
  } catch (e) {
    if (String(e.code || '').startsWith('SQLITE_CONSTRAINT')) return null;
    throw e;
  }
}

function requestTitle(run) {
  return run.fixed_version
    ? `Rebuild on patched ${rtLabel(run.runtime)} ${run.fixed_version} (${run.advisory_key})`
    : `${rtLabel(run.runtime)} ${run.from_version} has no fix on its branch: upgrade (${run.advisory_key})`;
}

/** The open request for this app and advisory set, created when there is none. */
export function ensureRequest(db, app, run) {
  if (run.request_id) return run.request_id;
  const prior = db.prepare(`SELECT p.request_id FROM runtime_patch_runs p JOIN enhancement_requests r ON r.id = p.request_id
    WHERE p.app_id = ? AND p.advisory_key = ? AND p.request_id IS NOT NULL AND r.status != 'done' ORDER BY p.id DESC LIMIT 1`).get(app.id, run.advisory_key);
  if (prior) return update(db, run, { request_id: prior.request_id }).request_id;
  const message = [
    requestTitle(run), '',
    `${app.slug} runs ${rtLabel(run.runtime)} ${run.from_version}, which has a remote-code-execution flaw (${run.advisory_key}).`,
    run.fixed_version ? `- Fixed in: ${run.fixed_version}` : '- Fixed in: no release on this branch',
    run.base_image ? `- Base image: ${run.base_image}` : null,
    '- No code change is needed: the same commit is rebuilt on a patched runtime.',
  ].filter((l) => l !== null).join('\n');
  const id = Number(db.prepare(`INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status, kind)
    VALUES (?, NULL, ?, ?, 'new', 'runtime-patch')`).run(app.slug, ACTOR, message).lastInsertRowid);
  return update(db, run, { request_id: id }).request_id;
}

function addNote(db, requestId, body, resolved) {
  if (!requestId) return;
  try {
    db.prepare(`INSERT INTO enhancement_comments (enhancement_id, type, body, author_user_id, author_name, status, resolved_at)
      VALUES (?, 'note', ?, NULL, ?, ?, ?)`).run(requestId, body.slice(0, 8000), ACTOR, resolved ? 'resolved' : 'open', resolved ? sqlTime(Date.now()) : null);
  } catch (e) {
    log.warn(`[runtime-patch] note on request #${requestId} failed: ${e.message}`);
  }
}

function approvalDetail(run, outcome) {
  return {
    actor: ACTOR, policy: POLICY_NAME, outcome, kind: 'runtime', advisory: run.advisory_key, runtime: run.runtime,
    from_version: run.from_version, to_version: run.to_version, fixed_version: run.fixed_version,
    base_image: run.base_image, from_digest: run.from_digest, to_digest: run.to_digest, commit: run.commit_sha,
    sandbox_deployment_id: run.sandbox_deployment_id, production_deployment_id: run.production_deployment_id,
    release_check_id: run.release_check_id, request_id: run.request_id, run_id: run.id, reason: run.reason || null,
  };
}

function finish(db, app, run, outcome, now = Date.now()) {
  const status = outcome.status;
  if (status === 'deferred') {
    update(db, run, { status, reason: outcome.reason, finished_at: sqlTime(now), retry_after: sqlTime(now + (outcome.extra.retryAfterMs || RETRY_SOON_MS)) });
    return run;
  }
  update(db, run, { status, reason: outcome.reason || null, finished_at: sqlTime(Date.now()) });
  if (status === 'ineligible') return run;
  ensureRequest(db, app, run);
  logAudit(null, app.id, status === 'applied' || status === 'rolled_back' ? 'change.auto_approved' : 'change.auto_patch_fallback', approvalDetail(run, status), 'system');
  const rt = rtLabel(run.runtime);
  const head = status === 'applied'
    ? `${ACTOR} rebuilt commit ${String(run.commit_sha).slice(0, 12)} on ${run.base_image} (${rt} ${run.from_version} → ${run.to_version}) under "${POLICY_NAME}" (sandbox #${run.sandbox_deployment_id}, production #${run.production_deployment_id}).`
    : status === 'rolled_back'
      ? `${ACTOR} promoted the rebuild on patched ${rt} to production (#${run.production_deployment_id}); it failed its health check and production was rolled back. ${run.reason || ''} Over to a person.`
      : `${ACTOR} did not rebuild this app: ${run.reason} A person must act.`;
  addNote(db, run.request_id, head, status === 'applied');
  if (status === 'applied') {
    db.prepare("UPDATE enhancement_requests SET status = 'done', done_note = ? WHERE id = ? AND status != 'done'")
      .run(`Closed automatically: production now runs ${rt} ${run.to_version}.`, run.request_id);
  }
  sendRuntimePatchMail(db, app, run);
  return run;
}

async function waitForDeployment(db, id, d) {
  const deadline = d.now() + d.deployTimeoutMs;
  for (;;) {
    const row = db.prepare('SELECT id, status, commit_hash, commit_sha, finished_at FROM deployments WHERE id = ?').get(id);
    if (row && ['live', 'failed', 'rolled_back'].includes(row.status)) return row;
    if (d.now() > deadline) return row || { id, status: 'timeout' };
    await sleep(d.pollMs);
  }
}

async function productionHealthy(db, app, deployment, d) {
  const deadline = d.now() + d.healthSettleMs;
  const since = deployment.finished_at || sqlTime(d.now());
  for (;;) {
    const h = db.prepare("SELECT is_down, last_check_at FROM health_state WHERE app_id = ? AND env = 'production'").get(app.id);
    if (h && h.last_check_at && h.last_check_at >= since) return !h.is_down;
    if (d.now() > deadline) return !(h && h.is_down);
    await sleep(d.pollMs);
  }
}

async function recordBase(db, d, slug, env, deploymentId) {
  try {
    const ref = await d.containerImage(slug, env);
    const base = ref ? await d.imageBase(ref) : null;
    if (base) db.prepare('UPDATE deployments SET base_image = ?, base_digest = ? WHERE id = ?').run(base.image, base.digest, deploymentId);
    return ref;
  } catch (_) {
    return null;
  }
}

async function runtimeOf(d, slug, env, runtime) {
  let ref = null;
  try { ref = await d.containerImage(slug, env); } catch (_) { ref = null; }
  return { ref, version: ref ? await d.imageVersion(ref, runtime) : null };
}

const atLeast = (v, fixed) => { try { return !!v && compareVersions(v, fixed) >= 0; } catch (_) { return false; } };

async function execute(db, app, row, run, kind, d) {
  const rt = rtLabel(row.runtime);
  const prodLive = liveDeployment(db, app.id, 'production');
  if (!prodLive) throw fallback('production has no live release to rebuild.');
  let prodSha;
  if (kind === 'local') {
    prodSha = await deploymentCommit(app.slug, prodLive, d.resolveCommit);
    if (!prodSha) throw fallback(`production deployment #${prodLive.id} records commit ${prodLive.commit_hash}, which does not name exactly one commit in the repository; a person must check production.`);
    const branch = app.branch || 'main';
    const tip = await d.branchHead(app, branch);
    if (!exactCommit(tip, prodSha)) throw fallback(`the branch has changes that are not in production (${branch} is at ${String(tip).slice(0, 12)}, production runs ${prodSha.slice(0, 12)}); a person must promote them first.`);
  } else {
    prodSha = String(prodLive.commit_sha || '').toLowerCase();
    if (!isFullSha(prodSha)) throw fallback(`production deployment #${prodLive.id} has no full commit recorded, so a rebuild cannot be pinned to it; a person must redeploy production once.`);
    const sbLive = liveDeployment(db, app.id, 'sandbox');
    if (!sbLive || !exactCommit(String(sbLive.commit_sha || '').toLowerCase(), prodSha)) {
      throw fallback(`sandbox does not run production's commit ${prodSha.slice(0, 12)} (it runs ${sbLive?.commit_sha ? String(sbLive.commit_sha).slice(0, 12) : 'nothing recorded'}), and a rebuild would replace it; a person must act.`);
    }
  }
  update(db, run, { commit_sha: prodSha });

  let digest;
  try {
    digest = await d.currentDigest(row.base_image);
  } catch (e) {
    if (e instanceof UnsupportedRegistry) throw fallback(`${e.message}; a person must rebuild on a patched base.`);
    throw defer(`the registry could not be asked about ${row.base_image} (${e.message}); will retry`);
  }
  if (digest === row.base_digest || digest === run.to_digest) {
    throw defer(`${row.base_image} on the registry is still ${digest.slice(0, 19)}, which was already built on; waiting for a patched image`, WAIT_FOR_BASE_MS);
  }
  update(db, run, { to_digest: digest });

  const late = await transientBlock(db, app, d);
  if (late) throw defer(`${late}; will retry`);
  for (const env of ['sandbox', 'production']) {
    const risk = await d.assessRisk({ db, app, env });
    if (risk?.at_risk) throw fallback(`a redeploy of ${env} would lose data (${risk.summary}); that needs a person to acknowledge it.`);
  }
  try {
    await d.refuseDeployForMemory({ db, app, env: 'sandbox', userId: null });
  } catch (e) {
    throw fallback(`the sandbox deploy was refused (${e.message}).`);
  }

  const sandboxId = Number(db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, commit_sha, commit_message, deployed_by, log)
    VALUES (?, 'sandbox', 'pending', ?, ?, ?, NULL, ?)`).run(app.id, prodLive.commit_hash || prodSha, prodSha,
    `rebuild on patched ${rt}`, `${ACTOR}: rebuild on a fresh ${row.base_image} (${run.advisory_key})`).lastInsertRowid);
  update(db, run, { sandbox_deployment_id: sandboxId });
  const fresh = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  await Promise.resolve(d.deployApp(sandboxId, fresh, 'sandbox', await d.ports(fresh.slot), { targetCommit: prodSha, freshBase: true }))
    .catch((e) => log.warn(`[runtime-patch] sandbox deploy ${sandboxId}: ${e.message}`));
  const sb = await waitForDeployment(db, sandboxId, d);
  const sbHealth = db.prepare("SELECT is_down FROM health_state WHERE app_id = ? AND env = 'sandbox'").get(app.id);
  if (sb.status !== 'live' || sbHealth?.is_down) {
    throw fallback(`sandbox deployment #${sandboxId} ${sb.status === 'live' ? 'is failing its health check' : `ended ${sb.status}`}; production was not touched.`);
  }
  if (!exactCommit(await deploymentCommit(app.slug, sb, d.resolveCommit), prodSha)) throw fallback(`sandbox deployment #${sandboxId} built ${sb.commit_hash}, not production's commit ${prodSha.slice(0, 12)}; production was not touched.`);
  await recordBase(db, d, app.slug, 'sandbox', sandboxId);
  const sbRt = await runtimeOf(d, app.slug, 'sandbox', row.runtime);
  if (!atLeast(sbRt.version, row.fixed_version)) {
    throw defer(`the rebuilt sandbox (#${sandboxId}) runs ${rt} ${sbRt.version || 'unknown'}, not ${row.fixed_version} or later: ${row.base_image} has no fixed image yet; production was not touched`, WAIT_FOR_BASE_MS);
  }
  update(db, run, { to_version: sbRt.version });

  const rc = await d.runReleaseCheck({ db, app: fresh, userId: null, trigger: 'runtime-patch' });
  update(db, run, { release_check_id: rc.id });
  if (rc.blocked || rc.result === 'fail') {
    const failing = (rc.checks || []).filter((c) => c.status === 'fail').map((c) => `${c.label}: ${c.reasons.join('; ')}`).join(' | ');
    throw fallback(`release check #${rc.id} did not pass (${failing}); the rebuild is live in sandbox #${sandboxId} and production was not touched.`);
  }

  const stop = await stillAllowed(db, app, d);
  const prodNow = liveDeployment(db, app.id, 'production');
  const why = stop || (!prodNow || prodNow.id !== prodLive.id ? `production changed while this run was in progress (it now runs deployment #${prodNow?.id ?? 'none'})` : null);
  if (why) throw fallback(`${why}; nothing was promoted (the rebuild is live in sandbox #${sandboxId}).`);

  let promoted;
  try {
    promoted = await d.promoteApp(fresh, null, { expectSandboxDeploymentId: sandboxId, freshBase: true });
  } catch (e) {
    throw fallback(`promote was refused: ${e.message}`);
  }
  const prodId = Number(promoted.deployment_id);
  update(db, run, { production_deployment_id: prodId });
  const prod = await waitForDeployment(db, prodId, d);
  if (prod.status !== 'live') {
    throw new Outcome('rolled_back', `production deployment #${prodId} ended ${prod.status}; the deploy health gate kept the previous release running.`);
  }
  if (!(await productionHealthy(db, app, prod, d))) {
    const stopRollback = await stillAllowed(db, app, d);
    if (stopRollback) throw fallback(`production deployment #${prodId} failed its health check after going live, and the automatic rollback did not run because ${stopRollback}; a person must roll production back.`);
    let how;
    try { const r = await d.rollbackApp(fresh, 'production', null, null); how = `rolled back to deployment #${r.rollback_to} (#${r.deployment_id})`; } catch (e) { how = `the rollback failed: ${e.message}`; }
    throw new Outcome('rolled_back', `production deployment #${prodId} failed its health check after going live; ${how}.`);
  }
  await recordBase(db, d, app.slug, 'production', prodId);
  const prodRt = await runtimeOf(d, app.slug, 'production', row.runtime);
  if (!atLeast(prodRt.version, row.fixed_version)) {
    throw fallback(`production deployment #${prodId} is healthy but still runs ${rt} ${prodRt.version || 'unknown'} (the production build did not use a fresh base); a person must rebuild production.`);
  }
  // Later plain redeploys of this commit reuse the commit's image tag, so it
  // must name the patched image, not the one it replaced.
  for (const r of [sbRt.ref, prodRt.ref]) {
    if (r && RT_SUFFIX.test(r)) { try { await d.retag(r, r.replace(RT_SUFFIX, '')); } catch (e) { log.warn(`[runtime-patch] retag ${r}: ${e.message}`); } }
  }
  return new Outcome('applied', null);
}

/** Act on one affected production row. Returns { action, reason, run_id? }. Never throws. */
export async function processApp(db, row) {
  const d = dep();
  let app, kind;
  try {
    app = db.prepare('SELECT * FROM apps WHERE id = ?').get(row.app_id);
    if (!app) return { action: 'skip', reason: 'app not found' };
    let local = false;
    try { local = await d.usesLocalRepo(app); } catch (_) { local = false; }
    kind = sourceKind(app, local);
    const why = personReason(db, app, row, kind);
    if (why) return { action: 'skip', reason: why };
    const blocked = await transientBlock(db, app, d);
    if (blocked) return { action: 'skip', reason: blocked };
  } catch (e) {
    return { action: 'skip', reason: e.message };
  }
  const run = beginRun(db, app, row, d.now());
  if (!run) return { action: 'skip', reason: 'already handled for this production image, or another run is in progress' };
  let outcome;
  try {
    outcome = await execute(db, app, row, run, kind, d);
  } catch (e) {
    outcome = e instanceof Outcome ? e : fallback(`unexpected error: ${e.message}`);
  }
  try {
    finish(db, app, run, outcome, d.now());
  } catch (e) {
    log.error(`[runtime-patch] ${app.slug} run #${run.id}: could not record the outcome: ${e.message}`);
  }
  log.info(`[runtime-patch] ${app.slug}: ${outcome.status}${outcome.reason ? ` (${outcome.reason})` : ''}`);
  return { action: outcome.status, reason: outcome.reason, run_id: run.id };
}

/** Mark runs a restart interrupted as fallbacks, so their lock does not outlive the process. */
export function recoverInterruptedRuns(db) {
  const rows = db.prepare("SELECT * FROM runtime_patch_runs WHERE status = 'running'").all();
  for (const run of rows) {
    const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(run.app_id);
    if (app) finish(db, app, run, fallback('AppCrane restarted while this rebuild was running; check the app\'s sandbox and production before acting.'));
  }
  return rows.length;
}

let lastSurvey = { at: null, rows: [] };
export const latestSurvey = () => lastSurvey;

let running = false;
export async function runRuntimePatchSweep(db = getDb()) {
  if (running) return { skipped: 'a sweep is already running' };
  running = true;
  try {
    const d = dep();
    const rows = await surveyRuntimes(db, d);
    lastSurvey = { at: new Date(d.now()).toISOString(), rows };
    try { notifyAdminsOfAdvisories(db, rows); } catch (e) { log.warn(`[runtime-patch] admin notice failed: ${e.message}`); }
    const results = [];
    for (const row of rows.filter((r) => r.env === 'production' && r.handling === 'auto')) {
      if (results.filter((r) => r.action !== 'skip').length >= MAX_PER_SWEEP) break;
      results.push({ app: row.slug, ...(await processApp(db, row)) });
    }
    setJobDetail('runtime-patch', {
      severity: rows.length ? 'warning' : 'ok',
      affected: rows.map(({ advisory_details, ...r }) => r),
      last: results.slice(-5),
    });
    return { rows, results };
  } finally {
    running = false;
  }
}

let timer = null;
export function startRuntimePatchWorker() {
  if (timer) return;
  try { recoverInterruptedRuns(getDb()); } catch (e) { log.warn(`[runtime-patch] recovery failed: ${e.message}`); }
  jobStarted('runtime-patch', { cadenceMs: SWEEP_MS });
  const tick = () => trackJob('runtime-patch', () => runRuntimePatchSweep()).catch((e) => log.error(`[runtime-patch] sweep failed: ${e.message}`));
  setTimeout(tick, 2 * 60_000).unref?.();
  timer = setInterval(tick, SWEEP_MS);
  timer.unref?.();
  log.info('[runtime-patch] worker started');
}

export function stopRuntimePatchWorker() {
  if (timer) { clearInterval(timer); timer = null; }
}
