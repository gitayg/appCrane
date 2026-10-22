// RCE auto-patch: the policy that approves, in place of a person, a dependency
// bump fixing a remote-code-execution advisory on a crane-hosted app.
//
// Scope: vulnerability requests (vulnRequests.js) still in triage, on managed
// apps whose repository is on this host. GitHub-backed, upload and image apps
// are never touched. Every guardrail below must hold; the first one that does
// not hands the request back to the human flow with the reason as a note, and
// nothing further happens. A guardrail that only time can satisfy (cooldown,
// an unreachable OSV or registry) defers the request instead.
//
// One run per app at a time: a partial unique index on auto_patch_runs allows
// one 'running' row per app, so the lock holds across processes too.

import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { logAudit } from '../../middleware/audit.js';
import { trackJob, jobStarted, setJobDetail } from '../jobHealth.js';
import { classifyAdvisory } from './classify.js';
import { effectiveForApp, POLICY_NAME } from './policy.js';
import { dependencyMode, verifyNpmBump, NPM_REGISTRY, NPM_HELPER_MEMORY_MB } from './npmBump.js';
import { sendAutoPatchMail } from './mail.js';

export const ACTOR = 'AppCrane auto-patch';
export const SWEEP_MS = 15 * 60 * 1000;
const RETRY_SOON_MS = 60 * 60 * 1000;
const MAX_PER_SWEEP = 10;

const defaults = {
  now: () => Date.now(),
  pollMs: 5000,
  deployTimeoutMs: 30 * 60 * 1000,
  healthSettleMs: 5 * 60 * 1000,
  fetchAdvisories: async (ids) => (await import('../appScan.js')).fetchAdvisories(ids),
  queryOsv: async (pkgs) => (await import('../appScan.js')).queryOsv(pkgs),
  publishedAt: async (name, version) => (await import('./registry.js')).npmPublishedAt(name, version),
  runBump: async (a) => (await import('./npmBump.js')).runNpmBump(a),
  branchHead: async (app, branch) => (await import('../managedRepo.js')).localBranchHeadSha(app, branch),
  readFile: async (app, path, branch) => (await import('../managedRepo.js')).readManagedRepoFile(app, path, { branch }),
  push: async (app, files, opts) => (await import('../managedRepo.js')).pushFilesToManagedRepo(app, files, opts),
  deployApp: async (...a) => (await import('../deployer.js')).deployApp(...a),
  promoteApp: async (...a) => (await import('../deployer.js')).promoteApp(...a),
  rollbackApp: async (...a) => (await import('../deployer.js')).rollbackApp(...a),
  runReleaseCheck: async (ctx) => (await import('../releaseCheck.js')).runReleaseCheck(ctx),
  admitHelper: async (ctx) => (await import('../memoryAdmission.js')).admitContainer(ctx),
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
  usesLocalRepo: async (app) => (await import('../managedRepo.js')).usesLocalRepo(app),
};

let testDeps = null;
/** Test seam: replaces any of the defaults above. */
export function _setAutoPatchDepsForTests(d) { testDeps = d; }
const dep = () => ({ ...defaults, ...(testDeps || {}) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sqlTime = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');

export function parseVulnKey(key) {
  const v = JSON.parse(key);
  if (!Array.isArray(v) || v.length !== 4) throw new Error('not a vulnerability request key');
  return { appId: Number(v[0]), ecosystem: String(v[1]), name: String(v[2]), advisoryId: String(v[3]) };
}

class Outcome extends Error {
  constructor(status, reason, extra = {}) { super(reason); this.status = status; this.reason = reason; this.extra = extra; }
}
const fallback = (reason, extra) => new Outcome('fallback', reason, extra);
const defer = (reason, retryAfterMs) => new Outcome('deferred', reason, { retryAfterMs });
const ineligible = (reason, extra) => new Outcome('ineligible', reason, extra);

/** Requests the worker may look at now. */
export function candidateRequests(db, now = Date.now()) {
  return db.prepare(`
    SELECT r.id, r.app_slug, r.vuln_key FROM enhancement_requests r
    WHERE r.vuln_key IS NOT NULL AND r.status = 'new' AND r.validated_at IS NULL
      AND NOT EXISTS (
        SELECT 1 FROM auto_patch_runs p WHERE p.request_id = r.id
          AND NOT (p.status = 'deferred' AND (p.retry_after IS NULL OR p.retry_after <= ?)))
    ORDER BY r.id
  `).all(sqlTime(now));
}

function findFinding(db, appId, ecosystem, name, advisoryId) {
  const rows = db.prepare(`
    SELECT s.env, s.findings_json FROM app_vuln_scans s
    WHERE s.app_id = ? AND s.id = (
      SELECT id FROM app_vuln_scans WHERE app_id = s.app_id AND env = s.env AND status IN ('ok', 'findings')
      ORDER BY scanned_at DESC, id DESC LIMIT 1)
    ORDER BY CASE s.env WHEN 'production' THEN 0 ELSE 1 END
  `).all(appId);
  for (const r of rows) {
    for (const f of r.findings_json ? JSON.parse(r.findings_json) : []) {
      if (f.ecosystem === ecosystem && f.name === name && (f.ids || []).includes(advisoryId)) return { ...f, env: r.env };
    }
  }
  return null;
}

async function transientBlock(db, app, d) {
  if (await d.restoreInProgress(app.slug)) return 'a database restore is running';
  const inflight = db.prepare(`SELECT id, env FROM deployments WHERE app_id = ? AND status IN ('pending','building','deploying')
    AND started_at > datetime('now', '-30 minutes') LIMIT 1`).get(app.id);
  if (inflight) return `deployment #${inflight.id} (${inflight.env}) is in progress`;
  let coder;
  try { coder = await d.coderState(app.slug); } catch (e) { return `could not read the coder workspace (${e.message})`; }
  if (coder?.busy) return 'a coder session is working on this app';
  if (coder?.dirty) return 'a coder session has uncommitted work on this app';
  return null;
}

function beginRun(db, app, req, key) {
  const existing = db.prepare('SELECT * FROM auto_patch_runs WHERE request_id = ?').get(req.id);
  try {
    if (existing) {
      const r = db.prepare(`UPDATE auto_patch_runs SET status = 'running', started_at = datetime('now'), finished_at = NULL, retry_after = NULL
        WHERE id = ? AND status = 'deferred'`).run(existing.id);
      return r.changes ? db.prepare('SELECT * FROM auto_patch_runs WHERE id = ?').get(existing.id) : null;
    }
    const id = db.prepare(`INSERT INTO auto_patch_runs (app_id, request_id, advisory_id, ecosystem, package, status)
      VALUES (?, ?, ?, ?, ?, 'running')`).run(app.id, req.id, key.advisoryId, key.ecosystem, key.name).lastInsertRowid;
    return db.prepare('SELECT * FROM auto_patch_runs WHERE id = ?').get(id);
  } catch (e) {
    if (String(e.code || '').startsWith('SQLITE_CONSTRAINT')) return null;
    throw e;
  }
}

function update(db, run, fields) {
  const cols = Object.keys(fields);
  if (!cols.length) return run;
  db.prepare(`UPDATE auto_patch_runs SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`).run(...cols.map((c) => fields[c]), run.id);
  Object.assign(run, fields);
  return run;
}

function addNote(db, requestId, body, resolved) {
  if (!requestId) return;
  try {
    const id = db.prepare(`INSERT INTO enhancement_comments (enhancement_id, type, body, author_user_id, author_name, status, resolved_at)
      VALUES (?, 'note', ?, NULL, ?, ?, ?)`).run(requestId, body.slice(0, 8000), ACTOR, resolved ? 'resolved' : 'open', resolved ? sqlTime(Date.now()) : null).lastInsertRowid;
    return id;
  } catch (e) {
    log.warn(`[auto-patch] note on request #${requestId} failed: ${e.message}`);
  }
}

function approvalDetail(run, outcome) {
  return {
    actor: ACTOR, policy: POLICY_NAME, outcome, advisory: run.advisory_id, ecosystem: run.ecosystem, package: run.package,
    from_version: run.from_version, to_version: run.to_version, commit: run.commit_sha,
    sandbox_deployment_id: run.sandbox_deployment_id, production_deployment_id: run.production_deployment_id,
    release_check_id: run.release_check_id, request_id: run.request_id, run_id: run.id, reason: run.reason || null,
  };
}

function finish(db, app, run, outcome, now = Date.now()) {
  const status = outcome.status;
  if (status === 'deferred') {
    const firstDefer = !run.reason || run.reason !== outcome.reason;
    update(db, run, { status, reason: outcome.reason, finished_at: sqlTime(now), retry_after: sqlTime(now + (outcome.extra.retryAfterMs || RETRY_SOON_MS)) });
    if (firstDefer && outcome.extra.note) addNote(db, run.request_id, `${ACTOR}: ${outcome.reason}`, false);
    return run;
  }
  update(db, run, { status, reason: outcome.reason || null, finished_at: sqlTime(Date.now()), ...(outcome.extra.fields || {}) });
  if (status === 'ineligible') return run;

  if (status === 'applied' || status === 'rolled_back') {
    logAudit(null, app.id, 'change.auto_approved', approvalDetail(run, status), 'system');
  } else {
    logAudit(null, app.id, 'change.auto_patch_fallback', approvalDetail(run, status), 'system');
  }
  const head = status === 'applied'
    ? `${ACTOR} applied ${run.package} ${run.from_version} → ${run.to_version} under "${POLICY_NAME}" (commit ${String(run.commit_sha).slice(0, 12)}, sandbox #${run.sandbox_deployment_id}, production #${run.production_deployment_id}). This request closes itself when the next scan no longer finds the advisory.`
    : status === 'rolled_back'
      ? `${ACTOR} promoted ${run.package} ${run.from_version} → ${run.to_version} to production (#${run.production_deployment_id}); it failed its health check and production was rolled back. ${run.reason || ''} Over to a person.`
      : `${ACTOR} did not apply this fix: ${run.reason} The request is back on the human flow.`;
  addNote(db, run.request_id, head, status === 'applied');
  sendAutoPatchMail(db, app, run);
  return run;
}

async function waitForDeployment(db, id, d) {
  const deadline = d.now() + d.deployTimeoutMs;
  for (;;) {
    const row = db.prepare('SELECT id, status, commit_hash, finished_at FROM deployments WHERE id = ?').get(id);
    if (row && ['live', 'failed', 'rolled_back'].includes(row.status)) return row;
    if (d.now() > deadline) return row || { id, status: 'timeout' };
    await sleep(d.pollMs);
  }
}

const sameCommit = (a, b) => !!a && !!b && (String(a).startsWith(String(b)) || String(b).startsWith(String(a)));

async function readJson(d, app, path, branch) {
  try { return (await d.readFile(app, path, branch)).content; } catch (e) {
    if (e.code === 'FILE_NOT_FOUND' || e.status === 404) return null;
    throw e;
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

/** The live production deployment, or null. Its commit is what production runs. */
function liveProduction(db, appId) {
  return db.prepare(`SELECT id, commit_hash FROM deployments WHERE app_id = ? AND env = 'production' AND status = 'live'
    ORDER BY id DESC LIMIT 1`).get(appId) || null;
}

/**
 * Null when the run may still act on production; otherwise why not. Read
 * again right before a promote or a rollback, because a person can turn the
 * policy off, opt the app out or start a restore while a sandbox build runs.
 */
async function stillAllowed(db, app, d) {
  const eff = effectiveForApp(db, app);
  if (!eff.enabled) return `auto-patch was turned off while this run was in progress (${eff.reason})`;
  if (await d.restoreInProgress(app.slug)) return 'a database restore started while this run was in progress';
  return null;
}

async function revertCommit(d, app, branch, commit, files, run, why = 'sandbox deploy failed') {
  try {
    await d.push(app, files, {
      branch, expectParent: commit, deployOnPush: false,
      message: `${ACTOR}: revert ${run.package} ${run.to_version} (${why})`,
    });
    return 'the bump commit was reverted';
  } catch (e) {
    return `the bump commit could not be reverted (${e.message}); it is still on the branch`;
  }
}

async function execute(db, app, req, run, key, d) {
  const finding = findFinding(db, app.id, key.ecosystem, key.name, key.advisoryId);
  if (!finding) throw ineligible('no environment\'s latest scan still reports this advisory');
  update(db, run, { from_version: finding.version, to_version: finding.fixed || null });

  const { records, failures } = await d.fetchAdvisories([key.advisoryId]);
  if (failures?.size || !records?.get(key.advisoryId)) throw defer('the OSV advisory could not be read; will retry', RETRY_SOON_MS);
  const cls = classifyAdvisory(records.get(key.advisoryId));
  update(db, run, { classification_json: JSON.stringify(cls) });
  if (!cls.rce) throw ineligible(cls.reason);

  if (key.ecosystem !== 'npm') throw fallback(`${key.ecosystem} is not auto-patched; only npm (package-lock.json) is.`);
  if (!finding.fixed) throw fallback('OSV publishes no fixed version for this advisory.');

  const q = await d.queryOsv([{ name: key.name, version: finding.fixed, ecosystem: 'npm' }]);
  if (!q.ok) throw defer(`OSV could not be asked about ${key.name}@${finding.fixed}; will retry`, RETRY_SOON_MS);
  if (q.findings.length) throw fallback(`${key.name}@${finding.fixed} has advisories of its own (${q.findings.flatMap((f) => f.ids).join(', ')}).`);

  const cooldownMs = effectiveForApp(db, app).policy.cooldown_hours * 3600_000;
  let published;
  try { published = await d.publishedAt(key.name, finding.fixed); } catch (e) {
    if (/not on the npm registry/.test(e.message)) throw fallback(e.message);
    throw defer(`the npm registry did not say when ${key.name}@${finding.fixed} was published; will retry`, RETRY_SOON_MS);
  }
  const readyAt = published.getTime() + cooldownMs;
  if (d.now() < readyAt) {
    const o = defer(`${key.name}@${finding.fixed} was published ${published.toISOString()}; the policy waits ${cooldownMs / 3600_000}h, so it is applied after ${new Date(readyAt).toISOString()}.`, readyAt - d.now());
    o.extra.note = true;
    throw o;
  }

  const branch = app.branch || 'main';
  const tip = await d.branchHead(app, branch);
  // The bump is built on the branch tip and promoted, so everything on the tip
  // reaches production with it. Only a tip that IS production may be patched:
  // a commit a person released to sandbox but never promoted is unreviewed for
  // production, and auto-patch must not be the thing that ships it.
  const prodLive = liveProduction(db, app.id);
  if (!prodLive || !/^[0-9a-f]{7,40}$/i.test(String(prodLive.commit_hash || ''))) {
    throw fallback('production has no live release with a recorded commit, so there is nothing auto-patch may build on; a person must deploy production first.');
  }
  if (!sameCommit(tip, prodLive.commit_hash)) {
    throw fallback(`the branch has changes that are not in production (${branch} is at ${String(tip).slice(0, 12)}, production deployment #${prodLive.id} runs ${prodLive.commit_hash}); a person must promote them first.`);
  }
  const pkgText = await readJson(d, app, 'package.json', branch);
  const lockText = await readJson(d, app, 'package-lock.json', branch);
  if (!pkgText || !lockText) throw fallback('the repository has no package.json and package-lock.json at its root (subdirectory lockfiles are not auto-patched).');
  for (const other of ['yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', '.npmrc']) {
    if (await readJson(d, app, other, branch)) throw fallback(`the repository root has ${other}; only a plain package-lock.json against the public registry is auto-patched.`);
  }
  let pkg, lock;
  try { pkg = JSON.parse(pkgText); lock = JSON.parse(lockText); } catch (e) { throw fallback(`package.json or package-lock.json is not valid JSON (${e.message}).`); }
  if (pkg.workspaces) throw fallback('the app uses npm workspaces, which are not auto-patched.');
  const entries = Object.entries(lock.packages || {}).filter(([k]) => k === `node_modules/${key.name}` || k.endsWith(`/node_modules/${key.name}`));
  const vulnerable = entries.filter(([, v]) => v.version === finding.version);
  if (!vulnerable.length) throw fallback(`${key.name}@${finding.version} is not in the root package-lock.json.`);
  if (vulnerable.some(([, v]) => typeof v.resolved === 'string' && !v.resolved.startsWith(NPM_REGISTRY))) throw fallback(`${key.name} resolves from a registry other than the public npm registry.`);
  const mode = dependencyMode(pkg, key.name);
  if (!mode) throw fallback(`${key.name} is declared in more than one dependency section or only as a peer dependency.`);

  try {
    await d.admitHelper({ name: 'appcrane-auto-patch', memoryMb: NPM_HELPER_MEMORY_MB, cpus: 1, kind: 'auto-patch', slug: app.slug, appId: app.id, automatic: true, what: 'auto-patch', onWarn: 'silent' });
  } catch (e) {
    throw defer(`the server has no room for the npm helper right now (${e.message}); will retry`, RETRY_SOON_MS);
  }
  let after;
  try {
    after = await d.runBump({ packageJson: pkgText, packageLock: lockText, name: key.name, version: finding.fixed, mode });
  } catch (e) {
    throw fallback(e.message);
  }
  const verdict = verifyNpmBump({ before: { packageJson: pkgText, packageLock: lockText }, after, name: key.name, fromVersion: finding.version, toVersion: finding.fixed, mode });
  if (!verdict.ok) throw fallback(`the bump changed more than ${key.name}: ${verdict.problems.slice(0, 5).join('; ')}.`);

  const late = await transientBlock(db, app, d);
  if (late) throw defer(`${late}; will retry`, RETRY_SOON_MS);
  for (const env of ['sandbox', 'production']) {
    const risk = await d.assessRisk({ db, app, env });
    if (risk?.at_risk) throw fallback(`a redeploy of ${env} would lose data (${risk.summary}); that needs a person to acknowledge it.`);
  }

  const files = [{ path: 'package-lock.json', content: after.packageLock }];
  if (mode === 'direct') files.push({ path: 'package.json', content: after.packageJson });
  const original = [{ path: 'package-lock.json', content: lockText }];
  if (mode === 'direct') original.push({ path: 'package.json', content: pkgText });
  let pushed;
  try {
    pushed = await d.push(app, files, {
      branch, expectParent: tip, deployOnPush: false, actorId: null,
      message: `${ACTOR}: bump ${key.name} ${finding.version} -> ${finding.fixed} (${key.advisoryId})\n\nApproved by ${POLICY_NAME}.`,
    });
  } catch (e) {
    if (e.code === 'BRANCH_MOVED') throw defer(`the branch moved while the bump was prepared (${e.message}); will retry`, 10 * 60 * 1000);
    throw e;
  }
  const commit = pushed.commit.sha;
  update(db, run, { commit_sha: commit });

  try {
    await d.refuseDeployForMemory({ db, app, env: 'sandbox', userId: null });
  } catch (e) {
    const note = await revertCommit(d, app, branch, commit, original, run);
    throw fallback(`the sandbox deploy was refused (${e.message}); ${note}.`);
  }
  const sandboxId = Number(db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, commit_message, deployed_by, log)
    VALUES (?, 'sandbox', 'pending', ?, ?, NULL, ?)`).run(app.id, commit, `bump ${key.name} to ${finding.fixed}`, `${ACTOR}: ${key.advisoryId}`).lastInsertRowid);
  update(db, run, { sandbox_deployment_id: sandboxId });
  const { getPortsForSlot } = await import('../portAllocator.js');
  const fresh = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  await Promise.resolve(d.deployApp(sandboxId, fresh, 'sandbox', getPortsForSlot(fresh.slot))).catch((e) => log.warn(`[auto-patch] sandbox deploy ${sandboxId}: ${e.message}`));
  const sb = await waitForDeployment(db, sandboxId, d);
  const sbHealth = db.prepare("SELECT is_down FROM health_state WHERE app_id = ? AND env = 'sandbox'").get(app.id);
  if (sb.status !== 'live' || sbHealth?.is_down) {
    const note = await revertCommit(d, app, branch, commit, original, run);
    throw fallback(`sandbox deployment #${sandboxId} ${sb.status === 'live' ? 'is failing its health check' : `ended ${sb.status}`}; production was not touched and ${note}.`);
  }
  if (!sameCommit(sb.commit_hash, commit)) throw fallback(`sandbox deployment #${sandboxId} built ${sb.commit_hash}, not the bump commit ${commit.slice(0, 12)} (another push landed); production was not touched.`);

  const rc = await d.runReleaseCheck({ db, app: fresh, userId: null, trigger: 'auto-patch' });
  update(db, run, { release_check_id: rc.id });
  if (rc.blocked || rc.result === 'fail') {
    const failing = rc.checks.filter((c) => c.status === 'fail').map((c) => `${c.label}: ${c.reasons.join('; ')}`).join(' | ');
    throw fallback(`release check #${rc.id} did not pass (${failing}); the fix is live in sandbox #${sandboxId} and production was not touched.`);
  }

  const stop = await stillAllowed(db, app, d);
  const prodNow = liveProduction(db, app.id);
  const why = stop || (!prodNow || !sameCommit(tip, prodNow.commit_hash)
    ? `production changed while this run was in progress (it now runs deployment #${prodNow?.id ?? 'none'})` : null);
  if (why) {
    const note = await revertCommit(d, app, branch, commit, original, run, 'not promoted');
    throw fallback(`${why}; nothing was promoted (the fix is live in sandbox #${sandboxId}) and ${note}.`);
  }

  let promoted;
  try {
    promoted = await d.promoteApp(fresh, null, { expectSandboxDeploymentId: sandboxId });
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
    if (stopRollback) {
      throw fallback(`production deployment #${prodId} failed its health check after going live, and the automatic rollback did not run because ${stopRollback}; a person must roll production back.`);
    }
    let how;
    try { const r = await d.rollbackApp(fresh, 'production', null, null); how = `rolled back to deployment #${r.rollback_to} (#${r.deployment_id})`; } catch (e) { how = `the rollback failed: ${e.message}`; }
    throw new Outcome('rolled_back', `production deployment #${prodId} failed its health check after going live; ${how}.`);
  }
  return new Outcome('applied', null);
}

/** Look at one request. Returns { action, reason, run_id? }. Never throws. */
export async function processRequest(db, req) {
  const d = dep();
  let key, app;
  try {
    key = parseVulnKey(req.vuln_key);
    app = db.prepare('SELECT * FROM apps WHERE id = ?').get(key.appId);
    if (!app || app.slug !== req.app_slug) return { action: 'skip', reason: 'app not found' };
    let local = false;
    try { local = await d.usesLocalRepo(app); } catch (_) { local = false; }
    if (!local) return { action: 'skip', reason: 'not a crane-hosted (local repository) app' };
    const eff = effectiveForApp(db, app);
    if (!eff.enabled) return { action: 'skip', reason: `auto-patch is off: ${eff.reason}` };
    const blocked = await transientBlock(db, app, d);
    if (blocked) return { action: 'skip', reason: blocked };
  } catch (e) {
    return { action: 'skip', reason: e.message };
  }
  const run = beginRun(db, app, req, key);
  if (!run) return { action: 'skip', reason: 'another auto-patch is running on this app' };
  let outcome;
  try {
    outcome = await execute(db, app, req, run, key, d);
  } catch (e) {
    outcome = e instanceof Outcome ? e : fallback(`unexpected error: ${e.message}`);
  }
  try {
    finish(db, app, run, outcome, d.now());
  } catch (e) {
    log.error(`[auto-patch] ${app.slug} run #${run.id}: could not record the outcome: ${e.message}`);
  }
  log.info(`[auto-patch] ${app.slug} request #${req.id}: ${outcome.status}${outcome.reason ? ` (${outcome.reason})` : ''}`);
  return { action: outcome.status, reason: outcome.reason, run_id: run.id };
}

/** Mark runs a restart interrupted as fallbacks, so their lock does not outlive the process. */
export function recoverInterruptedRuns(db) {
  const rows = db.prepare("SELECT * FROM auto_patch_runs WHERE status = 'running'").all();
  for (const run of rows) {
    const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(run.app_id);
    if (!app) continue;
    finish(db, app, run, fallback('AppCrane restarted while this auto-patch was running; check the app\'s sandbox and production before acting.'));
  }
  return rows.length;
}

let running = false;
export async function runAutoPatchSweep(db = getDb()) {
  if (running) return { skipped: 'a sweep is already running' };
  running = true;
  const results = [];
  try {
    const seen = new Set();
    for (const req of candidateRequests(db, dep().now())) {
      if (results.filter((r) => r.action !== 'skip').length >= MAX_PER_SWEEP) break;
      if (seen.has(req.app_slug)) continue;
      const r = await processRequest(db, req);
      results.push({ request_id: req.id, app: req.app_slug, ...r });
      if (r.action !== 'skip' && r.action !== 'ineligible') seen.add(req.app_slug);
    }
    setJobDetail('auto-patch', { looked_at: results.length, last: results.slice(-5) });
    return { results };
  } finally {
    running = false;
  }
}

let timer = null;
export function startAutoPatchWorker() {
  if (timer) return;
  try { recoverInterruptedRuns(getDb()); } catch (e) { log.warn(`[auto-patch] recovery failed: ${e.message}`); }
  jobStarted('auto-patch');
  const tick = () => trackJob('auto-patch', () => runAutoPatchSweep()).catch((e) => log.error(`[auto-patch] sweep failed: ${e.message}`));
  setTimeout(tick, 60_000).unref?.();
  timer = setInterval(tick, SWEEP_MS);
  timer.unref?.();
  log.info('[auto-patch] worker started');
}

export function stopAutoPatchWorker() {
  if (timer) { clearInterval(timer); timer = null; }
}
