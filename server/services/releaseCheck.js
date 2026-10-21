// The release check: a security gate run on every production deploy and
// promote (migration 139).
//
// Checks, each pass / warn / fail with reasons:
//   intake          the app's intake allows production (appIntake.js)
//   dependencies    the candidate release's lockfile scan (or image scan) has
//                   no advisory with a published fix; advisories with no fix warn
//   secrets         no credential-shaped string in the candidate tree
//   access_rules    path rules present, when the classification requires them
//   sso_gate        no headless mode, bypass paths, custom domain or public
//                   visibility, unless the classification allows it
//   sandbox_health  the sandbox release being shipped is live and healthy
//
// The mode comes from the classification policy (dataClassification.js):
// enforce refuses on a failed check, warn records it, off skips the checks.
// Intake is not governed by the mode: it has its own policy flag, and a
// failed intake refuses in every mode. A failed check can be covered by an
// exception with a reason and an expiry; intake cannot.

import { existsSync, readFileSync, realpathSync } from 'fs';
import { join, resolve } from 'path';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { isPlatformAdmin } from '../utils/roles.js';
import { roleForUserOnApp } from './permissions.js';
import { logAudit } from '../middleware/audit.js';
import { recordEvent } from './eventStore.js';
import { intakeGate } from './appIntake.js';
import { getClassification, getClassificationPolicy } from './dataClassification.js';
import { effectiveRules, parseAccessRules } from './accessRules.js';
import { scanTreeForSecrets } from './releaseSecretScan.js';

export const CHECK_IDS = Object.freeze(['intake', 'dependencies', 'secrets', 'access_rules', 'sso_gate', 'sandbox_health']);
export const EXCEPTABLE = Object.freeze(CHECK_IDS.filter((c) => c !== 'intake'));
const LABELS = {
  intake: 'Intake approved',
  dependencies: 'Dependency scan',
  secrets: 'No secrets in code',
  access_rules: 'Access rules',
  sso_gate: 'SSO gate not bypassed',
  sandbox_health: 'Sandbox release healthy',
};
const MAX_EXCEPTION_DAYS = 90;
const DEFAULT_SCAN_TIMEOUT_MS = 90_000;

let deps = null;
/** Test seam: { scanApp, scanTree, now } replace the real scanners. */
export function _setReleaseCheckDepsForTests(d) { deps = d; }

function scanTimeoutMs() {
  const n = Number(process.env.RELEASE_CHECK_SCAN_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_SCAN_TIMEOUT_MS;
}

function withTimeout(promise, ms, what) {
  let t;
  return Promise.race([
    promise.finally(() => clearTimeout(t)),
    new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${what} did not finish within ${Math.round(ms / 1000)}s`)), ms); t.unref?.(); }),
  ]);
}

function check(id, status, reasons, extra = {}) {
  return { id, label: LABELS[id], status, reasons: reasons.filter(Boolean), ...extra };
}

function dataDir() { return resolve(process.env.DATA_DIR || './data'); }

function sandboxRelease(db, app) {
  const dep = db.prepare(`SELECT id, commit_hash, version, finished_at, started_at FROM deployments
    WHERE app_id = ? AND env = 'sandbox' AND status = 'live' ORDER BY started_at DESC, id DESC LIMIT 1`).get(app.id);
  if (!dep) return null;
  let dir = null;
  if (app.source_type !== 'image') {
    const cur = join(dataDir(), 'apps', app.slug, 'sandbox', 'current');
    try { dir = existsSync(cur) ? realpathSync(cur) : null; } catch { dir = null; }
  }
  return { ...dep, dir };
}

function intakeCheck(db, app) {
  const g = intakeGate(db, app);
  return check('intake', g.ok ? 'pass' : 'fail', [g.message], { intake_status: g.status });
}

function judgeFindings(findings, label) {
  const fixable = findings.filter((f) => f.fixed);
  const unfixed = findings.filter((f) => !f.fixed);
  const name = (f) => `${f.name}@${f.version} (${(f.ids || []).slice(0, 2).join(', ')})${f.fixed ? ` fixed in ${f.fixed}` : ''}`;
  if (fixable.length) {
    return check('dependencies', 'fail', [
      `${label}: ${fixable.length} vulnerable package(s) with a published fix`,
      ...fixable.slice(0, 5).map(name),
      unfixed.length ? `${unfixed.length} more with no published fix` : null,
    ], { findings: findings.length, fixable: fixable.length });
  }
  if (unfixed.length) {
    return check('dependencies', 'warn', [
      `${label}: ${unfixed.length} vulnerable package(s), none with a published fix yet`,
      ...unfixed.slice(0, 5).map(name),
    ], { findings: findings.length });
  }
  return check('dependencies', 'pass', [`${label}: no known vulnerabilities`], { findings: 0 });
}

function judgeScanRow(row, label) {
  if (!row) return check('dependencies', 'fail', [`${label}: no scan result`]);
  if (row.status === 'error') return check('dependencies', 'fail', [`${label}: the scan could not complete (${row.error || 'unknown error'}), so the release is not shown to be clean`]);
  if (row.status === 'skipped') return check('dependencies', 'pass', [`${label}: nothing to scan (${row.error || 'no recognised manifest'})`]);
  return judgeFindings(row.findings_json ? JSON.parse(row.findings_json) : [], label);
}

async function scanTreeDeps(dir) {
  const { findLockfiles, parseLockfile, queryOsv } = await import('./appScan.js');
  const manifests = findLockfiles(dir);
  if (manifests.length === 0) return { status: 'skipped', error: 'no recognised manifest in the release' };
  const seen = new Set();
  const packages = [];
  for (const m of manifests) {
    for (const p of parseLockfile(m.path, m.ecosystem, m.entry)) {
      const k = `${p.ecosystem}:${p.name}@${p.version}`;
      if (!seen.has(k)) { seen.add(k); packages.push(p); }
    }
  }
  const osv = await queryOsv(packages);
  if (!osv.ok) return { status: 'error', error: osv.error };
  return { status: osv.findings.length ? 'findings' : 'ok', findings_json: osv.findings.length ? JSON.stringify(osv.findings) : null };
}

async function dependencyCheck(db, app, { releaseDir, commit, sandbox }) {
  const label = app.source_type === 'image' ? 'Image scan' : 'Dependency scan';
  const runScanApp = deps?.scanApp || (async (...a) => (await import('./appScan.js')).scanApp(...a));
  const runTree = deps?.scanTree || scanTreeDeps;
  const timeout = scanTimeoutMs();
  try {
    // The sandbox release is the candidate when nothing else is in hand, or
    // when the tree being deployed is the sandbox's own commit.
    const useSandbox = sandbox && (!releaseDir || (commit && sandbox.commit_hash && commit === sandbox.commit_hash) || app.source_type === 'image');
    if (useSandbox) {
      const { latestScan } = await import('./appScan.js');
      const since = sandbox.finished_at || sandbox.started_at;
      let row = latestScan(db, app.id, 'sandbox');
      const fresh = row && row.status !== 'error' && (!since || row.scanned_at >= since);
      if (!fresh) row = await withTimeout(runScanApp(db, app, 'sandbox', 'release-check'), timeout, 'The scan');
      return judgeScanRow(row, `${label} of sandbox release #${sandbox.id}`);
    }
    if (releaseDir && app.source_type !== 'image') {
      const row = await withTimeout(Promise.resolve(runTree(releaseDir)), timeout, 'The scan');
      return judgeScanRow(row, `${label} of the release being deployed`);
    }
    return check('dependencies', 'warn', [`${label}: no candidate release to scan before deploy (no live sandbox); the deploy-time scan reports after it ships`]);
  } catch (e) {
    return check('dependencies', 'fail', [`${label}: ${e.message}, so the release is not shown to be clean`]);
  }
}

function secretsCheck(app, dir) {
  if (app.source_type === 'image') return check('secrets', 'pass', ['Image app: there is no source tree to scan'], { applicable: false });
  if (!dir || !existsSync(dir)) return check('secrets', 'warn', ['No candidate release tree on disk to scan before deploy']);
  const scan = (deps?.scanSecrets || scanTreeForSecrets)(dir, { deadline: Date.now() + 20_000 });
  if (scan.findings.length) {
    return check('secrets', 'fail', [
      `${scan.findings.length}${scan.truncated ? '+' : ''} credential-shaped string(s) in the release (values not shown)`,
      ...scan.findings.slice(0, 10).map((f) => `${f.file}:${f.line} (${f.rule})`),
    ]);
  }
  if (scan.truncated) return check('secrets', 'warn', [`Scanned ${scan.files} file(s) before the scan limit; the rest were not checked`]);
  return check('secrets', 'pass', [`Scanned ${scan.files} file(s), node_modules skipped`]);
}

function manifestRuleCount(dir) {
  if (!dir) return 0;
  const p = join(dir, 'deployhub.json');
  if (!existsSync(p)) return 0;
  try { return (parseAccessRules(JSON.parse(readFileSync(p, 'utf8')).access) || []).length; } catch { return 0; }
}

function accessRulesCheck(db, app, policy, level, dir) {
  const prod = effectiveRules(db, app.id, 'production').length;
  const manifest = manifestRuleCount(dir);
  const sandboxManifest = db.prepare("SELECT rules_json FROM app_access_rules WHERE app_id = ? AND env = 'sandbox' AND source = 'manifest'").get(app.id);
  const sb = sandboxManifest ? JSON.parse(sandboxManifest.rules_json).length : 0;
  const total = Math.max(prod, manifest, sb);
  if (!policy.require_access_rules) {
    return check('access_rules', 'pass', [total ? `${total} path rule(s) in place` : `Not required for ${level} apps`]);
  }
  if (total) return check('access_rules', 'pass', [`${total} path rule(s) in place (required for ${level} apps)`]);
  return check('access_rules', 'fail', [`${level} apps must declare path access rules (deployhub.json "access" or the dashboard Access rules card) before production`]);
}

function ssoCheck(app, policy, level) {
  const bypass = [];
  if (app.auth_mode === 'headless') bypass.push('auth_mode is headless: nothing is checked at the gate');
  let paths = [];
  try { paths = app.auth_bypass_paths ? JSON.parse(app.auth_bypass_paths) : []; } catch { paths = app.auth_bypass_paths ? [String(app.auth_bypass_paths)] : []; }
  if (Array.isArray(paths) && paths.length && app.auth_mode !== 'headless') bypass.push(`${paths.length} auth bypass path(s)`);
  if (app.domain && String(app.domain).trim()) bypass.push(`custom domain ${String(app.domain).trim()} is served without the SSO gate`);
  const isPublic = app.visibility === 'public' || app.public_access === 1;
  const fails = [];
  const notes = [];
  for (const b of bypass) (policy.allow_sso_bypass ? notes : fails).push(b);
  if (isPublic) (policy.allow_public_visibility ? notes : fails).push('visibility is public');
  if (fails.length) return check('sso_gate', 'fail', [`Not allowed for ${level} apps:`, ...fails]);
  if (notes.length) return check('sso_gate', 'pass', [`Allowed for ${level} apps:`, ...notes]);
  return check('sso_gate', 'pass', ['Every request passes the SSO gate']);
}

function sandboxHealthCheck(db, app, sandbox, trigger) {
  if (!sandbox) {
    return check('sandbox_health', trigger === 'promote' ? 'fail' : 'warn', ['No live sandbox release: production is not shipping a release that ran in sandbox']);
  }
  const h = db.prepare("SELECT is_down, last_status, last_check_at FROM health_state WHERE app_id = ? AND env = 'sandbox'").get(app.id);
  if (h?.is_down) return check('sandbox_health', 'fail', [`Sandbox release #${sandbox.id} is failing its health check`]);
  return check('sandbox_health', 'pass', [`Sandbox release #${sandbox.id}${sandbox.version ? ` (v${sandbox.version})` : ''} is live${h?.last_status === 200 ? ' and healthy' : ''}`]);
}

export function activeExceptions(db, appId) {
  return db.prepare(`SELECT e.*, u.name AS created_by_name FROM release_check_exceptions e LEFT JOIN users u ON u.id = e.created_by
    WHERE e.app_id = ? AND e.revoked_at IS NULL AND e.expires_at > datetime('now') ORDER BY e.id DESC`).all(appId);
}

export function resolveMode(db, level) {
  const policy = getClassificationPolicy(db);
  return policy.release_check_mode === 'by_classification' ? policy.levels[level].release_check : policy.release_check_mode;
}

/**
 * Run and store one release check. Never throws for a failed check; see
 * assertProductionRelease for the refusal.
 * @param {{ db?: object, app: object, userId?: number|null, trigger: string, releaseDir?: string|null,
 *           commit?: string|null, deploymentId?: number|null }} ctx
 */
export async function runReleaseCheck(ctx) {
  const db = ctx.db || getDb();
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(ctx.app.id) || ctx.app;
  const { level } = getClassification(db, app.id);
  const fullPolicy = getClassificationPolicy(db);
  const policy = fullPolicy.levels[level];
  const mode = resolveMode(db, level);
  const sandbox = sandboxRelease(db, app);
  const dir = ctx.releaseDir || sandbox?.dir || null;
  const candidate = ctx.releaseDir
    ? `release being deployed${ctx.commit ? ` @ ${String(ctx.commit).slice(0, 12)}` : ''}`
    : (sandbox ? `sandbox release #${sandbox.id}${sandbox.commit_hash ? ` @ ${String(sandbox.commit_hash).slice(0, 12)}` : ''}` : 'none');

  const checks = [intakeCheck(db, app)];
  if (mode !== 'off') {
    checks.push(await dependencyCheck(db, app, { releaseDir: ctx.releaseDir || null, commit: ctx.commit || null, sandbox }));
    checks.push(secretsCheck(app, dir));
    checks.push(accessRulesCheck(db, app, policy, level, dir));
    checks.push(ssoCheck(app, policy, level));
    checks.push(sandboxHealthCheck(db, app, sandbox, ctx.trigger));
  }
  const exceptions = activeExceptions(db, app.id);
  for (const c of checks) {
    if (c.status !== 'fail' || c.id === 'intake') continue;
    const ex = exceptions.find((e) => e.check_id === c.id);
    if (ex) {
      c.status = 'excepted';
      c.exception = { id: ex.id, reason: ex.reason, expires_at: ex.expires_at, created_by: ex.created_by_name || ex.created_by };
    }
  }
  const intakeFailed = checks[0].status === 'fail';
  const failed = checks.filter((c) => c.status === 'fail' && c.id !== 'intake');
  const result = intakeFailed || failed.length ? 'fail'
    : mode === 'off' ? 'skipped'
      : checks.some((c) => c.status === 'warn') ? 'warn' : 'pass';
  const isVulnFail = (c) => c.id === 'dependencies' && c.fixable > 0;
  const blocked = intakeFailed
    || (fullPolicy.block_vulnerable_dependencies && failed.some(isVulnFail))
    || (mode === 'enforce' && failed.some((c) => !isVulnFail(c)));

  const info = db.prepare(`INSERT INTO release_checks (app_id, env, deployment_id, trigger, candidate, data_classification, mode, result, blocked, checks_json, created_by)
    VALUES (?, 'production', ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(app.id, ctx.deploymentId ?? null, String(ctx.trigger || 'deploy').slice(0, 32),
    candidate, level, mode, result, blocked ? 1 : 0, JSON.stringify(checks), ctx.userId ?? null);
  const record = { id: Number(info.lastInsertRowid), app: app.slug, trigger: ctx.trigger, candidate, data_classification: level, mode, result, blocked, checks };

  if (result === 'fail' || result === 'warn') {
    recordEvent({
      kind: 'release_check', severity: blocked ? 'warning' : 'info', appId: app.id, userId: ctx.userId ?? null,
      summary: `Release check ${blocked ? 'blocked' : result === 'fail' ? 'failed (not enforced)' : 'passed with warnings'} for production (${level}, ${mode})`,
      refTable: 'release_checks', refId: record.id,
      data: { failed: checks.filter((c) => c.status === 'fail').map((c) => c.id), mode },
    });
  }
  return record;
}

export function refusalMessage(record) {
  const failing = record.checks.filter((c) => c.status === 'fail');
  const lines = failing.map((c) => `- ${c.label}: ${c.reasons.join('; ')}`);
  return `Release check refused production for ${record.app} (${record.data_classification}, mode ${record.mode}):\n${lines.join('\n')}`;
}

/**
 * Run the check and throw when it refuses. 403 INTAKE_NOT_APPROVED when intake
 * is the reason, else 409 RELEASE_CHECK_FAILED. err.releaseCheck holds the
 * checklist for the route and MCP responses.
 */
export async function assertProductionRelease(ctx) {
  const record = await runReleaseCheck(ctx);
  if (!record.blocked) return record;
  const intakeFailed = record.checks[0].status === 'fail';
  const e = intakeFailed
    ? new AppError(`${record.checks[0].reasons[0]}\n${refusalMessage(record)}`, 403, 'INTAKE_NOT_APPROVED')
    : new AppError(refusalMessage(record), 409, 'RELEASE_CHECK_FAILED');
  e.releaseCheck = record;
  throw e;
}

/** Express helper: a refusal from assertProductionRelease, with its checklist. */
export function sendReleaseRefusal(res, err) {
  return res.status(err.status).json({ error: { code: err.code, message: err.message }, release_check: err.releaseCheck });
}

/**
 * The in-deploy check, run by deployApp for every production deploy before
 * any container is stopped or started. Rollbacks, and redeploys of the live
 * release by auto-heal or the bulk redeploy, are not new releases and skip it.
 */
export async function enforceReleaseCheckInDeploy({ app, deployId, releaseDir, commit, opts = {}, appendLog = () => {} }) {
  if (opts.releaseCheck === 'skip') return null;
  const db = getDb();
  const row = db.prepare('SELECT log, deployed_by FROM deployments WHERE id = ?').get(deployId);
  if (/^(auto-heal:|auto-queued after)/.test(row?.log || '')) return null;
  const record = await runReleaseCheck({ db, app, userId: row?.deployed_by ?? null, trigger: 'deploy', releaseDir, commit, deploymentId: deployId });
  appendLog(`Release check #${record.id}: ${record.result} (${record.data_classification}, mode ${record.mode})`);
  for (const c of record.checks) if (c.status !== 'pass') appendLog(`  ${c.status}: ${c.label}: ${c.reasons.join('; ')}`);
  if (record.blocked) {
    const e = new Error(refusalMessage(record));
    e.releaseCheck = record;
    throw e;
  }
  return record;
}

export function latestReleaseCheck(db, appId) {
  const r = db.prepare('SELECT * FROM release_checks WHERE app_id = ? ORDER BY id DESC LIMIT 1').get(appId);
  return r ? hydrate(r) : null;
}

export function listReleaseChecks(db, appId, limit = 20) {
  return db.prepare('SELECT * FROM release_checks WHERE app_id = ? ORDER BY id DESC LIMIT ?').all(appId, Math.min(Math.max(Number(limit) || 20, 1), 100)).map(hydrate);
}

function hydrate(r) {
  return { ...r, blocked: !!r.blocked, checks: JSON.parse(r.checks_json), checks_json: undefined };
}

function assertCanManageExceptions(db, app, user) {
  if (isPlatformAdmin(user)) return;
  const { level } = getClassification(db, app.id);
  const policy = getClassificationPolicy(db).levels[level];
  if (policy.exceptions_by === 'platform_admin') {
    throw new AppError(`Only platform admins can record release check exceptions on ${level} apps`, 403, 'FORBIDDEN');
  }
  if (roleForUserOnApp(user, app) !== 'owner') {
    throw new AppError('Only the app owner or a platform admin can record release check exceptions', 403, 'FORBIDDEN');
  }
}

/** Accept the risk on one check, with a reason and an expiry (max 90 days). */
export function addException(db, app, { check_id, reason, expires_at, days }, user) {
  assertCanManageExceptions(db, app, user);
  if (!EXCEPTABLE.includes(check_id)) throw new AppError(`check_id must be one of ${EXCEPTABLE.join(', ')}`, 400, 'VALIDATION');
  const why = typeof reason === 'string' ? reason.trim().slice(0, 1000) : '';
  if (why.length < 10) throw new AppError('An exception needs a reason of at least 10 characters', 400, 'VALIDATION');
  let exp;
  if (expires_at) {
    exp = new Date(expires_at);
  } else {
    const d = Number(days);
    if (!Number.isFinite(d) || d <= 0) throw new AppError('Give expires_at or days', 400, 'VALIDATION');
    exp = new Date(Date.now() + d * 86400_000);
  }
  if (Number.isNaN(exp.getTime())) throw new AppError('expires_at is not a valid date', 400, 'VALIDATION');
  if (exp.getTime() <= Date.now()) throw new AppError('expires_at must be in the future', 400, 'VALIDATION');
  if (exp.getTime() > Date.now() + MAX_EXCEPTION_DAYS * 86400_000) throw new AppError(`An exception can last at most ${MAX_EXCEPTION_DAYS} days`, 400, 'VALIDATION');
  const expSql = exp.toISOString().slice(0, 19).replace('T', ' ');
  const id = Number(db.prepare('INSERT INTO release_check_exceptions (app_id, check_id, reason, expires_at, created_by) VALUES (?, ?, ?, ?, ?)')
    .run(app.id, check_id, why, expSql, user.id).lastInsertRowid);
  logAudit(user.id, app.id, 'release-check-exception-add', { id, check_id, reason: why, expires_at: expSql });
  recordEvent({ kind: 'release_check.exception', severity: 'warning', appId: app.id, userId: user.id,
    summary: `Release check exception on '${check_id}' until ${expSql}`, refTable: 'release_check_exceptions', refId: id,
    data: { check_id, expires_at: expSql } });
  return db.prepare('SELECT * FROM release_check_exceptions WHERE id = ?').get(id);
}

export function revokeException(db, app, id, user) {
  assertCanManageExceptions(db, app, user);
  const row = db.prepare('SELECT * FROM release_check_exceptions WHERE id = ? AND app_id = ?').get(id, app.id);
  if (!row) throw new AppError('Exception not found', 404, 'NOT_FOUND');
  db.prepare("UPDATE release_check_exceptions SET revoked_at = datetime('now'), revoked_by = ? WHERE id = ?").run(user.id, id);
  logAudit(user.id, app.id, 'release-check-exception-revoke', { id, check_id: row.check_id });
  recordEvent({ kind: 'release_check.exception', severity: 'info', appId: app.id, userId: user.id,
    summary: `Release check exception on '${row.check_id}' revoked`, refTable: 'release_check_exceptions', refId: id });
  return { id, revoked: true };
}
