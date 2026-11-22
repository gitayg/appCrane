// Safe self-update: everything that can fail is done in a staging clone before
// the live tree moves, and the outcome is recorded where scripts/safe-boot.sh
// (the health gate and the rollback) and the next boot (the audit) can read it.
//
//   <repo>/.self-update/staging    the target commit, with its node_modules and SPA
//   <repo>/.self-update/previous   the live node_modules and SPA the update replaced
//
// Both sit inside the repo so moving node_modules is a rename on one filesystem.

import { execFileSync } from 'child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync, renameSync, cpSync, symlinkSync } from 'fs';
import { join } from 'path';
import { ensureSpaBuilt } from './spaBuilder.js';

const SPA_OUT = join('docs', 'admin-app');
const STAMP = '.built-from';

export function workDirs(cwd) {
  const root = join(cwd, '.self-update');
  return { root, staging: join(root, 'staging'), previous: join(root, 'previous') };
}

function errText(e) {
  return (e.stderr?.toString?.().trim() || e.stdout?.toString?.().trim() || e.message || String(e)).slice(-4000);
}

function parseVersion(v) {
  const m = String(v).trim().replace(/^[v=]/, '').match(/^(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?/);
  if (!m) return null;
  const num = (s) => (s === undefined || s === 'x' || s === '*' ? null : Number(s));
  return [Number(m[1]), num(m[2]), num(m[3])];
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) {
    const x = a[i] ?? 0; const y = b[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// The subset of npm's range grammar package.json engines use: comparators
// (>=, >, <=, <, =), bare and x-ranges, ^ and ~, joined by spaces and ||.
// Anything else is reported as unknown rather than guessed at.
export function satisfiesEngine(version, range) {
  const have = parseVersion(version);
  if (!have || !range || !String(range).trim()) return { ok: true, known: false };
  let known = true;
  const ok = String(range).split('||').some((part) => part.trim().split(/\s+/).filter(Boolean).every((tok) => {
    const m = tok.match(/^(>=|<=|>|<|=|\^|~)?(.+)$/);
    const want = m && parseVersion(m[2]);
    if (!want) { known = false; return true; }
    const op = m[1] || '';
    const c = cmp(have, want);
    if (op === '>=') return c >= 0;
    if (op === '>') return c > 0;
    if (op === '<=') return c <= 0;
    if (op === '<') return c < 0;
    if (op === '^') return c >= 0 && have[0] === want[0];
    if (op === '~') return c >= 0 && have[0] === want[0] && (want[1] === null || have[1] === want[1]);
    return want.every((w, i) => w === null || have[i] === w);
  }));
  return { ok, known };
}

export function pendingMigrationsAt(cwd, sha, db) {
  const out = execFileSync('git', ['ls-tree', '--name-only', sha, 'server/migrations/'], { cwd, stdio: 'pipe' }).toString();
  const files = out.split('\n').map((p) => p.split('/').pop()).filter((f) => f && f.endsWith('.sql')).sort();
  let applied = new Set();
  try { applied = new Set(db.prepare('SELECT name FROM _migrations').all().map((r) => r.name)); } catch (_) {}
  return files.filter((f) => !applied.has(f));
}

/**
 * Prove the target commit installs and builds, without touching the live tree.
 * Returns {ok, step?, error?, sha, targetVersion, pendingMigrations, spa, stagingDir}.
 */
export function preflightUpdate({ cwd, sha, db, nodeVersion, skipEngineCheck = false, onLog = () => {} }) {
  const { root, staging } = workDirs(cwd);
  const fail = (step, error) => ({ ok: false, step, error, sha, stagingDir: staging });
  const git = (args, dir = cwd) => execFileSync('git', args, { cwd: dir, stdio: 'pipe', timeout: 60000 }).toString().trim();

  let targetPkg;
  try { targetPkg = JSON.parse(git(['show', `${sha}:package.json`])); }
  catch (e) { return fail('resolve', `target ${sha} has no readable package.json: ${errText(e)}`); }

  const engine = targetPkg?.engines?.node;
  if (engine && !skipEngineCheck) {
    const v = satisfiesEngine(nodeVersion, engine);
    if (!v.ok) return fail('engine', `v${targetPkg.version} requires Node ${engine}; this host runs Node ${nodeVersion}.`);
  }

  let pendingMigrations = [];
  try { pendingMigrations = pendingMigrationsAt(cwd, sha, db); }
  catch (e) { return fail('migrations', `could not list the target's migrations: ${errText(e)}`); }

  try {
    rmSync(staging, { recursive: true, force: true });
    mkdirSync(root, { recursive: true });
    onLog(`preflight: staging ${sha.slice(0, 7)} in ${staging}`);
    git(['clone', '--shared', '--no-checkout', '--quiet', cwd, staging], root);
    git(['checkout', '--quiet', '--detach', sha], staging);
  } catch (e) { return fail('stage', `could not check out ${sha} into ${staging}: ${errText(e)}`); }

  try {
    onLog('preflight: npm ci --omit=dev in staging');
    execFileSync('npm', ['ci', '--omit=dev', '--prefer-offline', '--no-audit', '--no-fund'], {
      cwd: staging, stdio: 'pipe', timeout: 600000,
    });
  } catch (e) { return fail('install', errText(e)); }

  const liveStamp = join(cwd, SPA_OUT, STAMP);
  if (existsSync(liveStamp)) {
    mkdirSync(join(staging, SPA_OUT), { recursive: true });
    writeFileSync(join(staging, SPA_OUT, STAMP), readFileSync(liveStamp));
  }
  const liveStudioModules = join(cwd, 'studio-web', 'node_modules');
  if (existsSync(liveStudioModules) && existsSync(join(staging, 'studio-web'))) {
    try { symlinkSync(liveStudioModules, join(staging, 'studio-web', 'node_modules'), 'dir'); } catch (_) {}
  }
  const spa = ensureSpaBuilt(staging, { onLog });
  if (!spa.rebuilt && spa.reason !== 'up-to-date') return fail('spa', spa.error || 'admin SPA build failed');

  return {
    ok: true, sha, stagingDir: staging,
    targetVersion: targetPkg.version,
    pendingMigrations,
    spa: { rebuilt: !!spa.rebuilt, reason: spa.reason },
  };
}

export function discardStaging(cwd) {
  rmSync(workDirs(cwd).staging, { recursive: true, force: true });
}

/**
 * Switch the live tree to the staged commit. The live node_modules and SPA are
 * kept in .self-update/previous so a rollback restores them without a network.
 * On failure the live tree is put back as it was and the error is rethrown.
 */
export function applyStagedRelease({ cwd, sha, previousSha, spaRebuilt }) {
  const { staging, previous } = workDirs(cwd);
  const live = { modules: join(cwd, 'node_modules'), spa: join(cwd, SPA_OUT) };
  const prev = { modules: join(previous, 'node_modules'), spa: join(previous, 'admin-app') };
  const git = (args) => execFileSync('git', args, { cwd, stdio: 'pipe', timeout: 60000 }).toString().trim();

  rmSync(previous, { recursive: true, force: true });
  mkdirSync(previous, { recursive: true });
  if (existsSync(live.spa)) cpSync(live.spa, prev.spa, { recursive: true });
  const movedModules = existsSync(live.modules);
  if (movedModules) renameSync(live.modules, prev.modules);

  try {
    const out = git(['reset', '--hard', sha]);
    renameSync(join(staging, 'node_modules'), live.modules);
    if (spaRebuilt) {
      rmSync(live.spa, { recursive: true, force: true });
      renameSync(join(staging, SPA_OUT), live.spa);
    }
    rmSync(staging, { recursive: true, force: true });
    return out;
  } catch (e) {
    try { git(['reset', '--hard', previousSha]); } catch (_) {}
    if (movedModules) {
      rmSync(live.modules, { recursive: true, force: true });
      renameSync(prev.modules, live.modules);
    }
    if (existsSync(prev.spa)) {
      rmSync(live.spa, { recursive: true, force: true });
      cpSync(prev.spa, live.spa, { recursive: true });
    }
    throw e;
  }
}

/** What /api/self-update records for safe-boot.sh before the live tree moves. */
export function buildPendingRecord({ cwd, previousVersion, previousSha, preflight, snapshot, healthUrl, dbPath, pid }) {
  return {
    previous_version: previousVersion,
    previous_sha: previousSha,
    target_version: preflight.targetVersion,
    target_sha: preflight.sha,
    started_at: new Date().toISOString(),
    pid,
    health_url: healthUrl,
    previous_dir: workDirs(cwd).previous,
    db_path: dbPath,
    pending_migrations: preflight.pendingMigrations,
    restore_db: !!snapshot.ok && preflight.pendingMigrations.length > 0,
    spa: preflight.spa,
    snapshot: snapshot.ok ? { id: snapshot.id, dir: snapshot.dir, files: snapshot.files } : null,
    snapshot_error: snapshot.ok ? null : snapshot.error,
  };
}

/** Mark the last update for rollback; safe-boot.sh acts on it when this process exits. */
export function requestRollback(file, info, { by, restoreDb }) {
  writePending(file, {
    ...info,
    rollback_requested_at: new Date().toISOString(),
    rollback_requested_by: by ?? null,
    rollback_reason: `requested by a platform admin (${by ?? 'unknown'})`,
    restore_db: !!restoreDb,
  });
}

export function readPending(file) {
  try { return JSON.parse(readFileSync(file, 'utf8')); } catch (_) { return null; }
}

function writePending(file, info) {
  writeFileSync(file, JSON.stringify(info, null, 2));
}

/**
 * Record what the previous process exit led to, once, at boot (after the DB is up).
 * Under safe-boot an update that reached its target version is not done yet:
 * the health gate decides, and watchUpdateOutcome audits its verdict.
 * Returns the outcome written, or null when there was nothing to reconcile.
 */
export function reconcilePendingUpdate({ file, version, underSafeBoot, audit, now = () => new Date().toISOString() }) {
  const info = readPending(file);
  if (!info) return null;

  if (info.rolled_back_at) {
    if (info.rollback_audited_at) return null;
    writePending(file, {
      ...info, completed_at: info.completed_at || now(), success: false, outcome: 'rolled_back',
      final_version: version, audited_at: info.audited_at || now(), rollback_audited_at: now(),
    });
    audit('self-update-rolled-back', {
      from: info.previous_version, to: info.target_version, running: version,
      reason: info.rollback_reason, db_restored: !!info.db_restored,
      requested_by: info.rollback_requested_by ?? null,
    });
    return 'rolled_back';
  }
  if (info.completed_at || info.audited_at) return null;

  const success = info.target_version === version;
  const gated = success && !!info.health_url && underSafeBoot;
  const outcome = gated ? (info.health_ok_at ? 'updated' : 'verifying') : (success ? 'updated' : 'failed');
  const done = outcome !== 'verifying';
  writePending(file, {
    ...info, completed_at: now(), success, final_version: version, outcome,
    ...(done ? { audited_at: now() } : {}),
  });
  if (done) {
    audit(success ? 'self-update-completed' : 'self-update-failed', {
      from: info.previous_version, to: info.target_version, running: version,
      health: info.health_ok_at ? 'passed' : 'unverified',
    });
  }
  return outcome;
}

/** Poll for safe-boot.sh's health verdict and audit it. Returns a stop function. */
export function watchUpdateOutcome({ file, audit, intervalMs = 2000, maxMs = 15 * 60 * 1000, now = () => new Date().toISOString() }) {
  const started = Date.now();
  const timer = setInterval(() => {
    const info = readPending(file);
    if (!info || info.audited_at || info.rolled_back_at || Date.now() - started > maxMs) return clearInterval(timer);
    if (!info.health_ok_at) return;
    clearInterval(timer);
    writePending(file, { ...info, outcome: 'updated', audited_at: now() });
    audit('self-update-completed', {
      from: info.previous_version, to: info.target_version, health: 'passed', health_ok_at: info.health_ok_at,
    });
  }, intervalMs);
  timer.unref?.();
  return () => clearInterval(timer);
}

/** Whether an explicit rollback to the recorded previous commit can run now. */
export function rollbackAvailability(info, { version, headSha, underSafeBoot, previousDir }) {
  if (!underSafeBoot) return { ok: false, code: 'SAFE_BOOT_REQUIRED', message: 'Rollback is performed by scripts/safe-boot.sh between processes; this server was not started by it.' };
  if (!info || !info.previous_sha) return { ok: false, code: 'NO_PREVIOUS', message: 'No recorded self-update to roll back.' };
  if (info.rolled_back_at || info.rollback_requested_at) return { ok: false, code: 'ALREADY_ROLLED_BACK', message: `The update to v${info.target_version} was already rolled back.` };
  if (info.outcome !== 'updated' || info.final_version !== version) return { ok: false, code: 'NOT_UPDATED', message: `The last self-update did not leave this server on its target version (outcome: ${info.outcome || 'unknown'}).` };
  if (info.target_sha && headSha && info.target_sha !== headSha) return { ok: false, code: 'TREE_MOVED', message: `The working tree is at ${headSha.slice(0, 7)}, not the updated commit ${info.target_sha.slice(0, 7)}; roll back by hand.` };
  return {
    ok: true,
    previous_version: info.previous_version,
    previous_sha: info.previous_sha,
    restores_dependencies: existsSync(join(previousDir, 'node_modules')),
    snapshot: info.snapshot?.id ?? null,
    pending_migrations: info.pending_migrations ?? [],
  };
}
