import { execFile } from 'child_process';
import { promisify } from 'util';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';
import { SANDBOX_TENANT, getSeparateSandboxDb } from './sandboxDb.js';

// Restoring an app's data while the app keeps running interleaves the app's own
// writes with the restore, and the app goes on serving whatever is half loaded.
// So a restore stops the app container(s) that use the data, restores, and
// starts them again whatever happened — and holds a per-app lock meanwhile, so
// no deploy, rollback, promote, restart or second restore lands in between.
//
// The lock is in process memory: AppCrane is one Node process, and a restart
// mid-restore kills the restore with it. Keyed by slug, because every guard
// that consults it (docker.startApp, the deploy routes, the health checker)
// already holds the slug.
//
// Stop is `docker stop` WITHOUT `rm`, and start is docker.restartApp on that same
// container: same image, env, mounts and memory cap. Memory admission
// (memoryAdmission.js) gates docker.startApp only, which recreates a container;
// going through it after a stop would NOT be covered by its "not raising the
// total" rule (that rule counts the cap of the RUNNING container of the same
// name, and a stopped one is not running), so the same-container start is
// what keeps a restore from ever being refused a start for memory.

const execFileAsync = promisify(execFile);
const active = new Map();

export const RESTORE_IN_PROGRESS = 'RESTORE_IN_PROGRESS';

function containerName(slug, env) {
  return `appcrane-${slug}-${env}`;
}

export function restoreInProgress(slug, env = null) {
  const a = active.get(slug);
  return !!a && (env == null || a.envs.includes(env));
}

export function restoreStatus(slug) {
  const a = active.get(slug);
  if (!a) return { in_progress: false };
  return { in_progress: true, phase: a.phase, envs: [...a.envs], started_at: a.startedAt };
}

export function assertNoRestoreInProgress(slug, env) {
  if (!restoreInProgress(slug, env)) return;
  throw new AppError(
    `A database restore is in progress for ${slug}/${env}; the app is stopped until it finishes. Try again in a moment.`,
    409, RESTORE_IN_PROGRESS,
  );
}

/**
 * The environments whose containers use the data being restored: `env` (its
 * /data), plus each restored database's users. Production's database is also
 * sandbox's unless the app has a separate sandbox database.
 */
export function envsForRestore(appId, { env = null, tenants = [] } = {}) {
  const envs = new Set(env ? [env] : []);
  const separate = getSeparateSandboxDb(getDb(), appId);
  for (const t of tenants) {
    if ((t || '') === SANDBOX_TENANT) envs.add('sandbox');
    else {
      envs.add('production');
      if (!separate) envs.add('sandbox');
    }
  }
  return ['production', 'sandbox'].filter((e) => envs.has(e));
}

async function isRunning(name) {
  try {
    const { stdout } = await execFileAsync('docker', ['inspect', '--format', '{{.State.Running}}', name], { timeout: 15000 });
    return stdout.trim() === 'true';
  } catch (_) {
    return false;
  }
}

async function stopContainer(name) {
  await execFileAsync('docker', ['stop', name], { timeout: 60000 });
}

async function alertStartFailure(app, env, message) {
  log.error(`[restore] ${app.slug}/${env}: ${message}`);
  try {
    const { notifyDeploy } = await import('./emailService.js');
    await notifyDeploy(app, env, 'unknown', 'failed', message);
  } catch (_) { /* best-effort, like a failed deploy's notice */ }
}

/**
 * Run `work` with the app's containers for `envs` stopped and the app locked.
 *
 * Refuses (409) when a restore of this app is already running or a deploy is in
 * flight for one of `envs`. A container that is not running is left alone and
 * not started afterwards. A container that cannot be stopped aborts the
 * restore before `work` runs. Every container this stopped is started again in
 * `finally`, and a start that fails is alerted like a failed deploy.
 *
 * Returns { result, steps, startFailures }. When `work` throws, the error is
 * rethrown with `restoreSteps` and `startFailures` attached.
 */
export async function runWithAppStopped({ app, envs, keepRunning = false }, work) {
  if (active.has(app.slug)) {
    throw new AppError(`A restore of ${app.slug} is already running; wait for it to finish.`, 409, RESTORE_IN_PROGRESS);
  }
  const entry = { envs: [...envs], phase: 'starting', startedAt: new Date().toISOString() };
  active.set(app.slug, entry);
  const steps = [];
  const stopped = [];
  const startFailures = [];
  let failure = null;
  let result;
  try {
    const { assertNoInflightDeploy } = await import('./deployer.js');
    for (const env of envs) assertNoInflightDeploy(getDb(), app.id, env, app.slug);

    try {
      if (!keepRunning) {
        entry.phase = 'stopping';
        for (const env of envs) {
          const name = containerName(app.slug, env);
          const t0 = Date.now();
          if (!(await isRunning(name))) {
            steps.push({ step: 'stop', env, ok: true, ms: Date.now() - t0, note: 'not running' });
            continue;
          }
          try {
            await stopContainer(name);
          } catch (e) {
            steps.push({ step: 'stop', env, ok: false, ms: Date.now() - t0, error: e.message });
            throw new AppError(`Could not stop the ${env} app before restoring, so nothing was restored: ${e.message}`, 500, 'APP_STOP_FAILED');
          }
          stopped.push(env);
          steps.push({ step: 'stop', env, ok: true, ms: Date.now() - t0 });
        }
      }
      entry.phase = 'restoring';
      const t0 = Date.now();
      try {
        result = await work();
        steps.push({ step: 'restore', ok: true, ms: Date.now() - t0 });
      } catch (e) {
        steps.push({ step: 'restore', ok: false, ms: Date.now() - t0, error: e.message });
        throw e;
      }
    } catch (e) {
      failure = e;
    } finally {
      if (stopped.length) {
        entry.phase = 'starting_app';
        const { restartApp } = await import('./docker.js');
        for (const env of stopped) {
          const t0 = Date.now();
          try {
            await restartApp(app.slug, env);
            steps.push({ step: 'start', env, ok: true, ms: Date.now() - t0 });
          } catch (e) {
            steps.push({ step: 'start', env, ok: false, ms: Date.now() - t0, error: e.message });
            startFailures.push({ env, error: e.message });
            await alertStartFailure(app, env, `the app did not start again after a database restore: ${e.message}`);
          }
        }
      }
    }
  } finally {
    active.delete(app.slug);
  }
  log.info(`[restore] ${app.slug}: ${describeSteps(steps)}`);
  if (failure) throw Object.assign(failure, { restoreSteps: steps, startFailures });
  return { result, steps, startFailures };
}

export function describeSteps(steps) {
  return steps.map((s) => `${s.step}${s.env ? ` ${s.env}` : ''} ${s.ms}ms ${s.ok ? (s.note || 'ok') : 'FAILED'}`).join(' -> ') || 'nothing to do';
}

export function __resetRestoreLocksForTests() { active.clear(); }
