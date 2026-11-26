import { mkdirSync } from 'fs';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { getPortsForSlot } from './portAllocator.js';
import log from '../utils/logger.js';
import { parseContainerCommand, parseVolumePaths, resolveVolumeMounts } from './containerRuntimeSpec.js';
import { SANDBOX_TENANT } from './sandboxDb.js';

// The body of POST /api/apps/:slug/restart/:env, moved here unchanged so the
// host-gateway repair (hostGateway.js) recreates a container exactly the way
// the Restart button does. Permission checks stay in the route.
//
// Stops the container and starts a new one from the image it was running, with
// the env, mounts, command and limits read again from the database. A plain
// docker restart keeps the old container (and its baked-in env and /etc/hosts).
//
// actor: the requesting user row, or a 'system:<who>' string for AppCrane's own
// repairs (no user; memory admission sees an automatic start).

// In-flight recreations per app+env. An automatic one (a system actor) is
// exclusive: it refuses to start beside any other recreation of that env, it
// re-checks deploys, restores and sleep/wake immediately before it stops the
// container, and the paths that replace or stop the container consult it:
// deployApp waits for it before its own swap (waitForAutomaticRecreate), and
// the restart route, database restore and the env sleeper refuse or skip.
const inFlight = new Map();
const keyOf = (appId, env) => `${appId}:${env}`;

export const RECREATE_IN_PROGRESS = 'RECREATE_IN_PROGRESS';
export const AUTOMATIC_RECREATE_WAIT_MS = 180_000;

/** Is a recreation of app+env running in this process right now? */
export function recreateInFlight(appId, env) {
  return !!inFlight.get(keyOf(appId, env))?.size;
}

/** The automatic (system actor) recreation of app+env in flight, or null. */
export function automaticRecreateInFlight(appId, env) {
  for (const e of inFlight.get(keyOf(appId, env)) || []) if (e.automatic) return e;
  return null;
}

export function automaticRecreateMessage(slug, env) {
  return `AppCrane is recreating the ${slug} ${env} container automatically (host.docker.internal repair). Try again in a minute.`;
}

/** Throws 409 RECREATE_IN_PROGRESS while an automatic recreation of app+env runs. */
export function assertNoAutomaticRecreate(app, env) {
  if (!automaticRecreateInFlight(app.id, env)) return;
  throw new AppError(automaticRecreateMessage(app.slug, env), 409, RECREATE_IN_PROGRESS);
}

/**
 * Wait (bounded) until no automatic recreation of app+env is in flight.
 * Throws 409 RECREATE_IN_PROGRESS when one is still running after timeoutMs.
 */
export async function waitForAutomaticRecreate(app, env, { timeoutMs = AUTOMATIC_RECREATE_WAIT_MS, onWait = null } = {}) {
  const deadline = Date.now() + timeoutMs;
  let told = false;
  for (let e = automaticRecreateInFlight(app.id, env); e; e = automaticRecreateInFlight(app.id, env)) {
    if (!told && onWait) { onWait(`Waiting for AppCrane's automatic recreate of ${app.slug} ${env} (host.docker.internal repair) to finish before replacing the container.`); told = true; }
    const left = deadline - Date.now();
    if (left <= 0) {
      throw new AppError(`${automaticRecreateMessage(app.slug, env)} It was still running after ${Math.round(timeoutMs / 1000)} s, so nothing was stopped.`, 409, RECREATE_IN_PROGRESS);
    }
    let timer;
    await Promise.race([e.done, new Promise((r) => { timer = setTimeout(r, left); })]);
    clearTimeout(timer);
  }
}

/**
 * Why an automatic recreation of app+env may not run now, or null. Any
 * deploy row that has not finished counts, however old (the same check the
 * env sleeper uses).
 */
export async function envBusyReason(db, app, env) {
  const { restoreInProgress } = await import('./managedDbRestoreGuard.js');
  const { deployInFlight } = await import('./envSleeper.js');
  const { envIsSleepingById } = await import('./envSleepState.js');
  const { opInFlight } = await import('./envWake.js');
  return busyNow({ restoreInProgress, deployInFlight, envIsSleepingById, opInFlight }, db, app, env);
}

function busyNow(g, db, app, env) {
  if (g.restoreInProgress(app.slug, env)) return 'a database restore is in progress';
  if (g.deployInFlight(db, app.id, env)) return 'a deploy is in progress';
  if (g.opInFlight(app.id, env)) return 'a sleep or wake is in progress';
  if (g.envIsSleepingById(app.id, env, db)) return 'the environment is asleep or waking';
  return null;
}

// precheck: for a system actor, an async () => reason|null run just before the
// stop (the host-gateway repair re-reads the --add-host decision there). The
// busy checks run after it, synchronously, right before dockerStop; onStop()
// runs once they pass, synchronously, as the stop begins.
export async function recreateEnvContainer({ app, env, actor, reason = 'restart', precheck = null, onStop = null }) {
  const key = keyOf(app.id, env);
  const automatic = typeof actor === 'string';
  if (automatic && recreateInFlight(app.id, env)) {
    throw new AppError(`A restart of ${app.slug} ${env} is already in progress.`, 409, RECREATE_IN_PROGRESS);
  }
  let release;
  const entry = { automatic, actor: automatic ? actor : actor?.id ?? null, done: new Promise((r) => { release = r; }) };
  if (!inFlight.has(key)) inFlight.set(key, new Set());
  inFlight.get(key).add(entry);
  try {
    return await recreate({ app, env, actor, reason, precheck, onStop });
  } finally {
    inFlight.get(key).delete(entry);
    if (!inFlight.get(key).size) inFlight.delete(key);
    release();
  }
}

async function recreate({ app, env, actor, reason, precheck, onStop }) {
  const systemActor = typeof actor === 'string';
  if (systemActor) log.info(`Restart appcrane-${app.slug}-${env} by ${actor} (${reason})`);
  const db = getDb();
  const ports = getPortsForSlot(app.slot);
  const { resolveStoredEnv, SecretRefError } = await import('../services/secretRefs.js');
  const { execFile } = await import('child_process');
  const { promisify } = await import('util');
  const { resolve, join } = await import('path');
  const execFileAsync = promisify(execFile);

  const containerName = `appcrane-${app.slug}-${env}`;

  // Find the image currently running. If the container doesn't exist (never deployed or pruned),
  // fall back to the most recent live deployment record.
  let image = null;
  try {
    image = await (await import('../services/docker.js')).getContainerImage(app.slug, env);
  } catch (_) {}

  if (!image) {
    throw new AppError(`Container ${containerName} not found. Run a deploy first.`, 400, 'NO_CONTAINER');
  }

  // Platform variables a deploy derived from the release's deployhub.json,
  // which restart cannot re-read: carried over from the container being
  // replaced, by exact name only, so nothing else the old container had leaks
  // forward. Before this, a restart dropped them and a multitenant app lost its
  // tenant root and per-user quota until the next deploy.
  const CARRIED_FROM_DEPLOY = ['APPCRANE_TENANT_ROOT', 'APPCRANE_TENANT_QUOTA_BYTES'];
  const carried = {};
  try {
    const { stdout } = await execFileAsync('docker', ['inspect', containerName, '--format', '{{json .Config.Env}}'], { timeout: 10000 });
    for (const kv of JSON.parse(stdout.trim() || '[]')) {
      const i = kv.indexOf('=');
      if (i > 0 && CARRIED_FROM_DEPLOY.includes(kv.slice(0, i))) carried[kv.slice(0, i)] = kv.slice(i + 1);
    }
  } catch (_) { /* unreadable: fall back to the multitenant flag below */ }
  if (app.multitenant && !carried.APPCRANE_TENANT_ROOT) carried.APPCRANE_TENANT_ROOT = '/data/tenants';

  // Rebuild runtime env vars from DB
  const envVars = db.prepare(
    'SELECT key, value_encrypted FROM env_vars WHERE app_id = ? AND env = ?'
  ).all(app.id, env);

  // An unresolved Secrets Manager reference stops here, with the running
  // container untouched: dockerStop is further down.
  let storedEnv;
  try {
    storedEnv = await resolveStoredEnv(app, env, envVars);
  } catch (e) {
    if (e instanceof SecretRefError) throw new AppError(e.message, 502, e.code);
    throw e;
  }
  const { values: runtimeEnvVars, decryptFailures } = storedEnv;
  // v2.7.30: loud decrypt failures — a silently-dropped secret on restart
  // is exactly the "I set it and it's still missing" mystery.
  if (decryptFailures.length) {
    log.warn(`Restart ${containerName}: ${decryptFailures.length} env var(s) failed to decrypt (ENCRYPTION_KEY mismatch?), omitted: ${decryptFailures.join(', ')}`);
  }

  // v2.65.0: managed database credentials, same rule as the deploy path — the
  // app's catalogue entry (or a custom app's deployhub.json) names the variables, and an env var the app itself
  // carries wins over the injected credential. Restart rebuilds the container's
  // whole environment from scratch, so skipping this here would silently strip
  // the database credentials off a restarted app that had them at deploy.
  // Deliberately placed BEFORE the CRANE_URL/DATA_DIR block below for the same
  // reason as in the deployer: those are platform vars that always win.
  // The managed database's client certificate mount (read-only, this
  // container only), when its login requires one. Same as the deploy path.
  let dbCertMounts = [];
  let dbScope = null;
  {
    const { injectManagedDbForEnv } = await import('../services/deployer.js');
    // A custom app's database is declared in its release's deployhub.json.
    const { readReleaseManifestDatabase } = await import('../services/manifestDatabase.js');
    const appEnvDir = resolve(join(resolve(process.env.DATA_DIR || './data'), 'apps', app.slug, env));
    const releaseDb = readReleaseManifestDatabase(appEnvDir);
    if (releaseDb.error) log.warn(`Restart ${containerName}: ignoring the release's deployhub.json database block: ${releaseDb.error}`);
    // Same helper as the deploy, so a sandbox restart under "Separate sandbox
    // database" re-injects the SANDBOX's credentials (provisioning them if the
    // setting was turned on since the last deploy), and goes back to the shared
    // database once it is turned off.
    const mdbEnv = await injectManagedDbForEnv({
      app, env, runtimeEnvVars, claimedKeys: decryptFailures, manifestNeeds: releaseDb.needs,
      isRestart: true,
      image,
      appendLog: (line) => log.info(`Restart ${containerName}: ${line}`),
    });
    dbCertMounts = mdbEnv.mounts || [];
    dbScope = mdbEnv.separateSandbox ? SANDBOX_TENANT : '';
    if (mdbEnv.injected.length) {
      // Key names only. The values include a database password.
      log.info(`Restart ${containerName}: injected managed ${mdbEnv.engine} database var(s): ${mdbEnv.injected.join(', ')}`);
    }
    if (mdbEnv.deferred.length) {
      log.info(`Restart ${containerName}: kept the app's own value for ${mdbEnv.deferred.join(', ')} over the managed ${mdbEnv.engine} credential`);
    }
  }
  const cranePort = process.env.PORT || 5001;
  const craneUrl = process.env.CRANE_DOMAIN ? `https://${process.env.CRANE_DOMAIN}` : `http://localhost:${cranePort}`;
  // APP_BASE_PATH is intentionally NOT set at runtime — see deployer.js and
  // bugs/2026-04-26-appcrane-app-base-path-resolution.md
  Object.assign(runtimeEnvVars, {
    CRANE_URL: craneUrl,
    CRANE_INTERNAL_URL: `http://localhost:${cranePort}`,
    DATA_DIR: '/data',
  });

  // v2.8.3: email service is available to every app — inject the token
  // (provisioning on first need) + host-gateway URL so the container can reach
  // AppCrane's internal email API.
  {
    const { getServiceTokenPlaintext, issueServiceToken } = await import('../services/appServiceToken.js');
    const token = getServiceTokenPlaintext(app) || issueServiceToken(app.id);
    runtimeEnvVars.APPCRANE_SERVICE_TOKEN = token;
    runtimeEnvVars.CRANE_INTERNAL_URL = `http://host.docker.internal:${cranePort}`;
  }

  Object.assign(runtimeEnvVars, carried);
  Object.assign(runtimeEnvVars, (await import('../services/llmGateway/env.js')).llmGatewayEnv(app, env));
  Object.assign(runtimeEnvVars, (await import('../services/aiAct/transparency.js')).aiNoticeEnv(getDb(), app));

  // v2.97.0: the identity-signing secret, for THIS environment, exactly as the
  // deploy path injects it. Restart rebuilds the whole environment, so leaving
  // it out here would silently turn signature checking off in a restarted app.
  {
    const { identitySecretFor } = await import('../services/identitySignature.js');
    runtimeEnvVars.APPCRANE_IDENTITY_SECRET = identitySecretFor(db, app.id, env);
  }

  const dataDir = resolve(process.env.DATA_DIR || './data');
  const sharedDir = resolve(join(dataDir, 'apps', app.slug, env, 'shared'));
  const bePort = env === 'production' ? ports.prod_be : ports.sand_be;

  // Parse resource limits the same way the deployer does
  let limits = { max_ram_mb: 512, max_cpu_percent: 50 };
  try {
    const parsed = JSON.parse(app.resource_limits || '{}');
    limits = {
      max_ram_mb: Number(parsed.max_ram_mb) || 512,
      max_cpu_percent: Number(parsed.max_cpu_percent) || 50,
    };
  } catch (_) {}

  // Recreate: stop + start with fresh env
  const { startApp: dockerStart, stopApp: dockerStop } = await import('../services/docker.js');
  // v2.70.0: the same mounts and command the deploy path resolves. Restarting
  // with the hardcoded single /data mount and no command silently un-did both:
  // an app with a declared volume came back with an empty directory where its
  // state had been, and an app that needs a command came back exiting 0 — from
  // an action whose entire contract is "same app, fresh env vars".
  const { mounts: containerVolumes } =
    resolveVolumeMounts({ sharedDir, paths: parseVolumePaths(app.volume_paths) });
  for (const vol of containerVolumes) if (!vol.base) mkdirSync(vol.host, { recursive: true });
  // A declared volume's directory is created (and, if still empty, seeded) in a
  // throwaway container, never by a host mkdir through a path the app can
  // redirect with a link (volumeHelper.js).
  const declaredVolumes = containerVolumes.filter((vol) => vol.base);
  if (declaredVolumes.length) {
    const { seedNewVolumeMounts } = await import('../services/volumeSeeder.js');
    await seedNewVolumeMounts({ image, volumes: declaredVolumes });
  }
  // Verified before the stop too: an untrusted image under enforce is refused
  // with the running container left alone.
  await (await import('../services/imageTrust/verify.js')).enforceImageTrust({ slug: app.slug, env, image, what: 'restart' });
  // Admitted before the stop: a refusal leaves the running container alone.
  const { admitAppStart } = await import('../services/deployer.js');
  await admitAppStart({ app, env, userId: systemActor ? null : actor?.id ?? null, automatic: systemActor, what: 'restart' });
  if (systemActor) {
    const g = {
      restoreInProgress: (await import('./managedDbRestoreGuard.js')).restoreInProgress,
      deployInFlight: (await import('./envSleeper.js')).deployInFlight,
      envIsSleepingById: (await import('./envSleepState.js')).envIsSleepingById,
      opInFlight: (await import('./envWake.js')).opInFlight,
    };
    const pre = precheck ? await precheck() : null;
    const current = db.prepare('SELECT id, slug FROM apps WHERE id = ?').get(app.id);
    const busy = pre || (!current || current.slug !== app.slug ? 'the app was renamed or deleted' : busyNow(g, db, app, env));
    if (busy) throw new AppError(`Not recreated: ${busy}. The running container was left alone.`, 409, 'RECREATE_SKIPPED');
  }
  onStop?.();
  await dockerStop(app.slug, env).catch(() => {});
  await dockerStart({
    admission: false,
    slug: app.slug,
    env,
    image,
    hostPort: bePort,
    containerPort: app.container_port,
    command: parseContainerCommand(app.container_command),
    envVars: runtimeEnvVars,
    volumes: [...containerVolumes, ...dbCertMounts],
    memoryMb: limits.max_ram_mb,
    cpus: limits.max_cpu_percent / 100,
    addHostGateway: true,
    dbScope,
  });

  return {
    message: `Restarted ${app.slug} ${env} with updated env vars`,
    image,
    injected_keys: Object.keys(runtimeEnvVars),
    decrypt_failures: decryptFailures,
  };
}
