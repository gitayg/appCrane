import net from 'net';
import { execFile } from 'child_process';
import { existsSync } from 'fs';
import { join, resolve } from 'path';
import { promisify } from 'util';
import { getDb } from '../db.js';
import { getPortsForSlot } from './portAllocator.js';
import { getIngressForApp } from './tcpIngress.js';
import log from '../utils/logger.js';

const execFileAsync = promisify(execFile);

const PROBE_TIMEOUT_MS = 5000;

/**
 * A successful probe records status 200 whatever the protocol was.
 *
 * A TCP handshake has no status code, but `runCheck` and every reader of
 * `health_state.last_status` — the dashboard, the CPU/health panel, the
 * auto-restart threshold — already treat 200 as "healthy" and anything else as
 * a failure. Inventing a different success value would render as DOWN
 * everywhere, so the protocols share one sentinel.
 */
const HEALTHY = 200;

let checkIntervals = new Map();

// ── Disk-quota detection (v2.44.0) ───────────────────────────────────────────
//
// The tenant quota deployer.js injects as APPCRANE_TENANT_QUOTA_BYTES is
// ADVISORY: /data is a plain bind mount with no --storage-opt and no project
// quota, so the number only binds an app that chooses to honour it. Nothing
// stops an app from filling a shared host filesystem and taking every other app
// on the box down with it — a whole-platform outage caused by one app's bug.
//
// Enforcement is not something this file can do (see the note below on what it
// would take). Detection is: measure what each app's /data actually holds and
// tell a human before the disk runs out, rather than after.
//
// Interval: 15 minutes, on its own timer rather than folded into runCheck().
// The liveness probes run every 30s per app-env and a directory walk is orders
// of magnitude more expensive than a socket connect; disk usage is also a
// slow-moving quantity, so probing it 30x more often buys nothing and would
// make the health checker the heaviest thing on the box.
const DISK_CHECK_MS = 15 * 60_000;

// Re-alert at most daily per app-env while it stays over. The first crossing is
// the signal; repeating it every 15 minutes for a week turns the alert into
// something people filter, which is the failure mode this whole item is about.
// Held in memory on purpose: a restart re-alerts, and re-stating an unresolved
// over-quota condition after a restart is correct behaviour, not noise.
const DISK_ALERT_COOLDOWN_MS = 24 * 60 * 60_000;

// Platform-wide default budget per app-env, overridable with the
// `app_disk_quota_mb` setting. Chosen as a detection threshold, not a
// contract — apps on this platform are web services with a SQLite file and
// uploads, so a 2 GB /data is already unusual enough to be worth a look.
const DEFAULT_APP_QUOTA_MB = 2048;

let diskTimer = null;
const diskAlertedAt = new Map();

/**
 * Bytes held under `dir`, or null if it cannot be measured.
 *
 * `du -sk` rather than a JS walk: the case being detected is a directory with
 * an enormous number of files, which is exactly where a per-entry readdir/stat
 * loop in the event loop gets slow enough to matter.
 *
 * A non-zero exit is not treated as failure on its own. du exits 1 when it
 * cannot descend into a subdirectory — routine now that containers run
 * non-root and write their own trees — but still prints the total for
 * everything it did read. An undercount is a usable lower bound; discarding it
 * would blind the check on precisely the busiest apps.
 */
async function measureDirBytes(dir) {
  try {
    const { stdout } = await execFileAsync('du', ['-sk', dir], { timeout: 120_000, maxBuffer: 1 << 20 });
    const kb = parseInt(String(stdout).trim().split(/\s+/)[0], 10);
    return Number.isFinite(kb) ? kb * 1024 : null;
  } catch (e) {
    const kb = parseInt(String(e.stdout || '').trim().split(/\s+/)[0], 10);
    if (Number.isFinite(kb)) return kb * 1024;
    log.warn(`[disk-quota] could not measure ${dir}: ${e.message}`);
    return null;
  }
}

/**
 * Measure every app's mounted /data and alert on anything over quota.
 *
 * WHAT THIS DOES NOT DO: it does not stop the write. Real enforcement needs the
 * filesystem in the loop — an XFS project quota on the app's data subtree, or a
 * per-app loopback image mounted at /data (or a Docker volume created with
 * --storage-opt size=, which needs a quota-capable backing filesystem). All
 * three are host-provisioning decisions and belong in deployer.js and the
 * install path, not here. Until one of them lands, an app over budget is
 * something a human is told about, not something the kernel refuses.
 */
async function runDiskChecks() {
  const db = getDb();
  const configured = Number(
    db.prepare("SELECT value FROM settings WHERE key = 'app_disk_quota_mb'").get()?.value
  );
  const quotaBytes = (Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_APP_QUOTA_MB) * 1024 * 1024;

  const dataDir = resolve(process.env.DATA_DIR || './data');
  const apps = db.prepare('SELECT id, name, slug FROM apps').all();

  for (const app of apps) {
    for (const env of ['production', 'sandbox']) {
      // Mirrors deployer.js: the container's /data is this host directory.
      const dir = resolve(join(dataDir, 'apps', app.slug, env, 'shared', 'data'));
      if (!existsSync(dir)) continue;

      const used = await measureDirBytes(dir);
      const key = `${app.id}-${env}`;

      if (used == null || used <= quotaBytes) {
        // Clear the cooldown once back under, so the next crossing alerts again
        // instead of being swallowed by a stale 24h suppression.
        diskAlertedAt.delete(key);
        continue;
      }

      log.error(`[disk-quota] ${app.slug} ${env} is over budget: ${Math.round(used / 1024 / 1024)} MB used of ${Math.round(quotaBytes / 1024 / 1024)} MB`);

      const lastAlert = diskAlertedAt.get(key) || 0;
      if (Date.now() - lastAlert < DISK_ALERT_COOLDOWN_MS) continue;
      diskAlertedAt.set(key, Date.now());

      try {
        const { logAudit } = await import('../middleware/audit.js');
        logAudit(null, app.id, 'disk-quota-exceeded', { env, used_bytes: used, quota_bytes: quotaBytes });
      } catch (e) {
        log.warn(`[disk-quota] audit write failed for ${app.slug}: ${e.message}`);
      }

      try {
        const { notifyDiskQuota } = await import('./emailService.js');
        await notifyDiskQuota(app, env, used, quotaBytes);
      } catch (e) {
        log.error(`[disk-quota] alert for ${app.slug} ${env} failed to send: ${e.message}`);
      }
    }
  }
}

/**
 * Start health checking for all apps.
 */
export function startHealthChecker() {
  const db = getDb();
  const configs = db.prepare(`
    SELECT hc.*, a.slug, a.slot FROM health_configs hc
    JOIN apps a ON a.id = hc.app_id
    WHERE hc.enabled = 1
  `).all();

  for (const config of configs) {
    scheduleCheck(config);
  }

  // Deliberately no immediate first run: boot is the busiest moment on the box
  // and an over-quota disk is not a condition that changes in 15 minutes.
  if (!diskTimer) {
    diskTimer = setInterval(() => {
      runDiskChecks().catch(e => log.error(`[disk-quota] sweep failed: ${e.message}`));
    }, DISK_CHECK_MS);
  }

  log.info(`Health checker started for ${configs.length} endpoints`);
}

/**
 * Schedule periodic health check for one app/env.
 */
function scheduleCheck(config) {
  const key = `${config.app_id}-${config.env}`;

  // Clear existing interval
  if (checkIntervals.has(key)) {
    clearInterval(checkIntervals.get(key));
  }

  const intervalMs = (config.interval_sec || 30) * 1000;

  const interval = setInterval(() => {
    runCheck(config).catch(e => log.error(`Health check error: ${e.message}`));
  }, intervalMs);

  checkIntervals.set(key, interval);
}

/**
 * HTTP probe: healthy means the endpoint answered 200.
 */
async function probeHttp(url) {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);

    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    return { status: response.status, responseMs: Date.now() - start };
  } catch (e) {
    // v2.6.10: surface the underlying cause. Node's fetch wraps the
    // real error as `cause`; without unwrapping it we lost "bad port"
    // (WHATWG block list), "ECONNREFUSED" vs "ETIMEDOUT", etc. — every
    // failure looked like a generic "fetch failed" and operators chased
    // wrong hypotheses for hours (castle / slot 23 → port 4045 = NFS
    // lockd, blocked by undici). Logged at WARN since healthy apps
    // would generate noise — only fires on failure.
    const cause = e?.cause?.message || e?.cause?.code || e?.message || String(e);
    return { status: 0, responseMs: Date.now() - start, error: cause };
  }
}

/**
 * TCP probe: healthy means the container completed a TCP handshake.
 *
 * A tcp app is on the platform precisely because it does not speak HTTP — a
 * CONNECT proxy cannot answer a GET /api/health, so fetch() would fail every
 * time, trip the auto-restart threshold, and leave the app in a permanent
 * restart loop. "The listener accepted a connection" is the strongest liveness
 * signal available without knowing the app's protocol.
 *
 * Same v2.6.10 lesson as the HTTP path: report the errno, not "probe failed".
 * ECONNREFUSED (container exited or never bound), ETIMEDOUT (bound but wedged)
 * and EHOSTUNREACH send an operator down completely different paths, and a
 * probe that only said "down" is the silent failure that comment exists to
 * prevent.
 */
function probeTcp(host, port) {
  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;
    const socket = net.createConnection({ host, port });

    const done = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ ...result, responseMs: Date.now() - start });
    };

    socket.setTimeout(PROBE_TIMEOUT_MS);
    socket.once('connect', () => done({ status: HEALTHY }));
    socket.once('timeout', () => done({ status: 0, error: `ETIMEDOUT (no TCP handshake within ${PROBE_TIMEOUT_MS}ms)` }));
    socket.once('error', (e) => done({ status: 0, error: e.code || e.message }));
  });
}

/**
 * Run a single health check.
 */
async function runCheck(config) {
  const db = getDb();
  const ports = getPortsForSlot(config.slot);
  const port = config.env === 'production' ? ports.prod_be : ports.sand_be;

  // Read the ingress type fresh on every probe instead of from `config`:
  // scheduleCheck() closes over the row it was created with, so an app flipped
  // to tcp would keep getting HTTP probes — and failing them into a restart
  // loop — until the process restarted.
  //
  // v2.45.0: 'dual' takes the HTTP branch on purpose. Both branches probe the
  // SAME loopback port — the choice is only handshake vs HTTP — and a handshake
  // is strictly the weaker of the two: it proves a socket is bound and nothing
  // else. That is all a pure-tcp app can offer. A dual app has a real HTTP
  // control plane on this port, so giving it the handshake would be a pure
  // downgrade: measured, a listener that accepts connections and never answers
  // reads HEALTHY under the tcp branch and DOWN under the http one, so a wedged
  // control plane — the plane Caddy actually serves users from — would look fine
  // and never reach the auto-restart below. So the condition is === 'tcp' and
  // must not be widened to !== 'http' when a publishing type is added:
  // publishing a raw port and being unable to speak HTTP are different facts,
  // and only the second one earns the weaker probe.
  const { ingress_type } = getIngressForApp(db, config.app_id);
  const isTcp = ingress_type === 'tcp';

  // Both protocols probe the LOOPBACK port every container publishes, never
  // the public one. The probe must work before the operator opens the
  // firewall, and must not depend on a public_port allocation existing.
  const target = isTcp
    ? `tcp://127.0.0.1:${port}`
    : `http://localhost:${port}${config.endpoint}`;

  const probe = isTcp
    ? await probeTcp('127.0.0.1', port)
    : await probeHttp(target);

  const { status, responseMs } = probe;
  if (probe.error) {
    log.warn(`[health-probe] ${config.slug} ${config.env} ${target}: ${probe.error}`);
  }

  // Get current state
  const state = db.prepare('SELECT * FROM health_state WHERE app_id = ? AND env = ?')
    .get(config.app_id, config.env);

  if (!state) return;

  const wasDown = state.is_down;
  const prevFails = state.consecutive_fails;

  if (status === HEALTHY) {
    // Healthy
    db.prepare(`
      UPDATE health_state SET consecutive_fails = 0, last_check_at = datetime('now'),
        last_status = ?, last_response_ms = ?, is_down = 0
      WHERE app_id = ? AND env = ?
    `).run(status, responseMs, config.app_id, config.env);

    // Recovery notification
    if (wasDown) {
      log.info(`[RECOVERY] ${config.slug} ${config.env} is back up`);
      try {
        const { notifyHealthChange } = await import('./emailService.js');
        notifyHealthChange(config.app_id, config.env, 'recovered');
      } catch (e) {}
    }
  } else {
    // Failed
    const newFails = prevFails + 1;
    const isNowDown = newFails >= config.down_threshold;

    db.prepare(`
      UPDATE health_state SET consecutive_fails = ?, last_check_at = datetime('now'),
        last_status = ?, last_response_ms = ?, is_down = ?
      WHERE app_id = ? AND env = ?
    `).run(newFails, status, responseMs, isNowDown ? 1 : 0, config.app_id, config.env);

    // Auto-restart at fail threshold
    if (newFails === config.fail_threshold) {
      log.warn(`[AUTO-RESTART] ${config.slug} ${config.env} (${newFails} consecutive failures)`);
      try {
        const { restartApp } = await import('./docker.js');
        await restartApp(config.slug, config.env);

        const { logAudit } = await import('../middleware/audit.js');
        logAudit(null, config.app_id, 'health-restart', { env: config.env, consecutive_fails: newFails });
      } catch (e) {
        log.error(`Auto-restart failed for ${config.slug}: ${e.message}`);
      }
    }

    // Down notification
    if (isNowDown && !wasDown) {
      log.error(`[DOWN] ${config.slug} ${config.env} is DOWN (${newFails} failures)`);
      try {
        const { notifyHealthChange } = await import('./emailService.js');
        notifyHealthChange(config.app_id, config.env, 'down');
      } catch (e) {}
    }
  }
}

/**
 * Stop all health checks.
 */
export function stopHealthChecker() {
  for (const [key, interval] of checkIntervals) {
    clearInterval(interval);
  }
  checkIntervals.clear();
  if (diskTimer) { clearInterval(diskTimer); diskTimer = null; }
  log.info('Health checker stopped');
}

/**
 * Refresh checks for a specific app (after config change).
 */
export function refreshAppChecks(appId) {
  const db = getDb();
  const configs = db.prepare(`
    SELECT hc.*, a.slug, a.slot FROM health_configs hc
    JOIN apps a ON a.id = hc.app_id
    WHERE hc.app_id = ? AND hc.enabled = 1
  `).all(appId);

  for (const config of configs) {
    scheduleCheck(config);
  }
}
