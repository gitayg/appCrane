import net from 'net';
import { getDb } from '../db.js';
import { getPortsForSlot } from './portAllocator.js';
import { getIngressForApp } from './tcpIngress.js';
import log from '../utils/logger.js';

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
