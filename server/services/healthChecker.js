import { getDb } from '../db.js';
import { getPortsForSlot } from './portAllocator.js';
import log from '../utils/logger.js';

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
 * Run a single health check.
 */
async function runCheck(config) {
  const db = getDb();
  const ports = getPortsForSlot(config.slot);
  const port = config.env === 'production' ? ports.prod_be : ports.sand_be;
  const url = `http://localhost:${port}${config.endpoint}`;

  const start = Date.now();
  let status = 0;
  let responseMs = 0;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    status = response.status;
    responseMs = Date.now() - start;
  } catch (e) {
    responseMs = Date.now() - start;
    status = 0;
  }

  // Get current state
  const state = db.prepare('SELECT * FROM health_state WHERE app_id = ? AND env = ?')
    .get(config.app_id, config.env);

  if (!state) return;

  const wasDown = state.is_down;
  const prevFails = state.consecutive_fails;

  if (status === 200) {
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
