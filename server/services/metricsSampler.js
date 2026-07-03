/**
 * v2.21.8: periodic resource sampler. Every SAMPLE_MS it reads live CPU/mem
 * for each running app+env from Docker and appends a row to metrics_history,
 * then prunes anything older than RETAIN_DAYS. This is what backs the per-app
 * CPU/memory charts in Manage — metricsCollector only ever gave a snapshot.
 *
 * Only online containers are recorded; a stopped env simply leaves a gap in
 * the series (which reads correctly as "not running" on the chart).
 */
import { getDb } from '../db.js';
import { getProcessMetrics } from './docker.js';
import log from '../utils/logger.js';

const SAMPLE_MS = 5 * 60 * 1000; // every 5 minutes
const RETAIN_DAYS = 7;
let _timer = null;

async function tick() {
  try {
    const db = getDb();
    const apps = db.prepare('SELECT id, slug FROM apps').all();
    const ins = db.prepare(
      'INSERT INTO metrics_history (app_id, env, cpu_percent, mem_mb) VALUES (?, ?, ?, ?)'
    );
    for (const app of apps) {
      for (const env of ['production', 'sandbox']) {
        try {
          const m = await getProcessMetrics(app.slug, env);
          if (m && m.status === 'online') {
            ins.run(app.id, env, m.cpu || 0, m.memory || 0);
          }
        } catch (_) { /* container gone / docker hiccup — skip this sample */ }
      }
    }
    db.prepare(`DELETE FROM metrics_history WHERE recorded_at < datetime('now', '-${RETAIN_DAYS} days')`).run();
  } catch (e) {
    log.warn(`[metrics-sampler] tick failed: ${e.message}`);
  }
}

export function startMetricsSampler() {
  if (_timer) return;
  tick();
  _timer = setInterval(() => { tick().catch(() => {}); }, SAMPLE_MS);
  log.info(`[metrics-sampler] started (every ${SAMPLE_MS / 60000} min, ${RETAIN_DAYS}-day retention)`);
}
