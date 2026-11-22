/**
 * v2.21.8: periodic resource sampler. Every SAMPLE_MS it reads live CPU/mem
 * for each running app+env from Docker and appends a row to metrics_history,
 * then prunes anything older than RETAIN_DAYS. This is what backs the per-app
 * CPU/memory charts in Manage — metricsCollector only ever gave a snapshot.
 *
 * Only online containers are recorded; a stopped env simply leaves a gap in
 * the series (which reads correctly as "not running" on the chart).
 *
 * One tick is one `docker stats` for every running container plus the shared
 * ps + inspect snapshot (dockerSnapshot.js), whatever the number of apps: an
 * inspect and a stats per app-env took ~1 s each and ~35 s per tick on a host
 * of 33 containers.
 */
import { getDb } from '../db.js';
import { runningContainers, statsAll } from './dockerSnapshot.js';
import { parseMemUsage } from './memoryAdmission.js';
import log from '../utils/logger.js';
import { jobStarted, trackJob, noteJobFailure } from './jobHealth.js';

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
    let running = null;
    let stats = null;
    try {
      running = new Set((await runningContainers()).filter((c) => c.status === 'running').map((c) => c.name));
      if (running.size) stats = await statsAll();
    } catch (e) { log.debug(`[metrics-sampler] docker did not answer: ${e.message}`); /* skip this sample */ }
    for (const app of apps) {
      for (const env of ['production', 'sandbox']) {
        const name = `appcrane-${app.slug}-${env}`;
        const s = running?.has(name) ? stats?.get(name) : null;
        if (!s) continue;
        ins.run(app.id, env, parseFloat(s.cpuPerc.replace('%', '')) || 0, parseMemUsage(s.memUsage) ?? 0);
      }
    }
    db.prepare(`DELETE FROM metrics_history WHERE recorded_at < datetime('now', '-${RETAIN_DAYS} days')`).run();
  } catch (e) {
    log.warn(`[metrics-sampler] tick failed: ${e.message}`);
    noteJobFailure('metrics-sampler', e);
  }
}

export function startMetricsSampler() {
  if (_timer) return;
  jobStarted('metrics-sampler');
  trackJob('metrics-sampler', tick).catch(() => {});
  _timer = setInterval(() => { trackJob('metrics-sampler', tick).catch(() => {}); }, SAMPLE_MS);
  log.info(`[metrics-sampler] started (every ${SAMPLE_MS / 60000} min, ${RETAIN_DAYS}-day retention)`);
}
export { tick as sampleMetricsOnce };
