import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { getJobHealth, trackJob, isJobRunning, enableJobHealthAlerts, JOBS } from '../services/jobHealth.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { getAdmissionSettings, measureMemory, MODES, MODE_KEY, RESERVE_KEY, toMb } from '../services/memoryAdmission.js';
import { getLastHostSample, getThresholds, THRESHOLD_DEFAULTS } from '../services/hostResources.js';
import { getCpuAdmissionSettings, measureCpu, containersWithoutWeight, CPU_MODES, CPU_MODE_KEY, CPU_RESERVE_KEY } from '../services/cpuAdmission.js';
import { getHostCpuPriority, readBuildCapStatus } from '../services/cpuPriority.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';

enableJobHealthAlerts();

const router = Router();

// Jobs whose run is already exposed as a single exported function that is safe
// to call on demand. Every other job is display-only.
const RUN_NOW = {
  'credential-check': async () => (await import('../services/credentialChecker.js')).runCredentialCheckOnce(),
  'local-backup': async () => (await import('../services/localBackup.js')).runLocalBackup(),
};

// GET /api/settings/* is public at the global gate (settings reads classify
// themselves), so this route carries its own auth.
router.get('/job-health', requireAuth, requirePlatformAdmin, (req, res) => {
  const jobs = getJobHealth().map(j => ({ ...j, can_run_now: !!RUN_NOW[j.id] }));
  res.json({ jobs, generated_at: new Date().toISOString() });
});

router.post('/job-health/:id/run', requireAuth, requirePlatformAdmin, (req, res, next) => {
  const { id } = req.params;
  if (!JOBS[id]) return next(new AppError('Unknown job', 404, 'NOT_FOUND'));
  const run = RUN_NOW[id];
  if (!run) return next(new AppError('This job cannot be run on demand', 400, 'NOT_RUNNABLE'));
  if (isJobRunning(id)) return next(new AppError('This job is already running', 409, 'ALREADY_RUNNING'));
  trackJob(id, run).catch(e => log.warn(`[job-health] run-now ${id} failed: ${e.message}`));
  res.status(202).json({ started: true, id });
});

// Memory committed vs capacity, the admission settings and the last host
// sample (Settings > Job Health).
router.get('/server-capacity', requireAuth, requirePlatformAdmin, async (req, res) => {
  const db = getDb();
  const m = await measureMemory({ fresh: req.query.fresh === '1', db });
  const c = await measureCpu({ fresh: req.query.fresh === '1', db });
  const round = (n) => Math.round(n * 100) / 100;
  res.json({
    settings: { ...getAdmissionSettings(db), cpu: getCpuAdmissionSettings(db), thresholds: getThresholds(db), threshold_defaults: THRESHOLD_DEFAULTS },
    cpu: {
      cores: c.cores, cores_source: c.coresSource, reserve_cores: round(c.reserveCores), reserve_source: c.reserveSource,
      capacity_cores: round(c.capacityCores), committed_cores: round(c.committedCores), error: c.error, measured_at: c.measuredAt,
      uncapped: c.containers.filter((x) => x.uncapped).map((x) => x.label).slice(0, 15),
      unweighted: containersWithoutWeight(c).map((x) => x.label).slice(0, 15),
      host_priority: getHostCpuPriority(),
      builds: await readBuildCapStatus(),
    },
    memory: {
      total_mb: toMb(m.totalBytes), total_source: m.totalSource,
      reserve_mb: toMb(m.reserveBytes), reserve_source: m.reserveSource,
      capacity_mb: toMb(m.capacityBytes), committed_mb: toMb(m.committedBytes),
      error: m.error, measured_at: m.measuredAt,
      containers: [...m.containers].sort((a, b) => b.countedBytes - a.countedBytes).slice(0, 15).map((c) => ({
        name: c.name, label: c.label, kind: c.kind,
        cap_mb: c.unlimited ? null : toMb(c.capBytes), counted_mb: toMb(c.countedBytes), counted_from: c.countedFrom,
      })),
    },
    host: getLastHostSample(),
  });
});

router.put('/server-capacity', requireAuth, requirePlatformAdmin, (req, res, next) => {
  const body = req.body || {};
  const writes = [];
  if (body.mode !== undefined) {
    if (!MODES.includes(body.mode)) return next(new AppError(`mode must be one of ${MODES.join(', ')}`, 400, 'VALIDATION'));
    writes.push([MODE_KEY, body.mode]);
  }
  if (body.reserve_mb !== undefined) {
    if (body.reserve_mb === null || body.reserve_mb === '') writes.push([RESERVE_KEY, '']);
    else if (!Number.isInteger(body.reserve_mb) || body.reserve_mb < 0 || body.reserve_mb > 1048576) {
      return next(new AppError('reserve_mb must be a whole number of MB (0 to 1048576), or null for the default', 400, 'VALIDATION'));
    } else writes.push([RESERVE_KEY, String(body.reserve_mb)]);
  }
  if (body.cpu_mode !== undefined) {
    if (!CPU_MODES.includes(body.cpu_mode)) return next(new AppError(`cpu_mode must be one of ${CPU_MODES.join(', ')}`, 400, 'VALIDATION'));
    writes.push([CPU_MODE_KEY, body.cpu_mode]);
  }
  if (body.cpu_reserve_cores !== undefined) {
    if (body.cpu_reserve_cores === null || body.cpu_reserve_cores === '') writes.push([CPU_RESERVE_KEY, '']);
    else if (typeof body.cpu_reserve_cores !== 'number' || !Number.isFinite(body.cpu_reserve_cores) || body.cpu_reserve_cores < 0 || body.cpu_reserve_cores > 1024) {
      return next(new AppError('cpu_reserve_cores must be a number of cores (0 to 1024), or null for the default', 400, 'VALIDATION'));
    } else writes.push([CPU_RESERVE_KEY, String(body.cpu_reserve_cores)]);
  }
  for (const k of Object.keys(THRESHOLD_DEFAULTS)) {
    const v = body.thresholds?.[k];
    if (v === undefined) continue;
    if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || (k.endsWith('_pct') && v > 100)) {
      return next(new AppError(`thresholds.${k} must be a number of 0 or more${k.endsWith('_pct') ? ' and at most 100' : ''}`, 400, 'VALIDATION'));
    }
    writes.push([`host_alert_${k}`, String(v)]);
  }
  const db = getDb();
  const up = db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`);
  db.transaction(() => { for (const [k, v] of writes) up.run(k, v, req.user.id); })();
  try { logAudit(req.user.id, null, 'settings.server-capacity', Object.fromEntries(writes)); } catch (_) {}
  res.json({ settings: { ...getAdmissionSettings(db), cpu: getCpuAdmissionSettings(db), thresholds: getThresholds(db) } });
});

export default router;
