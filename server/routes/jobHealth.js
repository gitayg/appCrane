import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { getJobHealth, trackJob, isJobRunning, enableJobHealthAlerts, JOBS } from '../services/jobHealth.js';
import { AppError } from '../utils/errors.js';
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

export default router;
