import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { isAppOwnerOrPlatformAdmin } from '../services/permissions.js';
import { listIncidents, getStability, incidentCounts, lastIncident, loopSettings } from '../services/restartIncidents.js';

// Restart incidents (services/restartIncidents.js). Mounted at /api.
//
//   GET /api/apps/:slug/incidents?env=&limit=   anyone with access to the app
//
// Every member sees the summaries, memory figures and exit state. The log tail
// is container output, so it follows GET /api/:slug/logs/:env: the app owner or
// a platform admin only.

const router = Router();
const ENVS = ['production', 'sandbox'];
const DAY = 86_400_000;

router.get('/apps/:slug/incidents', requireAuth, requireAppAccess, (req, res) => {
  // Not req.query: requireAppAccess replaces req.app with the app row.
  const params = new URL(req.originalUrl, 'http://x').searchParams;
  const env = params.get('env');
  if (env != null && !ENVS.includes(env)) throw new AppError('env must be production or sandbox', 400, 'VALIDATION');
  const limit = Math.min(Math.max(parseInt(params.get('limit'), 10) || 50, 1), 200);
  const db = getDb();
  const withLogs = isAppOwnerOrPlatformAdmin(req.user, req.app);
  const envs = {};
  for (const e of env ? [env] : ENVS) {
    envs[e] = {
      ...getStability({ appId: req.app.id, env: e, db }),
      last_incident: lastIncident({ appId: req.app.id, env: e, db }),
      last_7_days: incidentCounts({ appId: req.app.id, env: e, sinceMs: Date.now() - 7 * DAY, db }),
    };
  }
  res.json({
    incidents: listIncidents({ appId: req.app.id, env, limit, withLogs, db }),
    envs,
    log_tail_visible: withLogs,
    rules: loopSettings(db),
  });
});

export default router;
