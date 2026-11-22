import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { isAppOwnerAdminOrPlatformAdmin } from '../services/permissions.js';
import {
  getPlatformPolicy, getAppPolicy, effectivePolicy, parsePolicyBody, setPlatformPolicy, setAppPolicy,
  sleepEnabledAnywhere, sleepBlockers, IDLE_MIN, IDLE_MAX, INACTIVE_MIN, INACTIVE_MAX, OUT_OF_WINDOW_IDLE_MIN,
} from '../services/sleepPolicy.js';
import { sleepRow } from '../services/envSleepState.js';
import { activityOf } from '../services/envActivity.js';

// Environment sleep settings (services/sleepPolicy.js) and state.
// Mounted at /api. Auth is per route: a pathless guard on /api would 401
// everything else mounted there.
//
//   GET  /api/apps/:slug/sleep            any member: the settings, the values in
//                                         effect, and each env's state
//   PUT  /api/apps/:slug/sleep            owner, app admin or platform admin
//   POST /api/apps/:slug/sleep/:env/wake  any member who can open the app anyway
//   GET  /api/sleep/defaults              platform admin
//   PUT  /api/sleep/defaults              platform admin

const router = Router();
const ENVS = ['sandbox', 'production'];
const LIMITS = { sandbox_idle_minutes: [IDLE_MIN, IDLE_MAX], inactive_days: [INACTIVE_MIN, INACTIVE_MAX], out_of_window_idle_minutes: OUT_OF_WINDOW_IDLE_MIN };

function requireSleepEditor(req, _res, next) {
  if (isAppOwnerAdminOrPlatformAdmin(req.user, req.app)) return next();
  next(new AppError('Only an owner or admin of this app can change when it sleeps.', 403, 'FORBIDDEN'));
}

async function reloadIfGateChanged(before) {
  if (sleepEnabledAnywhere(getDb()) === before) return;
  const { reloadCaddy } = await import('../services/caddy.js');
  await reloadCaddy().catch(() => {});
}

function view(db, app) {
  const envs = {};
  for (const env of ENVS) {
    const row = sleepRow(db, app.id, env);
    const act = activityOf(db, app.id, env);
    envs[env] = {
      state: row?.state || 'awake',
      reason: row?.reason || null,
      slept_at: row?.slept_at || null,
      woke_at: row?.woke_at || null,
      last_error: row?.last_error || null,
      last_request_at: act.lastRequestAt ? new Date(act.lastRequestAt).toISOString() : null,
      not_eligible: sleepBlockers(db, app, env),
    };
  }
  return {
    app: app.slug,
    override: getAppPolicy(db, app.id),
    platform: getPlatformPolicy(db),
    effective: effectivePolicy(db, app.id),
    envs,
    limits: LIMITS,
    can_edit: false,
  };
}

router.get('/apps/:slug/sleep', requireAuth, requireAppAccess, (req, res) => {
  const out = view(getDb(), req.app);
  out.can_edit = isAppOwnerAdminOrPlatformAdmin(req.user, req.app);
  res.json(out);
});

router.put('/apps/:slug/sleep', requireAuth, requireAppAccess, requireSleepEditor, auditMiddleware('sleep-settings-update'), async (req, res) => {
  const db = getDb();
  const values = parsePolicyBody(req.body || {}, { allowNull: true });
  const before = sleepEnabledAnywhere(db);
  setAppPolicy(db, req.app.id, values, req.user.id);
  await reloadIfGateChanged(before);
  const out = view(db, req.app);
  out.can_edit = true;
  res.json(out);
});

router.post('/apps/:slug/sleep/:env/wake', requireAuth, requireAppAccess, auditMiddleware('env-wake-request'), async (req, res) => {
  const env = req.params.env;
  if (!ENVS.includes(env)) throw new AppError('env must be sandbox or production', 400, 'VALIDATION');
  const { wakeEnv } = await import('../services/envWake.js');
  const r = await wakeEnv(req.app, env, { reason: 'manual', userId: req.user.id });
  if (!r.ok) throw new AppError(`Could not wake ${req.app.slug} (${env}): ${r.error}`, r.code === 'INSUFFICIENT_MEMORY' ? 409 : 500, r.code || 'WAKE_FAILED');
  res.json({ ok: true, already_awake: !!r.already, healthy: r.healthy ?? true, ms: r.ms ?? 0 });
});

router.get('/sleep/defaults', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ defaults: getPlatformPolicy(getDb()), limits: LIMITS });
});

router.put('/sleep/defaults', requireAuth, requirePlatformAdmin, auditMiddleware('sleep-defaults-update'), async (req, res) => {
  const db = getDb();
  const values = parsePolicyBody(req.body || {}, { allowNull: false });
  const before = sleepEnabledAnywhere(db);
  setPlatformPolicy(db, values, req.user.id);
  await reloadIfGateChanged(before);
  res.json({ defaults: getPlatformPolicy(db), limits: LIMITS });
});

export default router;
