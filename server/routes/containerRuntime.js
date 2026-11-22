import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { roleForUserOnApp } from '../services/permissions.js';
import {
  platformDefault, setPlatformDefault, hostRuntimes, exceptions, effectiveRuntime, setAppOverride, runtimeStatus,
} from '../services/containerRuntime.js';

// Container runtime policy (services/containerRuntime.js).
// adminRouter  /api/container-runtime/settings   platform default + what the
//                                                host's dockerd offers
//                                                (platform admin)
// appRouter    /api/apps/:slug/runtime           this app's runtime per env;
//                                                PUT sets or clears the app
//                                                override (owner / app admin
//                                                may only raise isolation;
//                                                lowering is platform admin)

const TAKES_EFFECT = 'at the next deploy or restart (container recreate) of each app environment';

export const adminRouter = Router();

async function settingsView() {
  return { default: platformDefault(), host: await hostRuntimes(), exceptions: exceptions(), takes_effect: TAKES_EFFECT };
}

adminRouter.get('/settings', requireAuth, requirePlatformAdmin, async (req, res) => {
  res.json(await settingsView());
});

adminRouter.put('/settings', requireAuth, requirePlatformAdmin, async (req, res) => {
  await setPlatformDefault(req.body?.default, req.user);
  res.json(await settingsView());
});

export const appRouter = Router();

function requireRuntimeEditor(req, _res, next) {
  if (req.user.role === 'platform_admin') return next();
  const tier = roleForUserOnApp(req.user, req.app);
  if (tier !== 'owner' && tier !== 'admin') return next(new AppError('Only an owner or admin of this app can change its container runtime.', 403, 'FORBIDDEN'));
  next();
}

async function appView(app) {
  const eff = effectiveRuntime(app);
  const envs = {};
  for (const env of ['production', 'sandbox']) envs[env] = await runtimeStatus(app, `appcrane-${app.slug}-${env}`);
  return { ...eff, envs, takes_effect: TAKES_EFFECT };
}

appRouter.get('/:slug/runtime', requireAuth, requireAppAccess, async (req, res) => {
  res.json(await appView(req.app));
});

appRouter.put('/:slug/runtime', requireAuth, requireAppAccess, requireRuntimeEditor, async (req, res) => {
  const body = req.body || {};
  if (!('runtime' in body)) throw new AppError('runtime is required: "runc", "runsc", or null for the platform default', 400, 'VALIDATION');
  await setAppOverride(req.app, body.runtime, req.user, { isPlatformAdmin: req.user.role === 'platform_admin', reason: body.reason });
  res.json({ ...(await appView(req.app)), redeploy_needed: true });
});
