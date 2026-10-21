import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { roleForUserOnApp } from '../services/permissions.js';
import { gatewayHandler, ROUTES, providerError } from '../services/llmGateway/proxy.js';
import {
  getConfig, maskConfig, updateConfig, getAppSettings, setAppEnabled, setAppOverrides, effectiveLimits,
  providerReady, LlmConfigError, ENVS,
} from '../services/llmGateway/config.js';
import { usageSummary, spentSoFar } from '../services/llmGateway/usage.js';
import { gatewayBaseUrl } from '../services/llmGateway/env.js';

// LLM gateway for hosted apps (services/llmGateway/*).
//
// default export  /api/service/llm/*   the gateway itself: gateway-token auth,
//                                      internal-only, fixed path allowlist.
//                                      Mounted before the global JSON parser:
//                                      it parses with its own size limit.
// adminRouter     /api/llm-gateway/*   platform config and usage (platform admin)
// appRouter       /api/apps/:slug/llm-gateway[...]   per-app opt-in and usage

const service = Router();
for (const key of Object.keys(ROUTES)) {
  const [provider, path] = key.split(' ');
  service.post(`/${provider}${path}`, gatewayHandler(provider, path));
}
service.use((req, res) => {
  const provider = req.path.startsWith('/anthropic') ? 'anthropic' : 'openai';
  res.status(404).json(providerError(provider, 404, 'not_found_error', `${req.method} ${req.path} is not available through AppCrane's LLM gateway.`));
});
export default service;

// req.query reads req.app, which requireAppAccess replaces with the apps row.
function daysParam(req) {
  return new URL(req.originalUrl, 'http://local').searchParams.get('days');
}

function configError(e) {
  if (e instanceof LlmConfigError) throw new AppError(e.message, 400, 'VALIDATION');
  throw e;
}

export const adminRouter = Router();

adminRouter.get('/config', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ config: maskConfig(getConfig()), gateway_url: gatewayBaseUrl() });
});

adminRouter.put('/config', requireAuth, requirePlatformAdmin, auditMiddleware('llm-gateway-config'), (req, res) => {
  let cfg;
  try { cfg = updateConfig(req.body, req.user.id); } catch (e) { configError(e); }
  res.json({ config: maskConfig(cfg) });
});

adminRouter.get('/usage', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json(usageSummary({ days: daysParam(req) }));
});

adminRouter.get('/apps', requireAuth, requirePlatformAdmin, (req, res) => {
  const rows = getDb().prepare(`
    SELECT a.slug, a.name, g.enabled, g.overrides_json, g.updated_at
    FROM llm_gateway_apps g JOIN apps a ON a.id = g.app_id ORDER BY a.slug
  `).all();
  res.json({ apps: rows.map((r) => ({ slug: r.slug, name: r.name, enabled: !!r.enabled, overrides: JSON.parse(r.overrides_json || '{}'), updated_at: r.updated_at })) });
});

export const appRouter = Router();

function requireGatewayEditor(req, _res, next) {
  if (req.user.role === 'platform_admin') return next();
  const tier = roleForUserOnApp(req.user, req.app);
  if (tier !== 'owner' && tier !== 'admin') {
    return next(new AppError("Only an owner or admin of this app can see or change its LLM gateway setting.", 403, 'FORBIDDEN'));
  }
  next();
}

function appView(app) {
  const cfg = getConfig();
  const settings = getAppSettings(app.id);
  const envs = {};
  for (const env of ENVS) envs[env] = { limits: effectiveLimits(cfg, settings, env), spent: spentSoFar(app.id, env) };
  return {
    app: app.slug,
    enabled: settings.enabled,
    overrides: settings.overrides,
    providers: { anthropic: providerReady(cfg, 'anthropic'), openai: providerReady(cfg, 'openai') },
    envs,
  };
}

appRouter.get('/:slug/llm-gateway', requireAuth, requireAppAccess, requireGatewayEditor, (req, res) => {
  res.json(appView(req.app));
});

appRouter.put('/:slug/llm-gateway', requireAuth, requireAppAccess, requireGatewayEditor, auditMiddleware('llm-gateway-app'), (req, res) => {
  if (typeof req.body?.enabled !== 'boolean') throw new AppError('enabled must be true or false', 400, 'VALIDATION');
  setAppEnabled(req.app.id, req.body.enabled, req.user.id);
  res.json({ ...appView(req.app), redeploy_needed: true });
});

appRouter.put('/:slug/llm-gateway/overrides', requireAuth, requirePlatformAdmin, requireAppAccess, auditMiddleware('llm-gateway-app-overrides'), (req, res) => {
  try { setAppOverrides(req.app.id, req.body?.overrides ?? {}, req.user.id); } catch (e) { configError(e); }
  res.json(appView(req.app));
});

appRouter.get('/:slug/llm-gateway/usage', requireAuth, requireAppAccess, requireGatewayEditor, (req, res) => {
  res.json(usageSummary({ appId: req.app.id, days: daysParam(req) }));
});
