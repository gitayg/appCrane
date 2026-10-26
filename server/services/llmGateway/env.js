import { getDb } from '../../db.js';
import { getConfig, getAppSettings, providerReady, ENVS } from './config.js';
import { gatewayTokenPlaintext, issueGatewayToken } from './tokens.js';

export function gatewayBaseUrl() {
  return `http://host.docker.internal:${process.env.PORT || 5001}/api/service/llm`;
}

/**
 * Container env vars for an app that uses the gateway, for each provider the
 * platform has configured: the official SDKs' base-URL variable pointed at the
 * gateway and their API-key variable set to the app's gateway token. Returns {}
 * when the app has not opted in. Never returns a provider key.
 *
 * Callers assign the result after the app's own env vars, so it replaces an
 * ANTHROPIC_API_KEY / OPENAI_API_KEY the app set itself.
 */
export function llmGatewayEnv(app, env, db = getDb()) {
  if (!app?.id || !ENVS.includes(env)) return {};
  if (!getAppSettings(app.id, db).enabled) return {};
  const cfg = getConfig(db);
  const anthropic = providerReady(cfg, 'anthropic');
  const openai = providerReady(cfg, 'openai');
  if (!anthropic && !openai) return {};
  const token = gatewayTokenPlaintext(app.id, env, db) || issueGatewayToken(app.id, env, db);
  const base = gatewayBaseUrl();
  const out = { APPCRANE_LLM_GATEWAY_URL: base };
  if (anthropic) {
    out.ANTHROPIC_BASE_URL = `${base}/anthropic`;
    out.ANTHROPIC_API_KEY = token;
  }
  if (openai) {
    out.OPENAI_BASE_URL = `${base}/openai/v1`;
    out.OPENAI_API_KEY = token;
  }
  return out;
}
