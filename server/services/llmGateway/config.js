import { getDb } from '../../db.js';
import { encrypt, decrypt } from '../encryption.js';
import { secretPreview } from '../secretMask.js';

export const PROVIDERS = Object.freeze(['anthropic', 'openai']);
export const ENVS = Object.freeze(['production', 'sandbox']);
export const LIMIT_KEYS = Object.freeze([
  'requests_per_minute', 'requests_per_day', 'tokens_per_day', 'usd_per_month', 'max_tokens_per_request',
]);

const SETTINGS_KEY = 'llm_gateway';

export const DEFAULT_BASE_URLS = Object.freeze({
  anthropic: 'https://api.anthropic.com',
  openai: 'https://api.openai.com',
});

export const DEFAULT_MAX_BODY_KB = 8192;

export class LlmConfigError extends Error {}

function emptyConfig() {
  return {
    providers: {
      anthropic: { enabled: false, key_encrypted: null, base_url: DEFAULT_BASE_URLS.anthropic },
      openai: { enabled: false, key_encrypted: null, base_url: DEFAULT_BASE_URLS.openai, auth_header: 'bearer' },
    },
    private_hosts: [],
    allowed_models: { anthropic: [], openai: [] },
    model_map: { anthropic: {}, openai: {} },
    prices: {},
    limits: { max_body_kb: DEFAULT_MAX_BODY_KB },
    classification_models: {},
  };
}

function parseJson(raw, fallback) {
  try { const v = JSON.parse(raw); return v && typeof v === 'object' ? v : fallback; } catch { return fallback; }
}

/** The stored platform config, keys still encrypted. */
export function getConfig(db = getDb()) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(SETTINGS_KEY);
  const base = emptyConfig();
  if (!row?.value) return base;
  const stored = parseJson(row.value, {});
  for (const p of PROVIDERS) base.providers[p] = { ...base.providers[p], ...(stored.providers?.[p] || {}) };
  for (const k of ['private_hosts', 'prices', 'classification_models']) if (stored[k]) base[k] = stored[k];
  for (const k of ['allowed_models', 'model_map']) base[k] = { ...base[k], ...(stored[k] || {}) };
  base.limits = { ...base.limits, ...(stored.limits || {}) };
  return base;
}

/** The provider key in plaintext, for the outbound request only. Null when unset. */
export function providerKey(cfg, provider) {
  const enc = cfg.providers?.[provider]?.key_encrypted;
  if (!enc) return null;
  try { return decrypt(enc); } catch { return null; }
}

export function providerReady(cfg, provider) {
  return !!(cfg.providers?.[provider]?.enabled && cfg.providers[provider].key_encrypted);
}

/** What the admin API returns: every key reduced to "configured" plus a masked tail. */
export function maskConfig(cfg) {
  const out = JSON.parse(JSON.stringify(cfg));
  for (const p of PROVIDERS) {
    const plain = providerKey(cfg, p);
    delete out.providers[p].key_encrypted;
    out.providers[p].key_configured = !!plain;
    out.providers[p].key_preview = plain ? secretPreview(plain) : null;
  }
  return out;
}

function strList(v, label) {
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || v.some((s) => typeof s !== 'string' || !s.trim() || s.length > 200)) {
    throw new LlmConfigError(`${label} must be a list of non-empty strings`);
  }
  return [...new Set(v.map((s) => s.trim()))];
}

function strMap(v, label) {
  if (v === undefined) return undefined;
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new LlmConfigError(`${label} must be an object`);
  const out = {};
  for (const [k, val] of Object.entries(v)) {
    if (typeof val !== 'string' || !val.trim() || k.length > 200 || val.length > 200) throw new LlmConfigError(`${label}.${k} must be a model name`);
    out[k] = val.trim();
  }
  return out;
}

export function parseLimits(v, label = 'limits') {
  if (v === undefined) return undefined;
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new LlmConfigError(`${label} must be an object`);
  const out = {};
  for (const [k, val] of Object.entries(v)) {
    if (![...LIMIT_KEYS, 'max_body_kb'].includes(k)) throw new LlmConfigError(`${label}.${k} is not a known limit`);
    if (val === null || val === '') { out[k] = null; continue; }
    const n = Number(val);
    if (!Number.isFinite(n) || n < 0) throw new LlmConfigError(`${label}.${k} must be a number >= 0 (0 or empty = no limit)`);
    out[k] = n;
  }
  return out;
}

function parseBaseUrl(raw, provider) {
  if (raw === undefined) return undefined;
  if (raw === null || raw === '') return DEFAULT_BASE_URLS[provider];
  let u;
  try { u = new URL(String(raw)); } catch { throw new LlmConfigError(`${provider}.base_url is not a URL`); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new LlmConfigError(`${provider}.base_url must be http(s)`);
  if (u.username || u.password) throw new LlmConfigError(`${provider}.base_url must not carry credentials`);
  if (u.search || u.hash) throw new LlmConfigError(`${provider}.base_url must not carry a query or fragment`);
  return u.toString().replace(/\/+$/, '');
}

/**
 * Apply a patch from the admin API. A provider `api_key` replaces the stored
 * key; an empty string clears it; absent leaves it alone.
 */
export function updateConfig(patch, userId, db = getDb()) {
  if (!patch || typeof patch !== 'object') throw new LlmConfigError('Body must be an object');
  const cfg = getConfig(db);
  for (const p of PROVIDERS) {
    const pp = patch.providers?.[p];
    if (!pp) continue;
    if (pp.enabled !== undefined) cfg.providers[p].enabled = !!pp.enabled;
    if (pp.api_key !== undefined) {
      if (typeof pp.api_key !== 'string' || pp.api_key.length > 500) throw new LlmConfigError(`${p}.api_key must be a string`);
      cfg.providers[p].key_encrypted = pp.api_key.trim() ? encrypt(pp.api_key.trim()) : null;
    }
    const bu = parseBaseUrl(pp.base_url, p);
    if (bu !== undefined) cfg.providers[p].base_url = bu;
    if (p === 'openai' && pp.auth_header !== undefined) {
      if (!['bearer', 'api-key'].includes(pp.auth_header)) throw new LlmConfigError('openai.auth_header must be bearer or api-key');
      cfg.providers.openai.auth_header = pp.auth_header;
    }
  }
  const hosts = strList(patch.private_hosts, 'private_hosts');
  if (hosts) cfg.private_hosts = hosts.map((h) => h.toLowerCase());
  for (const p of PROVIDERS) {
    const am = strList(patch.allowed_models?.[p], `allowed_models.${p}`);
    if (am) cfg.allowed_models[p] = am;
    const mm = strMap(patch.model_map?.[p], `model_map.${p}`);
    if (mm) cfg.model_map[p] = mm;
  }
  if (patch.prices !== undefined) cfg.prices = parsePrices(patch.prices);
  const lim = parseLimits(patch.limits);
  if (lim) cfg.limits = { ...cfg.limits, ...lim };
  if (patch.classification_models !== undefined) {
    const cm = patch.classification_models;
    if (!cm || typeof cm !== 'object' || Array.isArray(cm)) throw new LlmConfigError('classification_models must be an object');
    const out = {};
    for (const [k, v] of Object.entries(cm)) out[k] = strList(v, `classification_models.${k}`);
    cfg.classification_models = out;
  }
  db.prepare(`
    INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by
  `).run(SETTINGS_KEY, JSON.stringify(cfg), userId ?? null);
  return cfg;
}

function parsePrices(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new LlmConfigError('prices must be an object of { model: { input, output } }');
  const out = {};
  for (const [model, p] of Object.entries(v)) {
    const input = Number(p?.input);
    const output = Number(p?.output);
    if (!Number.isFinite(input) || !Number.isFinite(output) || input < 0 || output < 0) {
      throw new LlmConfigError(`prices.${model} needs input and output in USD per million tokens`);
    }
    out[model] = { input, output };
  }
  return out;
}

// ── per app ───────────────────────────────────────────────────────────────

export function getAppSettings(appId, db = getDb()) {
  const row = db.prepare('SELECT enabled, overrides_json, updated_at FROM llm_gateway_apps WHERE app_id = ?').get(appId);
  return {
    enabled: !!row?.enabled,
    overrides: row ? parseJson(row.overrides_json, {}) : {},
    updated_at: row?.updated_at || null,
  };
}

export function setAppEnabled(appId, enabled, userId, db = getDb()) {
  db.prepare(`
    INSERT INTO llm_gateway_apps (app_id, enabled, updated_by) VALUES (?, ?, ?)
    ON CONFLICT(app_id) DO UPDATE SET enabled = excluded.enabled, updated_by = excluded.updated_by, updated_at = datetime('now')
  `).run(appId, enabled ? 1 : 0, userId ?? null);
}

/** Platform admin only: { allowed_models?, limits?, env_limits?: { production?, sandbox? } }. */
export function setAppOverrides(appId, raw, userId, db = getDb()) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new LlmConfigError('overrides must be an object');
  const out = {};
  if (raw.allowed_models !== undefined) {
    out.allowed_models = {};
    for (const p of PROVIDERS) {
      const l = strList(raw.allowed_models?.[p], `allowed_models.${p}`);
      if (l) out.allowed_models[p] = l;
    }
  }
  const lim = parseLimits(raw.limits);
  if (lim) out.limits = lim;
  if (raw.env_limits !== undefined) {
    out.env_limits = {};
    for (const e of ENVS) {
      const el = parseLimits(raw.env_limits?.[e], `env_limits.${e}`);
      if (el) out.env_limits[e] = el;
    }
  }
  db.prepare(`
    INSERT INTO llm_gateway_apps (app_id, overrides_json, updated_by) VALUES (?, ?, ?)
    ON CONFLICT(app_id) DO UPDATE SET overrides_json = excluded.overrides_json, updated_by = excluded.updated_by, updated_at = datetime('now')
  `).run(appId, JSON.stringify(out), userId ?? null);
  return out;
}

/** Limit k for this app and env: env override, then app override, then platform default. 0/null = none. */
export function effectiveLimits(cfg, appSettings, env) {
  const out = {};
  const o = appSettings.overrides || {};
  for (const k of [...LIMIT_KEYS, 'max_body_kb']) {
    const v = o.env_limits?.[env]?.[k] ?? o.limits?.[k] ?? cfg.limits?.[k] ?? null;
    out[k] = v ? Number(v) : null;
  }
  return out;
}

function matches(pattern, model) {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return model.startsWith(pattern.slice(0, -1));
  return pattern === model;
}

/**
 * Every allowlist that applies must admit the model: the platform's, the
 * app's override, and the one for the app's data classification. An empty or
 * absent list does not restrict.
 */
export function modelAllowed(cfg, appSettings, provider, model, classification = null) {
  const lists = [
    cfg.allowed_models?.[provider],
    appSettings.overrides?.allowed_models?.[provider],
    classification ? cfg.classification_models?.[classification] : null,
  ];
  for (const l of lists) {
    if (Array.isArray(l) && l.length && !l.some((p) => matches(p, model))) return false;
  }
  return true;
}

export function mapModel(cfg, provider, model) {
  const map = cfg.model_map?.[provider] || {};
  if (model && map[model]) return map[model];
  if (!model && map.default) return map.default;
  return model;
}

export function estimateCost(cfg, model, inputTokens, outputTokens) {
  const p = cfg.prices?.[model];
  if (!p) return null;
  return (inputTokens * p.input + outputTokens * p.output) / 1e6;
}

/**
 * The app's data classification, when the apps table carries one (another
 * change adds it). Absent column or value: null, and no classification list applies.
 */
export function appClassification(app, db = getDb()) {
  if (app && typeof app.data_classification === 'string' && app.data_classification) return app.data_classification;
  try {
    const cols = db.prepare('PRAGMA table_info(apps)').all();
    if (!cols.some((c) => c.name === 'data_classification')) return null;
    return db.prepare('SELECT data_classification FROM apps WHERE id = ?').get(app.id)?.data_classification || null;
  } catch {
    return null;
  }
}
