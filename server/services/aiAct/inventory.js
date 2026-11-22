// AI-system inventory: every app with LLM gateway traffic or an intake AI-use
// answer of anything but "none", joined with its intake and transparency
// settings. Traffic comes from llm_gateway_usage, so it covers only calls made
// through AppCrane's gateway; an app calling a provider directly with its own
// key is visible here only through its intake answer.

import { toCsv } from '../evidencePack/util.js';
import { AI_USING } from './classification.js';
import { appRetention } from './retention.js';

export function aiInventory(db) {
  const traffic = db.prepare(`
    SELECT app_id, COUNT(*) AS calls, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
           SUM(CASE WHEN outcome = 'refused' THEN 1 ELSE 0 END) AS refused,
           SUM(input_tokens) AS input_tokens, SUM(output_tokens) AS output_tokens, SUM(cost_usd) AS cost_usd
    FROM llm_gateway_usage GROUP BY app_id`).all();
  const models = db.prepare(`SELECT DISTINCT app_id, provider, model FROM llm_gateway_usage ORDER BY provider, model`).all();
  const byApp = new Map(traffic.map((t) => [t.app_id, { ...t, providers: new Set(), models: new Set() }]));
  for (const m of models) {
    const t = byApp.get(m.app_id);
    t.providers.add(m.provider);
    if (m.model) t.models.add(m.model);
  }
  const apps = db.prepare(`
    SELECT a.id, a.slug, a.name, p.ai_use, p.annex_iii_category, p.ai_use_set_at, p.notice_enabled,
           i.data_classification, i.status AS intake_status, g.enabled AS gateway_enabled
    FROM apps a
    LEFT JOIN app_ai_profile p ON p.app_id = a.id
    LEFT JOIN app_intake i ON i.app_id = a.id
    LEFT JOIN llm_gateway_apps g ON g.app_id = a.id
    ORDER BY a.slug`).all();

  const items = [];
  for (const a of apps) {
    const t = byApp.get(a.id);
    if (!t && !AI_USING.includes(a.ai_use)) continue;
    const declaredNone = a.ai_use === 'none';
    const unanswered = a.ai_use == null;
    const mismatch = !!t && (declaredNone || unanswered);
    items.push({
      app: a.slug,
      name: a.name,
      ai_use: a.ai_use,
      annex_iii_category: a.annex_iii_category,
      data_classification: a.data_classification || 'internal',
      intake_status: a.intake_status || 'none',
      gateway_enabled: !!a.gateway_enabled,
      providers: t ? [...t.providers].sort() : [],
      models: t ? [...t.models].sort() : [],
      first_seen: t?.first_seen ?? null,
      last_seen: t?.last_seen ?? null,
      calls: t?.calls ?? 0,
      refused_calls: t?.refused ?? 0,
      input_tokens: t?.input_tokens ?? 0,
      output_tokens: t?.output_tokens ?? 0,
      cost_usd: t?.cost_usd ?? null,
      transparency_notice: !!a.notice_enabled,
      llm_log_retention_days: appRetention(db, a.id).llm_gateway_logs_days,
      mismatch,
      mismatch_reason: !mismatch ? null : declaredNone ? 'gateway_traffic_but_intake_says_none' : 'gateway_traffic_but_ai_use_not_answered',
    });
  }
  return {
    generated_at: new Date().toISOString(),
    source: 'llm_gateway_usage rows still inside their retention window, joined with the intake AI-use answer',
    apps: items,
    mismatches: items.filter((i) => i.mismatch).length,
  };
}

export const INVENTORY_COLUMNS = ['app', 'name', 'ai_use', 'annex_iii_category', 'data_classification', 'intake_status', 'gateway_enabled',
  'providers', 'models', 'first_seen', 'last_seen', 'calls', 'refused_calls', 'input_tokens', 'output_tokens', 'cost_usd',
  'transparency_notice', 'llm_log_retention_days', 'mismatch', 'mismatch_reason'];

export function aiInventoryCsv(db) {
  const rows = aiInventory(db).apps.map((r) => ({ ...r, providers: r.providers.join(' '), models: r.models.join(' ') }));
  return toCsv(rows, INVENTORY_COLUMNS);
}
