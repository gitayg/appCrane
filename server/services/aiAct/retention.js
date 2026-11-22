// LLM gateway log retention with a floor for apps classified as using AI.
//
// llm_gateway_usage keeps one metadata row per gateway call (app, env,
// provider, model, outcome, tokens, cost, latency; no prompt, response or
// user). Rows are kept `llm_gateway_retention_days` (default 90). For an app
// whose intake AI use is assistive, decisions_about_people or annex_iii the
// window is at least AI_LOG_FLOOR_DAYS, whatever the setting says.

import { getDb } from '../../db.js';
import { AppError } from '../../utils/errors.js';
import { logAudit } from '../../middleware/audit.js';
import { AI_USING } from './classification.js';

export const DEFAULT_LLM_RETENTION_DAYS = 90;
// Six calendar months are at most 184 days (July to December).
export const AI_LOG_FLOOR_DAYS = 184;
export const MIN_DAYS = 1;
export const MAX_DAYS = 3650;
const KEY = 'llm_gateway_retention_days';
const DAY = 86_400_000;

const sqliteTime = (ms) => new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
const AI_IN = `(${AI_USING.map(() => '?').join(', ')})`;

export function validDays(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= MIN_DAYS && n <= MAX_DAYS ? n : null;
}

export function configuredDays(db = getDb()) {
  let v = null;
  try { v = db.prepare('SELECT value FROM settings WHERE key = ?').get(KEY)?.value ?? null; } catch (_) {}
  return validDays(v) ?? DEFAULT_LLM_RETENTION_DAYS;
}

export function setConfiguredDays(days, user, db = getDb()) {
  const n = validDays(days);
  if (n == null) throw new AppError(`days must be a whole number from ${MIN_DAYS} to ${MAX_DAYS}`, 400, 'VALIDATION');
  const before = configuredDays(db);
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(KEY, String(n), user?.id ?? null);
  logAudit(user?.id ?? null, null, 'llm-gateway-retention-change', { from: before, to: n });
  return retentionPolicy(db);
}

export const effectiveDays = (configured, aiUse) => (AI_USING.includes(aiUse) ? Math.max(configured, AI_LOG_FLOOR_DAYS) : configured);

export function retentionPolicy(db = getDb()) {
  const configured = configuredDays(db);
  return { configured_days: configured, ai_floor_days: AI_LOG_FLOOR_DAYS, ai_effective_days: effectiveDays(configured, 'assistive'), min_days: MIN_DAYS, max_days: MAX_DAYS };
}

export function appRetention(db, appId) {
  const configured = configuredDays(db);
  const aiUse = db.prepare('SELECT ai_use FROM app_ai_profile WHERE app_id = ?').get(appId)?.ai_use ?? null;
  const days = effectiveDays(configured, aiUse);
  return { llm_gateway_logs_days: days, configured_days: configured, floor_applied: days !== configured, ai_floor_days: AI_LOG_FLOOR_DAYS };
}

/** Delete gateway rows past their window. `now` is injectable for tests. Returns { other, ai } counts. */
export function pruneLlmUsage({ now = Date.now(), db = getDb() } = {}) {
  const configured = configuredDays(db);
  const aiDays = effectiveDays(configured, AI_USING[0]);
  const aiApps = `SELECT app_id FROM app_ai_profile WHERE ai_use IN ${AI_IN}`;
  const other = db.prepare(`DELETE FROM llm_gateway_usage WHERE created_at < ? AND app_id NOT IN (${aiApps})`)
    .run(sqliteTime(now - configured * DAY), ...AI_USING).changes;
  const ai = db.prepare(`DELETE FROM llm_gateway_usage WHERE created_at < ? AND app_id IN (${aiApps})`)
    .run(sqliteTime(now - aiDays * DAY), ...AI_USING).changes;
  return { other, ai, configured_days: configured, ai_days: aiDays };
}
