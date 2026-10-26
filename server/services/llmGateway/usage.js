import { getDb } from '../../db.js';
import { recordEvent } from '../eventStore.js';

// Usage rows are metadata only. Budgets count every forwarded request
// (outcome other than 'refused'); a refused request is recorded so the
// dashboard shows it, but it does not spend the budget it was refused by.

const RETENTION_DAYS = 90;
const PRUNE_EVERY = 500;
let insertsSincePrune = 0;

export function recordUsage(row, db = getDb()) {
  db.prepare(`
    INSERT INTO llm_gateway_usage (app_id, env, provider, endpoint, model, status, outcome, stream, input_tokens, output_tokens, cost_usd, latency_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    row.appId, row.env, row.provider, row.endpoint, row.model ? String(row.model).slice(0, 200) : null,
    row.status ?? null, row.outcome, row.stream ? 1 : 0,
    Math.max(0, Math.floor(row.inputTokens || 0)), Math.max(0, Math.floor(row.outputTokens || 0)),
    row.costUsd ?? null, row.latencyMs ?? null,
  );
  if (++insertsSincePrune >= PRUNE_EVERY) {
    insertsSincePrune = 0;
    db.prepare(`DELETE FROM llm_gateway_usage WHERE created_at < datetime('now', ?)`).run(`-${RETENTION_DAYS} days`);
  }
}

export function spentSoFar(appId, env, db = getDb()) {
  const day = db.prepare(`
    SELECT COUNT(*) AS requests, COALESCE(SUM(input_tokens + output_tokens), 0) AS tokens
    FROM llm_gateway_usage WHERE app_id = ? AND env = ? AND outcome != 'refused' AND created_at >= date('now')
  `).get(appId, env);
  const month = db.prepare(`
    SELECT COALESCE(SUM(cost_usd), 0) AS usd
    FROM llm_gateway_usage WHERE app_id = ? AND env = ? AND outcome != 'refused' AND created_at >= date('now', 'start of month')
  `).get(appId, env);
  return { requestsToday: day.requests, tokensToday: day.tokens, usdThisMonth: month.usd };
}

const minuteWindows = new Map();

/** Sliding one-minute window per app and env. Returns false when the call would exceed `perMinute`. */
export function takeRateSlot(appId, env, perMinute, now = Date.now()) {
  if (!perMinute) return true;
  const key = `${appId}/${env}`;
  const list = (minuteWindows.get(key) || []).filter((t) => now - t < 60_000);
  if (list.length >= perMinute) { minuteWindows.set(key, list); return false; }
  list.push(now);
  minuteWindows.set(key, list);
  return true;
}

export function _resetRateWindowsForTests() { minuteWindows.clear(); }

/**
 * The first refusal reason under `limits`, or null. Checked before the request
 * leaves, so one request can take a token or cost budget past its limit; the
 * next one is refused.
 */
export function budgetRefusal(appId, env, limits, db = getDb()) {
  const s = spentSoFar(appId, env, db);
  if (limits.requests_per_day && s.requestsToday >= limits.requests_per_day) {
    return { code: 'LLM_BUDGET_REQUESTS', message: `This app's ${env} environment has used its ${limits.requests_per_day} LLM requests for today (UTC).` };
  }
  if (limits.tokens_per_day && s.tokensToday >= limits.tokens_per_day) {
    return { code: 'LLM_BUDGET_TOKENS', message: `This app's ${env} environment has used its ${limits.tokens_per_day} LLM tokens for today (UTC).` };
  }
  if (limits.usd_per_month && s.usdThisMonth >= limits.usd_per_month) {
    return { code: 'LLM_BUDGET_COST', message: `This app's ${env} environment has reached its estimated LLM spend of $${limits.usd_per_month} for this month.` };
  }
  return null;
}

/** One event per app, env and reason per 10 minutes: the event store gets aggregates, not every call. */
export function noteGatewayProblem(app, env, reason, summary) {
  recordEvent({
    kind: 'llm.request',
    severity: 'info',
    appId: app.id,
    appSlug: app.slug,
    summary,
    data: { env, reason },
    dedupeKey: `llm.request/${app.id}/${env}/${reason}`,
    dedupeMs: 10 * 60_000,
  });
}

/** Per day, app, env, provider and model. `appId` narrows to one app. */
export function usageSummary({ appId = null, days = 30 } = {}, db = getDb()) {
  const d = Math.min(Math.max(Number(days) || 30, 1), 90);
  const rows = db.prepare(`
    SELECT date(u.created_at) AS day, u.app_id, a.slug AS app_slug, u.env, u.provider, u.model,
           COUNT(*) AS requests,
           SUM(CASE WHEN u.outcome = 'ok' THEN 0 ELSE 1 END) AS failed,
           SUM(CASE WHEN u.outcome = 'refused' THEN 1 ELSE 0 END) AS refused,
           SUM(u.input_tokens) AS input_tokens, SUM(u.output_tokens) AS output_tokens,
           SUM(u.cost_usd) AS cost_usd, CAST(AVG(u.latency_ms) AS INTEGER) AS avg_latency_ms
    FROM llm_gateway_usage u LEFT JOIN apps a ON a.id = u.app_id
    WHERE u.created_at >= date('now', ?) ${appId ? 'AND u.app_id = ?' : ''}
    GROUP BY day, u.app_id, u.env, u.provider, u.model
    ORDER BY day DESC, requests DESC
    LIMIT 2000
  `).all(...[`-${d - 1} days`, ...(appId ? [appId] : [])]);
  return { days: d, rows };
}
