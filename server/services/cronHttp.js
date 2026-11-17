// A kind='http' cron run: GET <http_path> on the app's own container, the way
// Vercel calls a vercel.json cron path.
//
// The request goes to the loopback port the container publishes (the port the
// health checker probes), never through Caddy, so the app's access rules and
// AppCrane sign-in do not stand between the scheduler and the route. Redirects
// are not followed, as on Vercel. CRON_SECRET, when the app has one for this
// environment, is sent as `Authorization: Bearer <it>` and is removed from
// anything written to the row or the log.

import { getDb } from '../db.js';
import { getPortsForSlot } from './portAllocator.js';
import { resolveStoredEnv } from './secretRefs.js';

const BODY_TAIL_BYTES = 2048;
export const CRON_USER_AGENT = 'vercel-cron/1.0 (compatible; AppCrane)';

export function cronTargetUrl(app, env, path) {
  const ports = getPortsForSlot(app.slot);
  const port = env === 'production' ? ports.prod_be : ports.sand_be;
  return `http://127.0.0.1:${port}${path}`;
}

export async function readCronSecret(app, env) {
  const rows = getDb().prepare("SELECT key, value_encrypted FROM env_vars WHERE app_id = ? AND env = ? AND key = 'CRON_SECRET'").all(app.id, env);
  if (!rows.length) return null;
  const { values } = await resolveStoredEnv(app, env, rows);
  return typeof values.CRON_SECRET === 'string' && values.CRON_SECRET ? values.CRON_SECRET : null;
}

function scrub(text, secret) {
  return secret ? String(text).split(secret).join('[CRON_SECRET]') : String(text);
}

/** {exitCode, httpStatus, log, error}. exitCode 0 for a 2xx answer, 1 otherwise. */
export async function runHttpCron(app, job, { fetchImpl = fetch } = {}) {
  const url = cronTargetUrl(app, job.env, job.http_path);
  let secret = null;
  try {
    secret = await readCronSecret(app, job.env);
  } catch (e) {
    return { exitCode: 1, httpStatus: null, log: `CRON_SECRET could not be read: ${e.message}`, error: 'CRON_SECRET could not be read' };
  }
  const headers = { 'user-agent': CRON_USER_AGENT, 'x-vercel-cron-schedule': job.schedule };
  if (secret) headers.authorization = `Bearer ${secret}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), job.timeout_seconds * 1000);
  const auth = secret ? 'with Authorization: Bearer CRON_SECRET' : 'without Authorization (no CRON_SECRET set)';
  try {
    const res = await fetchImpl(url, { method: 'GET', headers, redirect: 'manual', signal: controller.signal });
    let body = '';
    try { body = await res.text(); } catch (_) {}
    const ok = res.status >= 200 && res.status < 300;
    const lines = [`GET ${job.http_path} ${auth} -> HTTP ${res.status}`];
    if (body) lines.push(scrub(body, secret).slice(-BODY_TAIL_BYTES));
    return { exitCode: ok ? 0 : 1, httpStatus: res.status, log: lines.join('\n'), error: ok ? null : `HTTP ${res.status}` };
  } catch (e) {
    const why = controller.signal.aborted
      ? `no answer within ${job.timeout_seconds}s`
      : (e?.cause?.code || e?.cause?.message || e?.message || String(e));
    return { exitCode: 1, httpStatus: null, log: scrub(`GET ${job.http_path} ${auth} failed: ${why}`, secret), error: scrub(why, secret) };
  } finally {
    clearTimeout(timer);
  }
}
