// The capability-grants job (Job Health): every few minutes, grants past their
// expiry are ended. Capabilities whose registry entry says onExpiry 'revoke'
// lose the setting (bypass paths, headless, public visibility, e-mail, LLM
// gateway); 'flag' ones (managed database, raw ports, secret store
// connections) keep it and show as expired-in-place to platform admins, because
// dropping a database or closing a port clients rely on is not a timer's call.

import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { jobStarted, trackJob, setJobDetail } from '../jobHealth.js';
import { expireDue } from './store.js';

export const JOB_ID = 'capability-grants';
const TICK_MS = 5 * 60_000;
let timer = null;

export async function sweepCapabilityGrants(db = getDb(), { reloadCaddy = null } = {}) {
  const results = expireDue(db);
  if (results.some((r) => r.reload)) {
    try {
      const reload = reloadCaddy || (await import('../caddy.js')).reloadCaddy;
      await reload();
    } catch (e) { log.warn(`[capabilities] Caddy reload after expiry failed: ${e.message}`); }
  }
  const flagged = db.prepare("SELECT COUNT(*) AS n FROM capability_requests WHERE status = 'expired' AND expiry_action = 'flagged'").get().n;
  setJobDetail(JOB_ID, { expired_now: results.length, flagged_in_place: flagged, at: new Date().toISOString() });
  return results;
}

export function startCapabilityGrantsWorker() {
  if (timer) return;
  jobStarted(JOB_ID, { cadenceMs: TICK_MS });
  const run = () => trackJob(JOB_ID, () => sweepCapabilityGrants()).catch((e) => log.warn(`[capabilities] sweep failed: ${e.message}`));
  run();
  timer = setInterval(run, TICK_MS);
  timer.unref?.();
}

export function stopCapabilityGrantsWorker() {
  if (timer) { clearInterval(timer); timer = null; }
}
