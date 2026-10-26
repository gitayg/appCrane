import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { jobStarted, trackJob } from '../jobHealth.js';
import { recordEvent } from '../eventStore.js';
import { getPolicy, scopesOf } from './policy.js';
import { createCampaign, closeCampaign, sqlMs } from './campaigns.js';
import { sendReminderMails, sendEscalationMails, sendUnreviewedReport } from './notify.js';

export const JOB_ID = 'access-reviews';
export const TICK_MS = 60 * 60_000;
const DAY = 86_400_000;

/**
 * One pass: start the campaigns the cadence makes due (when enabled), remind
 * reviewers before the due date, escalate overdue campaigns to platform admins
 * once, and close campaigns whose grace period ended (reporting what was never
 * reviewed when the policy says 'report').
 */
export function runAccessReviewTick({ db = getDb(), now = Date.now() } = {}) {
  const policy = getPolicy(db);
  const out = { started: [], reminded: 0, escalated: 0, closed: [] };
  if (policy.enabled) {
    for (const { scope, cadence_days } of scopesOf(policy)) {
      if (db.prepare("SELECT 1 FROM access_review_campaigns WHERE scope = ? AND status = 'open'").get(scope)) continue;
      const last = db.prepare('SELECT started_at FROM access_review_campaigns WHERE scope = ? ORDER BY id DESC LIMIT 1').get(scope);
      if (last && now - sqlMs(last.started_at) < cadence_days * DAY) continue;
      try { out.started.push(createCampaign(db, { scope, now }).id); } catch (e) { log.warn(`[access-reviews] ${scope} campaign not started: ${e.message}`); }
    }
  }
  for (const c of db.prepare("SELECT * FROM access_review_campaigns WHERE status = 'open' ORDER BY id").all()) {
    const due = sqlMs(c.due_at);
    const pending = db.prepare("SELECT COUNT(*) AS n FROM access_reviews WHERE campaign_id = ? AND status = 'pending'").get(c.id).n;
    if (!pending) { out.closed.push(closeCampaign(db, c.id, { reason: 'complete' }).id); continue; }
    if (now >= due - policy.reminder_days * DAY && now < due) out.reminded += sendReminderMails(db, c.id);
    if (now >= due && !c.escalated_at) {
      out.escalated += sendEscalationMails(db, c.id);
      db.prepare("UPDATE access_review_campaigns SET escalated_at = datetime('now') WHERE id = ?").run(c.id);
      recordEvent({ kind: 'access_review.overdue', severity: 'warning', summary: `${c.name} is overdue: ${pending} review(s) not finished`,
        refTable: 'access_review_campaigns', refId: c.id, data: { pending } });
    }
    if (now >= sqlMs(c.grace_until) && !c.grace_processed_at) {
      if (c.overdue_action === 'report') sendUnreviewedReport(db, c.id);
      db.prepare("UPDATE access_review_campaigns SET grace_processed_at = datetime('now') WHERE id = ?").run(c.id);
      out.closed.push(closeCampaign(db, c.id, { reason: 'grace-expired' }).id);
    }
  }
  return out;
}

let timer = null;

export function startAccessReviews() {
  if (timer) return;
  jobStarted(JOB_ID, { cadenceMs: TICK_MS });
  const tick = () => trackJob(JOB_ID, async () => runAccessReviewTick()).catch(e => log.warn(`[access-reviews] ${e.message}`));
  const first = setTimeout(tick, 2 * 60_000);
  first.unref?.();
  timer = setInterval(tick, TICK_MS);
  timer.unref?.();
}

export function stopAccessReviews() {
  if (timer) clearInterval(timer);
  timer = null;
}
