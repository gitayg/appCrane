// Cron runs against a container that is not there.
//
// A cron job is a `docker exec` into the app's container. When that container
// is gone (an app stopped, a failed deploy, a host restart that did not bring
// it back) every tick used to exec anyway and fail with "No such container":
// one production box logged ~14k of those lines a day for two days while its
// disk filled. So the scheduler checks first, skips the run with the reason on
// the row, and says so ONCE per job when it pauses and once when it resumes,
// with one mail to the app's owners per outage of an app+env. State is
// in-memory: a restart during an outage re-announces it once, which is the
// right amount of noise for "still broken after a restart".

import { execFile } from 'child_process';
import { enqueueEmail } from './emailQueue.js';
import { appUpgradeRecipients } from './appWhatsNewMail.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import { BRAND, bulletList, renderBrandedEmail } from './mail/brandedLayout.js';
import log from '../utils/logger.js';

export const CRON_MAIL_SOURCE = 'cron-no-container';
const INSPECT_TIMEOUT_MS = 15_000;

const pausedJobs = new Map(); // job key -> reason
const outages = new Map();    // `${app_id}:${env}` -> ISO time the outage was first seen

/** {running, reason}: reason says why a run would be skipped, null when running. */
export function inspectContainer(name) {
  return new Promise((res) => {
    execFile('docker', ['inspect', '--format', '{{.State.Running}}|{{.State.Status}}', name], { timeout: INSPECT_TIMEOUT_MS }, (err, stdout, stderr) => {
      if (err) {
        const detail = String(stderr || err.message || '').trim();
        if (/no such (object|container)/i.test(detail)) return res({ running: false, reason: `container ${name} does not exist` });
        return res({ running: false, reason: `container ${name} could not be inspected: ${detail.slice(0, 200)}` });
      }
      const [running, status] = String(stdout || '').trim().split('|');
      if (running === 'true') return res({ running: true, reason: null });
      res({ running: false, reason: `container ${name} is not running (status: ${status || 'unknown'})` });
    });
  });
}

const jobKey = (job) => `${job.app_id}:${job.env}:${job.name}`;

export function noteContainerDown(db, job, app, reason) {
  const key = jobKey(job);
  if (!pausedJobs.has(key)) {
    pausedJobs.set(key, reason);
    log.warn(`[cron] ${key} paused: ${reason}. Scheduled runs are skipped until the container is running again.`);
  }
  const outageKey = `${job.app_id}:${job.env}`;
  if (outages.has(outageKey)) return;
  const since = new Date().toISOString();
  outages.set(outageKey, since);
  mailOutage(db, job, app, reason, since);
}

export function noteContainerUp(job) {
  const key = jobKey(job);
  if (pausedJobs.delete(key)) log.info(`[cron] ${key} resumed: the container is running again`);
  outages.delete(`${job.app_id}:${job.env}`);
}

function recipients(db, appId) {
  const owners = appUpgradeRecipients(db, appId).map((u) => u.email);
  if (owners.length) return owners;
  return db.prepare(`SELECT email FROM users WHERE role = 'platform_admin' AND active = 1
                     AND email IS NOT NULL AND trim(email) != ''`).all().map((r) => r.email);
}

function mailOutage(db, job, app, reason, since) {
  const where = `${app.slug}/${job.env}`;
  const subject = `[AppCrane] Cron jobs paused: ${where} has no running container`;
  const intro = `AppCrane is skipping the scheduled cron jobs of ${where} because ${reason}.`;
  const after = 'They resume on their own once the container runs again; redeploy or restart the app to bring it back.';
  for (const to of recipients(db, job.app_id)) {
    try {
      enqueueEmail({
        to, subject, appId: job.app_id, env: job.env, source: CRON_MAIL_SOURCE,
        text: `${intro}\n\n${after}\n\nFirst job affected: ${job.name}\n`,
        html: renderBrandedEmail({
          preheader: intro, greeting: 'Hi,', intro,
          bodyHtml: bulletList([`First job affected: ${job.name}`, `Since: ${since}`])
            + `<p style="margin:12px 0 0;font-size:13px;color:${BRAND.dim};">${after}</p>`,
          cta: { label: 'Open the app', url: `${dashboardBaseUrl()}/app?slug=${encodeURIComponent(app.slug)}` },
          footer: 'You get this because you own or administer this app on AppCrane.',
        }),
        idempotencyKey: `cron-no-container:${job.env}:${since}:${to.trim().toLowerCase()}`,
      });
    } catch (e) {
      log.warn(`[cron] outage mail to ${to} skipped: ${e.message}`);
    }
  }
}

export function _resetCronContainerGuardForTests() {
  pausedJobs.clear();
  outages.clear();
}
