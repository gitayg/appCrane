// One e-mail to each owner per auto-patch outcome: applied, rolled back, or
// handed back to the human flow. Idempotent on (app, run, outcome, recipient).

import { enqueueEmail } from '../emailQueue.js';
import { appOwners } from '../memoryAdmissionMail.js';
import { requestUrl } from '../vulnRequests.js';
import { bulletList, renderBrandedEmail } from '../mail/brandedLayout.js';
import { POLICY_NAME } from './policy.js';
import { preExistingFindings } from '../releaseCheck.js';
import log from '../../utils/logger.js';

export const AUTO_PATCH_MAIL_SOURCE = 'auto-patch';

const HEADLINE = {
  applied: (r) => `Auto-patched ${r.package} ${r.from_version} → ${r.to_version} in production`,
  rolled_back: (r) => `Auto-patch of ${r.package} rolled back: production failed its health check`,
  fallback: (r) => (r.production_deployment_id
    ? `Auto-patch of ${r.package} failed in production and was NOT rolled back: act now`
    : `Auto-patch did not apply ${r.package}: back to you`),
};

export function autoPatchMail(app, run, { preExisting = [] } = {}) {
  const subject = `[AppCrane] ${app.slug}: ${HEADLINE[run.status](run)}`;
  const lines = [
    `Advisory: ${run.advisory_id}`,
    `Package: ${run.package} ${run.from_version || '?'}${run.to_version ? ` → ${run.to_version}` : ''} (${run.ecosystem})`,
    `Approved by: ${POLICY_NAME} (AppCrane auto-patch), not a person`,
    run.commit_sha ? `Commit: ${run.commit_sha.slice(0, 12)}` : null,
    run.sandbox_deployment_id ? `Sandbox deployment: #${run.sandbox_deployment_id}` : null,
    run.production_deployment_id ? `Production deployment: #${run.production_deployment_id}` : null,
    run.reason ? `${run.status === 'applied' ? 'Note' : 'Why'}: ${run.reason}` : null,
    preExisting.length ? `Already in production before this fix, unchanged by it (${preExisting.length}): ${preExisting.join('; ')}` : null,
  ].filter(Boolean);
  const intro = run.status === 'applied'
    ? 'A dependency fix for a remote-code-execution advisory passed every guardrail and was shipped without a person approving it. The request closes itself after the next clean scan.'
    : run.status === 'rolled_back'
      ? 'The fix reached production, failed its health check there, and production was rolled back to the previous release. The request is back in your queue.'
      : run.production_deployment_id
        ? 'The fix reached production and failed its health check there, and the automatic rollback did not run. A person must check production and roll it back now.'
        : 'A guardrail did not hold, so nothing was promoted to production. The request stays in your queue for a person to handle as before.';
  const text = [intro, '', ...lines.map((l) => `- ${l}`), '', run.request_id ? requestUrl(run.request_id) : ''].join('\n');
  const html = renderBrandedEmail({
    preheader: HEADLINE[run.status](run),
    intro,
    bodyHtml: bulletList(lines),
    cta: run.request_id ? { label: 'Open the request', url: requestUrl(run.request_id) } : null,
    footer: 'You receive this as an owner of the app. Owners and platform admins can turn auto-patch off on the app\'s Manage page.',
  });
  return { subject, text, html };
}

export function sendAutoPatchMail(db, app, run) {
  if (!HEADLINE[run.status]) return 0;
  const m = autoPatchMail(app, run, { preExisting: preExistingFindings(db, run.release_check_id) });
  let sent = 0;
  for (const owner of appOwners(db, app.id)) {
    try {
      const r = enqueueEmail({
        appId: app.id, to: owner.email, subject: m.subject, text: m.text, html: m.html,
        source: AUTO_PATCH_MAIL_SOURCE, idempotencyKey: `auto-patch:${run.id}:${run.status}:${owner.id}`,
      });
      if (!r.deduped) sent++;
    } catch (e) {
      log.warn(`[auto-patch] mail to owner ${owner.id} of ${app.slug} skipped: ${e.message}`);
    }
  }
  return sent;
}
