// Runtime patch mail: one e-mail to each owner per run outcome, and one e-mail
// to the platform admins per runtime advisory listing every affected app.

import { enqueueEmail } from '../emailQueue.js';
import { appOwners } from '../memoryAdmissionMail.js';
import { requestUrl, dashboardBaseUrl } from '../vulnRequests.js';
import { bulletList, renderBrandedEmail } from '../mail/brandedLayout.js';
import { POLICY_NAME } from './policy.js';
import { RUNTIMES } from './runtimeAdvisories.js';
import log from '../../utils/logger.js';

export const RUNTIME_MAIL_SOURCE = 'runtime-patch';
export const ADVISORY_MAIL_SOURCE = 'runtime-advisory';

const label = (run) => RUNTIMES[run.runtime]?.label || run.runtime;

const HEADLINE = {
  applied: (r) => `Rebuilt on patched ${label(r)} ${r.to_version} in production`,
  rolled_back: (r) => `Rebuild on patched ${label(r)} rolled back: production failed its health check`,
  fallback: (r) => (r.production_deployment_id
    ? `Rebuild on patched ${label(r)} failed in production and was NOT rolled back: act now`
    : `${label(r)} ${r.from_version} needs a person: not rebuilt automatically`),
};

export function runtimePatchMail(app, run) {
  const subject = `[AppCrane] ${app.slug}: ${HEADLINE[run.status](run)}`;
  const lines = [
    `Advisories: ${run.advisory_key}`,
    `${label(run)}: ${run.from_version || '?'}${run.to_version ? ` → ${run.to_version}` : ''}${run.fixed_version ? ` (fixed in ${run.fixed_version})` : ''}`,
    run.base_image ? `Base image: ${run.base_image}` : null,
    `Approved by: ${POLICY_NAME} (AppCrane runtime patch), not a person`,
    run.commit_sha ? `Commit: ${run.commit_sha.slice(0, 12)} (unchanged; same code on a patched runtime)` : null,
    run.sandbox_deployment_id ? `Sandbox deployment: #${run.sandbox_deployment_id}` : null,
    run.production_deployment_id ? `Production deployment: #${run.production_deployment_id}` : null,
    run.reason ? `${run.status === 'applied' ? 'Note' : 'Why'}: ${run.reason}` : null,
  ].filter(Boolean);
  const intro = run.status === 'applied'
    ? `The ${label(run)} runtime your app ran had a remote-code-execution flaw. AppCrane rebuilt the same code on the patched runtime, checked it in sandbox, and shipped it to production without a person approving it.`
    : run.status === 'rolled_back'
      ? 'The rebuild reached production, failed its health check there, and production was rolled back to the previous release. A person must act: the app still runs the vulnerable runtime.'
      : run.production_deployment_id
        ? 'The rebuild reached production and failed its health check there, and the automatic rollback did not run. A person must check production now.'
        : 'A guardrail did not hold, so nothing was promoted to production. The app still runs the vulnerable runtime and a person must act.';
  const text = [intro, '', ...lines.map((l) => `- ${l}`), '', run.request_id ? requestUrl(run.request_id) : ''].join('\n');
  const html = renderBrandedEmail({
    preheader: HEADLINE[run.status](run), intro, bodyHtml: bulletList(lines),
    cta: run.request_id ? { label: 'Open the request', url: requestUrl(run.request_id) } : null,
    footer: 'You receive this as an owner of the app. Owners and platform admins can turn auto-patch off on the app\'s Manage page.',
  });
  return { subject, text, html };
}

export function sendRuntimePatchMail(db, app, run) {
  if (!HEADLINE[run.status]) return 0;
  const m = runtimePatchMail(app, run);
  let sent = 0;
  for (const owner of appOwners(db, app.id)) {
    try {
      const r = enqueueEmail({
        appId: app.id, to: owner.email, subject: m.subject, text: m.text, html: m.html,
        source: RUNTIME_MAIL_SOURCE, idempotencyKey: `runtime-patch:${run.id}:${run.status}:${owner.id}`,
      });
      if (!r.deduped) sent++;
    } catch (e) {
      log.warn(`[runtime-patch] mail to owner ${owner.id} of ${app.slug} skipped: ${e.message}`);
    }
  }
  return sent;
}

function adminEmails(db) {
  return db.prepare("SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL AND trim(email) != ''")
    .all().map((r) => r.email);
}

/**
 * E-mail the platform admins about advisories they have not been told about,
 * with every affected app. Returns the advisory ids announced.
 */
export function notifyAdminsOfAdvisories(db, rows) {
  const byAdvisory = new Map();
  for (const r of rows) for (const id of r.advisories) {
    if (!byAdvisory.has(id)) byAdvisory.set(id, []);
    byAdvisory.get(id).push(r);
  }
  const fresh = [...byAdvisory.keys()].filter((id) => !db.prepare('SELECT 1 FROM runtime_advisory_notices WHERE advisory_id = ?').get(id)).sort();
  if (!fresh.length) return [];
  const affected = rows.filter((r) => r.advisories.some((id) => fresh.includes(id)));
  const lines = affected.map((r) => `${r.slug} (${r.env}): ${RUNTIMES[r.runtime]?.label || r.runtime} ${r.version}, fixed in ${r.fixed_version || 'no release on this branch'}; ${r.handling === 'auto' ? 'AppCrane will rebuild it' : `a person must act: ${r.why}`}`);
  const appCount = new Set(affected.map((r) => r.slug)).size;
  const subject = `[AppCrane] ${appCount} app${appCount === 1 ? '' : 's'} run a runtime with a remote-code-execution flaw (${fresh.join(', ')})`;
  const intro = `These apps run a language runtime affected by ${fresh.join(', ')}. Apps marked for AppCrane are rebuilt on the patched runtime automatically; the rest need a person.`;
  const url = `${dashboardBaseUrl()}/settings`;
  const text = [intro, '', ...lines.map((l) => `- ${l}`), '', `Settings > Job Health: ${url}`].join('\n');
  const html = renderBrandedEmail({ preheader: subject, intro, bodyHtml: bulletList(lines), cta: { label: 'Open Job Health', url }, footer: 'You receive this as a platform admin, once per advisory.' });
  const key = `runtime-advisory:${fresh.join(',')}`;
  db.transaction(() => {
    for (const id of fresh) db.prepare('INSERT OR IGNORE INTO runtime_advisory_notices (advisory_id, app_count) VALUES (?, ?)').run(id, byAdvisory.get(id).length);
  })();
  for (const to of adminEmails(db)) {
    try {
      enqueueEmail({ to, subject, text, html, appId: null, source: ADVISORY_MAIL_SOURCE, idempotencyKey: `${key}:${to}` });
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[runtime-patch] advisory mail to an admin skipped: ${e.message}`);
    }
  }
  return fresh;
}
