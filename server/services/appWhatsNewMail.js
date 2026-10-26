// "What's new in <App> vX": when an app ships a new version to production, its
// owners and app admins get one mail with the text the app's What's New dialog
// shows for that version (the production deployment's commit_message).
//
// An upgrade is a successful production deploy whose version is known, differs
// from the previous production deployment's, and whose version, commit or
// artifact has never been live in production for this app before. So the first
// production deploy, a redeploy of the same version, a rollback (it restores a
// commit or image digest that was live before, even where it relabels the
// version) and rolling forward again after one send nothing. Sandbox and failed deploys never reach
// this: deployer.js calls it only after a production deploy goes live.
//
// Recipients: active humans with an e-mail holding the owner or admin role on
// the app. Members, agents and platform admins without a role on the app are
// not mailed; platform admins hear about AppCrane itself, not every app.
//
// One mail per (app, version, recipient): app_id plus the idempotency key
// `app-whats-new:<version>:<email>` is unique in email_queue (migration 060).
// Per-app switch: app_settings.whats_new_email (migration 125), default on.

import { enqueueEmail } from './emailQueue.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import { BRAND, esc, renderBrandedEmail, versionPill } from './mail/brandedLayout.js';
import log from '../utils/logger.js';

export const APP_WHATS_NEW_SOURCE = 'app-whats-new';

export function getAppWhatsNewEmail(db, appId) {
  const row = db.prepare('SELECT whats_new_email FROM app_settings WHERE app_id = ?').get(appId);
  return row ? row.whats_new_email === 1 : true;
}

export function setAppWhatsNewEmail(db, appId, on) {
  db.prepare(`
    INSERT INTO app_settings (app_id, whats_new_email) VALUES (?, ?)
    ON CONFLICT(app_id) DO UPDATE SET whats_new_email = excluded.whats_new_email, updated_at = datetime('now')
  `).run(appId, on ? 1 : 0);
}

export function parseAppWhatsNewEmail(v) {
  if (v === true || v === 1) return true;
  if (v === false || v === 0) return false;
  return undefined;
}

/** Active human owners and app admins of the app with an e-mail; one per address. */
export function appUpgradeRecipients(db, appId) {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.email FROM app_user_roles r
    JOIN users u ON u.id = r.user_id
    WHERE r.app_id = ? AND r.app_role IN ('owner', 'admin')
      AND u.active = 1 AND u.email IS NOT NULL AND trim(u.email) != ''
      AND COALESCE(u.kind, 'human') = 'human'
    ORDER BY u.id
  `).all(appId);
  const seen = new Set();
  return rows.filter((u) => {
    const k = u.email.trim().toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** Why this deployment is, or is not, an upgrade worth mailing about. */
export function upgradeDecision(db, deployment) {
  if (!deployment || deployment.env !== 'production' || deployment.status !== 'live') return 'not-live-production';
  const version = String(deployment.version || '').trim();
  if (!version || version === 'unknown') return 'no-version';
  const prev = db.prepare(`
    SELECT version FROM deployments
    WHERE app_id = ? AND env = 'production' AND status IN ('live', 'rolled_back') AND id != ?
    ORDER BY id DESC LIMIT 1
  `).get(deployment.app_id, deployment.id);
  if (!prev) return 'first-deploy';
  if (prev.version === version) return 'same-version';
  const commit = deployment.commit_hash && deployment.commit_hash !== 'unknown' ? deployment.commit_hash : null;
  const before = db.prepare(`
    SELECT 1 FROM deployments
    WHERE app_id = ? AND env = 'production' AND status IN ('live', 'rolled_back') AND id != ?
      AND (version = ? OR (? IS NOT NULL AND commit_hash = ?) OR (? IS NOT NULL AND artifact_sha256 = ?))
    LIMIT 1
  `).get(deployment.app_id, deployment.id, version, commit, commit,
    deployment.artifact_sha256 ?? null, deployment.artifact_sha256 ?? null);
  if (before) return 'seen-before';
  return 'upgrade';
}

export function appUrl(slug) {
  return `${dashboardBaseUrl()}/launch/${encodeURIComponent(slug)}`;
}

export function renderAppWhatsNew({ app, version, notes, name }) {
  const url = appUrl(app.slug);
  const subject = `[AppCrane] What's new in ${app.name} v${version}`;
  const intro = `${app.name} was updated to v${version}.`;
  const lines = String(notes || '').split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.trim());
  const none = 'No release notes were written for this version.';
  const footer = `You get this because you own or administer ${app.name} on AppCrane. `
    + "The app's owner or an app admin can turn these e-mails off in the app's settings.";

  let text = `Hi${name ? ' ' + name : ''},\n\n${intro}\n\nWhat's new in v${version}:\n`;
  text += lines.length ? lines.map((l) => `${l}\n`).join('') : `${none}\n`;
  text += `\nOpen ${app.name}: ${url}\n\n${footer}\n`;

  const notesHtml = lines.length
    ? `<div style="margin:6px 0 0;font-size:14px;line-height:21px;color:${BRAND.text};">${lines.map(esc).join('<br>')}</div>`
    : `<p style="margin:6px 0 0;font-size:14px;color:${BRAND.dim};">${esc(none)}</p>`;
  const html = renderBrandedEmail({
    preheader: intro,
    greeting: `Hi${name ? ' ' + name : ''},`,
    intro,
    bodyHtml: `<div style="margin:18px 0 0;">${versionPill(version)}`
      + `<div style="margin:10px 0 0;padding:12px 14px;border-left:3px solid ${BRAND.accent};background:${BRAND.page};">${notesHtml}</div></div>`,
    cta: { label: `Open ${app.name}`, url },
    footer,
  });
  return { subject, text, html };
}

/**
 * Queue the upgrade mail for a production deployment that just went live.
 * Throws only on a database fault; the deployer guards the call.
 * @returns {{ status: string, sent?: number, skipped?: number }}
 */
export function queueAppUpgradeMail({ db, app, deployId, enqueue = enqueueEmail }) {
  const deployment = db.prepare('SELECT * FROM deployments WHERE id = ?').get(deployId);
  const status = upgradeDecision(db, deployment);
  if (status !== 'upgrade') return { status };
  if (!getAppWhatsNewEmail(db, app.id)) return { status: 'disabled' };

  const fresh = db.prepare('SELECT id, name, slug FROM apps WHERE id = ?').get(app.id) || app;
  const version = String(deployment.version).trim();
  let sent = 0, skipped = 0;
  for (const u of appUpgradeRecipients(db, app.id)) {
    const idempotencyKey = `app-whats-new:${version}:${u.email.trim().toLowerCase()}`;
    const { subject, text, html } = renderAppWhatsNew({ app: fresh, version, notes: deployment.commit_message, name: u.name });
    try {
      const r = enqueue({ to: u.email, subject, text, html, appId: app.id, env: 'production', idempotencyKey, source: APP_WHATS_NEW_SOURCE });
      if (r?.deduped) skipped++; else sent++;
    } catch (e) {
      skipped++;
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[app-whats-new] ${fresh.slug} v${version}: skipped ${u.email}: ${e.message}`);
    }
  }
  log.info(`[app-whats-new] ${fresh.slug} v${version}: queued ${sent}, skipped ${skipped}`);
  return { status: 'sent', sent, skipped };
}
