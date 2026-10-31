// Who hears about a memory-admission refusal or warning, and how often.
//
// Refused: the person who triggered it (a deploy's deployed_by, the coder's
// user) gets "try again later"; a deploy with no human behind it (git push,
// webhook, poller, auto-heal) goes to the app's owners instead. One mail per
// recipient, app and environment per hour.
// Refused or warned: every platform admin gets the numbers and the containers
// holding the most memory, one mail per app per hour, plus an audit row.
//
// Platform mail (app_id NULL), deduped by the idempotency key, which migration
// 133 makes unique for source 'memory-admission'.

import { enqueueEmail } from './emailQueue.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import { BRAND, esc, bulletList, renderBrandedEmail } from './mail/brandedLayout.js';
import { readUsage, toMb } from './memoryAdmission.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';

export const MEMORY_MAIL_SOURCE = 'memory-admission';
const TOP_N = 5;

function hourBucket(now = new Date()) {
  return now.toISOString().slice(0, 13);
}

function humanWithEmail(db, userId) {
  if (userId == null) return null;
  return db.prepare(`SELECT id, name, email FROM users WHERE id = ? AND active = 1
                     AND email IS NOT NULL AND trim(email) != '' AND COALESCE(kind, 'human') = 'human'`).get(userId) || null;
}

export function appOwners(db, appId) {
  if (appId == null) return [];
  return db.prepare(`
    SELECT u.id, u.name, u.email FROM app_user_roles r JOIN users u ON u.id = r.user_id
    WHERE r.app_id = ? AND r.app_role = 'owner' AND u.active = 1
      AND u.email IS NOT NULL AND trim(u.email) != '' AND COALESCE(u.kind, 'human') = 'human'
    ORDER BY u.id
  `).all(appId);
}

export function platformAdmins(db) {
  return db.prepare(`SELECT id, name, email FROM users WHERE role = 'platform_admin' AND active = 1
                     AND email IS NOT NULL AND trim(email) != ''`).all();
}

/** The people told to try again later: the trigger, or the owners of an automatic deploy. */
export function userRecipients(db, { userId, automatic, appId }) {
  const who = automatic ? null : humanWithEmail(db, userId);
  const list = who ? [who] : appOwners(db, appId);
  const seen = new Set();
  return list.filter((u) => {
    const k = u.email.trim().toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function send(m) {
  try {
    enqueueEmail({ ...m, appId: null, source: MEMORY_MAIL_SOURCE });
    return true;
  } catch (e) {
    if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[memory-admission] mail to ${m.to} skipped: ${e.message}`);
    return false;
  }
}

async function topContainers(measurement) {
  const top = [...measurement.containers].sort((a, b) => b.countedBytes - a.countedBytes).slice(0, TOP_N);
  const usage = await readUsage(top.map((c) => c.name));
  return top.map((c) => ({
    label: c.label, name: c.name, image: c.image || null, kind: c.kind, countedFrom: c.countedFrom,
    capMb: c.unlimited ? null : toMb(c.capBytes),
    usageMb: usage.has(c.name) ? toMb(usage.get(c.name)) : null,
  }));
}

// The image says what a container is when its name does not (Docker's random
// names, or a container AppCrane did not start).
function containerLine(c) {
  const cap = c.capMb == null ? 'no limit' : `cap ${c.capMb} MB`;
  const use = c.usageMb == null ? 'usage unknown' : `using ${c.usageMb} MB`;
  const image = c.image ? ` [image ${c.image}]` : '';
  const counted = c.kind === 'other' ? ', not started by AppCrane, counted at its usage' : '';
  return `${c.label}${image}: ${cap}, ${use}${counted}`;
}

export async function notifyMemoryAdmission({
  db, outcome, message, verdict, measurement, subject, what, slug, env, appId = null, userId = null, automatic = false,
}) {
  const hour = hourBucket();
  const base = dashboardBaseUrl();
  const sent = { users: [], admins: [] };
  const refused = outcome === 'refused';

  if (refused) {
    for (const u of userRecipients(db, { userId, automatic, appId })) {
      const ok = send({
        to: u.email,
        subject: `[AppCrane] ${subject}: ${what} refused, not enough server memory`,
        text: `Hi${u.name ? ` ${u.name}` : ''},\n\n${message}\n\nPlease try again later.\n`,
        html: renderBrandedEmail({
          preheader: `Your ${what} of ${subject} was not started. Try again later.`,
          greeting: `Hi${u.name ? ` ${u.name}` : ''},`,
          intro: message,
          bodyHtml: `<p style="margin:12px 0 0;font-size:14px;line-height:21px;color:${BRAND.text};">Please try again later.</p>`,
          cta: { label: 'Open AppCrane', url: base },
          footer: automatic
            ? `You get this because you own ${slug || subject} and this ${what} started automatically.`
            : `You get this because you started this ${what}.`,
        }),
        idempotencyKey: `memory-admission:user:${slug || subject}:${env || '-'}:${hour}:${u.email.trim().toLowerCase()}`,
      });
      if (ok) sent.users.push(u.email);
    }
  }

  const top = await topContainers(measurement);
  const numbers = [
    `Needed: ${toMb(verdict.newBytes)} MB${verdict.replacedBytes ? ` (replacing ${toMb(verdict.replacedBytes)} MB)` : ''}`,
    `Free: ${toMb(verdict.freeBytes)} MB`,
    `Committed: ${toMb(verdict.committedBytes)} MB of ${toMb(verdict.capacityBytes)} MB capacity`,
    `Host memory: ${toMb(measurement.totalBytes)} MB (${measurement.totalSource === 'docker' ? 'from docker info' : 'docker info failed; this machine\'s RAM'}), reserve ${toMb(measurement.reserveBytes)} MB`,
  ];
  const adminText = `${message}\n\n${numbers.join('\n')}\n\nContainers holding the most memory:\n`
    + `${top.map((c) => `- ${containerLine(c)}`).join('\n') || '- (none running)'}\n\n`
    + 'Lower a container\'s memory limit, stop an unused sandbox, or raise the reserve in Settings > Job Health.\n';
  for (const a of platformAdmins(db)) {
    const ok = send({
      to: a.email,
      subject: `[AppCrane] Memory admission ${refused ? 'refused' : 'warning'}: ${subject}`,
      text: adminText,
      html: renderBrandedEmail({
        preheader: `${subject}: ${refused ? 'refused' : 'started past capacity'}`,
        greeting: 'Hi,',
        intro: message,
        bodyHtml: bulletList(numbers)
          + `<p style="margin:14px 0 0;font-size:14px;font-weight:600;color:${BRAND.text};">Containers holding the most memory</p>`
          + bulletList(top.length ? top.map(containerLine) : ['(none running)'])
          + `<p style="margin:12px 0 0;font-size:13px;line-height:20px;color:${BRAND.dim};">${esc('Lower a container\'s memory limit, stop an unused sandbox, or raise the reserve in Settings > Job Health.')}</p>`,
        cta: { label: 'Open Job Health', url: `${base}/settings#jobs` },
        footer: 'You get this because you are a platform admin of this AppCrane.',
      }),
      idempotencyKey: `memory-admission:admin:${slug || subject}:${hour}:${a.email.trim().toLowerCase()}`,
    });
    if (ok) sent.admins.push(a.email);
  }

  try {
    logAudit(userId ?? null, appId ?? null, refused ? 'memory.admission.refused' : 'memory.admission.warned', {
      what, subject, env: env || null, automatic: !!automatic,
      need_mb: toMb(verdict.newBytes), free_mb: toMb(verdict.freeBytes),
      committed_mb: toMb(verdict.committedBytes), capacity_mb: toMb(verdict.capacityBytes),
    });
  } catch (e) {
    log.warn(`[memory-admission] audit row skipped: ${e.message}`);
  }
  return sent;
}
