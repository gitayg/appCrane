import log from '../utils/logger.js';

// One plain notice to an app's owners (platform admins when it has none) for
// each environment the host.docker.internal repair recreated. Same recipients
// and queue as the restart-loop mail (emailService.notifyRestartLoop).

export const HOST_GATEWAY_REPAIR_MAIL_SOURCE = 'host-gateway-repair';

export async function notifyHostGatewayRepair({ db, appId, env, outcome, lineBefore, lineAfter = null, error = null, at }) {
  const { enqueueEmail } = await import('./emailQueue.js');
  const { appOwners, platformAdmins } = await import('./memoryAdmissionMail.js');
  const { dashboardBaseUrl } = await import('./vulnRequests.js');
  const app = db.prepare('SELECT id, name, slug FROM apps WHERE id = ?').get(appId);
  if (!app) return [];
  const owners = appOwners(db, appId);
  const seen = new Set();
  const people = (owners.length ? owners : platformAdmins(db)).filter((u) => {
    const k = u.email.trim().toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  if (!people.length) {
    log.warn(`[host-gateway] repair of ${app.slug}/${env} not mailed: no owner and no platform admin has an email address`);
    return [];
  }
  const fixed = outcome === 'fixed';
  const when = new Date(at).toISOString().replace('T', ' ').slice(0, 19);
  const subject = `[AppCrane] ${app.slug} (${env}) was restarted to repair host.docker.internal`;
  let body = `At ${when} UTC AppCrane recreated the ${env} container of ${app.name} (${app.slug}). `;
  body += `Its /etc/hosts mapped host.docker.internal to an invalid address ("${lineBefore}"), so the app could not reach AppCrane or a managed database.\n\n`;
  body += `AppCrane stopped and removed the container and started a new one from the same image, with the current settings, the same way Restart on the app page does.\n\n`;
  body += fixed
    ? `Result: fixed. The new container maps "${lineAfter}".\n`
    : `Result: still broken${error ? ` (${error})` : ''}. Restart it from the app page, or ask a platform administrator to look at the Job Health page.\n`;
  body += `\nApp page: ${dashboardBaseUrl()}/app?slug=${encodeURIComponent(app.slug)}\n`;
  const sent = [];
  for (const u of people) {
    try {
      enqueueEmail({
        appId, env, to: u.email, source: HOST_GATEWAY_REPAIR_MAIL_SOURCE, fromName: 'AppCrane',
        subject, text: `Hi${u.name ? ` ${u.name}` : ''},\n\n${body}\nYou get this because you ${owners.length ? 'own' : 'administer the AppCrane that runs'} ${app.slug}.\n`,
        idempotencyKey: `${HOST_GATEWAY_REPAIR_MAIL_SOURCE}:${env}:${at}:${u.email.trim().toLowerCase()}`,
      });
      sent.push(u.email);
    } catch (e) {
      log.warn(`[host-gateway] repair mail to ${u.email} skipped: ${e.message}`);
    }
  }
  return sent;
}
