import log from '../utils/logger.js';

let transporter = null;

async function getTransporter() {
  if (transporter) return transporter;

  if (!process.env.SMTP_HOST) {
    log.debug('SMTP not configured. Emails will be logged only.');
    return null;
  }

  try {
    const nodemailer = await import('nodemailer');
    transporter = nodemailer.default.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: parseInt(process.env.SMTP_PORT) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
    return transporter;
  } catch (e) {
    log.error(`Failed to create email transporter: ${e.message}`);
    return null;
  }
}

export async function sendEmail({ to, subject, text, html }) {
  const transport = await getTransporter();

  if (!transport) {
    log.info(`[EMAIL mock] To: ${to} | Subject: ${subject}`);
    log.debug(`[EMAIL mock] Body: ${text?.slice(0, 200)}`);
    return { mock: true };
  }

  const result = await transport.sendMail({
    from: process.env.SMTP_FROM || 'appcrane@example.com',
    to,
    subject,
    text,
    html,
  });

  log.info(`Email sent to ${to}: ${subject}`);
  return result;
}

export async function notifyDeploy(app, env, version, status, errorMsg) {
  const { getDb } = await import('../db.js');
  const db = getDb();

  const eventCol = status === 'success' ? 'on_deploy_success' : 'on_deploy_fail';

  const configs = db.prepare(`
    SELECT nc.email FROM notification_configs nc
    WHERE nc.app_id = ? AND nc.${eventCol} = 1
  `).all(app.id);

  const icon = status === 'success' ? 'OK' : 'FAILED';
  const subject = `[AppCrane] ${app.slug} ${env} deploy ${icon}`;

  let body = `App: ${app.name} (${app.slug})\n`;
  body += `Environment: ${env}\n`;
  body += `Version: ${version}\n`;
  body += `Status: ${status.toUpperCase()}\n`;
  body += `Time: ${new Date().toISOString()}\n`;

  if (errorMsg) {
    body += `\nError: ${errorMsg}\n`;
  }

  for (const config of configs) {
    await sendEmail({ to: config.email, subject, text: body }).catch(e => {
      log.error(`Failed to send deploy notification to ${config.email}: ${e.message}`);
    });
  }
}

export async function notifyHealthChange(appId, env, status) {
  const { getDb } = await import('../db.js');
  const db = getDb();

  const eventCol = status === 'down' ? 'on_app_down' : 'on_app_recovered';

  const configs = db.prepare(`
    SELECT nc.email FROM notification_configs nc
    WHERE nc.app_id = ? AND nc.${eventCol} = 1
  `).all(appId);

  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
  if (!app) return;

  const icon = status === 'down' ? 'DOWN' : 'RECOVERED';
  const subject = `[AppCrane] ${app.slug} ${env} is ${icon}`;

  let body = `App: ${app.name} (${app.slug})\n`;
  body += `Environment: ${env}\n`;
  body += `Status: ${icon}\n`;
  body += `Time: ${new Date().toISOString()}\n`;

  if (status === 'down') {
    body += `\nACTION REQUIRED: Check app logs and consider rollback.\n`;
  }

  for (const config of configs) {
    await sendEmail({ to: config.email, subject, text: body }).catch(e => {
      log.error(`Failed to send health notification to ${config.email}: ${e.message}`);
    });
  }
}
