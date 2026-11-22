// Which AppCrane sent a mail: an admin of several gets the same notice from
// each, and "[AppCrane] Server critical: Memory available" did not say which
// server was short. sendEmail() stamps every message with withServerName().
// CRANE_DOMAIN is the public identity; without it the OS hostname still tells
// two machines apart (as in credentialChecker.js).

import { hostname } from 'os';

export function serverName() {
  return (process.env.CRANE_DOMAIN || '').trim() || hostname();
}

const escapeHtml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const FOOTER = /platform admin of this AppCrane/g;

export function withServerName({ subject, text, html }) {
  const server = serverName();
  return {
    subject: typeof subject === 'string' ? subject.replace(/^\[AppCrane\]/, `[AppCrane: ${server}]`) : subject,
    text: typeof text === 'string' ? text.replace(FOOTER, `platform admin of the AppCrane at ${server}`) : text,
    html: typeof html === 'string' ? html.replace(FOOTER, `platform admin of the AppCrane at ${escapeHtml(server)}`) : html,
  };
}
