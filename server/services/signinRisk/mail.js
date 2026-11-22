import crypto from 'crypto';
import { hashApiKey } from '../encryption.js';
import { enqueueEmail } from '../emailQueue.js';
import { dashboardBaseUrl } from '../vulnRequests.js';

// Platform mail for sign-in risk signals, through the e-mail queue (which
// only ever mails active registered users). Each function returns true when
// a message was queued, never throws.

const REPORT_TTL_DAYS = 7;

/** A single-use "not you?" link for userId. The raw token exists only in the e-mail. */
export function createReportLink(db, userId, devicePublicId = null) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare(`INSERT INTO signin_report_links (token_hash, user_id, device_public_id, expires_at)
    VALUES (?, ?, ?, datetime('now', ?))`).run(hashApiKey(token), userId, devicePublicId, `+${REPORT_TTL_DAYS} days`);
  return `${dashboardBaseUrl()}/api/signin-security/not-me?t=${token}`;
}

export function sendNewDeviceMail(db, user, { devicePublicId, ua, ip, method }) {
  try {
    const link = createReportLink(db, user.id, devicePublicId);
    const when = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    enqueueEmail({
      appId: null,
      source: 'signin-risk',
      to: user.email,
      subject: '[AppCrane] New sign-in to your account',
      text: [
        'Your AppCrane account was just signed in to from a browser it has not seen before.',
        '',
        `When: ${when}`,
        `Browser: ${ua || 'Unknown browser'}`,
        `IP address: ${ip || 'unknown'}`,
        ...(method ? [`Method: ${method}`] : []),
        '',
        'If this was you, there is nothing to do.',
        '',
        'Not you? Open this link to sign out every session and forget every remembered device on your account,',
        `then change your password (or ask your platform admin to reset it): ${link}`,
        `The link works once and expires in ${REPORT_TTL_DAYS} days.`,
      ].join('\n'),
    });
    return true;
  } catch (_) {
    return false;
  }
}

export function sendLockedMail(user, { untilIso, minutes, ip }) {
  try {
    enqueueEmail({
      appId: null,
      source: 'signin-risk',
      to: user.email,
      subject: '[AppCrane] Password sign-in to your account was paused',
      text: [
        `Too many wrong passwords were entered for your AppCrane account, so password sign-in is paused for ${minutes} minute(s), until ${untilIso.replace('T', ' ').slice(0, 16)} UTC.`,
        `Last attempt from IP address: ${ip || 'unknown'}`,
        '',
        'You can still sign in with single sign-on, or with your password from a browser you have signed in from before. Sessions you already have keep working.',
        'A platform admin can lift the pause early. If these attempts were not you, consider changing your password.',
      ].join('\n'),
    });
    return true;
  } catch (_) {
    return false;
  }
}
