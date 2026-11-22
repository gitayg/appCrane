import { AppError } from '../../utils/errors.js';
import { knownDeviceFor, noteSuccessfulSignIn } from './devices.js';
import { clearSubject, lockState, recordPasswordFailure, subjectFor } from './lockout.js';
import { elevatedThrottle, noteFailure } from './stuffing.js';
import { KINDS, signal } from './signals.js';

// What the sign-in routes call. Each hook is one line at its call site.

export const LOCKED_MESSAGE = 'Too many failed sign-in attempts for this account. Try again later, sign in with single sign-on, or ask a platform admin.';

/**
 * Before a password is checked. Throws 429 when the source network is under
 * the raised stuffing throttle or the subject is locked; the password is
 * then never evaluated, so a locked answer says nothing about it. Returns the
 * context the failure / success hooks need.
 */
export function guardPasswordAttempt(db, req, res, { user, login, ip }) {
  const wait = elevatedThrottle(ip);
  if (wait) {
    res.set('Retry-After', String(wait));
    throw new AppError('Too many sign-in attempts from your network. Try again in a minute.', 429, 'RATE_LIMITED');
  }
  const knownDevice = user ? knownDeviceFor(db, req, user.id) : null;
  const key = subjectFor({ user, login, knownDevice });
  const state = lockState(db, key);
  if (state.locked) {
    if (user) {
      signal({
        kind: KINDS.lockedRefused, severity: 'info', subjectUserId: user.id,
        summary: 'Password sign-in refused: account locked',
        data: { ip, subject: key.split(':')[0], until: state.until },
        dedupeKey: `locked-refused:${key}`, dedupeMs: 60_000,
      });
    }
    res.set('Retry-After', String(state.retry_after_s));
    throw new AppError(LOCKED_MESSAGE, 429, 'SIGNIN_LOCKED');
  }
  return { key, knownDevice };
}

export function onPasswordFailure(db, ctx, { user, login, ip, method = 'password' }) {
  try { noteFailure(ip, user ? `u:${user.id}` : `l:${String(login || '').trim().toLowerCase()}`, { method: 'password' }); } catch (_) {}
  return recordPasswordFailure(db, { key: ctx.key, user, ip, method });
}

export function onPasswordSuccess(db, ctx) {
  try { clearSubject(db, ctx.key); } catch (_) {}
}

export function onSignInSuccess(req, res, user, { method, ip }) {
  return noteSuccessfulSignIn(req, res, user, { method, ip });
}

/** An unknown API key from ip: feeds the stuffing signal (distinct keys per network). */
export function onApiKeyFailure(ip, keyHash) {
  try { noteFailure(ip, keyHash, { method: 'api_key' }); } catch (_) {}
}

/** A failed OAuth client authentication (/oauth/token, /oauth/revoke): distinct client ids per network. */
export function onOAuthClientFailure(ip, clientId) {
  try { noteFailure(ip, String(clientId ?? ''), { method: 'oauth_client' }); } catch (_) {}
}
