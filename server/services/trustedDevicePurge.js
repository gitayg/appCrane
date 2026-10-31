import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { jobStarted, trackJob } from './jobHealth.js';
import { purgeExpiredDevices } from './trustedDevices.js';

// Daily removal of expired MFA trusted-device rows. Expired rows are already
// refused at sign-in (trustedDevices.js checks expiry on every use), so this
// only keeps the table and the user's device list from collecting dead rows.
// Same shape as eventRetention.js.

const DAY = 86_400_000;
const FIRST_RUN_DELAY_MS = 10 * 60_000;
let timers = [];

export async function runTrustedDevicePurge(db = getDb(), now = Date.now()) {
  const n = purgeExpiredDevices(db, now);
  if (n) log.info(`[mfa] removed ${n} expired trusted device(s)`);
  return n;
}

export function startTrustedDevicePurge() {
  if (timers.length) return;
  jobStarted('mfa-trusted-device-purge');
  const run = () => trackJob('mfa-trusted-device-purge', () => runTrustedDevicePurge())
    .catch(e => log.warn(`[mfa] trusted-device purge failed: ${e.message}`));
  const first = setTimeout(run, FIRST_RUN_DELAY_MS);
  const daily = setInterval(run, DAY);
  first.unref?.();
  daily.unref?.();
  timers = [first, daily];
}

export function stopTrustedDevicePurge() {
  for (const t of timers) { clearTimeout(t); clearInterval(t); }
  timers = [];
}
