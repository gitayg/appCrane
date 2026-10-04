// Pass lifecycle: who may hold which tunnel address, and until when.
export const SUBNET_PREFIX = '10.77.0';   // /24; .1 is the Nesher device itself
const FIRST_HOST = 2, LAST_HOST = 254;
const PURGE_AFTER_MS = 7 * 24 * 3600 * 1000;

export function passStatus(p, now = Date.now()) {
  if (p.revokedAt) return 'revoked';
  if (Date.parse(p.expiresAt) <= now) return 'expired';
  return 'active';
}

export const isLive = (p, now) => passStatus(p, now) === 'active';

/** The lowest tunnel address no live pass holds, or null when the /24 is full. */
export function allocateAddress(passes, now = Date.now()) {
  const used = new Set(passes.filter(p => isLive(p, now)).map(p => p.address));
  for (let h = FIRST_HOST; h <= LAST_HOST; h++) {
    const a = `${SUBNET_PREFIX}.${h}`;
    if (!used.has(a)) return a;
  }
  return null;
}

/** Drop passes that ended more than a week ago, so the history stays short. */
export function purgeOld(passes, now = Date.now()) {
  return passes.filter(p => {
    if (isLive(p, now)) return true;
    const ended = Date.parse(p.revokedAt || p.expiresAt);
    return now - ended < PURGE_AFTER_MS;
  });
}

/** What the Nesher agent should have configured right now. Never includes a private key. */
export function desiredPeers(passes, now = Date.now()) {
  return passes.filter(p => isLive(p, now)).map(p => ({
    publicKey: p.publicKey,
    presharedKey: p.presharedKey,
    allowedIps: `${p.address}/32`,
    expiresAt: Math.floor(Date.parse(p.expiresAt) / 1000),
  }));
}
