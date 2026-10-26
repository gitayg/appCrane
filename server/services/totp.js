import crypto from 'crypto';

// RFC 4226 (HOTP) and RFC 6238 (TOTP) on Node's crypto, no dependency.
// SHA1 is the default because every authenticator app implements it; SHA256 is
// offered for deployments that want a SHA-2 HMAC (several apps ignore the
// otpauth `algorithm` parameter and always compute SHA1, so SHA256 only works
// with an app that honours it).

export const PERIOD_SECONDS = 30;
export const DIGITS = 6;
export const ALGORITHMS = Object.freeze(['SHA1', 'SHA256']);

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error('invalid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function normalizeAlgorithm(alg) {
  const a = String(alg || 'SHA1').toUpperCase().replace('-', '');
  return ALGORITHMS.includes(a) ? a : null;
}

export function hotp(secret, counter, { algorithm = 'SHA1', digits = DIGITS } = {}) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac(algorithm.toLowerCase(), secret).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export function timeStep(nowMs = Date.now(), period = PERIOD_SECONDS) {
  return Math.floor(nowMs / 1000 / period);
}

export function totp(secret, nowMs = Date.now(), opts = {}) {
  return hotp(secret, timeStep(nowMs, opts.period || PERIOD_SECONDS), opts);
}

/**
 * The time step a code matches within ±window steps, or null. The caller
 * decides about replay: it must refuse a step it has already accepted.
 */
export function matchStep(secret, code, { nowMs = Date.now(), algorithm = 'SHA1', window = 1, digits = DIGITS } = {}) {
  const c = String(code || '').replace(/\s/g, '');
  if (!new RegExp(`^\\d{${digits}}$`).test(c)) return null;
  const now = timeStep(nowMs);
  let found = null;
  for (let d = -window; d <= window; d++) {
    const candidate = hotp(secret, now + d, { algorithm, digits });
    if (crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(c)) && found === null) found = now + d;
  }
  return found;
}

export function generateSecret(algorithm = 'SHA1') {
  return crypto.randomBytes(algorithm === 'SHA256' ? 32 : 20);
}

export function otpauthUri({ secretB32, account, issuer = 'AppCrane', algorithm = 'SHA1' }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const p = new URLSearchParams({ secret: secretB32, issuer, algorithm, digits: String(DIGITS), period: String(PERIOD_SECONDS) });
  return `otpauth://totp/${label}?${p.toString()}`;
}
