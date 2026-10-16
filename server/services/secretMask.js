import crypto from 'crypto';
import { deriveSecret } from './encryption.js';

// Shared by appcrane_get_secret (MCP) and the masked env-var list (REST), so
// both doors describe a value the same way without handing it over.
// Keyed with a secret derived from the instance key: anyone who can list an
// app's env vars sees the fingerprint, and a plain hash of a short secret could
// be checked against guesses offline. Same value, same fingerprint, on this
// instance only.
export function secretFingerprint(plain) {
  return crypto.createHmac('sha256', deriveSecret('env-var-fingerprint')).update(plain).digest('hex').slice(0, 8);
}

// Last 3 chars only when the value is long enough that 3 chars is a small
// fraction; otherwise mask entirely (don't leak short passwords).
export function secretPreview(plain) {
  const len = plain.length;
  return len >= 10 ? `${'•'.repeat(Math.min(len - 3, 8))}${plain.slice(-3)}` : '•'.repeat(Math.min(len, 8));
}

export function opaquePreview(plain) {
  return '•'.repeat(Math.min(plain.length, 8));
}
