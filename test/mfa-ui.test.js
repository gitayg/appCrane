import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { createHash } from 'crypto';

// SPA side of local MFA and the inactivity sign-out: the dependency-free QR
// encoder, the idle-timer arithmetic, and the sign-in screen's second step.

const { encodeQr } = await import('../studio-web/src/components/mfa/qr.ts');
const idle = await import('../studio-web/src/components/mfa/idle.ts');
const read = (p) => readFileSync(new URL(`../studio-web/src/${p}`, import.meta.url), 'utf8');

const URI = 'otpauth://totp/AppCrane:alice%40example.test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=AppCrane&algorithm=SHA1&digits=6&period=30';
const fingerprint = (m) => createHash('sha256').update(m.map(r => r.map(b => (b ? 1 : 0)).join('')).join('\n')).digest('hex');

test('the QR encoder output is pinned to matrices a real decoder read back', () => {
  // Both matrices were rendered to PNG and decoded with macOS CoreImage
  // (CIDetectorTypeQRCode) to the exact input text on 2026-10-21, along with
  // 193-, 400- and 1200-character inputs (versions 10, 15, 29). A change to
  // the encoder that alters the output has to be re-verified the same way.
  const m = encodeQr(URI);
  assert.equal(m.length, 49, 'version 8 at level M for a 134-byte URI');
  assert.equal(fingerprint(m), '14b329cc69b37c669aad6778688fbf1bfaf83a6173859e75db21513cd3ff359a');
  const small = encodeQr('hi');
  assert.equal(small.length, 21);
  assert.equal(fingerprint(small), '81240590f3a630b03aa70a8aaf521ec30c4911af3307da27eeb2126afcb5b39a');
});

test('QR structure: three finder patterns and the fixed dark module', () => {
  const m = encodeQr(URI);
  const n = m.length;
  const finderAt = (x0, y0) => {
    for (let dy = 0; dy < 7; dy++) for (let dx = 0; dx < 7; dx++) {
      const ring = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
      assert.equal(m[y0 + dy][x0 + dx], ring !== 2, `finder at ${x0},${y0} cell ${dx},${dy}`);
    }
  };
  finderAt(0, 0); finderAt(n - 7, 0); finderAt(0, n - 7);
  assert.equal(m[n - 8][8], true);
});

test('idle state: active, then a warning in the last two minutes, then expired', () => {
  const t0 = 1_800_000_000_000;
  assert.deepEqual(idle.idleState(t0 + 27 * 60_000, t0, 30, 120), { phase: 'active' });
  assert.deepEqual(idle.idleState(t0 + 28 * 60_000 + 1000, t0, 30, 120), { phase: 'warn', secondsLeft: 119 });
  assert.deepEqual(idle.idleState(t0 + 30 * 60_000, t0, 30, 120), { phase: 'expired' });
  assert.equal(idle.formatCountdown(119), '1:59');
  assert.equal(idle.signedOutMessage('30'), 'You were signed out after 30 minutes of inactivity.');
  assert.equal(idle.signedOutMessage(null), null);
});

test('the sign-in screen runs the second step instead of storing a missing token', () => {
  const login = read('components/Login.tsx');
  assert.match(login, /data\.error\?\.code === 'MFA_REQUIRED'/);
  assert.match(login, /data\.error\?\.code === 'MFA_ENROLL_REQUIRED'/);
  assert.match(login, /'\/api\/identity\/mfa\/verify'/);
  assert.match(login, /'\/api\/identity\/mfa\/enroll\/confirm'/);
  const pass = login.slice(login.indexOf('const doPassLogin'), login.indexOf('async function mfaPost'));
  assert.ok(pass.indexOf('MFA_REQUIRED') < pass.indexOf("localStorage.setItem('cc_identity_token'"),
    'the MFA branch must come before the token is stored, or an undefined token is saved');
  assert.match(login, /takeSignedOutMessage\(\)/, 'the inactivity sign-out message is shown');
});

test('the idle guard signs out through the server and leaves the note for the sign-in screen', () => {
  const guard = read('components/mfa/IdleSessionGuard.tsx');
  assert.match(guard, /fetch\('\/api\/identity\/logout'/);
  assert.match(guard, /sessionStorage\.setItem\(IDLE_SIGNED_OUT_KEY/);
  assert.match(guard, /localStorage\.removeItem\('cc_identity_token'\)/);
});
