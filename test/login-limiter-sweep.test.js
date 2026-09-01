import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The login rate limiter must not leak a Map entry per source IP (v2.55.1).
//
// checkLoginRateLimit only ever replaces a bucket when THAT ip comes back after
// its window has closed. An address that tries once and never returns keeps its
// entry for the life of the process, so every distinct IP that touches
// /api/identity/login costs permanent memory — and the endpoint hit from many
// addresses is precisely this one, which makes the growth fastest under the
// attack the limiter exists to blunt.
//
// index.js already sweeps _apiRateMap on a 5-minute interval. The login limiter
// was written without one. This covers the sweep, not the limiting: the 5/min
// behaviour was already correct and is asserted here only to prove the sweep
// does not break it.
//
// `now` is injected rather than slept through — a test that waits 60 real
// seconds to watch a window close is a test people delete.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-loginsweep-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb } = await import('../server/db.js');
initDb();
const { checkLoginRateLimit, _sweepLoginAttempts } = await import('../server/routes/identity.js');

const T0 = 1_800_000_000_000; // a fixed instant; the limiter only does arithmetic on it

test('the limiter still allows 5 attempts a minute and refuses the 6th', () => {
  const ip = '203.0.113.10';
  for (let i = 0; i < 5; i++) {
    assert.equal(checkLoginRateLimit(ip, T0), true, `attempt ${i + 1} should be allowed`);
  }
  assert.equal(checkLoginRateLimit(ip, T0), false, 'the 6th attempt in the window must be refused');
});

test('a fresh window reopens after 60s', () => {
  const ip = '203.0.113.11';
  for (let i = 0; i < 5; i++) checkLoginRateLimit(ip, T0);
  assert.equal(checkLoginRateLimit(ip, T0), false);
  assert.equal(checkLoginRateLimit(ip, T0 + 60_001), true, 'the window is 60s, not permanent');
});

test('expired buckets are collected', () => {
  // A thousand addresses that each try once and never come back — a botnet
  // spraying one password, or just a month of ordinary traffic.
  for (let i = 0; i < 1000; i++) checkLoginRateLimit(`198.51.100.${i % 256}.${i}`, T0);

  const before = _sweepLoginAttempts(T0); // nothing expired yet
  assert.ok(before >= 1000, `expected the buckets to still be held, got ${before}`);

  // Swept well past every window opened by the earlier tests too — this module's
  // Map is shared across them, and a sweep at T0+60_001 would leave the bucket
  // the previous test reopened at T0+60_001 (resetAt T0+120_001) still live.
  const after = _sweepLoginAttempts(T0 + 200_000);
  assert.equal(after, 0,
    'every bucket was more than 60s old and none were collected — this is the leak: one Map ' +
    'entry per source IP, held for the life of the process');
});

test('the sweep never evicts a bucket that is still counting', () => {
  const stale = '203.0.113.20';
  const active = '203.0.113.21';
  checkLoginRateLimit(stale, T0);
  checkLoginRateLimit(active, T0 + 59_000); // window closes at T0+119_000

  _sweepLoginAttempts(T0 + 60_001);

  // The active bucket must have kept its count, or an attacker could clear
  // their own limit by waiting for a sweep.
  for (let i = 0; i < 4; i++) checkLoginRateLimit(active, T0 + 59_000);
  assert.equal(checkLoginRateLimit(active, T0 + 59_000), false,
    'the surviving bucket lost its count — a sweep must not reset a window that is still open');
});

test('the sweep timer does not hold the process open', async () => {
  // A bare setInterval in a module that route tests import keeps `node --test`
  // alive after the assertions finish, which looks like a hung suite.
  const src = await import('fs').then((fs) =>
    fs.readFileSync(new URL('../server/routes/identity.js', import.meta.url), 'utf8'));
  assert.match(src, /_loginSweeper\.unref\?\.\(\)/,
    'the interval must be unref()d or it pins the event loop');
});
