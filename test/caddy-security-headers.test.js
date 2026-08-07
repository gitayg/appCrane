import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Baseline security headers on the generated Caddyfile (v2.35.0).
//
// A credentialed WAS scan found AppCrane's own /api/* responses carried HSTS
// and nosniff while PROXIED app responses (/<slug>) carried neither — the app
// container emits its own headers and Caddy passed them straight through. The
// site-level header block closes that split for every app at once.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-hdr-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
// Parameterized: frame_ancestors is `'self'`, quotes included, which breaks a
// SQL string literal if inlined.
const appId = db.prepare(
  'INSERT INTO apps (name,slug,slot,source_type,frame_ancestors) VALUES (?,?,?,?,?)'
).run('Hdr', 'hdr', 1, 'managed', "'self'").lastInsertRowid;
db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')").run(appId);

const { generateCaddyfile } = await import('../server/services/caddy.js');
const cf = generateCaddyfile();

test('proxied apps inherit the baseline security headers', () => {
  assert.match(cf, /\?Strict-Transport-Security "max-age=31536000; includeSubDomains"/);
  assert.match(cf, /\?X-Content-Type-Options "nosniff"/);
  assert.match(cf, /\?Referrer-Policy "strict-origin-when-cross-origin"/);
  assert.match(cf, /\?Permissions-Policy/);
});

test('server banners are stripped', () => {
  assert.match(cf, /-X-Powered-By/, 'app containers leak X-Powered-By: Express');
  assert.match(cf, /-Server/);
});

test('headers use ? (set-if-absent) so an app can override its own', () => {
  // A bare `header Name value` would clobber a value the app deliberately set,
  // and would double up AppCrane's own Express-set headers.
  for (const h of ['Strict-Transport-Security', 'X-Content-Type-Options', 'Referrer-Policy']) {
    assert.ok(cf.includes(`?${h}`), `${h} must be set-if-absent, not forced`);
    assert.ok(!new RegExp(`^\\s+${h} `, 'm').test(cf), `${h} is being forced rather than defaulted`);
  }
});

test('X-Frame-Options is NOT set globally', () => {
  // Deliberate. A blanket SAMEORIGIN would break the per-app iframe embedding
  // added in v2.24.5/v2.25.0 (Product Hub embeds an SSO-gated app). CSP
  // frame-ancestors supersedes XFO and is emitted per app, where the policy is
  // actually known. Do not "fix" the scanner's Missing-X-Frame-Options finding
  // by adding it here — that trades a shipped feature for a clean report.
  assert.ok(!/\?X-Frame-Options/.test(cf), 'global X-Frame-Options would break app embedding');
  // The per-app frame-ancestors policy must still be emitted.
  assert.match(cf, /frame-ancestors/);
});
