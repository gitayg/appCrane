import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Environment sleep for production on a custom domain. With custom_domain_auth
// the domain's requests pass forward_auth (so AppCrane sees them) and, while
// sleep is on, its site block carries the same wake rewrite as an app host, so
// production may sleep there. Without custom_domain_auth the domain is a
// passthrough AppCrane cannot see: production stays ineligible, with the
// reason. env-sleep-custom-domain-live.test.js runs it through a real caddy:2.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-env-sleep-cd-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const policy = await import('../server/services/sleepPolicy.js');
const { generateCaddyfile, setAccessLogDirCheck } = await import('../server/services/caddy.js');
const { originalTarget } = await import('../server/services/sleepWakeHandler.js');
setAccessLogDirCheck(() => true);

let slot = 400;
function mkApp(slug, { domain = null, cda = 0, authMode = 'authenticated' } = {}) {
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,auth_mode,domain,custom_domain_auth) VALUES (?,?,?,'managed',?,?,?)")
    .run(slug, slug, ++slot, authMode, domain, cda).lastInsertRowid);
  for (const env of ['sandbox', 'production']) {
    db.prepare("INSERT INTO deployments (app_id, env, status, started_at, finished_at) VALUES (?, ?, 'live', datetime('now'), datetime('now'))").run(id, env);
  }
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const signedIn = mkApp('cdauth', { domain: 'cdauth.example.test', cda: 1 });
const passthrough = mkApp('cdopen', { domain: 'cdopen.example.test', cda: 0 });
const headless = mkApp('cdheadless', { domain: 'cdheadless.example.test', cda: 1, authMode: 'headless' });

function siteBlock(cf, host) {
  const start = cf.indexOf(`\n${host} {\n`);
  assert.ok(start >= 0, `no site block for ${host}`);
  const end = cf.indexOf('\n}\n', start);
  return cf.slice(start, end + 3);
}

test('eligibility: a custom domain with AppCrane sign-in no longer blocks production sleep; a passthrough one still does, with the reason', () => {
  assert.deepEqual(policy.sleepBlockers(db, signedIn, 'production'), []);
  const open = policy.sleepBlockers(db, passthrough, 'production');
  assert.equal(open.length, 1);
  assert.match(open[0], /custom domain without AppCrane sign-in \(custom_domain_auth\), so AppCrane does not see its requests/);
  assert.ok(policy.sleepBlockers(db, headless, 'production').some((r) => /custom domain without AppCrane sign-in/.test(r)), 'a headless app is passthrough on its domain too');
  assert.deepEqual(policy.sleepBlockers(db, passthrough, 'sandbox'), [], 'the sandbox is never served on the custom domain');
});

test('Caddyfile: the signed-in custom domain gets the wake rewrite only while sleep is on; the passthrough never does', () => {
  db.prepare('DELETE FROM app_sleep_policy').run();
  policy.setPlatformPolicy(db, { sandbox_idle_minutes: 0, inactive_days: 0, sandbox_schedule: 'off' }, null);
  const off = generateCaddyfile();
  // Sleep off, the only error handler is Caddy's own page (services/caddyErrorPage.js).
  assert.doesNotMatch(siteBlock(off, 'cdauth.example.test'), /_crashed|X-AppCrane-Wake|@cranedown/, 'sleep off must leave the block as it was');

  policy.setAppPolicy(db, signedIn.id, { inactive_days: 7 }, null);
  try {
    const token = policy.wakeToken(db);
    const on = generateCaddyfile();
    const block = siteBlock(on, 'cdauth.example.test');
    assert.match(block, new RegExp(`handle_errors \\{\\n {8}@appdown expression \`\\{err\\.status_code\\} in \\[502, 503, 504\\]\`\\n[\\s\\S]*?\\n {8}handle @appdown \\{\\n {12}rewrite \\* /api/_crashed/cdauth\\{uri\\}\\n {12}request_header X-AppCrane-Wake "${token}"\\n {12}reverse_proxy 127\\.0\\.0\\.1:5001`));
    assert.match(block, /forward_auth 127\.0\.0\.1:5001 \{\n {16}uri \/api\/identity\/verify\?app=cdauth&env=production&host=isolated/);
    assert.doesNotMatch(block, /uri strip_prefix|@appcrane_compat/, 'a custom domain has no /<slug> prefix to undo');
    assert.doesNotMatch(siteBlock(on, 'cdopen.example.test'), /_crashed|X-AppCrane-Wake/);
    assert.doesNotMatch(siteBlock(on, 'cdheadless.example.test'), /_crashed|X-AppCrane-Wake/);
  } finally {
    db.prepare('DELETE FROM app_sleep_policy').run();
  }
});

test('the wake 307 on a custom domain goes back to the path the client asked for, without the slug', () => {
  const target = (url, host) => originalTarget(db, { originalUrl: url, headers: { host } }, 'cdauth', 'production', 'cdauth');
  assert.equal(target('/api/_crashed/cdauth/a/b?c=1', 'cdauth.example.test'), '/a/b?c=1');
  assert.equal(target('/api/_crashed/cdauth', 'CDAUTH.example.test:443'), '/');
  assert.equal(target('/api/_crashed/cdauth/a', 'crane.test.local'), '/cdauth/a', 'the platform host keeps its /<slug> mount');
  assert.equal(target('/api/_crashed/cdauth/a', 'cdopen.example.test'), '/cdauth/a', 'another app\'s domain is not this app\'s');
  assert.equal(target('/api/_crashed/cdauth//evil.example/x', 'cdauth.example.test'), '/evil.example/x', 'a protocol-relative Location escaped');
});
