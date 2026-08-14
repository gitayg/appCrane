import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';

// Supply chain: verification fails CLOSED, and the build says what it installed.
//
// This file exists because the agent that wrote the implementation shipped, and
// the agent that was to test it died mid-run — so v2.44.0 went out with these
// changes unpinned. Everything here is written against the real exports.
//
// The behaviour that matters: a verifier which waves through its OWN errors can
// be bypassed by breaking it. Before v2.44.0 any GitHub non-2xx or network error
// skipped verification and let the deploy proceed, so an attacker who could make
// the API unreachable — or simply an outage — was indistinguishable from a
// verified commit. Failure is now treated the same as a mismatch unless an
// operator has explicitly said otherwise.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-sc-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { verifyCommitSha } = await import('../server/services/supplyChain.js');
const { ensureDockerfile } = await import('../server/services/dockerfileGen.js');

/** A real git repo, so the local SHA is read the way production reads it. */
function repoAt(sha0 = null) {
  const dir = mkdtempSync(join(tmpdir(), 'sc-repo-'));
  const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe' });
  git('init', '-q');
  git('config', 'user.email', 't@t.test');
  git('config', 'user.name', 't');
  writeFileSync(join(dir, 'f.txt'), sha0 || 'x');
  git('add', '.');
  git('commit', '-qm', 'c');
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
  return { dir, head };
}

const appRow = (over = {}) => ({
  id: 1, slug: 'sc', name: 'SC', branch: 'main',
  source_type: 'github', github_url: 'https://github.com/o/r',
  github_token_encrypted: null, last_managed_push_sha: null, ...over,
});

/** Swap global.fetch for the duration of one call. */
async function withFetch(impl, fn) {
  const real = global.fetch;
  global.fetch = impl;
  try { return await fn(); } finally { global.fetch = real; }
}
// Shape matters: githubHeadSha reads body.commit.sha. An `object.sha` mock (the
// git-refs shape rather than the branch shape) makes every success look like
// "200 with no commit SHA", which fails CLOSED — so the mismatch tests would
// have passed for the wrong reason and proved nothing.
const ok = (sha) => async () => ({
  ok: true, status: 200, json: async () => ({ commit: { sha } }), text: async () => '',
});
const status = (code) => async () => ({
  ok: false, status: code, json: async () => ({}), text: async () => 'nope',
});
const netFail = () => async () => { throw new Error('ECONNREFUSED'); };

function setEnabled(on) {
  db.prepare(`INSERT INTO settings (key,value) VALUES ('supply_chain_verify_enabled', ?)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(on ? '1' : '0');
}
setEnabled(true);

// ---------------------------------------------------------------------------
// Fail-closed
// ---------------------------------------------------------------------------

test('a matching SHA verifies and does not throw — the baseline these tests need', async () => {
  const { dir, head } = repoAt();
  const lines = [];
  const r = await withFetch(ok(head), () => verifyCommitSha(appRow(), dir, 'main', l => lines.push(l)));
  assert.equal(r.verified, true);
  assert.equal(r.localSha, head);
  assert.equal(r.remoteSha, head);
  assert.ok(!r.failOpen, 'a clean verification must not report itself as fail-open');
  assert.ok(lines.some(l => /verify: OK/i.test(l)), `the deploy log does not record the pass: ${JSON.stringify(lines)}`);
});

test('a MISMATCH throws — the check that always worked', async () => {
  const { dir } = repoAt();
  await assert.rejects(
    () => withFetch(ok('0'.repeat(40)), () => verifyCommitSha(appRow(), dir, 'main', () => {})),
    /Supply-chain verify/i,
  );
});

test('a GitHub 500 now BLOCKS the deploy instead of waving it through', async () => {
  // The v2.44.0 fix. Previously any non-2xx skipped verification and proceeded.
  const { dir } = repoAt();
  await assert.rejects(
    () => withFetch(status(500), () => verifyCommitSha(appRow(), dir, 'main', () => {})),
    /Supply-chain verify FAILED/i,
  );
});

test('a network error BLOCKS the deploy too', async () => {
  const { dir } = repoAt();
  await assert.rejects(
    () => withFetch(netFail(), () => verifyCommitSha(appRow(), dir, 'main', () => {})),
    /Supply-chain verify FAILED/i,
  );
});

// ---------------------------------------------------------------------------
// The operator escape hatch, and what it must never do
// ---------------------------------------------------------------------------

test('APPCRANE_REQUIRE_VERIFY=0 rides out an outage but never reports OK', async () => {
  const { dir } = repoAt();
  process.env.APPCRANE_REQUIRE_VERIFY = '0';
  const lines = [];
  try {
    const r = await withFetch(status(503), () => verifyCommitSha(appRow(), dir, 'main', l => lines.push(l)));
    assert.equal(r.verified, false, 'an unverified deploy must not read as verified');
    assert.ok(r.failOpen, 'the result does not record that it proceeded unverified');
    assert.ok(lines.some(l => /NOT VERIFIED/i.test(l)),
      `the deploy log does not say the commit was unverified: ${JSON.stringify(lines)}`);
  } finally { delete process.env.APPCRANE_REQUIRE_VERIFY; }
});

test('the escape hatch does NOT excuse a mismatch', async () => {
  // The distinction the whole design rests on: "could not check" is negotiable,
  // "checked and it is wrong" is not. If the flag suppressed both, an attacker
  // who got it set would have turned verification off entirely.
  const { dir } = repoAt();
  process.env.APPCRANE_REQUIRE_VERIFY = '0';
  try {
    await assert.rejects(
      () => withFetch(ok('0'.repeat(40)), () => verifyCommitSha(appRow(), dir, 'main', () => {})),
      /Supply-chain verify/i,
    );
  } finally { delete process.env.APPCRANE_REQUIRE_VERIFY; }
});

test('the settings kill-switch reports skipped-and-unverified, not verified', async () => {
  const { dir } = repoAt();
  setEnabled(false);
  try {
    const lines = [];
    const r = await verifyCommitSha(appRow(), dir, 'main', l => lines.push(l));
    assert.equal(r.skipped, true);
    assert.equal(r.verified, false, 'a disabled check must never look like a passing one');
    assert.ok(lines.some(l => /NOT verified/i.test(l)));
  } finally { setEnabled(true); }
});

test('a managed app is verified against GitHub, not only against our own record', async () => {
  // Pinning the fix. source_type='managed' used to compare the clone against
  // app.last_managed_push_sha — a value AppCrane wrote itself, so it verified
  // nothing. A managed app whose local SHA matches our record must STILL fail
  // when GitHub disagrees.
  const { dir, head } = repoAt();
  const managed = appRow({ source_type: 'managed', last_managed_push_sha: head });
  await assert.rejects(
    () => withFetch(ok('1'.repeat(40)), () => verifyCommitSha(managed, dir, 'main', () => {})),
    /Supply-chain verify/i,
    'a managed app passed on our own stored SHA while GitHub reported a different commit',
  );
});

// ---------------------------------------------------------------------------
// Lockfile and dependency scanning in the generated build
// ---------------------------------------------------------------------------

function genDir({ lock = null } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sc-app-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'a', version: '1.0.0' }));
  if (lock) writeFileSync(join(dir, lock), '{}');
  return dir;
}
const gen = (dir, manifest = { be: { entry: 'node server.js' } }) =>
  ensureDockerfile({ releaseDir: dir, manifest, appBasePath: '/a', craneUrl: 'https://c', craneInternalUrl: 'http://h' });

test('a missing lockfile is reported, and a present one is not', async () => {
  const without = gen(genDir());
  const withLock = gen(genDir({ lock: 'package-lock.json' }));
  const text = JSON.stringify(without);
  assert.match(text, /lockfile|reproducib/i,
    'a build with no lockfile said nothing about it — npm install re-resolves every dependency');
  assert.doesNotMatch(JSON.stringify(withLock), /has no lockfile/i,
    'an app WITH a lockfile was warned anyway; the detector fires on everything');
});

test('the generated Dockerfile runs a dependency scan', async () => {
  const dir = genDir({ lock: 'package-lock.json' });
  gen(dir);
  const df = readFileSync(join(dir, 'Dockerfile'), 'utf8');
  assert.match(df, /npm audit|osv/i,
    'the generated build installs tenant dependencies and never checks them for known vulnerabilities');
});

test('the lockfile rule is lenient by default and strict on request', async () => {
  // Follows the APPCRANE_REQUIRE_NONROOT pattern: shipping strict would fail the
  // next deploy of every lockfile-less app at once, which is an outage, not a fix.
  assert.doesNotThrow(() => gen(genDir()), 'a missing lockfile blocks a deploy by default');
  process.env.APPCRANE_REQUIRE_LOCKFILE = '1';
  try {
    assert.throws(() => gen(genDir()), /lockfile/i,
      'APPCRANE_REQUIRE_LOCKFILE=1 did not make the missing lockfile fatal — the switch is inert');
    assert.doesNotThrow(() => gen(genDir({ lock: 'package-lock.json' })),
      'strict mode rejected an app that HAS a lockfile');
  } finally { delete process.env.APPCRANE_REQUIRE_LOCKFILE; }
});
