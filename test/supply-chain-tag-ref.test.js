import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';

// An app pinned to a release tag (app.branch = 'v0.3.0', set by the catalogue
// install pinning the latest release) failed every production deploy: the
// verifier asked GitHub's /branches/v0.3.0, got 404 "Branch not found", and
// refused the container swap. Measured against a public repo: /branches/<tag>
// is 404, /commits/refs/tags/<tag> is 200 with a top-level `sha`.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-sctag-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
db.prepare(`INSERT INTO settings (key,value) VALUES ('supply_chain_verify_enabled', '1')
            ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run();

const { verifyCommitSha } = await import('../server/services/supplyChain.js');

function repoAt() {
  const dir = mkdtempSync(join(tmpdir(), 'sctag-repo-'));
  const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe' });
  git('init', '-q');
  git('config', 'user.email', 't@t.test');
  git('config', 'user.name', 't');
  writeFileSync(join(dir, 'f.txt'), 'x');
  git('add', '.');
  git('commit', '-qm', 'c');
  git('tag', 'v0.3.0');
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
  return { dir, head };
}

const appRow = () => ({
  id: 1, slug: 'sctag', name: 'SC Tag', branch: 'v0.3.0',
  source_type: 'github', github_url: 'https://github.com/o/r',
  github_token_encrypted: null, last_managed_push_sha: null,
});

const BRANCH_URL = 'https://api.github.com/repos/o/r/branches/v0.3.0';
const TAG_URL = 'https://api.github.com/repos/o/r/commits/refs/tags/v0.3.0';

const res = (code, body) => ({
  ok: code >= 200 && code < 300, status: code,
  json: async () => body, text: async () => JSON.stringify(body),
});

/** Route global.fetch by URL for one call, recording every URL requested. */
async function withRoutes(routes, fn) {
  const seen = [];
  const real = global.fetch;
  global.fetch = async (url) => {
    seen.push(String(url));
    const h = routes[String(url)];
    return h ? h() : res(404, { message: 'Not Found' });
  };
  try { return { result: await fn(), seen }; } finally { global.fetch = real; }
}

test('a tag ref whose commit matches HEAD verifies, and the log names the tag', async () => {
  const { dir, head } = repoAt();
  const lines = [];
  const { result, seen } = await withRoutes({
    [BRANCH_URL]: () => res(404, { message: 'Branch not found' }),
    [TAG_URL]: () => res(200, { sha: head, commit: { tree: { sha: 'f'.repeat(40) } } }),
  }, () => verifyCommitSha(appRow(), dir, 'v0.3.0', (l) => lines.push(l)));
  assert.equal(result.verified, true);
  assert.equal(result.remoteSha, head);
  assert.deepEqual(seen, [BRANCH_URL, TAG_URL]);
  assert.ok(lines.some((l) => l.includes(`matches GitHub o/r tag v0.3.0`)), JSON.stringify(lines));
});

test('a tag ref whose commit differs from HEAD throws a mismatch', async () => {
  const { dir } = repoAt();
  await assert.rejects(
    withRoutes({
      [BRANCH_URL]: () => res(404, { message: 'Branch not found' }),
      [TAG_URL]: () => res(200, { sha: '0'.repeat(40) }),
    }, () => verifyCommitSha(appRow(), dir, 'v0.3.0', () => {})),
    /does not match GitHub's o\/r tag v0\.3\.0/,
  );
});

test('a ref that exists as a branch never asks for the tag', async () => {
  const { dir, head } = repoAt();
  const lines = [];
  const { result, seen } = await withRoutes({
    [BRANCH_URL]: () => res(200, { commit: { sha: head } }),
    [TAG_URL]: () => { throw new Error('tag endpoint must not be requested'); },
  }, () => verifyCommitSha(appRow(), dir, 'v0.3.0', (l) => lines.push(l)));
  assert.equal(result.verified, true);
  assert.deepEqual(seen, [BRANCH_URL]);
  assert.ok(lines.some((l) => l.includes('matches GitHub o/r@v0.3.0')), JSON.stringify(lines));
});

test('a 404 on both branch and tag fails closed', async () => {
  const { dir } = repoAt();
  const seen = [];
  const real = global.fetch;
  global.fetch = async (url) => { seen.push(String(url)); return res(404, { message: 'Not Found' }); };
  try {
    await assert.rejects(
      verifyCommitSha(appRow(), dir, 'v0.3.0', () => {}),
      /Supply-chain verify FAILED: could not confirm the deploying commit/,
    );
  } finally { global.fetch = real; }
  assert.deepEqual(seen, [BRANCH_URL, TAG_URL]);
});

test('a branch mismatch does not fall through to the tag', async () => {
  const { dir } = repoAt();
  const seen = [];
  const real = global.fetch;
  global.fetch = async (url) => {
    seen.push(String(url));
    return String(url) === BRANCH_URL ? res(200, { commit: { sha: '0'.repeat(40) } }) : res(200, { sha: '0'.repeat(40) });
  };
  try {
    await assert.rejects(verifyCommitSha(appRow(), dir, 'v0.3.0', () => {}), /does not match GitHub's o\/r@v0\.3\.0/);
  } finally { global.fetch = real; }
  assert.ok(!seen.includes(TAG_URL), JSON.stringify(seen));
});
