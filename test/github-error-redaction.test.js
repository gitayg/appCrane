import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Service-account error redaction (v2.31.1).
//
// MCP tool errors propagate verbatim through callTool to the caller's agent,
// and app OWNERS call those tools. So any string thrown out of githubService
// is effectively public to every owner of a managed app. It used to carry
// `/repos/<service-account>/AMC_<slug>`, which handed owners the platform's
// privileged GitHub identity, the internal naming convention, and the live
// health of the shared credential.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-ghred-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
initDb();

const SECRET_OWNER = 'super-secret-service-acct';
const { setServiceConfig } = await import('../server/services/githubService.js');
setServiceConfig({ owner: SECRET_OWNER, token: 'ghp_fake_token_value', enabled: true });

const { apiFetch } = await import('../server/services/githubService.js');

const realFetch = globalThis.fetch;
after(() => { globalThis.fetch = realFetch; });

function stub(status, body) {
  globalThis.fetch = async () => ({
    ok: false,
    status,
    statusText: 'Error',
    text: async () => JSON.stringify(body),
  });
}

async function grab(status, body, path) {
  stub(status, body);
  try {
    await apiFetch(path);
    assert.fail('expected apiFetch to throw');
  } catch (e) { return e; }
}

test('a 401 never names the service account or the repo path', async () => {
  const err = await grab(401, { message: 'Bad credentials' },
    `/repos/${SECRET_OWNER}/AMC_media-firewall-v2`);

  assert.ok(!err.message.includes(SECRET_OWNER), `message leaked the account: ${err.message}`);
  assert.ok(!err.message.includes('AMC_media-firewall-v2'), `message leaked the repo: ${err.message}`);
  assert.ok(!err.message.includes('/repos/'), 'message leaked the API path');
  // Still actionable, and points at the right person.
  assert.match(err.message, /platform admin/i);
  assert.match(err.message, /401/);
});

test('the full detail survives for the server log, off the public message', async () => {
  const err = await grab(401, { message: 'Bad credentials' },
    `/repos/${SECRET_OWNER}/AMC_x`);
  assert.ok(err.detail.includes(SECRET_OWNER), 'detail keeps the real path for operators');
  assert.notEqual(err.detail, err.message, 'detail and message must not be the same string');
  assert.equal(err.status, 401);
  assert.equal(err.serviceAccount, true);
});

test('other statuses are redacted too', async () => {
  for (const status of [403, 404, 422, 429, 500]) {
    const err = await grab(status, { message: `boom ${SECRET_OWNER}` },
      `/repos/${SECRET_OWNER}/AMC_y`);
    assert.ok(!err.message.includes('/repos/'), `${status} leaked the path`);
    // 422 echoes GitHub's own validation text, which is the one case where the
    // upstream message is genuinely useful — assert the PATH is still gone.
    if (status !== 422) {
      assert.ok(!err.message.includes(SECRET_OWNER), `${status} leaked the account: ${err.message}`);
    }
  }
});
