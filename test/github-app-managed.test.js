import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// A managed app still on GitHub can take a GitHub App installation, so the boot
// move onto this host can fetch it from an org that enforces SAML SSO. Once its
// repository is on this host there is nothing on GitHub to authenticate to.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-gh-app-managed-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
const { githubAppEligible } = await import('../server/services/githubCredential.js');

test('connected apps and managed apps still on GitHub can use the GitHub App', () => {
  assert.equal(githubAppEligible({ source_type: 'github' }), true);
  assert.equal(githubAppEligible({ source_type: 'managed', repo_backend: null }), true);
});

test('a managed app whose repository is on this host, and other kinds, cannot', () => {
  assert.equal(githubAppEligible({ source_type: 'managed', repo_backend: 'local' }), false);
  assert.equal(githubAppEligible({ source_type: 'artifact' }), false);
  assert.equal(githubAppEligible(null), false);
});
