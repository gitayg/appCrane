/**
 * Supply-chain SHA verification (v2.3.6+).
 *
 * After a deploy clones the app repo, AppCrane asks GitHub directly what
 * the head SHA of the deploying branch is and compares it to whatever
 * the local working tree has at HEAD. Any mismatch fails the deploy
 * before the container swap — defending against:
 *
 *   * a compromised PAT pushing a malicious commit to a *different* ref
 *     and the deploy picking it up by accident
 *   * a poisoned mid-box rewriting bytes on the wire (HTTPS makes this
 *     hard but not impossible — pinning belt+braces)
 *   * a malicious git mirror serving different content for the same URL
 *
 * It does NOT protect against compromise of GitHub itself, nor against
 * legitimate-but-unwanted commits made by an attacker who controls the
 * user's GitHub account. Those need different mitigations (signed
 * commits, branch protection rules).
 *
 * Toggleable via the supply_chain_verify_enabled setting (default '1' on
 * fresh installs; operators on air-gapped or offline boxes flip to '0').
 */

import { getDb } from '../db.js';
import { decrypt } from './encryption.js';
import { getServiceTokenInternal } from './githubService.js';
import { execFileSync } from 'child_process';
import log from '../utils/logger.js';

/**
 * Parse a github.com URL into { owner, repo }. Returns null for
 * non-github URLs (so the caller can skip verification gracefully on
 * self-hosted-git installs).
 */
function parseGithubUrl(url) {
  if (!url) return null;
  try {
    const u = new URL(url);
    if (!/(?:^|\.)github\.com$/.test(u.hostname)) return null;
    const parts = u.pathname.replace(/^\/+|\/+$/g, '').replace(/\.git$/, '').split('/');
    if (parts.length < 2) return null;
    return { owner: parts[0], repo: parts[1] };
  } catch (_) {
    return null;
  }
}

/**
 * Pick the right token for cross-checking against GitHub:
 *   - source_type='managed' apps use the service-account token
 *   - source_type='github' apps with a stored PAT use that
 *   - public repos can verify unauthenticated (60 req/hr/IP)
 */
function authForApp(app) {
  if (app.source_type === 'managed') {
    return getServiceTokenInternal();
  }
  if (app.github_token_encrypted) {
    try { return decrypt(app.github_token_encrypted); } catch (_) { return null; }
  }
  return null;
}

function isVerifyEnabled() {
  try {
    const row = getDb().prepare("SELECT value FROM settings WHERE key = 'supply_chain_verify_enabled'").get();
    return (row?.value ?? '1') === '1';
  } catch (_) {
    return true; // fail-open on settings read failure rather than blocking deploys system-wide
  }
}

/**
 * Verify the cloned working tree's HEAD SHA matches GitHub's claim for
 * the same branch. Throws on mismatch; resolves silently on match or
 * skip. Skip cases:
 *   - setting disabled
 *   - non-github URL (self-hosted git)
 *   - GitHub API call fails (network down, rate-limited) — we log a
 *     warning and proceed; failing-closed on transient network problems
 *     would brick deploys for everyone the moment GitHub has a hiccup.
 *
 * Caller (deployer.js) provides:
 *   - app:        full apps row (source_type, github_url, github_token_encrypted)
 *   - releaseDir: absolute path to the cloned working tree
 *   - branch:     branch name that was checked out (defaults to app.branch)
 *   - appendLog:  callback to write into the deploy log
 */
export async function verifyCommitSha(app, releaseDir, branch, appendLog) {
  if (!isVerifyEnabled()) {
    appendLog?.('Supply-chain verify: skipped (disabled in settings).');
    return { skipped: true, reason: 'disabled' };
  }
  const parsed = parseGithubUrl(app.github_url);
  if (!parsed) {
    appendLog?.('Supply-chain verify: skipped (not a github.com URL).');
    return { skipped: true, reason: 'non-github' };
  }

  // Local SHA from the cloned tree
  let localSha;
  try {
    localSha = execFileSync('git', ['-C', releaseDir, 'rev-parse', 'HEAD'], { timeout: 5000 })
      .toString().trim();
  } catch (e) {
    throw new Error(`supply-chain verify: failed to read local HEAD: ${e.message}`);
  }
  if (!/^[0-9a-f]{40}$/.test(localSha)) {
    throw new Error(`supply-chain verify: local HEAD '${localSha}' is not a 40-char SHA`);
  }

  // v2.10.2: managed apps — AppCrane authored the commit and pushed it to the
  // AMC_* mirror, then deploys immediately. GitHub's branch-API HEAD is
  // eventually-consistent and lags the push ~1s, so comparing the clone HEAD
  // to a fresh GitHub query is a read-after-write race (false FAIL on the first
  // deploy after every push). The external-tampering threat model doesn't apply
  // here, so verify against the SHA we recorded at push time instead — race-free
  // and still catches a genuinely-stale clone (clone HEAD != what we pushed).
  if (app.source_type === 'managed') {
    const expected = app.last_managed_push_sha;
    if (!expected || !/^[0-9a-f]{40}$/.test(expected)) {
      appendLog?.('Supply-chain verify: skipped (managed app, no recorded push SHA to compare).');
      return { skipped: true, reason: 'managed-no-sha', localSha };
    }
    if (expected !== localSha) {
      throw new Error(
        `Supply-chain verify FAILED: managed clone HEAD ${localSha.slice(0, 12)}… does not match the last pushed commit ${expected.slice(0, 12)}…. ` +
        `The clone is stale — re-run the deploy so it fetches the pushed commit.`
      );
    }
    appendLog?.(`Supply-chain verify: OK (managed clone HEAD matches last pushed commit ${localSha.slice(0, 12)}).`);
    return { skipped: false, localSha, remoteSha: expected, source: 'managed-pushed-sha' };
  }

  const branchName = branch || app.branch || 'main';
  const url = `https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/branches/${encodeURIComponent(branchName)}`;
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'appcrane-supply-chain-verify',
  };
  const token = authForApp(app);
  if (token) headers.Authorization = `Bearer ${token}`;

  let remoteSha;
  try {
    const r = await fetch(url, { headers, signal: AbortSignal.timeout(8000) });
    if (!r.ok) {
      // Network / auth / rate-limit problem. Log + skip rather than
      // bricking deploys when GitHub is glitchy. Real attacks tend to
      // produce mismatches, not 503s.
      const body = await r.text().catch(() => '');
      log.warn(`supply-chain verify: GitHub returned ${r.status} for ${parsed.owner}/${parsed.repo}@${branchName} — ${body.slice(0, 200)}`);
      appendLog?.(`Supply-chain verify: skipped (GitHub returned ${r.status}).`);
      return { skipped: true, reason: `github-${r.status}`, localSha };
    }
    const body = await r.json();
    remoteSha = body?.commit?.sha;
  } catch (e) {
    log.warn(`supply-chain verify: network error reaching GitHub: ${e.message}`);
    appendLog?.(`Supply-chain verify: skipped (network error: ${e.message}).`);
    return { skipped: true, reason: 'network', localSha };
  }

  if (!remoteSha || !/^[0-9a-f]{40}$/.test(remoteSha)) {
    appendLog?.(`Supply-chain verify: skipped (GitHub returned no SHA for ${branchName}).`);
    return { skipped: true, reason: 'no-remote-sha', localSha };
  }

  if (remoteSha !== localSha) {
    // The actual security signal. Refuse the deploy.
    throw new Error(
      `Supply-chain verify FAILED: local HEAD ${localSha.slice(0, 12)}… does not match GitHub's ${parsed.owner}/${parsed.repo}@${branchName} ${remoteSha.slice(0, 12)}…. ` +
      `Refusing to swap container. If this is a mirror or fork, set supply_chain_verify_enabled='0' in settings to bypass.`
    );
  }

  appendLog?.(`Supply-chain verify: OK (HEAD ${localSha.slice(0, 12)} matches GitHub ${parsed.owner}/${parsed.repo}@${branchName}).`);
  return { skipped: false, localSha, remoteSha };
}
