/**
 * Supply-chain SHA verification (v2.3.6+, made fail-closed in v2.44.0).
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
 * FAIL-CLOSED POLICY (v2.44.0)
 * ----------------------------
 * Until v2.44.0 every way of *not getting an answer* — any GitHub non-2xx,
 * any network error, a 2xx body with no SHA — logged a line and let the
 * deploy through. That made the check bypassable rather than merely
 * imperfect: the cheapest attack on a verifier that fails open is to break
 * the verifier, and for the unauthenticated path (public repos, 60 req/hr
 * per IP) exhausting the rate limit is enough to turn every subsequent
 * deploy into a silent skip. So "could not verify" is now the same outcome
 * as "did not match": the deploy stops.
 *
 * Two escape hatches, deliberately different in scope:
 *
 *   * supply_chain_verify_enabled='0' (setting) — turn the check off
 *     entirely. For air-gapped or offline boxes. Legitimate, and unchanged.
 *   * APPCRANE_REQUIRE_VERIFY=0 (env, on the AppCrane host) — keep checking
 *     and keep failing on a genuine SHA *mismatch*, but let an
 *     unreachable/erroring GitHub through with a loud NOT VERIFIED line.
 *     This is the pre-v2.44.0 behaviour, available for an operator riding
 *     out a GitHub outage without blinding the mismatch detector too.
 *
 * A skip is not the same as a pass. Two cases remain genuine skips because
 * verification is *inapplicable*, not *failed*: the setting being off, and a
 * non-github.com repo URL (self-hosted git — there is no second source of
 * truth to ask). Both return verified:false.
 *
 * MANAGED APPS
 * ------------
 * source_type='managed' used to compare the clone HEAD against
 * app.last_managed_push_sha and stop there. That value is one AppCrane
 * wrote itself at push time, so agreeing with it proves the clone is not
 * stale and nothing else — it is a freshness gate, not verification, and
 * calling it "verify OK" overstated what had been checked. As of v2.44.0
 * managed apps keep that gate and then go on to the same GitHub
 * cross-check as every other app, so they have a real external source of
 * truth. The read-after-write race that motivated the shortcut (GitHub's
 * branch API lags a push by ~1s, so an immediate deploy saw the old SHA)
 * is handled by retrying a mismatch a few times before believing it.
 */

import { getDb } from '../db.js';
import { decrypt } from './encryption.js';
import { getServiceTokenInternal } from './githubService.js';
import { execFileSync } from 'child_process';
import log from '../utils/logger.js';

// Attempt delays for the GitHub head-SHA read. Retried on a transient error
// AND on a SHA disagreement: a disagreement right after a push is far more
// likely to be GitHub's eventually-consistent branch API than an attack, and
// now that a mismatch is fatal a false positive costs a failed deploy.
const RETRY_DELAYS_MS = [0, 1500, 3000];
const FETCH_TIMEOUT_MS = 8000;

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
    // Unreadable settings table => assume enabled. A failed read must not be a
    // way to switch the check off; the operator turns it off by writing '0',
    // never by breaking the row.
    return true;
  }
}

/**
 * Whether an *unanswerable* verification still blocks the deploy. Default yes.
 * Only the exact string '0' relaxes it, so a typo'd value keeps the safe
 * behaviour rather than silently opting out.
 */
function failClosedOnError() {
  return process.env.APPCRANE_REQUIRE_VERIFY !== '0';
}

/**
 * One GitHub branch read. Throws on any outcome that is not a usable 40-char
 * SHA, tagging HTTP failures with .status so the retry loop can tell a
 * transient (5xx, rate limit) from a settled answer (404, 401).
 */
async function githubHeadSha(url, headers) {
  const r = await fetch(url, { headers, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!r.ok) {
    const body = await r.text().catch(() => '');
    const err = new Error(`GitHub returned ${r.status}${body ? ` — ${body.slice(0, 200)}` : ''}`);
    err.status = r.status;
    throw err;
  }
  const body = await r.json();
  const sha = body?.commit?.sha;
  if (!sha || !/^[0-9a-f]{40}$/.test(sha)) {
    throw new Error('GitHub returned a 200 with no commit SHA for this branch');
  }
  return sha;
}

/**
 * Read GitHub's head SHA, retrying while it disagrees with the clone or the
 * call fails transiently. Returns { sha } or { error }.
 *
 * 401 and 404 are settled answers, not hiccups — the token is wrong or the
 * branch/repo is not there — so they stop the loop immediately instead of
 * spending the full backoff on a result that will not change.
 */
async function resolveRemoteSha(url, headers, localSha) {
  let lastSha = null;
  let lastError = null;

  for (let i = 0; i < RETRY_DELAYS_MS.length; i++) {
    if (RETRY_DELAYS_MS[i] > 0) {
      await new Promise((r) => setTimeout(r, RETRY_DELAYS_MS[i]));
    }
    try {
      lastSha = await githubHeadSha(url, headers);
      lastError = null;
      if (lastSha === localSha) return { sha: lastSha };
    } catch (e) {
      lastSha = null;
      lastError = e;
      if (e.status === 401 || e.status === 404) break;
    }
  }

  return lastSha ? { sha: lastSha } : { error: lastError };
}

/**
 * Verification could not be completed. Blocks the deploy unless the operator
 * set APPCRANE_REQUIRE_VERIFY=0, in which case it is reported as NOT VERIFIED
 * (never as OK) and the deploy continues.
 */
function unanswered(reason, detail, appendLog, extra) {
  if (failClosedOnError()) {
    throw new Error(
      `Supply-chain verify FAILED: could not confirm the deploying commit — ${detail}. ` +
      `Refusing to swap container. Verification failure is treated the same as a mismatch because a ` +
      `verifier that waves through its own errors can be bypassed by breaking it. ` +
      `To ride out a GitHub outage set APPCRANE_REQUIRE_VERIFY=0 on the AppCrane host (mismatches still fail), ` +
      `or set supply_chain_verify_enabled='0' in settings to turn the check off entirely.`
    );
  }
  log.warn(`supply-chain verify: NOT VERIFIED (${reason}) — ${detail}; proceeding because APPCRANE_REQUIRE_VERIFY=0`);
  appendLog?.(`Supply-chain verify: NOT VERIFIED (${detail}). Proceeding because APPCRANE_REQUIRE_VERIFY=0 is set on the host.`);
  return { skipped: true, verified: false, failOpen: true, reason, ...extra };
}

/**
 * Verify the cloned working tree's HEAD SHA matches GitHub's claim for
 * the same branch. Throws on mismatch and on any failure to obtain an
 * answer (see FAIL-CLOSED POLICY above). Returns without throwing on a
 * match, and on the two inapplicable cases (check disabled, non-github URL).
 *
 * Caller (deployer.js) provides:
 *   - app:        full apps row (source_type, github_url, github_token_encrypted)
 *   - releaseDir: absolute path to the cloned working tree
 *   - branch:     branch name that was checked out (defaults to app.branch)
 *   - appendLog:  callback to write into the deploy log
 */
export async function verifyCommitSha(app, releaseDir, branch, appendLog) {
  if (!isVerifyEnabled()) {
    appendLog?.('Supply-chain verify: skipped (disabled in settings). The deploying commit was NOT verified against GitHub.');
    return { skipped: true, verified: false, reason: 'disabled' };
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

  // Freshness gate for managed apps. This compares the clone against a SHA
  // AppCrane itself recorded at push time, so it proves the clone is not
  // stale — it is NOT verification, and the GitHub cross-check below still
  // runs. A missing recorded SHA is therefore no longer a reason to skip.
  if (app.source_type === 'managed') {
    const expected = app.last_managed_push_sha;
    if (expected && /^[0-9a-f]{40}$/.test(expected) && expected !== localSha) {
      throw new Error(
        `Supply-chain verify FAILED: managed clone HEAD ${localSha.slice(0, 12)}… does not match the last pushed commit ${expected.slice(0, 12)}…. ` +
        `The clone is stale — re-run the deploy so it fetches the pushed commit.`
      );
    }
  }

  const parsed = parseGithubUrl(app.github_url);
  if (!parsed) {
    // Inapplicable rather than failed: a self-hosted git remote has no second
    // source of truth to ask. Note that this is also the shape of a bypass —
    // anyone able to repoint an app's github_url at a non-github host turns
    // verification off for that app — so it is stated in the deploy log
    // instead of being logged as a pass.
    appendLog?.('Supply-chain verify: skipped (not a github.com URL, no second source of truth). The deploying commit was NOT verified.');
    return { skipped: true, verified: false, reason: 'non-github', localSha };
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

  const { sha: remoteSha, error } = await resolveRemoteSha(url, headers, localSha);

  if (error) {
    log.warn(`supply-chain verify: could not read ${parsed.owner}/${parsed.repo}@${branchName} — ${error.message}`);
    return unanswered('github-unreachable', `GitHub head-SHA read for ${parsed.owner}/${parsed.repo}@${branchName} failed: ${error.message}`, appendLog, { localSha });
  }

  if (remoteSha !== localSha) {
    // The actual security signal. Refuse the deploy.
    throw new Error(
      `Supply-chain verify FAILED: local HEAD ${localSha.slice(0, 12)}… does not match GitHub's ${parsed.owner}/${parsed.repo}@${branchName} ${remoteSha.slice(0, 12)}…. ` +
      `Refusing to swap container. If this is a mirror or fork, set supply_chain_verify_enabled='0' in settings to bypass.`
    );
  }

  appendLog?.(`Supply-chain verify: OK (HEAD ${localSha.slice(0, 12)} matches GitHub ${parsed.owner}/${parsed.repo}@${branchName}).`);
  return { skipped: false, verified: true, localSha, remoteSha };
}
