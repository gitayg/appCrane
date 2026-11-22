/**
 * Is GitHub's copy of a Crane-hosted app's deploy branch the same as AppCrane's?
 *
 * Applies to a managed app whose repository lives on this host
 * (managedRepo.usesLocalRepo) and that also names a github_url, e.g. one the
 * owner dual-pushes to. The answer is from AppCrane's point of view:
 *   same     - both tips are the same commit
 *   ahead    - AppCrane has `ahead` commits GitHub does not
 *   behind   - GitHub has `behind` commits AppCrane does not
 *   diverged - both have commits the other lacks
 *   unknown  - not measured; `reason_code` and `reason` say why
 *
 * MEASURED, NEVER ASSUMED. Any failure (no credential, 401/403/SAML, missing
 * repo or branch, network, timeout) is 'unknown' with the reason. Nothing here
 * reports 'same' without having read both tips.
 *
 * THE APP'S REPOSITORY IS ONLY READ. GitHub's objects are fetched into a
 * throwaway bare repo in the OS temp dir whose objects/info/alternates points at
 * the app's object store, so the fetch negotiates against what AppCrane has and
 * the counts can walk both histories, while every write (objects, the fetched
 * ref, FETCH_HEAD) lands in the throwaway repo, which is deleted afterwards.
 *
 * The credential never enters a URL, argv or log: it travels as an
 * http.<origin>/.extraHeader through GIT_CONFIG_COUNT in the child's
 * environment (the localGit.migrationGit pattern), redirects are refused, and
 * every message is scrubbed of the token before it leaves this module. git runs
 * with localGit's isolated argv/env (no hooks, no host config) as its own
 * process group, killed as a group at the deadline.
 */

import { spawn as nodeSpawn } from 'child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import log from '../utils/logger.js';
import { usesLocalRepo } from './managedRepo.js';
import { repoPath, localRepoExists, isolatedGitArgs, isolatedGitEnv } from './localGit.js';
import { parseGithubRepo, resolveGitHubCredential } from './githubCredential.js';

export const CACHE_TTL_MS = 60 * 1000;
export const MIN_REFRESH_MS = 10 * 1000;
export const CHECK_TIMEOUT_MS = 30 * 1000;

const SHA_RE = /^[0-9a-f]{40}$/;
const BRANCH_RE = /^[A-Za-z0-9._/-]{1,200}$/;

const defaultDeps = {
  spawn: nodeSpawn,
  now: () => Date.now(),
  timeoutMs: CHECK_TIMEOUT_MS,
  allowedSchemes: ['https'],
  resolveRemote: defaultResolveRemote,
};
let deps = { ...defaultDeps };

export function _setGithubSyncDepsForTests(overrides) {
  deps = overrides ? { ...defaultDeps, ...overrides } : { ...defaultDeps };
  cache.clear();
  inflight.clear();
}

const cache = new Map();
const inflight = new Map();

/**
 * { url, token, credential } for the app's GitHub repo: the app's own
 * credential from githubCredential.resolveGitHubCredential (its GitHub App
 * installation, else its PAT), else anonymous, so a public repo can be compared.
 *
 * NEVER the platform's service-account token. An app's owner may set github_url
 * on a Crane-hosted app (routes/apps.js PUT), and that token reads every repo
 * the service account can, so using it would let an owner learn whether any of
 * those repos exists and what its branch tip is.
 */
export async function defaultResolveRemote(app) {
  const parsed = parseGithubRepo(app.github_url);
  if (!parsed) throw unknownError('bad_github_url', `The app's GitHub URL (${app.github_url}) is not a GitHub repository URL.`);
  const host = new URL(app.github_url).hostname;
  const url = `https://${host}/${parsed.fullName}.git`;
  let cred;
  try {
    cred = await resolveGitHubCredential(app);
  } catch (e) {
    throw unknownError('credential_error', `AppCrane could not get a GitHub credential for this app: ${e?.message || e}`);
  }
  if (cred?.token) return { url, token: cred.token, credential: cred.source };
  return { url, token: null, credential: 'none' };
}

function unknownError(code, message) {
  return Object.assign(new Error(message), { syncCode: code });
}

function scrubber(token) {
  if (!token) return (s) => String(s);
  const b64 = Buffer.from(`x-access-token:${token}`).toString('base64');
  return (s) => String(s).replaceAll(token, '[redacted]').replaceAll(b64, '[redacted]');
}

function runGit(gitDir, args, { url, token, deadline, scrub }) {
  const extra = ['-c', 'http.followRedirects=false', '-c', 'credential.helper='];
  const env = {};
  if (url) {
    const u = new URL(url);
    const scheme = u.protocol.replace(/:$/, '');
    if (!deps.allowedSchemes.includes(scheme)) {
      return Promise.reject(unknownError('bad_github_url', `The '${scheme}' transport is not allowed for a GitHub comparison.`));
    }
    if (u.username || u.password) {
      return Promise.reject(unknownError('bad_github_url', 'The GitHub URL must not carry credentials.'));
    }
    extra.push('-c', `protocol.${scheme}.allow=always`);
    if (token && (scheme === 'https' || scheme === 'http')) {
      env.GIT_CONFIG_COUNT = '1';
      env.GIT_CONFIG_KEY_0 = `http.${u.origin}/.extraHeader`;
      env.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`;
    }
  }
  const remaining = deadline - deps.now();
  if (!(remaining > 0)) return Promise.reject(Object.assign(new Error('deadline passed'), { gitTimeout: true }));
  return new Promise((resolveP, reject) => {
    const child = deps.spawn('git', isolatedGitArgs(gitDir, [...extra, ...args]), {
      env: isolatedGitEnv(env), stdio: ['ignore', 'pipe', 'pipe'], detached: true,
    });
    const out = [];
    let err = '';
    let timedOut = false;
    let settled = false;
    const settle = (fn) => { if (!settled) { settled = true; fn(); } };
    const timer = setTimeout(() => {
      timedOut = true;
      try { process.kill(-child.pid, 'SIGKILL'); } catch (_) { try { child.kill('SIGKILL'); } catch (_) { /* gone */ } }
    }, remaining);
    const timeoutError = () => Object.assign(new Error(`git ${args[0]} killed after ${remaining}ms`), { gitTimeout: true });
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => { if (err.length < 8192) err += c.toString('utf8'); });
    child.on('error', (e) => { clearTimeout(timer); settle(() => reject(Object.assign(new Error(scrub(e.message)), { stderr: '' }))); });
    child.on('exit', () => {
      if (!timedOut) return;
      clearTimeout(timer);
      child.stdout.destroy();
      child.stderr.destroy();
      settle(() => reject(timeoutError()));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      settle(() => {
        if (timedOut) return reject(timeoutError());
        if (code !== 0) return reject(Object.assign(new Error(scrub(`git ${args[0]} failed (exit ${code})`)), { stderr: scrub(err), exitCode: code }));
        resolveP(Buffer.concat(out).toString('utf8'));
      });
    });
  });
}

/** A failed remote git call as { code, message } in plain words. */
export function classifyRemoteFailure(e) {
  if (e?.syncCode) return { code: e.syncCode, message: e.message };
  if (e?.gitTimeout) return { code: 'timeout', message: 'GitHub did not answer in time.' };
  const s = String(e?.stderr || '');
  if (/SAML/i.test(s)) {
    return { code: 'saml_required', message: "GitHub refused the credential: the organization enforces SAML single sign-on and the credential is not authorized for it." };
  }
  if (/returned error: 40[13]\b|Authentication failed|could not read Username|terminal prompts disabled|Invalid username or password/i.test(s)) {
    return { code: 'auth_failed', message: 'GitHub refused the credential AppCrane used (or there is none and the repository is private).' };
  }
  if (/returned error: 404\b|Repository not found|does not appear to be a git repository/i.test(s)) {
    return { code: 'repo_not_found', message: 'GitHub says the repository does not exist, or the credential AppCrane used cannot see it.' };
  }
  if (/Could not resolve host|Failed to connect|Connection refused|Connection reset|timed out|unable to access|SSL|TLS|Empty reply|Recv failure/i.test(s)) {
    return { code: 'network', message: 'AppCrane could not reach GitHub over the network.' };
  }
  return { code: 'git_failed', message: 'Asking GitHub for the branch failed.' };
}

function base(app, branch) {
  return {
    state: 'unknown', ahead: null, behind: null, branch,
    crane_sha: null, github_sha: null, github_repo: parseGithubRepo(app.github_url)?.fullName || null,
    credential: null, checked_at: new Date(deps.now()).toISOString(), reason_code: null, reason: null,
  };
}

async function measure(app) {
  const branch = app.branch || 'main';
  const r = base(app, branch);
  const unknown = (code, reason) => Object.assign(r, { state: 'unknown', reason_code: code, reason });

  let local = false;
  try { local = usesLocalRepo(app); } catch (e) { return unknown('not_crane_hosted', e.message); }
  if (!local) return unknown('not_crane_hosted', 'This app\'s code is not stored on AppCrane, so there is no AppCrane copy to compare.');
  if (!app.github_url) return unknown('no_github_url', 'This app has no GitHub repository set, so there is nothing to compare.');
  if (!BRANCH_RE.test(branch)) return unknown('bad_branch', `The app's branch name '${branch}' is not one AppCrane can compare.`);
  if (!localRepoExists(app.slug)) return unknown('crane_repo_missing', 'AppCrane\'s copy of the repository is missing on this host.');

  const deadline = deps.now() + deps.timeoutMs;
  const craneDir = repoPath(app.slug);
  const noScrub = (s) => String(s);
  try {
    const sha = (await runGit(craneDir, ['rev-parse', '--verify', '--quiet', `refs/heads/${branch}^{commit}`], { deadline, scrub: noScrub })).trim();
    if (SHA_RE.test(sha)) r.crane_sha = sha;
  } catch (_) { /* missing branch: below */ }
  if (!r.crane_sha) return unknown('crane_branch_missing', `AppCrane's copy has no '${branch}' branch yet.`);

  let remote;
  try { remote = await deps.resolveRemote(app); } catch (e) {
    const c = classifyRemoteFailure(e);
    return unknown(c.code, c.message);
  }
  r.credential = remote.credential || (remote.token ? 'token' : 'none');
  const scrub = scrubber(remote.token);
  const opts = { url: remote.url, token: remote.token, deadline, scrub };
  const fail = (e) => {
    const c = classifyRemoteFailure(e);
    log.warn(`[github-sync] ${app.slug}: ${c.code}${e?.stderr ? `: ${scrub(e.stderr).trim().split('\n').slice(-1)[0]}` : ''}`);
    if (remote.credential === 'none' && c.code === 'auth_failed') {
      return unknown('no_credential', 'AppCrane has no GitHub credential for this app (no GitHub App installation or token), and GitHub refused to let it read the repository without one. Make the repository public, or attach a GitHub App installation or a token to this app.');
    }
    if (c.code === 'auth_failed' || c.code === 'repo_not_found') {
      return unknown(c.code, `${c.message} Make the repository public, or attach a GitHub App installation or a token to this app that can read it.`);
    }
    return unknown(c.code, c.message);
  };

  let listed;
  try {
    listed = await runGit(null, ['ls-remote', '--heads', '--', remote.url, `refs/heads/${branch}`], opts);
  } catch (e) { return fail(e); }
  const line = listed.split('\n').map((l) => l.trim()).find((l) => l.endsWith(`\trefs/heads/${branch}`));
  const ghSha = line ? line.split('\t')[0] : null;
  if (!ghSha || !SHA_RE.test(ghSha)) return unknown('github_branch_missing', `GitHub's repository has no '${branch}' branch.`);
  r.github_sha = ghSha;
  if (ghSha === r.crane_sha) return Object.assign(r, { state: 'same', ahead: 0, behind: 0 });

  const scratch = mkdtempSync(join(tmpdir(), 'appcrane-github-sync-'));
  try {
    await runGit(null, ['init', '--bare', '--quiet', scratch], { deadline, scrub });
    writeFileSync(join(scratch, 'objects', 'info', 'alternates'), `${join(craneDir, 'objects')}\n`);
    try {
      await runGit(scratch, [
        'fetch', '--quiet', '--no-tags', '--no-write-fetch-head', '--no-recurse-submodules', '--no-auto-gc',
        '--', remote.url, `+refs/heads/${branch}:refs/appcrane-github/${branch}`,
      ], opts);
    } catch (e) { return fail(e); }
    const fetched = (await runGit(scratch, ['rev-parse', '--verify', '--quiet', `refs/appcrane-github/${branch}^{commit}`], { deadline, scrub })).trim();
    if (!SHA_RE.test(fetched)) return unknown('git_failed', 'GitHub\'s branch could not be read after fetching it.');
    r.github_sha = fetched;
    if (fetched === r.crane_sha) return Object.assign(r, { state: 'same', ahead: 0, behind: 0 });
    const counts = (await runGit(scratch, ['rev-list', '--left-right', '--count', `${r.crane_sha}...${fetched}`], { deadline, scrub })).trim();
    const m = /^(\d+)\s+(\d+)$/.exec(counts);
    if (!m) return unknown('git_failed', 'AppCrane could not count the commits between the two copies.');
    const ahead = Number(m[1]);
    const behind = Number(m[2]);
    const state = ahead && behind ? 'diverged' : ahead ? 'ahead' : behind ? 'behind' : 'same';
    return Object.assign(r, { state, ahead, behind });
  } catch (e) {
    return fail(e);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/**
 * The comparison for one app, cached for CACHE_TTL_MS. `refresh` re-measures
 * unless the cached answer is younger than MIN_REFRESH_MS; concurrent callers
 * share one measurement.
 */
export function invalidateGithubSyncStatus(app) {
  for (const k of cache.keys()) if (k.startsWith(`${app.id}:`)) cache.delete(k);
}

export async function getGithubSyncStatus(app, { refresh = false } = {}) {
  const key = `${app.id}:${app.branch || 'main'}:${app.github_url || ''}`;
  const hit = cache.get(key);
  const age = hit ? deps.now() - hit.at : Infinity;
  if (hit && (age < MIN_REFRESH_MS || (!refresh && age < CACHE_TTL_MS))) return { ...hit.result, cached: true };
  if (inflight.has(key)) return { ...(await inflight.get(key)), cached: false };
  const p = measure(app).finally(() => inflight.delete(key));
  inflight.set(key, p);
  const result = await p;
  cache.set(key, { result, at: deps.now() });
  return { ...result, cached: false };
}
