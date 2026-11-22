/**
 * Export a Crane-hosted app's repository back to its GitHub repo (app.github_url).
 *
 * Pushes the deploy branch, and by default every tag, from the app's bare repo
 * under DATA_DIR/repos to GitHub in ONE atomic push, then reads GitHub's refs
 * back and reports `verified: true` only when each one equals the local SHA.
 *
 * NEVER A FORCE PUSH. Refspecs carry no '+', so GitHub itself refuses any
 * non-fast-forward update and any tag that already names another object;
 * --atomic means a refusal of one ref updates none. Before pushing, the
 * githubSyncStatus comparison refuses outright when GitHub has commits the
 * local copy lacks (behind / diverged), so the owner is told why instead of
 * getting a raw rejection.
 *
 * Credential: the app's own GitHub App installation, else its PAT
 * (githubSyncStatus.defaultResolveRemote over githubCredential), NEVER the
 * platform service-account token, which can write every repo that account
 * reaches. With no credential the export is refused. The token travels only
 * as an http.<origin>/.extraHeader in GIT_CONFIG_COUNT env, never a URL, argv
 * or log line; git runs with localGit's isolated argv/env (no hooks, no host
 * config), as its own process group, killed at the deadline.
 *
 * Every attempt that reaches GitHub (and every refusal after the app is known
 * to be exportable) writes one 'github-export' audit row.
 */

import { spawn as nodeSpawn } from 'child_process';
import log from '../utils/logger.js';
import { logAudit } from '../middleware/audit.js';
import { usesLocalRepo } from './managedRepo.js';
import { repoPath, localRepoExists, isolatedGitArgs, isolatedGitEnv } from './localGit.js';
import { parseGithubRepo } from './githubCredential.js';
import { defaultResolveRemote, classifyRemoteFailure, getGithubSyncStatus, invalidateGithubSyncStatus } from './githubSyncStatus.js';

export const EXPORT_TIMEOUT_MS = 120 * 1000;

const SHA_RE = /^[0-9a-f]{40}$/;
const BRANCH_RE = /^[A-Za-z0-9._/-]{1,200}$/;

const defaultDeps = {
  spawn: nodeSpawn,
  now: () => Date.now(),
  timeoutMs: EXPORT_TIMEOUT_MS,
  allowedSchemes: ['https'],
  resolveRemote: defaultResolveRemote,
  syncStatus: getGithubSyncStatus,
};
let deps = { ...defaultDeps };

export function _setGithubExportDepsForTests(overrides) {
  deps = overrides ? { ...defaultDeps, ...overrides } : { ...defaultDeps };
  inflight.clear();
}

const inflight = new Set();

/** Why an app cannot be exported at all (the route answers 404), or null. */
export function exportIneligibleReason(app) {
  let local = false;
  try { local = usesLocalRepo(app); } catch (_) { local = false; }
  if (!local) return 'This app\'s code is not stored on AppCrane, so there is nothing to export.';
  if (!app.github_url) return 'This app has no GitHub repository set, so there is nowhere to export to.';
  return null;
}

function scrubber(token) {
  if (!token) return (s) => String(s);
  const b64 = Buffer.from(`x-access-token:${token}`).toString('base64');
  return (s) => String(s).replaceAll(token, '[redacted]').replaceAll(b64, '[redacted]');
}

function exportError(code, message) {
  return Object.assign(new Error(message), { syncCode: code });
}

/** Resolves { code, stdout, stderr } whatever the exit code; rejects on spawn error or timeout. */
function runGit(gitDir, args, { url, token, deadline, scrub }) {
  const extra = ['-c', 'http.followRedirects=false', '-c', 'credential.helper='];
  const env = {};
  if (url) {
    const u = new URL(url);
    const scheme = u.protocol.replace(/:$/, '');
    if (!deps.allowedSchemes.includes(scheme)) {
      return Promise.reject(exportError('bad_github_url', `The '${scheme}' transport is not allowed for a GitHub export.`));
    }
    if (u.username || u.password) return Promise.reject(exportError('bad_github_url', 'The GitHub URL must not carry credentials.'));
    extra.push('-c', `protocol.${scheme}.allow=always`);
    if (token) {
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
    child.on('error', (e) => { clearTimeout(timer); settle(() => reject(new Error(scrub(e.message)))); });
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
        resolveP({ code, stdout: scrub(Buffer.concat(out).toString('utf8')), stderr: scrub(err) });
      });
    });
  });
}

async function gitOk(gitDir, args, opts) {
  const r = await runGit(gitDir, args, opts);
  if (r.code !== 0) throw Object.assign(new Error(`git ${args[0]} failed (exit ${r.code})`), { stderr: r.stderr, exitCode: r.code });
  return r.stdout;
}

function parseRefLines(text) {
  const m = new Map();
  for (const line of text.split('\n')) {
    const [sha, ref] = line.trim().split(/\s+/);
    if (sha && ref && SHA_RE.test(sha)) m.set(ref, sha);
  }
  return m;
}

/** `git push --porcelain` lines: flag \t from:to \t summary (reason). */
function parsePorcelain(text) {
  const rows = [];
  for (const line of text.split('\n')) {
    const m = /^([ +\-*=!])\t([^\t]*):([^\t]+)\t(.*)$/.exec(line);
    if (m) rows.push({ flag: m[1], ref: m[3], summary: m[4] });
  }
  return rows;
}

/**
 * Push the app's deploy branch (and tags unless `tags: false`) to GitHub.
 *
 * Returns { ok, state, reason_code, reason, branch, github_repo, credential,
 * local_sha, github_sha_before, github_sha_after, verified, ahead, behind,
 * refs: [{ ref, old_sha, new_sha, remote_sha, status }] }.
 * state: 'pushed' | 'up_to_date' | 'refused' | 'failed'. ok is true only for
 * pushed / up_to_date, and then verified is true.
 */
export async function exportToGithub(app, { userId = null, tags = true } = {}) {
  const branch = app.branch || 'main';
  const r = {
    ok: false, state: 'failed', reason_code: null, reason: null, branch,
    github_repo: parseGithubRepo(app.github_url)?.fullName || null, credential: null,
    local_sha: null, github_sha_before: null, github_sha_after: null, verified: false,
    ahead: null, behind: null, refs: [],
  };
  const ineligible = exportIneligibleReason(app);
  if (ineligible) return Object.assign(r, { state: 'refused', reason_code: 'not_exportable', reason: ineligible });

  if (inflight.has(app.id)) {
    return Object.assign(r, { state: 'refused', reason_code: 'in_progress', reason: 'An export of this app is already running.' });
  }
  inflight.add(app.id);
  try {
    await run(app, r, { tags });
  } catch (e) {
    const c = classifyRemoteFailure(e);
    Object.assign(r, { ok: false, state: 'failed', verified: false, reason_code: c.code, reason: c.message });
  } finally {
    inflight.delete(app.id);
    invalidateGithubSyncStatus(app);
  }
  try {
    logAudit(userId, app.id, 'github-export', {
      github_repo: r.github_repo, branch, tags, credential: r.credential, state: r.state, ok: r.ok,
      verified: r.verified, reason_code: r.reason_code,
      refs: r.refs.map(({ ref, old_sha, new_sha, remote_sha, status }) => ({ ref, old_sha, new_sha, remote_sha, status })),
    });
  } catch (e) {
    log.warn(`[github-export] ${app.slug}: audit write failed: ${e.message}`);
  }
  return r;
}

async function run(app, r, { tags }) {
  const { branch } = r;
  const refuse = (code, reason) => Object.assign(r, { state: 'refused', reason_code: code, reason });
  const failed = (code, reason) => Object.assign(r, { state: 'failed', reason_code: code, reason });
  if (!BRANCH_RE.test(branch)) return refuse('bad_branch', `The app's branch name '${branch}' is not one AppCrane can export.`);
  if (!localRepoExists(app.slug)) return failed('crane_repo_missing', 'AppCrane\'s copy of the repository is missing on this host.');

  const deadline = deps.now() + deps.timeoutMs;
  const craneDir = repoPath(app.slug);
  const noScrub = (s) => String(s);
  const localRefs = parseRefLines(await gitOk(craneDir, ['for-each-ref', '--format=%(objectname) %(refname)', `refs/heads/${branch}`, ...(tags ? ['refs/tags/'] : [])], { deadline, scrub: noScrub }));
  r.local_sha = localRefs.get(`refs/heads/${branch}`) || null;
  if (!r.local_sha) return refuse('crane_branch_missing', `AppCrane's copy has no '${branch}' branch yet.`);

  const remote = await deps.resolveRemote(app);
  r.credential = remote.credential || (remote.token ? 'token' : 'none');
  if (!remote.token) {
    return refuse('no_credential', 'AppCrane has no GitHub credential for this app (no GitHub App installation or token), so it cannot push. Attach a GitHub App installation or a token with write access to this app.');
  }
  const scrub = scrubber(remote.token);
  const opts = { url: remote.url, token: remote.token, deadline, scrub };

  const sync = await deps.syncStatus(app, { refresh: true });
  r.ahead = sync.ahead;
  r.behind = sync.behind;
  r.github_sha_before = sync.github_sha;
  if (sync.state === 'behind' || sync.state === 'diverged') {
    return refuse('github_ahead', `GitHub has ${sync.behind} commit${sync.behind === 1 ? '' : 's'} on '${branch}' that AppCrane does not, so pushing would overwrite them. AppCrane never force-pushes: bring those commits into AppCrane's copy first (git pull, then git push to AppCrane), then export again.`);
  }
  if (sync.state === 'unknown' && sync.reason_code !== 'github_branch_missing') {
    return refuse(sync.reason_code || 'unknown', `AppCrane could not compare with GitHub, so it did not push: ${sync.reason || 'unknown reason'}`);
  }

  const before = parseRefLines(await gitOk(null, ['ls-remote', '--refs', '--heads', '--tags', '--', remote.url], opts));
  const refspecs = [...localRefs.keys()].map((ref) => `${ref}:${ref}`);
  const pushed = await runGit(craneDir, ['push', '--porcelain', '--atomic', '--no-verify', '--', remote.url, ...refspecs], opts);
  const rows = parsePorcelain(pushed.stdout);
  r.refs = [...localRefs].map(([ref, sha]) => {
    const row = rows.find((x) => x.ref === ref);
    const status = !row ? 'unknown'
      : row.flag === '=' ? 'up_to_date'
        : row.flag === '!' ? 'rejected'
          : row.flag === '*' ? 'created' : 'updated';
    return { ref, old_sha: before.get(ref) || null, new_sha: sha, remote_sha: null, status, detail: row?.summary || null };
  });
  if (pushed.code !== 0) {
    const rejected = r.refs.filter((x) => x.status === 'rejected');
    log.warn(`[github-export] ${app.slug}: push exit ${pushed.code}: ${pushed.stderr.trim().split('\n').slice(-1)[0] || ''}`);
    if (rejected.length) {
      const nonFf = rejected.find((x) => /non-fast-forward|fetch first|stale info/.test(x.detail || ''));
      if (nonFf) return refuse('github_ahead', `GitHub refused to move ${nonFf.ref}: it has commits AppCrane does not. AppCrane never force-pushes, so nothing was pushed. Bring those commits into AppCrane's copy first, then export again.`);
      const tag = rejected.find((x) => x.ref.startsWith('refs/tags/'));
      if (tag) return refuse('tag_conflict', `GitHub already has ${tag.ref} pointing at a different object. AppCrane never overwrites a tag, so nothing was pushed.`);
      return refuse('push_rejected', `GitHub refused ${rejected.map((x) => x.ref).join(', ')} (${rejected[0].detail || 'no reason given'}), so nothing was pushed.`);
    }
    throw Object.assign(new Error('git push failed'), { stderr: pushed.stderr, exitCode: pushed.code });
  }

  const after = parseRefLines(await gitOk(null, ['ls-remote', '--refs', '--heads', '--tags', '--', remote.url], opts));
  for (const x of r.refs) x.remote_sha = after.get(x.ref) || null;
  r.github_sha_after = after.get(`refs/heads/${branch}`) || null;
  const mismatched = r.refs.filter((x) => x.remote_sha !== x.new_sha);
  if (mismatched.length) {
    r.verified = false;
    return failed('verify_mismatch', `The push finished, but GitHub now reports ${mismatched.map((x) => `${x.ref} at ${x.remote_sha ? x.remote_sha.slice(0, 12) : 'nothing'} instead of ${x.new_sha.slice(0, 12)}`).join('; ')}. Treat the export as failed and check the repository on GitHub.`);
  }
  r.verified = true;
  r.ok = true;
  r.state = r.refs.every((x) => x.status === 'up_to_date') ? 'up_to_date' : 'pushed';
  r.reason = r.state === 'up_to_date' ? 'GitHub already had every ref; nothing needed pushing.' : null;
  return r;
}
