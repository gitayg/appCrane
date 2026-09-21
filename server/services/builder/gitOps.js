import { execFileSync } from 'child_process';
import { lstatSync, readFileSync } from 'fs';
import { join, resolve } from 'path';
import log from '../../utils/logger.js';

// ---------------------------------------------------------------------------
// Releasing selected workspace changes (Phase 4a)
// ---------------------------------------------------------------------------
//
// This file used to open with `commitAndPush`: stage the workspace, commit, and
// `git push origin <branch>` to a GitHub remote. It went with /api/agents
// (v2.83.0), whose POST /:id/ship-sandbox was its last reachable caller —
// /api/coder dropped its own /ship in v2.82.0, and a Crane-hosted app has no
// remote to push to in the first place. The credential plumbing it alone used
// here (the session→app lookup, decrypt, tokenGitEnv, scrubToken) went with it;
// appContainer.js still has its own for the clone.
//
// What remains is the release path a Crane-hosted app actually has: read the
// changed files OUT of the workspace and commit them through the managed
// repository (managedRepo.pushFilesToManagedRepo), which is also what fires the
// sandbox deploy. Everything below is the file-reading half of that;
// routes/coder.js owns the HTTP half and the push itself.
//
// "The session's base commit" is the workspace HEAD. The workspace is a fresh
// clone per container (appContainer.cloneWorkspace) checked out on
// builder/<slug>, and nothing but this file commits into it, so HEAD is the
// commit the session started from.

/** Diff text per file is capped — a change list is for a human to read. */
const MAX_DIFF_BYTES = 64 * 1024;

/** One released file is read into memory whole, so there is a ceiling on it. */
export const MAX_RELEASE_FILE_BYTES = 5 * 1024 * 1024;

/**
 * Paths AppCrane itself writes into every workspace (services/github/snapshot.js).
 * They are platform scratch, not the app's source, so they are not offered as
 * changes — and because the change set is what `paths` is validated against, a
 * release naming one is refused rather than committing AppCrane's notes into
 * the app's repository.
 */
const EXCLUDED_PREFIXES = ['.appcrane/'];

// core.fileMode=false is not a convenience: appContainer.cloneWorkspace runs
// `chmod -R 777` over the workspace so the container user can write in it, which
// flips the executable bit on EVERY tracked file. With the default fileMode
// git then reports the whole tree as modified, and the change list — the thing
// the caller picks from — would be every file in the repo. The managed push
// writes mode 100644 unconditionally (services/localGit.js), so a mode is not
// releasable information in the first place.
function workspaceGit(workspaceDir) {
  return (args, opts = {}) => execFileSync(
    'git',
    ['-c', `safe.directory=${workspaceDir}`, '-c', 'core.fileMode=false', '-C', workspaceDir, ...args],
    { stdio: 'pipe', timeout: 60000, maxBuffer: 64 * 1024 * 1024, ...opts },
  );
}

/** Absolute path of a repo-relative path, or null if it escapes the workspace. */
function insideWorkspace(workspaceDir, p) {
  const root = resolve(workspaceDir);
  const abs = resolve(join(root, p));
  return abs === root || abs.startsWith(`${root}/`) ? abs : null;
}

function capDiff(text) {
  if (text.length <= MAX_DIFF_BYTES) return text;
  return `${text.slice(0, MAX_DIFF_BYTES)}\n… diff truncated at ${MAX_DIFF_BYTES} bytes …\n`;
}

/** `git diff` exits 1 when there IS a difference, which execFileSync throws on. */
function diffText(git, args) {
  try {
    return capDiff(git(args).toString('utf8'));
  } catch (err) {
    if (err.stdout) return capDiff(err.stdout.toString('utf8'));
    return '';
  }
}

/**
 * Working-tree changes in a session workspace against its HEAD, untracked files
 * included. Returns [{ path, status: 'added'|'modified'|'deleted', diff }],
 * sorted by path.
 *
 * Only regular files appear. A symlink is skipped deliberately: the agent owns
 * this workspace, the release path reads a selected path with readFileSync, and
 * a symlink to somewhere on the host would commit that file's bytes into the
 * app's repository. Skipping it here is what makes a release naming it fail the
 * "not in the change set" check instead.
 */
export function listWorkspaceChanges(workspaceDir) {
  const git = workspaceGit(workspaceDir);

  const headListing = (() => {
    try { return git(['ls-tree', '-r', '-z', '--full-tree', '--name-only', 'HEAD']).toString('utf8'); }
    catch (_) { return ''; }
  })();
  const inHead = new Set(headListing.split('\0').filter(Boolean));

  // --no-renames so a rename is reported as the delete + add it is, which is
  // exactly how the managed push has to express it anyway.
  const statusOut = git(['status', '--porcelain=v1', '-z', '--untracked-files=all', '--no-renames'])
    .toString('utf8');

  const out = [];
  for (const entry of statusOut.split('\0')) {
    if (entry.length < 4) continue;
    const path = entry.slice(3);
    if (EXCLUDED_PREFIXES.some((p) => path.startsWith(p))) continue;
    const abs = insideWorkspace(workspaceDir, path);
    if (!abs) continue;

    let st = null;
    try { st = lstatSync(abs); } catch (_) { st = null; }
    if (st && !st.isFile()) continue;

    const tracked = inHead.has(path);
    let status;
    if (!st) {
      // Gone from disk and never in HEAD: nothing to release either way.
      if (!tracked) continue;
      status = 'deleted';
    } else {
      status = tracked ? 'modified' : 'added';
    }

    const diff = tracked
      ? diffText(git, ['diff', '--no-color', '--no-ext-diff', 'HEAD', '--', path])
      : diffText(git, ['diff', '--no-color', '--no-ext-diff', '--no-index', '--', '/dev/null', path]);

    out.push({ path, status, diff });
  }

  out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

/**
 * One changed file, in the shape the managed push takes:
 * { path, content, encoding: 'utf-8' | 'base64' }.
 *
 * Anything that does not survive a utf-8 round trip is sent as base64 rather
 * than as a lossy string — reading an image or a compiled binary as utf-8 would
 * replace every invalid byte with U+FFFD and commit a corrupted file that still
 * looks like a successful release.
 */
export function readWorkspaceFileForRelease(workspaceDir, path) {
  const abs = insideWorkspace(workspaceDir, path);
  if (!abs) throw new Error(`'${path}' is outside the session workspace`);
  const st = lstatSync(abs);
  if (!st.isFile()) throw new Error(`'${path}' is not a regular file, so it cannot be released`);
  if (st.size > MAX_RELEASE_FILE_BYTES) {
    throw new Error(
      `'${path}' is ${st.size} bytes, over the ${MAX_RELEASE_FILE_BYTES}-byte limit for one released file. Nothing was committed.`,
    );
  }
  const buf = readFileSync(abs);
  const asText = buf.toString('utf8');
  const utf8Clean = !buf.includes(0) && Buffer.compare(Buffer.from(asText, 'utf8'), buf) === 0;
  return utf8Clean
    ? { path, content: asText, encoding: 'utf-8' }
    : { path, content: buf.toString('base64'), encoding: 'base64' };
}

/**
 * Record in the workspace that these paths were released, by committing them on
 * the session branch. Best effort and never fatal: the push has already landed
 * and IS the release; this only keeps the next change listing honest, so the
 * paths just released stop being offered again.
 */
export function markReleasedInWorkspace(workspaceDir, paths, commitMsg) {
  const git = workspaceGit(workspaceDir);
  try {
    git(['add', '-A', '--', ...paths]);
    git(['commit', '-m', commitMsg]);
    return true;
  } catch (err) {
    log.warn(`Coder release: workspace bookkeeping commit failed: ${err.message}`);
    return false;
  }
}
