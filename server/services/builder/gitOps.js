import { lstatSync } from 'fs';
import { join, resolve } from 'path';
import log from '../../utils/logger.js';
import { runWorkspaceGit, runWorkspaceScript } from './workspaceRunner.js';
import { readWorkspaceFiles } from './workspaceReader.js';
import { liveContainerNameFor } from './appContainer.js';

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
 * All the files of one release travel back through one container's stdout
 * into one buffer, under runInWorkspace's 64 MiB default maxBuffer. 48 MiB
 * leaves that headroom for the record headers, and is still nine files at the
 * per-file ceiling — far past any coder change a human picks from a list.
 */
export const MAX_RELEASE_BATCH_BYTES = 48 * 1024 * 1024;

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
// releasable information in the first place. It is part of WORKSPACE_GIT_ARGS.
//
// The workspace is also the agent's to rewrite, .git/ included, and its
// container is running while these are called: a check-then-run on the host
// can be raced (a .git/config swapped between the allowlist check and git's own
// read). So git runs INSIDE the session's container, as the agent's own user,
// never on the host (builder/workspaceRunner.js). The allowlist and
// HARDENED_GIT_ARGS still apply there, as defence in depth.
function workspaceGit(workspaceDir) {
  const container = liveContainerNameFor(workspaceDir);
  const git = (args, opts = {}) => runWorkspaceGit(workspaceDir, args, { container, ...opts });
  git.script = (script, args, opts = {}) => runWorkspaceScript(workspaceDir, script, args, { container, ...opts });
  return git;
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

/**
 * The change list in TWO container round trips, however many files changed.
 * One `docker exec` is ~50 ms and one helper container ~160 ms (measured on
 * Docker Desktop), so a diff per file — what this did when git ran on the host
 * — would cost seconds for a 50-file change. These scripts are constants;
 * every path reaches them as a positional argument, never as script text.
 *
 * LISTING_SCRIPT prints `ls-tree` of HEAD (NUL-terminated names), one extra
 * NUL, then `status -z`. Every ls-tree entry is non-empty, so the first "\0\0"
 * (or a leading "\0" when HEAD has no files) is the boundary.
 */
const LISTING_SCRIPT = [
  'git ls-tree -r -z --full-tree --name-only HEAD 2>/dev/null || true',
  "printf '\\0'",
  'git status --porcelain=v1 -z --untracked-files=all --no-renames',
].join('\n');

/**
 * DIFF_SCRIPT takes the byte cap, then (T|U, path) pairs: T diffs a tracked
 * path against HEAD, U an untracked one against /dev/null. Each record is
 * `path NUL diff NUL`. A diff never contains NUL: git prints "Binary files
 * differ" for any file that does. `head -c` caps each diff in the container,
 * so one huge file cannot blow the buffer for the rest; the pipeline's status
 * is head's, which is what makes `git diff`'s exit 1 ("there is a difference")
 * a non-event here.
 */
const DIFF_SCRIPT = [
  'cap=$1; shift',
  'while [ "$#" -gt 1 ]; do',
  '  kind=$1; p=$2; shift 2',
  "  printf '%s\\0' \"$p\"",
  '  if [ "$kind" = T ]; then',
  '    git diff --no-color --no-ext-diff --no-textconv HEAD -- "$p" 2>/dev/null | head -c "$cap"',
  '  else',
  '    git diff --no-color --no-ext-diff --no-textconv --no-index -- /dev/null "$p" 2>/dev/null | head -c "$cap"',
  '  fi',
  "  printf '\\0'",
  'done',
].join('\n');

/** Files per diff round trip — keeps one exec's argv far below any ARG_MAX. */
const DIFF_BATCH = 400;

function splitListing(buf) {
  const text = buf.toString('utf8');
  const cut = text.startsWith('\0') ? 0 : text.indexOf('\0\0') + 1;
  return { lsTree: text.slice(0, cut), status: text.slice(cut + 1) };
}

function batchDiffs(git, wanted) {
  const diffs = new Map();
  for (let i = 0; i < wanted.length; i += DIFF_BATCH) {
    const args = [String(MAX_DIFF_BYTES + 1)];
    for (const w of wanted.slice(i, i + DIFF_BATCH)) args.push(w.tracked ? 'T' : 'U', w.path);
    const out = git.script(DIFF_SCRIPT, args).toString('utf8').split('\0');
    for (let j = 0; j + 1 < out.length; j += 2) diffs.set(out[j], capDiff(out[j + 1]));
  }
  return diffs;
}

/**
 * Working-tree changes in a session workspace against its HEAD, untracked files
 * included. Returns [{ path, status: 'added'|'modified'|'deleted', diff }],
 * sorted by path.
 *
 * Only regular files appear. A symlink is skipped deliberately: a release must
 * never commit the bytes of whatever a link points at, so a release naming one
 * fails the "not in the change set" check here — and if it became a link after
 * this listing, the in-container reader reports it as one and the release is
 * refused there (readWorkspaceFilesForRelease).
 */
export function listWorkspaceChanges(workspaceDir) {
  const git = workspaceGit(workspaceDir);

  const { lsTree, status: statusOut } = splitListing(git.script(LISTING_SCRIPT, []));
  const inHead = new Set(lsTree.split('\0').filter(Boolean));

  const found = [];
  for (const entry of statusOut.split('\0')) {
    if (entry.length < 4) continue;
    const path = entry.slice(3);
    if (EXCLUDED_PREFIXES.some((p) => path.startsWith(p))) continue;
    const abs = insideWorkspace(workspaceDir, path);
    if (!abs) continue;

    // host-read-ok: metadata only — decides whether a path is offered, never
    // reads a byte of it. A parent swapped for a link here can at most make a
    // path appear or vanish from the list; its content is read in the
    // container, which reports the link instead of following it.
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
    found.push({ path, status, tracked });
  }

  const diffs = found.length ? batchDiffs(git, found) : new Map();
  const out = found.map(({ path, status }) => ({ path, status, diff: diffs.get(path) || '' }));
  out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

/**
 * The selected changed files, in the shape the managed push takes:
 * [{ path, content, encoding: 'utf-8' | 'base64' }], in the order given.
 *
 * Read INSIDE the container (builder/workspaceReader.js), in one round trip
 * for the whole release. This used to lstat each path on the host and then
 * readFileSync it: the agent's container runs throughout, so a symlink — or a
 * parent directory swapped for one — landing between the two made the host
 * read any file AppCrane can (DATA_DIR/.env, deployhub.db) and commit it into
 * the app's repository. The host now never opens a workspace path.
 *
 * A symlink is refused, as it always was: the change list skips symlinks and
 * the managed push writes every file as a 100644 blob (services/localGit.js),
 * so a release has never carried a link — and it must not carry the bytes of
 * whatever the link points at either. The reader reports the link (its target
 * string) instead of following it, and that is what the refusal names.
 *
 * Anything that does not survive a utf-8 round trip is sent as base64 rather
 * than as a lossy string — reading an image or a compiled binary as utf-8 would
 * replace every invalid byte with U+FFFD and commit a corrupted file that still
 * looks like a successful release.
 */
export function readWorkspaceFilesForRelease(workspaceDir, paths) {
  const recs = readWorkspaceFiles(workspaceDir, paths, {
    source: 'worktree',
    maxFileBytes: MAX_RELEASE_FILE_BYTES,
    maxBatchBytes: MAX_RELEASE_BATCH_BYTES,
    container: liveContainerNameFor(workspaceDir),
  });
  return paths.map((path) => {
    const r = recs.get(path);
    switch (r.kind) {
      case 'F': {
        const buf = r.body;
        const asText = buf.toString('utf8');
        const utf8Clean = !buf.includes(0) && Buffer.compare(Buffer.from(asText, 'utf8'), buf) === 0;
        return utf8Clean
          ? { path, content: asText, encoding: 'utf-8' }
          : { path, content: buf.toString('base64'), encoding: 'base64' };
      }
      case 'L':
        throw new Error(`'${path}' is a symlink (to ${JSON.stringify(r.target)}), not a regular file, so it cannot be released.`);
      case 'B':
        throw new Error(
          `'${path}' is ${r.size} bytes, over the ${MAX_RELEASE_FILE_BYTES}-byte limit for one released file. Nothing was committed.`,
        );
      case 'T':
        throw new Error(
          `the selected files are over the ${MAX_RELEASE_BATCH_BYTES}-byte limit for one release (reached at '${path}'). Release them in smaller groups. Nothing was committed.`,
        );
      case 'M':
        throw new Error(`'${path}' no longer exists in the workspace.`);
      default:
        throw new Error(`'${path}' is not a regular file, so it cannot be released.`);
    }
  });
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
