/**
 * Crew: the per-task Claude home a Crew app coder turn runs with.
 *
 * Each Crew turn runs in its own throwaway container (crewAppCoderRunner.js)
 * whose ~/.claude is DATA_DIR/crew-coder/<taskId>/claude and nothing else: not
 * the app's shared transcript directory (appContainer.transcriptDirFor), not
 * another task's home. A follow-up on the same task mounts the same home, so
 * `--resume <coder_session_id>` finds its transcript. The home goes when the
 * task closes or is deleted, and a restart sweeps homes whose task is closed
 * or gone, and any crew-coder container a previous process left behind.
 */
import { execFileSync } from 'child_process';
import { mkdirSync, chmodSync, existsSync, rmSync, readdirSync, lstatSync, openSync, readSync, writeSync, fstatSync, fchmodSync, closeSync, readlinkSync, realpathSync, constants } from 'fs';
import { join, resolve } from 'path';
import log from '../utils/logger.js';
import { transcriptDirFor, STUDIO_UID, STUDIO_GID } from './builder/appContainer.js';

// crew_tasks.id is crypto.randomBytes(16).toString('base64url') (crew.js newTaskId).
const TASK_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SESSION_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
const TERMINAL_STATES = ['completed', 'failed', 'canceled', 'rejected'];
export const CREW_CODER_CONTAINER_TYPE = 'crew-coder';

function rootDir() {
  return resolve(join(process.env.DATA_DIR || './data', 'crew-coder'));
}

function checkedId(taskId) {
  const id = String(taskId ?? '');
  if (!TASK_ID_RE.test(id)) throw new Error(`crewCoderHome: refusing task id ${JSON.stringify(id)}`);
  return id;
}

export function crewTaskHomeDir(taskId) {
  return join(rootDir(), checkedId(taskId), 'claude');
}

function own(dir) {
  try {
    // SECURITY FIX (review of v2.131.0): -h so a symlink a turn left in the
    // home is re-owned itself, never its target (GNU chown -R already does
    // not follow; this keeps it so on any chown).
    execFileSync('chown', ['-R', '-h', `${STUDIO_UID}:${STUDIO_GID}`, dir], { stdio: 'pipe' });
    chmodSync(dir, 0o700);
  } catch (_) {
    // Not root: leave it writable for the container's uid, as appContainer does
    // with the transcripts.
    try { chmodSync(dir, 0o777); } catch (_) {}
  }
}

function isRealDir(p) {
  try { return lstatSync(p).isDirectory(); } catch (_) { return false; }
}

/** mkdir that refuses to go through a symlink: false when `p` is anything but a real directory afterwards. */
function mkdirNoFollow(p) {
  try { mkdirSync(p); } catch (err) { if (err.code !== 'EEXIST') return false; }
  return isRealDir(p);
}

/**
 * Copy a regular file without following a symlink at either end and without
 * replacing anything already at `to`. False when it did not copy.
 */
// SECURITY FIX (review of v2.131.1): O_NOFOLLOW guards only the last path
// component, and the app container can swap a parent directory for a symlink
// between the checks and the open. So the file actually opened must be exactly
// `expected` under the real path of `root` (the transcript mount, which the
// container cannot replace), and the same inode as that path.
export function openedInside(fd, from, root, expected) {
  let opened;
  try { opened = readlinkSync(`/proc/self/fd/${fd}`); } catch (_) { opened = realpathSync(from); }
  if (opened !== join(realpathSync(root), expected)) return false;
  const a = fstatSync(fd);
  const b = lstatSync(opened);
  return a.dev === b.dev && a.ino === b.ino;
}

function copyNoFollow(from, to, within = null) {
  const { O_RDONLY, O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW } = constants;
  let src = null;
  let dst = null;
  try {
    src = openSync(from, O_RDONLY | O_NOFOLLOW);
    const st = fstatSync(src);
    if (!st.isFile()) return false;
    if (within && !openedInside(src, from, within.root, within.expected)) {
      log.warn('[crew-coder] legacy transcript not copied: it resolves outside the app transcript directory');
      return false;
    }
    dst = openSync(to, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600);
    fchmodSync(dst, st.mode & 0o777); // as copyFileSync did
    const buf = Buffer.alloc(64 * 1024);
    let n;
    while ((n = readSync(src, buf, 0, buf.length, null)) > 0) {
      let off = 0;
      while (off < n) off += writeSync(dst, buf, off, n - off);
    }
    return true;
  } catch (err) {
    log.warn(`[crew-coder] legacy transcript not copied: ${err.code || err.message}`);
    return false;
  } finally {
    if (src !== null) try { closeSync(src); } catch (_) {}
    if (dst !== null) try { closeSync(dst); } catch (_) {}
  }
}

/**
 * Create (or reuse) the task's home and return its host path. Mount points a
 * previous turn's credentials or skills bind left behind are removed: those are
 * mounted fresh for each turn. A task whose conversation started before
 * per-task homes existed has its transcript copied in from the app's shared
 * directory once, so its follow-up still resumes.
 */
export function prepareCrewTaskHome(taskId, { slug, resumeId = null } = {}) {
  const dir = crewTaskHomeDir(taskId);
  const fresh = !existsSync(dir);
  mkdirSync(dir, { recursive: true });
  // rmSync removes a symlink itself, never what it points at.
  for (const f of ['credentials.json', '.credentials.json', 'skills']) {
    try { rmSync(join(dir, f), { recursive: true, force: true }); } catch (_) {}
  }
  // SECURITY FIX (review of v2.131.0): the home is mounted read-write into the
  // turn's container, so a turn can leave symlinks (`projects`, `-workspace`,
  // a dangling `<sid>.jsonl`) that a root copy here would follow to write
  // anywhere on the host. The legacy copy now happens only into a home this
  // call created (no container has had it), through real directories only,
  // with a create-exclusive no-follow open at both ends: the app's transcript
  // directory is writable from the app container, so a symlinked legacy file
  // must not be read either.
  if (fresh && slug && resumeId && SESSION_ID_RE.test(String(resumeId))) {
    const legacyDir = join(transcriptDirFor(slug), '-workspace');
    const legacy = join(legacyDir, `${resumeId}.jsonl`);
    const projects = join(dir, 'projects');
    const ws = join(projects, '-workspace');
    if (isRealDir(legacyDir) && existsSync(legacy) && mkdirNoFollow(projects) && mkdirNoFollow(ws)) {
      copyNoFollow(legacy, join(ws, `${resumeId}.jsonl`), { root: transcriptDirFor(slug), expected: join('-workspace', `${resumeId}.jsonl`) });
    }
  }
  own(dir);
  return dir;
}

export function removeCrewTaskHome(taskId) {
  let id;
  try { id = checkedId(taskId); } catch (_) { return false; }
  const dir = join(rootDir(), id);
  if (!existsSync(dir)) return false;
  try {
    rmSync(dir, { recursive: true, force: true });
    return true;
  } catch (err) {
    log.warn(`[crew-coder] could not remove the home of task ${id}: ${err.message}`);
    return false;
  }
}

/** Remove every task home whose task is closed or no longer exists. Returns the ids removed. */
export function sweepCrewTaskHomes(db) {
  const root = rootDir();
  if (!existsSync(root)) return [];
  const removed = [];
  for (const entry of readdirSync(root)) {
    if (!TASK_ID_RE.test(entry)) {
      try { rmSync(join(root, entry), { recursive: true, force: true }); } catch (_) {}
      continue;
    }
    const t = db.prepare('SELECT state FROM crew_tasks WHERE id = ?').get(entry);
    if (!t || TERMINAL_STATES.includes(t.state)) {
      if (removeCrewTaskHome(entry)) removed.push(entry);
    }
  }
  return removed;
}

export function isTerminalState(state) {
  return TERMINAL_STATES.includes(state);
}

/** Remove crew-coder containers a previous AppCrane process left behind. */
export function recoverCrewCoderOrphans() {
  try {
    const out = execFileSync(
      'docker',
      ['ps', '-a', '--format', '{{.Names}}', '--filter', `label=appcrane.container.type=${CREW_CODER_CONTAINER_TYPE}`],
      { stdio: 'pipe', timeout: 8000 },
    );
    const names = out.toString().split('\n').map((s) => s.trim()).filter(Boolean);
    for (const n of names) {
      try { execFileSync('docker', ['rm', '-f', n], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}
    }
    if (names.length) log.info(`[crew-coder] removed ${names.length} orphan container(s) on startup`);
    return names;
  } catch (_) {
    return [];
  }
}
