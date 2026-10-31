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
import { mkdirSync, chmodSync, existsSync, rmSync, readdirSync, copyFileSync } from 'fs';
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
    execFileSync('chown', ['-R', `${STUDIO_UID}:${STUDIO_GID}`, dir], { stdio: 'pipe' });
    chmodSync(dir, 0o700);
  } catch (_) {
    // Not root: leave it writable for the container's uid, as appContainer does
    // with the transcripts.
    try { chmodSync(dir, 0o777); } catch (_) {}
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
  mkdirSync(dir, { recursive: true });
  for (const f of ['credentials.json', '.credentials.json', 'skills']) {
    try { rmSync(join(dir, f), { recursive: true, force: true }); } catch (_) {}
  }
  if (slug && resumeId && SESSION_ID_RE.test(String(resumeId))) {
    const target = join(dir, 'projects', '-workspace', `${resumeId}.jsonl`);
    const legacy = join(transcriptDirFor(slug), '-workspace', `${resumeId}.jsonl`);
    if (!existsSync(target) && existsSync(legacy)) {
      mkdirSync(join(dir, 'projects', '-workspace'), { recursive: true });
      copyFileSync(legacy, target);
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
