// Writing a file into an app's /data without trusting the app's own tree
// (security audit 2026-10-06, H1).
//
// An app's /data is app-writable, so it can hold symbolic links its code
// planted. A host-side mkdir/write/rename that follows them writes wherever the
// AppCrane process can (root on a default install). Checking the path as TEXT
// does not help; checking with realpath/lstat and then writing leaves a race
// the app can win by swapping a directory for a link in between.
//
// So:
//  - container RUNNING: the bytes are streamed INTO the container with
//    `docker cp -` (a tar on stdin). Docker resolves the path inside the
//    container, where a link can only point at the container's own files.
//    Nothing on the host follows anything the app wrote.
//  - container NOT running: no app code can change the tree during the write,
//    so the host path is walked one segment at a time with lstat and any
//    symbolic link is refused; the file is created exclusively and renamed.

import { execFile } from 'child_process';
import { promisify } from 'util';
import { lstatSync, mkdirSync, mkdtempSync, openSync, writeSync, closeSync, renameSync, rmSync, realpathSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { randomBytes } from 'crypto';

const run = promisify(execFile);
export const CONTAINER_DATA_PATH = '/data';

/**
 * Absolute host path of `rel` under `root`, refusing any symbolic link on the
 * way (including the last segment). Missing parent directories are created
 * when `createParents` is set. `rel` must already be a clean relative path.
 */
export function confinedHostPath(root, rel, { createParents = false } = {}) {
  const segs = String(rel).split('/').filter(Boolean);
  if (!segs.length) throw new Error('path is required');
  let cur = realpathSync(root);
  segs.forEach((seg, i) => {
    const next = join(cur, seg);
    const last = i === segs.length - 1;
    let st = null;
    try { st = lstatSync(next); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (st?.isSymbolicLink()) {
      throw new Error(`Security: '${segs.slice(0, i + 1).join('/')}' in /data is a symbolic link; refusing to follow it`);
    }
    if (!last) {
      if (!st) {
        if (!createParents) throw new Error(`'${segs.slice(0, i + 1).join('/')}' does not exist`);
        mkdirSync(next);
      } else if (!st.isDirectory()) {
        throw new Error(`'${segs.slice(0, i + 1).join('/')}' is not a directory`);
      }
    }
    cur = next;
  });
  return cur;
}

/**
 * `rel` reaches `tar` as an argument. A segment starting with "-" would be read
 * as a tar OPTION (--checkpoint-action=exec=... runs a command on the host), so
 * it is refused outright, and tar is also given "--" before it below.
 */
function assertCleanRel(rel) {
  const segs = String(rel).split('/');
  if (!rel || segs.some(s => s === '' || s === '.' || s === '..')) throw new Error('path must be a clean relative path');
  if (segs.some(s => s.startsWith('-'))) throw new Error('path segments must not start with "-"');
  if (/[\0\n\r]/.test(rel)) throw new Error('path must not contain control characters');
}

// 'running' | 'absent' | 'stopped'. Anything Docker will not answer clearly is
// an error, never "stopped": a host-side write is only safe when no app code
// can be changing the tree, so an unreadable state fails closed (security
// review of v2.97.1).
async function containerState(name) {
  try {
    const { stdout } = await run('docker', ['inspect', '-f', '{{.State.Running}}', name], { timeout: 10000 });
    const v = stdout.trim();
    if (v === 'true') return 'running';
    if (v === 'false') return 'stopped';
    throw new Error(`unexpected docker inspect output '${v.slice(0, 40)}'`);
  } catch (e) {
    const detail = String(e.stderr || e.message || '');
    if (/no such (object|container)/i.test(detail)) return 'absent';
    throw new Error(`cannot tell whether ${name} is running, so /data is not written: ${detail.trim().split('\n')[0].slice(0, 200)}`);
  }
}

/** Stream `buf` into the running container at /data/<rel> via `docker cp -`. */
async function writeIntoContainer(container, rel, buf) {
  const stage = mkdtempSync(join(tmpdir(), 'appcrane-cp-'));
  try {
    const file = join(stage, ...rel.split('/'));
    mkdirSync(dirname(file), { recursive: true });
    const fd = openSync(file, 'wx', 0o644);
    try { writeSync(fd, buf); } finally { closeSync(fd); }
    const { stdout: tar } = await run('tar', ['-C', stage, '-cf', '-', '--', rel], { encoding: 'buffer', maxBuffer: 1024 * 1024 * 1024, timeout: 120000 });
    await new Promise((resolve, reject) => {
      const child = execFile('docker', ['cp', '-', `${container}:${CONTAINER_DATA_PATH}`], { timeout: 120000 },
        (err, _out, stderr) => (err ? reject(new Error(`docker cp failed: ${String(stderr || err.message).trim()}`)) : resolve()));
      child.stdin.end(tar);
    });
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
}

/**
 * Write `buf` to /data/<rel> of the app's `env` container. Returns
 * { via: 'container' | 'host' } so callers can report which path was taken.
 */
export async function writeAppData({ dataDir, slug, env, rel, buf }) {
  assertCleanRel(rel);
  const container = `appcrane-${slug}-${env}`;
  // Running OR stopped: docker cp works on both and resolves the path inside
  // the container (verified live: a link to /etc in a stopped container's
  // bind-mounted /data wrote the container's /etc, not the host's). Checking
  // "stopped" and then writing on the host left a race: the container can start
  // in between (commit review of v2.97.1).
  if (await containerState(container) !== 'absent') {
    await writeIntoContainer(container, rel, buf);
    return { via: 'container' };
  }
  const root = join(dataDir, 'apps', slug, env, 'shared', 'data');
  mkdirSync(root, { recursive: true });
  const target = confinedHostPath(root, rel, { createParents: true });
  const tmp = join(dirname(target), `.appcrane-tmp-${randomBytes(8).toString('hex')}`);
  const fd = openSync(tmp, 'wx', 0o644); // exclusive: never opens an existing file or link
  try { writeSync(fd, buf); } finally { closeSync(fd); }
  renameSync(tmp, target); // rename replaces a path, it does not follow a link at the target
  return { via: 'host' };
}
