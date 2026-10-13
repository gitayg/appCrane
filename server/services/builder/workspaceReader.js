import { runInWorkspace } from './workspaceRunner.js';
import { assertSafeWorkspaceGit } from './workspaceGitGuard.js';

// ---------------------------------------------------------------------------
// Reading FILES out of an agent-writable workspace — never on the host
// ---------------------------------------------------------------------------
//
// workspaceRunner.js moved every workspace git/npm into a container because a
// host check-then-act on a path the agent can rewrite is a race the host
// cannot win. Reading a file's bytes is the same shape: the release path used
// to lstat a changed file ("is it a regular file?") and then readFileSync it,
// and the codebase-context builder read key files the same way. Between those
// two calls the agent's container — running the whole time — can swap the file
// for a symlink, or swap a PARENT directory for a symlink, and the host then
// reads whatever that points at with AppCrane's own rights: DATA_DIR/.env (the
// ENCRYPTION_KEY), deployhub.db, another app's workspace. The release would
// commit those bytes into the app's repository; the context builder would put
// them into an LLM prompt. No check from outside closes that window, for the
// same reason no config check did.
//
// So the host never opens a path inside the workspace. A FIXED Node program
// shipped here (READER_SCRIPT — never built from workspace content) runs inside
// the session's container or a confined helper (workspaceRunner.runInWorkspace),
// takes NUL-separated relative paths on stdin, and writes one length-prefixed
// record per path to stdout. Inside the container the only host directory in
// view is the workspace itself, so even a symlink that is followed can only
// reach what the agent could already read with its own Bash tool. It does not
// follow them anyway: a symlink is reported as a symlink (its target string),
// which the callers below refuse or label — never its target's bytes.
//
// Two sources, chosen per caller:
//
//   worktree — the working tree, untracked files included. The release reads
//              this: what the agent changed and has not committed is exactly
//              what a release ships. Opened O_NOFOLLOW, then the opened fd is
//              resolved through /proc/self/fd and must be exactly
//              <workspace>/<path> — that check is on the fd itself, so a parent
//              directory swapped for a symlink after the lstat is caught too,
//              not just a symlink in the last component.
//   commit   — a blob at a given commit, from git's object store (ls-tree for
//              the mode, cat-file for the bytes), never the working tree. The
//              context builder reads this: its document is cached under the
//              HEAD hash, so HEAD's blobs are what it describes. git's tree
//              lookup does not follow symlinks; a 120000 entry is reported as a
//              symlink whose target is the blob.
//
// Record framing (all in one stdout, in request order):
//
//   <kind> <n>\n<body>
//
//   F  regular file; body is its n bytes
//   P  regular file over the per-file cap, truncated (only when `truncate`);
//      body is its first n bytes
//   L  symlink; body is its n-byte target string
//   B  regular file of n bytes, over the per-file cap; no body
//   T  skipped: the batch budget was spent; no body
//   M  missing; no body
//   O  anything else (directory, fifo, device, submodule, a path that resolved
//      outside the workspace, an unreadable file); no body
//
// One container round trip per call, however many paths: a docker exec costs
// ~250 ms on Docker Desktop (v2.104.0 measurement), so one per file would make
// a 40-file release take ten seconds.

/** Record kinds that carry a body. */
const BODY_KINDS = new Set(['F', 'P', 'L']);
const HEADER_RE = /^([FPLBTMO]) (\d{1,12})$/;

/**
 * Runs INSIDE the container (`node -e`), stringified — it must not close over
 * anything in this module. argv: mode, per-file cap, batch budget, truncate
 * (0|1), commit (commit mode only). Paths arrive NUL-separated on stdin.
 */
function readerMain() {
  const fs = require('fs');
  const { spawnSync } = require('child_process');
  const [mode, capArg, budgetArg, truncArg, commit] = process.argv.slice(1);
  const cap = Number(capArg);
  let budget = Number(budgetArg);
  const truncate = truncArg === '1';
  const paths = fs.readFileSync(0).toString('utf8') // in-container: readerMain runs inside the container
   .split('\0').filter((p) => p.length);
  const root = fs.realpathSync('.');
  const out = [];
  const rec = (kind, n, body) => {
    out.push(Buffer.from(`${kind} ${n}\n`));
    if (body) out.push(body);
  };
  // The host validated these already; a second look costs nothing and keeps
  // this program safe to run on its own.
  const bad = (p) => p.startsWith('/') || p.includes('\0') || p.split('/').some((s) => s === '' || s === '.' || s === '..');

  function readFd(fd, n) {
    const buf = Buffer.alloc(n);
    let got = 0;
    while (got < n) {
      const r = fs.readSync(fd, buf, got, n - got, null);
      if (r === 0) break;
      got += r;
    }
    return buf.subarray(0, got);
  }

  function linkRecord(p) {
    let target;
    try { target = Buffer.from(fs.readlinkSync(p)); } catch (_) { return rec('O', 0); } // in-container: readerMain
    return rec('L', target.length, target);
  }

  function worktree(p) {
    let st;
    try { st = fs.lstatSync(p); } catch (_) { return rec('M', 0); }
    if (st.isSymbolicLink()) return linkRecord(p);
    if (!st.isFile()) return rec('O', 0);
    let fd;
    try {
      fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); // in-container: readerMain
    } catch (e) {
      // ELOOP: it became a symlink after the lstat. Report it as one.
      return e.code === 'ELOOP' ? linkRecord(p) : rec('O', 0);
    }
    try {
      const fst = fs.fstatSync(fd);
      if (!fst.isFile()) return rec('O', 0);
      // Where did the open REALLY land? /proc/self/fd names the opened file,
      // so a parent component swapped for a symlink shows up here even though
      // O_NOFOLLOW only guards the last one. Every Linux container has /proc;
      // the realpath fallback is for running this program off-Linux in tests.
      let real;
      try { real = fs.readlinkSync(`/proc/self/fd/${fd}`); } catch (_) { // in-container: readerMain
        try { real = fs.realpathSync(p); } catch (_e) { real = null; }
      }
      if (real !== `${root}/${p}`) return rec('O', 0);
      if (fst.size > cap && !truncate) return rec('B', fst.size);
      if (budget <= 0) return rec('T', 0);
      // cap + 1, never "the size fstat said": the file can grow between the
      // two, and the extra byte is how a grown file is still caught.
      let buf = readFd(fd, cap + 1);
      let partial = false;
      if (buf.length > cap) {
        if (!truncate) return rec('B', buf.length);
        buf = buf.subarray(0, cap);
        partial = true;
      }
      if (buf.length > budget) return rec('T', 0);
      budget -= buf.length;
      return rec(partial ? 'P' : 'F', buf.length, buf);
    } finally {
      fs.closeSync(fd);
    }
  }

  // Commit mode: one ls-tree for every path's mode and size, then the bytes of
  // each wanted blob through `cat-file blob | head -c`, so a huge blob is cut
  // in the pipe and never held whole. Both scripts are fixed; the sha and the
  // byte count are positional arguments.
  function commitMode() {
    const lt = spawnSync('git', ['ls-tree', '-z', '-l', '--full-tree', commit, '--', ...paths], { // in-container: readerMain
      env: { ...process.env, GIT_LITERAL_PATHSPECS: '1' }, maxBuffer: 16 * 1024 * 1024,
    });
    const entries = new Map();
    if (lt.status === 0) {
      for (const e of lt.stdout.toString('utf8').split('\0')) {
        const tab = e.indexOf('\t');
        if (tab < 0) continue;
        const [m, type, sha, size] = e.slice(0, tab).trim().split(/\s+/);
        entries.set(e.slice(tab + 1), { m, type, sha, size: Number(size) });
      }
    }
    const blob = (sha, n) => spawnSync('sh', ['-c', 'git cat-file blob "$1" | head -c "$2"', 'appcrane-reader', sha, String(n)], {
      maxBuffer: n + 1024,
    }).stdout || Buffer.alloc(0);
    for (const p of paths) {
      if (bad(p)) { rec('O', 0); continue; }
      const e = entries.get(p);
      if (!e) { rec('M', 0); continue; }
      if (e.type !== 'blob' || !/^[0-9a-f]{40,64}$/.test(e.sha)) { rec('O', 0); continue; }
      const isLink = e.m === '120000';
      if (!isLink && e.m !== '100644' && e.m !== '100755') { rec('O', 0); continue; }
      if (e.size > cap && !truncate && !isLink) { rec('B', e.size); continue; }
      if (budget <= 0) { rec('T', 0); continue; }
      const want = Math.min(e.size, cap);
      if (want > budget) { rec('T', 0); continue; }
      const buf = blob(e.sha, want);
      budget -= buf.length;
      if (isLink) rec('L', buf.length, buf);
      else rec(e.size > cap ? 'P' : 'F', buf.length, buf);
    }
  }

  if (mode === 'commit') commitMode();
  else for (const p of paths) { if (bad(p)) rec('O', 0); else worktree(p); }
  process.stdout.write(Buffer.concat(out));
}

export const READER_SCRIPT = `(${readerMain.toString()})();`;

/**
 * A repo-relative path from git's own listing, checked before it goes
 * anywhere: no absolute path, no `.` / `..` / empty component, no NUL (the
 * stdin separator). git never prints such a path for a working tree, so one
 * here is a bug or an attack, and it is refused rather than normalised.
 */
export function assertReadablePath(p) {
  if (typeof p !== 'string' || !p) throw new Error(`invalid workspace path ${JSON.stringify(p)}`);
  if (p.includes('\0')) throw new Error(`workspace path contains NUL: ${JSON.stringify(p)}`);
  if (p.startsWith('/')) throw new Error(`workspace path is absolute: ${JSON.stringify(p)}`);
  if (p.split('/').some((s) => s === '' || s === '.' || s === '..')) {
    throw new Error(`workspace path has an empty, '.' or '..' component: ${JSON.stringify(p)}`);
  }
}

/** Parse the reader's stdout into one record per requested path, or throw. */
export function parseReaderOutput(buf, paths, { maxFileBytes }) {
  const out = new Map();
  let off = 0;
  for (const p of paths) {
    const nl = buf.indexOf(0x0a, off);
    if (nl < 0 || nl - off > 32) throw new Error('workspace reader: truncated or malformed output');
    const m = HEADER_RE.exec(buf.subarray(off, nl).toString('latin1'));
    if (!m) throw new Error('workspace reader: malformed record header');
    const kind = m[1];
    const n = Number(m[2]);
    off = nl + 1;
    let body = null;
    if (BODY_KINDS.has(kind)) {
      // The host's own cap, not the container's word for it.
      if (n > maxFileBytes) throw new Error(`workspace reader: a ${n}-byte record is over the ${maxFileBytes}-byte cap`);
      if (off + n > buf.length) throw new Error('workspace reader: truncated record body');
      body = Buffer.from(buf.subarray(off, off + n));
      off += n;
    }
    out.set(p, kind === 'L' ? { kind, size: n, target: body.toString('utf8') } : { kind, size: n, body });
  }
  if (off !== buf.length) throw new Error('workspace reader: trailing output after the last record');
  return out;
}

/**
 * Read `paths` out of the workspace in ONE container round trip.
 * Returns Map<path, { kind, size, body?: Buffer, target?: string }>.
 *
 * `container` is the session's live container (docker exec as the studio
 * user) or null for a confined helper — see workspaceRunner.runInWorkspace.
 */
export function readWorkspaceFiles(workspaceDir, paths, {
  source = 'worktree', commit = null, maxFileBytes, maxBatchBytes, truncate = false, container = null, timeout = 60000,
} = {}) {
  if (!Number.isInteger(maxFileBytes) || maxFileBytes <= 0) throw new Error('readWorkspaceFiles needs maxFileBytes');
  if (!Number.isInteger(maxBatchBytes) || maxBatchBytes <= 0) throw new Error('readWorkspaceFiles needs maxBatchBytes');
  if (source !== 'worktree' && source !== 'commit') throw new Error(`unknown read source ${source}`);
  if (source === 'commit' && !/^(?:[0-9a-f]{40}|[0-9a-f]{64}|HEAD)$/.test(String(commit))) {
    throw new Error(`refusing to read at commit ${JSON.stringify(commit)}`);
  }
  for (const p of paths) assertReadablePath(p);
  if (new Set(paths).size !== paths.length) throw new Error('readWorkspaceFiles: duplicate path');
  if (!paths.length) return new Map();
  // commit mode runs git in the workspace: the same config allowlist every
  // workspace git gets (defence in depth inside the sandbox).
  if (source === 'commit') assertSafeWorkspaceGit(workspaceDir);
  const argv = ['node', '-e', READER_SCRIPT, '--', source, String(maxFileBytes), String(maxBatchBytes), truncate ? '1' : '0'];
  if (source === 'commit') argv.push(commit);
  const stdout = runInWorkspace(workspaceDir, argv, {
    container,
    // NODE_OPTIONS cleared so nothing in the container's environment can
    // --require a module into the reader.
    env: { NODE_OPTIONS: '' },
    input: `${paths.join('\0')}\0`,
    timeout,
    maxBuffer: maxBatchBytes + 64 * paths.length + 1024 * 1024,
  });
  const recs = parseReaderOutput(stdout, paths, { maxFileBytes });
  let total = 0;
  for (const r of recs.values()) if (r.body) total += r.body.length;
  if (total > maxBatchBytes) throw new Error(`workspace reader: ${total} bytes is over the ${maxBatchBytes}-byte batch cap`);
  return recs;
}
