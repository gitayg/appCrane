/**
 * File plumbing shared by the data archive (configBackup.js) and the per-repo
 * archives (repoArchive.js). Everything here streams: no archive, bundle or
 * data file is ever read whole into this process.
 *
 * WHY THE SYSTEM `tar` AND NOT adm-zip. adm-zip holds the whole archive in
 * memory in both directions (`toBuffer()` to write, `new AdmZip(buffer)` to
 * read), and it is synchronous, so a large export both balloons the heap and
 * freezes the event loop. `tar` spawned with an argument array writes straight
 * to a file from its own process: Node sees neither the bytes nor the
 * directory walk. It is on every supported host (GNU tar 1.34 on
 * node:22-bookworm, bsdtar 3.5 on macOS), so it adds no dependency.
 *
 * adm-zip also DEREFERENCED symlinks on export (measured: a /data symlink to a
 * file outside the app's tree was archived as that file's content). An app can
 * create symlinks in its own /data, so that was a way for a hosted app to get a
 * host file into the backup and, on restore, into its own tree. tar is run
 * without -h, so a symlink is archived as a symlink.
 *
 * Old (<= v2.73) backups are zips. They are read with the small streaming
 * reader at the bottom of this file, which inflates one entry at a time from
 * a file range and checks each entry's CRC-32.
 */

import { execFile } from 'child_process';
import { createReadStream, createWriteStream, existsSync, statfsSync } from 'fs';
import {
  mkdir, mkdtemp, open, opendir, realpath, lstat, stat, chmod,
} from 'fs/promises';
import { createHash } from 'crypto';
import { Transform } from 'stream';
import { pipeline } from 'stream/promises';
import { createInflateRaw, crc32 } from 'zlib';
import { join, resolve, dirname, basename, sep } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const repoRoot = resolve(join(__dirname, '..', '..'));
export const dataDir = () => resolve(process.env.DATA_DIR || join(repoRoot, 'data'));
export const backupsDir = () => join(dataDir(), 'backups');

export const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,99}$/;

export async function ensureBackupsDir() {
  const dir = backupsDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/** A private scratch dir inside DATA_DIR/backups (same filesystem as DATA_DIR, so renames are atomic). */
export async function newWorkDir(label) {
  const dir = await ensureBackupsDir();
  return mkdtemp(join(dir, `.${label}-`));
}

export function freeBytes(dir) {
  try {
    const st = statfsSync(existsSync(dir) ? dir : dataDir());
    return st.bavail * st.bsize;
  } catch (_) {
    return null;
  }
}

/**
 * Resolve an operator-supplied archive path and refuse anything outside
 * DATA_DIR/backups. A bare name is taken relative to that directory. The check
 * is done twice: on the resolved string, then on the real path, so a symlink
 * placed inside backups/ cannot point the import at an arbitrary file.
 */
export async function confineToBackups(raw) {
  const s = String(raw || '').trim();
  if (!s) throw Object.assign(new Error('path required (an archive inside the backups directory)'), { status: 400 });
  const dir = resolve(backupsDir());
  const abs = resolve(s.includes('/') ? s : join(dir, s));
  const inside = (p, root) => p !== root && p.startsWith(root + sep);
  if (!inside(abs, dir)) {
    throw Object.assign(new Error(`archive must be inside ${dir} (got ${basename(abs)} elsewhere)`), { status: 400 });
  }
  let real;
  try { real = await realpath(abs); } catch (_) {
    throw Object.assign(new Error(`No such archive: ${basename(abs)}`), { status: 404 });
  }
  const realDir = await realpath(dir);
  if (!inside(real, realDir)) {
    throw Object.assign(new Error(`archive must be inside ${dir} (${basename(abs)} resolves elsewhere)`), { status: 400 });
  }
  const st = await stat(real);
  if (!st.isFile()) throw Object.assign(new Error(`${basename(abs)} is not a file`), { status: 400 });
  return real;
}

// ---------------------------------------------------------------------------
// tar
// ---------------------------------------------------------------------------

function run(cmd, args, { maxStderr = 64 * 1024 } = {}) {
  return new Promise((resolveP) => {
    const child = execFile(cmd, args, { env: { PATH: process.env.PATH || '/usr/bin:/bin', LC_ALL: 'C' }, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => {
        resolveP({ code: err ? (typeof err.code === 'number' ? err.code : 127) : 0, stdout: String(stdout || ''), stderr: String(stderr || '').slice(-maxStderr) });
      });
    child.stdin?.end();
  });
}

let flavor = null;
export async function tarFlavor() {
  if (flavor) return flavor;
  const r = await run('tar', ['--version']);
  if (r.code !== 0) throw new Error('the system `tar` is not available; backups need it');
  flavor = /GNU tar/.test(r.stdout) ? 'gnu' : 'bsd';
  return flavor;
}

/**
 * Create `dest` from groups of { cwd, paths }. Each group becomes `-C cwd paths…`.
 * Paths are relative member names chosen by the caller and never start with
 * '-', so none can be read as an option.
 *
 * GNU tar exits 1 when a file changed while it was read — normal for a live
 * app's /data. That is returned as a warning, not a failure; any other non-zero
 * status is a failure.
 */
export async function createTar(dest, groups, { gzip = false } = {}) {
  const fl = await tarFlavor();
  const args = ['-c', ...(gzip ? ['-z'] : []), '-f', dest];
  for (const g of groups) {
    if (!g.paths.length) continue;
    for (const p of g.paths) {
      if (typeof p !== 'string' || !p || p.startsWith('-') || p.startsWith('/') || p.split('/').includes('..')) {
        throw new Error(`refusing tar member ${JSON.stringify(p)}`);
      }
    }
    args.push('-C', g.cwd, ...g.paths);
  }
  const r = await run('tar', args);
  const lines = r.stderr.split('\n').map((l) => l.trim()).filter(Boolean);
  if (r.code === 0) return { warnings: lines };
  if (fl === 'gnu' && r.code === 1 && lines.every((l) => /file changed as we read it/.test(l))) {
    return { warnings: lines };
  }
  throw new Error(`tar create failed (exit ${r.code}): ${lines.slice(-5).join(' | ')}`);
}

/** Extract `archive` into `destDir` (which must exist and be empty). */
export async function extractTar(archive, destDir, { gzip = false, members = [] } = {}) {
  for (const m of members) {
    if (typeof m !== 'string' || !m || m.startsWith('-') || m.startsWith('/')) throw new Error(`refusing tar member ${JSON.stringify(m)}`);
  }
  const r = await run('tar', ['-x', ...(gzip ? ['-z'] : []), '-f', archive, '-C', destDir, ...members]);
  if (r.code !== 0) {
    throw new Error(`tar extract failed (exit ${r.code}): ${r.stderr.trim().split('\n').slice(-5).join(' | ')}`);
  }
}

// ---------------------------------------------------------------------------
// Trees
// ---------------------------------------------------------------------------

/** Async walk yielding { rel, abs, type } without following symlinks. */
export async function* walk(root, rel = '') {
  const dir = await opendir(rel ? join(root, rel) : root);
  for await (const d of dir) {
    const r = rel ? `${rel}/${d.name}` : d.name;
    const type = d.isDirectory() ? 'dir' : d.isFile() ? 'file' : d.isSymbolicLink() ? 'symlink' : 'other';
    yield { rel: r, abs: join(root, r), type };
    if (type === 'dir') yield* walk(root, r);
  }
}

export async function treeBytes(root) {
  let total = 0;
  if (!existsSync(root)) return 0;
  for await (const e of walk(root)) {
    if (e.type === 'file') total += (await lstat(e.abs)).size;
  }
  return total;
}

export async function sha256File(path) {
  const h = createHash('sha256');
  await pipeline(createReadStream(path), new Transform({
    transform(chunk, _e, cb) { h.update(chunk); cb(); },
  }));
  return h.digest('hex');
}

export async function readHead(path, bytes) {
  const fh = await open(path, 'r');
  try {
    const buf = Buffer.alloc(bytes);
    const { bytesRead } = await fh.read(buf, 0, bytes, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

export async function privateFile(path) {
  await chmod(path, 0o600);
}

// ---------------------------------------------------------------------------
// Streaming zip reader (old backups only)
// ---------------------------------------------------------------------------

/**
 * The central directory of a zip on disk. Only what adm-zip ever wrote is
 * supported — stored or deflated entries, no encryption, no zip64 — and
 * anything else is refused by name rather than misread. The central directory
 * is metadata (46 bytes + name per entry), not archive data.
 */
export async function readZipDirectory(path) {
  const fh = await open(path, 'r');
  try {
    const { size } = await fh.stat();
    const tailLen = Math.min(size, 65557);
    const tail = Buffer.alloc(tailLen);
    await fh.read(tail, 0, tailLen, size - tailLen);
    let eocd = -1;
    for (let i = tailLen - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('Not a valid zip file');
    const count = tail.readUInt16LE(eocd + 10);
    const cdSize = tail.readUInt32LE(eocd + 12);
    const cdOffset = tail.readUInt32LE(eocd + 16);
    if (cdOffset === 0xffffffff || cdSize === 0xffffffff || count === 0xffff) throw new Error('zip64 backups are not supported');
    if (cdOffset + cdSize > size) throw new Error('Not a valid zip file (central directory out of range)');
    const cd = Buffer.alloc(cdSize);
    await fh.read(cd, 0, cdSize, cdOffset);
    const entries = [];
    let p = 0;
    for (let i = 0; i < count; i++) {
      if (p + 46 > cd.length || cd.readUInt32LE(p) !== 0x02014b50) throw new Error('Not a valid zip file (central directory corrupt)');
      const flags = cd.readUInt16LE(p + 8);
      const method = cd.readUInt16LE(p + 10);
      const crc = cd.readUInt32LE(p + 16);
      const compSize = cd.readUInt32LE(p + 20);
      const rawSize = cd.readUInt32LE(p + 24);
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      const offset = cd.readUInt32LE(p + 42);
      const name = cd.subarray(p + 46, p + 46 + nameLen).toString('utf8');
      p += 46 + nameLen + extraLen + commentLen;
      if (flags & 1) throw new Error(`zip entry ${name} is encrypted`);
      if (method !== 0 && method !== 8) throw new Error(`zip entry ${name} uses unsupported compression ${method}`);
      entries.push({ name, method, crc, compSize, rawSize, offset, isDirectory: name.endsWith('/') });
    }
    return { size, entries };
  } finally {
    await fh.close();
  }
}

/** Inflate one entry to `dest` (created exclusively), verifying size and CRC-32. */
export async function extractZipEntry(path, entry, dest) {
  const fh = await open(path, 'r');
  let dataStart;
  try {
    const lh = Buffer.alloc(30);
    await fh.read(lh, 0, 30, entry.offset);
    if (lh.readUInt32LE(0) !== 0x04034b50) throw new Error(`zip entry ${entry.name}: bad local header`);
    dataStart = entry.offset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
  } finally {
    await fh.close();
  }
  let crc = 0;
  let bytes = 0;
  const check = new Transform({
    transform(chunk, _e, cb) { crc = crc32(chunk, crc); bytes += chunk.length; cb(null, chunk); },
  });
  const stages = [];
  if (entry.compSize > 0) {
    stages.push(createReadStream(path, { start: dataStart, end: dataStart + entry.compSize - 1 }));
    if (entry.method === 8) stages.push(createInflateRaw());
  } else {
    const { Readable } = await import('stream');
    stages.push(Readable.from([]));
  }
  await pipeline(...stages, check, createWriteStream(dest, { flags: 'wx', mode: 0o600 }));
  if (bytes !== entry.rawSize || (crc >>> 0) !== entry.crc) {
    throw new Error(`zip entry ${entry.name} is corrupt (size or CRC mismatch)`);
  }
}
