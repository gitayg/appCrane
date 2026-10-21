import AdmZip from 'adm-zip';
import { inflateRawSync } from 'zlib';

// Reading an uploaded or downloaded project archive into memory, without ever
// writing an entry to disk and without trusting a single name or size in it.
//
// adm-zip is used only to walk the central directory. Its entryName is NOT
// used: adm-zip silently rewrites "a/../../x" to "x", which would turn a
// zip-slip attempt into an ordinary-looking file instead of a refusal. Names
// are decoded from the raw bytes and the whole archive is refused when any of
// them is absolute, contains "..", a backslash, a drive letter or a NUL.
// Entries are inflated here with a hard output cap, so a declared size that
// lies (a zip bomb) stops at the cap instead of at the end of memory.

const num = (envName, fallback) => {
  const n = Number(process.env[envName]);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

export function adoptLimits() {
  return {
    maxArchiveBytes: num('APPCRANE_ADOPT_MAX_ARCHIVE_BYTES', 50 * 1024 * 1024),
    maxTotalBytes: num('APPCRANE_ADOPT_MAX_TOTAL_BYTES', 150 * 1024 * 1024),
    maxFileBytes: num('APPCRANE_ADOPT_MAX_FILE_BYTES', 20 * 1024 * 1024),
    maxEntries: num('APPCRANE_ADOPT_MAX_ENTRIES', 20000),
    maxFiles: num('APPCRANE_ADOPT_MAX_FILES', 5000),
  };
}

// Never imported into the app's repository. Dependencies and build output are
// rebuilt from source; VCS metadata belongs to the old host.
const EXCLUDED_DIRS = new Set(['node_modules', '.git', '.next', '.nuxt', '.output', '.vercel', '.netlify',
  '.turbo', '.cache', '.parcel-cache', '__pycache__', '.venv', 'venv', '.pythonlibs', '.upm', '.svelte-kit']);
const EXCLUDED_FILES = new Set(['.DS_Store', 'Thumbs.db']);

export class ArchiveRefused extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
    this.statusCode = 400;
  }
}

/** The reason a raw entry name is unsafe, or null. */
export function unsafeEntryName(name) {
  if (typeof name !== 'string' || name.length === 0) return 'empty name';
  if (name.length > 1024) return 'name too long';
  if (name.includes('\0')) return 'NUL in name';
  if (name.includes('\\')) return 'backslash in name';
  if (name.startsWith('/')) return 'absolute path';
  if (/^[A-Za-z]:/.test(name)) return 'drive letter';
  const segs = name.replace(/\/+$/, '').split('/');
  if (segs.some((s) => s === '..')) return '".." segment';
  if (segs.some((s) => s === '')) return 'empty segment';
  return null;
}

function isSymlink(entry) {
  const mode = (entry.header.attr >>> 16) & 0o170000;
  return mode === 0o120000;
}

function inflateEntry(entry, cap) {
  const { method, flags } = entry.header;
  if (flags & 0x1) throw new ArchiveRefused('ARCHIVE_ENCRYPTED', 'The archive has an encrypted entry; export it without a password.');
  const raw = entry.getCompressedData();
  if (method === 0) {
    if (raw.length > cap) return null;
    return raw;
  }
  if (method === 8) {
    try {
      return inflateRawSync(raw, { maxOutputLength: cap });
    } catch (e) {
      if (e.code === 'ERR_BUFFER_TOO_LARGE' || /maxOutputLength|buffer/i.test(e.message)) return null;
      throw new ArchiveRefused('ARCHIVE_CORRUPT', `An entry could not be decompressed: ${e.message}`);
    }
  }
  throw new ArchiveRefused('ARCHIVE_METHOD', `Unsupported zip compression method ${method}; use a standard zip.`);
}

/**
 * Read a zip into { files: Map<path, Buffer>, skipped: [{ path, reason }], stripped }.
 * A single top-level directory shared by every entry (GitHub's zipball wraps
 * the tree in "<owner>-<repo>-<sha>/", a downloaded zip often in "<project>/")
 * is stripped. Throws ArchiveRefused for anything unsafe or over a limit.
 */
export function readProjectZip(buffer, limits = adoptLimits()) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) throw new ArchiveRefused('ARCHIVE_EMPTY', 'The archive is empty.');
  if (buffer.length > limits.maxArchiveBytes) {
    throw new ArchiveRefused('ARCHIVE_TOO_LARGE', `The archive is ${buffer.length} bytes, over the ${limits.maxArchiveBytes} byte limit.`);
  }
  let zip;
  try { zip = new AdmZip(buffer); } catch (e) {
    throw new ArchiveRefused('ARCHIVE_CORRUPT', `Not a readable zip archive: ${e.message}`);
  }
  let entries;
  try { entries = zip.getEntries(); } catch (e) {
    throw new ArchiveRefused('ARCHIVE_CORRUPT', `Not a readable zip archive: ${e.message}`);
  }
  if (entries.length > limits.maxEntries) {
    throw new ArchiveRefused('ARCHIVE_TOO_MANY_ENTRIES', `The archive has ${entries.length} entries, over the ${limits.maxEntries} limit.`);
  }

  const named = entries.map((e) => ({ entry: e, name: e.rawEntryName.toString('utf8') }));
  for (const { name } of named) {
    const why = unsafeEntryName(name);
    if (why) throw new ArchiveRefused('ARCHIVE_UNSAFE_PATH', `Refused: the archive has an unsafe entry name (${why}): ${JSON.stringify(name.slice(0, 200))}`);
  }

  const firstSegs = new Set(named.map(({ name }) => name.split('/')[0]));
  const allNested = named.every(({ name, entry }) => name.includes('/') || entry.isDirectory);
  const stripped = firstSegs.size === 1 && allNested ? [...firstSegs][0] : null;

  const files = new Map();
  const skipped = [];
  let total = 0;
  for (const { entry, name } of named) {
    if (entry.isDirectory || name.endsWith('/')) continue;
    const path = stripped ? name.slice(stripped.length + 1) : name;
    if (!path) continue;
    const segs = path.split('/');
    if (segs.slice(0, -1).some((s) => EXCLUDED_DIRS.has(s))) continue;
    if (EXCLUDED_FILES.has(segs[segs.length - 1])) continue;
    if (isSymlink(entry)) { skipped.push({ path, reason: 'symlink (not followed)' }); continue; }
    if (entry.header.size > limits.maxFileBytes) { skipped.push({ path, reason: `over ${limits.maxFileBytes} bytes` }); continue; }
    const data = inflateEntry(entry, limits.maxFileBytes);
    if (data === null) { skipped.push({ path, reason: `over ${limits.maxFileBytes} bytes` }); continue; }
    total += data.length;
    if (total > limits.maxTotalBytes) {
      throw new ArchiveRefused('ARCHIVE_TOO_LARGE', `The project unpacks to more than ${limits.maxTotalBytes} bytes (dependencies and build output excluded).`);
    }
    if (files.size >= limits.maxFiles) {
      throw new ArchiveRefused('ARCHIVE_TOO_MANY_FILES', `The project has more than ${limits.maxFiles} files (dependencies and build output excluded).`);
    }
    files.set(path, data);
  }
  if (files.size === 0) throw new ArchiveRefused('ARCHIVE_EMPTY', 'The archive holds no project files.');
  return { files, skipped, stripped };
}
