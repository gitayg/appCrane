import { lstatSync, realpathSync, openSync, writeSync, closeSync, constants as fsConstants } from 'fs';
import { resolve, sep, dirname } from 'path';

/**
 * Resolve a path and assert it stays within base.
 * Throws if the resolved path escapes the base directory.
 */
export function resolveSafe(base, ...parts) {
  const resolvedBase = resolve(base);
  const resolved = resolve(base, ...parts);
  if (resolved !== resolvedBase && !resolved.startsWith(resolvedBase + sep)) {
    throw new Error(`Path traversal attempt detected: ${resolved}`);
  }
  return resolved;
}

// A repository AppCrane clones onto the host — a release directory, an
// AppStudio or coder workspace — can commit symbolic links, and git checks
// them out as links. Every host-side read or write into such a tree has to
// refuse to follow one: `public/icon.png -> /root/appCrane/.env` was copied to
// the public icon URL, and a dangling `Dockerfile -> /etc/cron.d/x` made the
// generated Dockerfile land in /etc. These two helpers are that rule.

function isInside(realRoot, realPath) {
  return realPath === realRoot || realPath.startsWith(realRoot + sep);
}

/**
 * True only for a regular file (not a link) whose directory really resolves
 * inside `root`. Anything else — missing, a link, a directory, a parent that
 * is a link out of the tree — is false.
 */
export function regularFileInside(root, path) {
  try {
    if (!lstatSync(path).isFile()) return false;
    return isInside(realpathSync(root), realpathSync(dirname(path)));
  } catch (_) {
    return false;
  }
}

/**
 * writeFileSync that refuses a path whose directory resolves outside `root`
 * or whose last component is a link (O_NOFOLLOW: a dangling link is refused
 * too, rather than created through).
 */
export function writeFileInside(root, path, data, { mode = 0o644 } = {}) {
  const realDir = realpathSync(dirname(path));
  if (!isInside(realpathSync(root), realDir)) {
    throw new Error(`refusing to write ${path}: its directory resolves outside ${root}`);
  }
  let fd;
  try {
    fd = openSync(path, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC | fsConstants.O_NOFOLLOW, mode);
  } catch (e) {
    if (e.code === 'ELOOP' || e.code === 'EMLINK') throw new Error(`refusing to write ${path}: it is a symbolic link`);
    throw e;
  }
  try { writeSync(fd, data); } finally { closeSync(fd); }
}
