import { lstatSync } from 'fs';
import { join } from 'path';
import { writeFileInside } from '../utils/paths.js';

// A generated Dockerfile's `COPY . .` used to take the whole release directory,
// .git included. .git differs between two clones of the same commit (pack
// files, index, FETCH_HEAD), so the COPY layer and every layer after it missed
// the cache on each new clone, a promote included, and .git ended up inside the
// image. Nothing a generated build runs reads it: node:*-alpine and
// php:*-apache ship no git binary.
//
// node_modules is listed only where the generated build installs into it, so
// a committed node_modules cannot overwrite the tree `npm ci` just built. Other
// directories of that name are left in the context: an app may serve them.
//
// An app's own .dockerignore, or anything at that path, is never replaced.

/** Write .dockerignore into releaseDir unless one exists. Returns true when written. */
export function ensureDockerignore(releaseDir, { nodeModulesDirs = [] } = {}) {
  const path = join(releaseDir, '.dockerignore');
  try {
    lstatSync(path);
    return false;
  } catch (_) {}
  const entries = ['.git', ...nodeModulesDirs.map((d) => (d === '.' ? 'node_modules' : `${d}/node_modules`))];
  writeFileInside(releaseDir, path, `${[...new Set(entries)].join('\n')}\n`);
  return true;
}
