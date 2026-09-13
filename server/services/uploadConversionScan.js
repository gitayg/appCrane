/**
 * Read-only analysis of one uploaded release directory for uploadConversion.js:
 * what goes into the repo, what is excluded and why, which bundled .env values
 * would be imported, and whether the converted app would still build.
 *
 * Nothing here follows a symlink or writes anything.
 */

import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readdirSync, readFileSync, readlinkSync, readSync } from 'fs';
import { join, posix } from 'path';
import { parseDotenv } from './dotenvParse.js';
import { detectPhpApp } from './dockerfileGenPhp.js';

export const EXCLUDED_CAP = 200;
export const MAX_ENV_FILE_BYTES = 1024 * 1024;

const EXAMPLE_ENV_RE = /\.(example|sample|template)$/i;
const APPCRANE_KEY_RE = /^[A-Z_][A-Z0-9_]*$/i;
const INSTALL_RE = /\b(npm\s+(ci|install|i)\b|yarn(\s+install)?\b|pnpm\s+(i|install)\b|bun\s+install\b)/;
const FE_CANDIDATES = ['client', 'frontend', 'web', 'app', 'apps/web', 'apps/frontend'];
const BUNDLERS = ['vite', 'webpack', 'react-scripts', '@vitejs/plugin-react', '@vitejs/plugin-vue', 'parcel', 'rollup', 'esbuild'];

export function excludeReason(name) {
  if (name.startsWith('.env')) return 'env_file';
  if (name === 'node_modules') return 'node_modules';
  if (name.toLowerCase() === '.git') return 'git_dir';
  return null;
}

export function isExampleEnvName(name) {
  return EXAMPLE_ENV_RE.test(name);
}

/**
 * Walk a release. Returns { entries, trackedBytes, excluded, skippedFiles,
 * envFiles, nodeModulesParents, tooLarge }. Stops early once maxBytes or
 * maxFiles is exceeded (tooLarge set), so a huge tree is not walked to the end.
 */
export function scanRelease(root, { maxBytes = Infinity, maxFiles = Infinity } = {}) {
  const out = { entries: [], trackedBytes: 0, excluded: [], skippedFiles: [], envFiles: [], nodeModulesParents: [], tooLarge: null };
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    const abs = rel ? join(root, rel) : root;
    const names = readdirSync(abs).sort((a, b) => (Buffer.from(a) < Buffer.from(b) ? -1 : 1));
    const subdirs = [];
    for (const name of names) {
      const relPath = rel ? `${rel}/${name}` : name;
      const st = lstatSync(join(abs, name));
      const reason = excludeReason(name);
      if (reason) {
        out.excluded.push({ path: relPath, reason });
        if (reason === 'env_file') out.envFiles.push({ path: relPath, dir: rel, name, symlink: st.isSymbolicLink(), file: st.isFile() });
        if (reason === 'node_modules') out.nodeModulesParents.push(rel);
        continue;
      }
      if (name.includes('\n')) { out.skippedFiles.push({ path: relPath.replace(/\n/g, '\\n'), reason: 'newline_in_name' }); continue; }
      if (st.isDirectory()) { subdirs.push(relPath); continue; }
      if (st.isSymbolicLink()) {
        const target = readlinkSync(join(abs, name));
        const resolved = posix.normalize(posix.join(rel || '.', target));
        if (target.startsWith('/') || resolved === '..' || resolved.startsWith('../')) {
          out.excluded.push({ path: relPath, reason: 'symlink_outside_release' });
          continue;
        }
        out.entries.push({ path: relPath, kind: 'symlink', mode: '120000', target, size: Buffer.byteLength(target) });
        continue;
      }
      if (st.isFile()) {
        out.entries.push({ path: relPath, kind: 'file', mode: (st.mode & 0o111) ? '100755' : '100644', size: st.size });
        out.trackedBytes += st.size;
        if (out.trackedBytes > maxBytes) { out.tooLarge = { limit: 'bytes', max: maxBytes, reached: out.trackedBytes }; return out; }
        if (out.entries.length > maxFiles) { out.tooLarge = { limit: 'files', max: maxFiles, reached: out.entries.length }; return out; }
        continue;
      }
      out.skippedFiles.push({ path: relPath, reason: 'special_file' });
    }
    for (let i = subdirs.length - 1; i >= 0; i--) stack.push(subdirs[i]);
  }
  return out;
}

/** Read a file without following a symlink at its last component, refusing anything over `cap` bytes. */
export function readNoFollow(path, cap = Infinity) {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw Object.assign(new Error(`${path} is not a regular file`), { code: 'RELEASE_CHANGED' });
    if (st.size > cap) throw Object.assign(new Error(`${path} is larger than ${cap} bytes`), { code: 'FILE_TOO_LARGE' });
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, buf, off, st.size - off, off);
      if (n === 0) break;
      off += n;
    }
    if (off !== st.size) throw Object.assign(new Error(`${path} shrank while being read`), { code: 'RELEASE_CHANGED' });
    return buf;
  } finally {
    closeSync(fd);
  }
}

/**
 * Which bundled values become this env's AppCrane env vars.
 *
 * Imported, in order (later overrides earlier): root `.env`, then root
 * `.env.production` for production or `.env.sandbox` for sandbox. Nothing else
 * is parsed: `.env.development` / `.env.local` / `.env.test` are listed as not
 * imported (AppCrane has no development env, and the generated build runs with
 * NODE_ENV=production, so development values are not what either env ran);
 * example/sample/template files are ignored; nested files are listed; a
 * symlinked file is never read for values. (The FILES themselves are all kept,
 * outside git, by envFileStore.js — this is only about env vars.)
 */
export function analyzeEnvFiles(root, scan, env) {
  const values = new Map();
  const importedFrom = [];
  const parseErrors = [];
  const warnings = [];
  const invalidKeys = [];
  const order = ['.env', env === 'production' ? '.env.production' : '.env.sandbox'];

  for (const name of order) {
    const f = scan.envFiles.find((x) => x.dir === '' && x.name === name);
    if (!f) continue;
    if (f.symlink) { warnings.push({ path: f.path, reason: 'symlink_values_not_imported' }); continue; }
    if (!f.file) { warnings.push({ path: f.path, reason: 'not_a_file_not_read' }); continue; }
    let parsed;
    try {
      parsed = parseDotenv(readNoFollow(join(root, f.path), MAX_ENV_FILE_BYTES));
    } catch (e) {
      parseErrors.push({ path: f.path, reason: e.code === 'FILE_TOO_LARGE' ? 'file_too_large' : 'unreadable' });
      continue;
    }
    for (const err of parsed.errors) parseErrors.push({ path: f.path, ...err });
    importedFrom.push(f.path);
    for (const [k, v] of parsed.values) {
      if (!APPCRANE_KEY_RE.test(k)) { if (!invalidKeys.includes(k)) invalidKeys.push(k); continue; }
      values.set(k, v);
    }
  }
  for (const f of scan.envFiles) {
    if (isExampleEnvName(f.name) || (f.dir === '' && order.includes(f.name))) continue;
    warnings.push({ path: f.path, reason: f.dir === '' ? 'not_imported' : 'nested_not_imported' });
  }

  return { values, importedFrom, parseErrors, warnings, invalidKeys };
}

function readJson(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch (_) { return null; }
}

function detectFrontendWorkdir(root) {
  for (const dir of FE_CANDIDATES) {
    const pkg = readJson(join(root, dir, 'package.json'));
    if (!pkg) continue;
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    if (pkg?.scripts?.build && BUNDLERS.some((b) => deps[b])) return dir;
  }
  return null;
}

/**
 * Would the converted app still get its dependencies? Returns null when yes,
 * or a reason string when the bundled node_modules is load-bearing.
 *
 * Mirrors dockerfileGen.js: an app-provided Dockerfile is used as-is; otherwise
 * a composer.json app is built by dockerfileGenPhp.js (Composer only); otherwise
 * the generated Node Dockerfile installs at the root (--omit=dev), at
 * deployhub.json be.workdir / fe.workdir, or at an auto-detected frontend
 * workdir — and runs the root build script after an --omit=dev install.
 */
export function dependencyProblem(root, scan) {
  const parents = [...new Set(scan.nodeModulesParents)];
  if (parents.length === 0) return null;
  const where = (p) => (p ? `${p}/node_modules` : 'node_modules');

  const dockerfile = join(root, 'Dockerfile');
  if (existsSync(dockerfile) && lstatSync(dockerfile).isFile()) {
    const text = readFileSync(dockerfile, 'utf8');
    if (/node_modules/.test(text)) return 'the app-provided Dockerfile references node_modules, which the repository will not contain';
    if (!INSTALL_RE.test(text)) return `the app-provided Dockerfile runs no package install, so the bundled ${where(parents[0])} is what supplied its dependencies`;
    return null;
  }
  if (detectPhpApp(root)) return `a composer.json app is built with Composer only; the bundled ${where(parents[0])} would not be reinstalled`;

  const manifest = readJson(join(root, 'deployhub.json')) || {};
  const clean = (p) => String(p || '').replace(/^\/+|\/+$/g, '');
  const installed = new Set(['']);
  if (manifest?.be?.workdir) installed.add(clean(manifest.be.workdir));
  if (manifest?.fe?.workdir) installed.add(clean(manifest.fe.workdir));
  if (!manifest?.fe?.workdir && !manifest?.fe) {
    const fe = detectFrontendWorkdir(root);
    if (fe) installed.add(fe);
  }
  for (const p of parents) {
    const pkg = readJson(join(root, p, 'package.json'));
    if (!pkg) return `${where(p)} has no package.json beside it to install from`;
    if (!installed.has(p)) return `${where(p)} is outside every directory the generated Dockerfile installs in (${[...installed].map((d) => d || '.').join(', ')})`;
  }
  const feWorkdir = manifest?.fe?.workdir ? clean(manifest.fe.workdir) : (!manifest?.fe ? detectFrontendWorkdir(root) : null);
  if (parents.includes('') && !feWorkdir) {
    const pkg = readJson(join(root, 'package.json')) || {};
    const devDeps = Object.keys(pkg.devDependencies || {});
    const buildAtRoot = manifest?.fe?.build || manifest?.build?.frontend || pkg?.scripts?.build;
    if (buildAtRoot && devDeps.length) {
      return 'the generated Dockerfile installs with --omit=dev before running the build script, so the build\'s devDependencies came from the bundled node_modules';
    }
  }
  return null;
}
