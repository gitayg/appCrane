// The npm bump: npm's own resolver, in a confined helper container, then a
// diff of the lockfile that refuses anything but the one package moving.
//
// Measured with npm 10 before this was written:
//   direct dependency:     `npm install --package-lock-only <name>@<fixed>`
//                          changes the package's range in package.json and in
//                          the lockfile root, and its node_modules entry. Kept.
//   transitive dependency: the same command adds <name> to package.json; the
//                          original package.json is put back and a second
//                          `npm install --package-lock-only` drops the root edge
//                          and keeps node_modules/<name> at the fixed version,
//                          because a locked version that satisfies every
//                          dependent's range is left where it is. Net change:
//                          version, resolved and integrity of that one entry.
//
// No lifecycle script runs (--ignore-scripts and --package-lock-only extract no
// tarball). The container sees only package.json and package-lock.json: no
// .npmrc, no token, no other file of the app. The registry is the public npm
// registry, set explicitly; an app whose lockfile resolves the package from
// anywhere else is refused before this runs.

import { execFile, execFileSync } from 'child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, chmodSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';
import { randomBytes } from 'crypto';
import { OOM_APP_FLAG } from '../oomPriority.js';
import { CPU_BUILD_FLAG } from '../cpuPriority.js';

export const NPM_REGISTRY = 'https://registry.npmjs.org/';
export const NPM_HELPER_IMAGE = process.env.AUTO_PATCH_NPM_IMAGE || 'node:22-slim';
export const NPM_HELPER_LABEL = 'appcrane.container.type=auto-patch';
export const NPM_HELPER_MEMORY_MB = 1024;
const TIMEOUT_MS = 180_000;
const NAME_RE = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i;
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$/;

const SCRIPT = [
  'set -eu',
  'cd /work',
  'npm install --package-lock-only --ignore-scripts --no-audit --no-fund "$1@$2"',
  'if [ "$3" = transitive ]; then',
  '  cp /work/orig/package.json /work/package.json',
  '  npm install --package-lock-only --ignore-scripts --no-audit --no-fund',
  'fi',
].join('\n');

export function assertBumpTarget(name, version) {
  if (typeof name !== 'string' || !NAME_RE.test(name)) throw new Error(`refusing to bump an npm package named ${JSON.stringify(name)}`);
  if (typeof version !== 'string' || !VERSION_RE.test(version)) throw new Error(`refusing to bump to version ${JSON.stringify(version)}`);
}

/** The docker argv. Asserted by the tests: confinement must not drift. */
export function npmHelperArgs({ workDir, name, version, mode, containerName }) {
  assertBumpTarget(name, version);
  if (!['direct', 'transitive'].includes(mode)) throw new Error(`unknown bump mode ${mode}`);
  if (typeof workDir !== 'string' || !workDir.startsWith('/') || workDir.includes(':')) throw new Error('workDir must be an absolute path without ":"');
  return [
    'run', '--rm',
    '--name', containerName,
    '--label', NPM_HELPER_LABEL,
    OOM_APP_FLAG,
    CPU_BUILD_FLAG,
    '--pull', 'missing',
    '--user', '1000:1000',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', '256',
    '--memory', `${NPM_HELPER_MEMORY_MB}m`,
    '--cpus', '1',
    '--read-only',
    '--tmpfs', '/tmp:rw,nosuid,size=512m',
    '-v', `${workDir}:/work`,
    '-e', 'HOME=/tmp',
    '-e', 'npm_config_cache=/tmp/.npm',
    '-e', `npm_config_registry=${NPM_REGISTRY}`,
    '-e', 'npm_config_userconfig=/tmp/no-user-npmrc',
    '-e', 'npm_config_globalconfig=/tmp/no-global-npmrc',
    '-e', 'npm_config_ignore_scripts=true',
    '-e', 'npm_config_update_notifier=false',
    '--entrypoint', 'sh',
    NPM_HELPER_IMAGE,
    '-c', SCRIPT, 'appcrane-auto-patch', name, version, mode,
  ];
}

function scratchRoot() {
  const root = resolve(join(process.env.DATA_DIR || './data', 'tmp', 'auto-patch'));
  mkdirSync(root, { recursive: true });
  return root;
}

/**
 * Run the bump. Returns { packageJson, packageLock } as the bytes npm wrote.
 * Throws with the helper's stderr tail on failure.
 */
export async function runNpmBump({ packageJson, packageLock, name, version, mode }) {
  const workDir = mkdtempSync(join(scratchRoot(), 'bump-'));
  const containerName = `appcrane-auto-patch-${randomBytes(6).toString('hex')}`;
  try {
    mkdirSync(join(workDir, 'orig'));
    writeFileSync(join(workDir, 'package.json'), packageJson);
    writeFileSync(join(workDir, 'package-lock.json'), packageLock);
    writeFileSync(join(workDir, 'orig', 'package.json'), packageJson);
    chmodSync(workDir, 0o777);
    for (const f of ['package.json', 'package-lock.json']) chmodSync(join(workDir, f), 0o666);
    const args = npmHelperArgs({ workDir, name, version, mode, containerName });
    await new Promise((res, rej) => {
      execFile('docker', args, { timeout: TIMEOUT_MS, maxBuffer: 8 * 1024 * 1024 }, (err, _stdout, stderr) => {
        if (!err) return res();
        try { execFileSync('docker', ['rm', '-f', containerName], { stdio: 'ignore', timeout: 15_000 }); } catch (_) {}
        const tail = String(stderr || err.message).trim().split('\n').slice(-8).join('\n');
        rej(new Error(`npm could not resolve ${name}@${version}: ${tail}`));
      });
    });
    return {
      packageJson: readFileSync(join(workDir, 'package.json'), 'utf8'),
      packageLock: readFileSync(join(workDir, 'package-lock.json'), 'utf8'),
    };
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

const SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'];

function stable(v) {
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
const same = (a, b) => stable(a) === stable(b);

/** 'direct', 'transitive', or null when npm cannot be asked about it safely. */
export function dependencyMode(pkg, name) {
  const inSections = SECTIONS.filter((s) => pkg?.[s] && Object.prototype.hasOwnProperty.call(pkg[s], name));
  if (inSections.length > 1) return null;
  if (inSections.length === 1) return 'direct';
  if (pkg?.peerDependencies && Object.prototype.hasOwnProperty.call(pkg.peerDependencies, name)) return null;
  return 'transitive';
}

const isTargetPath = (key, name) => key === `node_modules/${name}` || key.endsWith(`/node_modules/${name}`);

function withoutTarget(obj, name) {
  const out = {};
  for (const s of Object.keys(obj || {})) {
    if (SECTIONS.includes(s) && obj[s] && typeof obj[s] === 'object') {
      const { [name]: _drop, ...rest } = obj[s];
      out[s] = rest;
    } else {
      out[s] = obj[s];
    }
  }
  return out;
}

function sectionOf(obj, name) {
  return SECTIONS.find((s) => obj?.[s] && Object.prototype.hasOwnProperty.call(obj[s], name)) || null;
}

function compareLegacy(before, after, name, path, problems) {
  const keys = new Set([...Object.keys(before || {}), ...Object.keys(after || {})]);
  for (const k of keys) {
    const b = before?.[k];
    const a = after?.[k];
    const here = `${path}${k}`;
    if (k === name) continue;
    if (!b || !a) { problems.push(`${here} was ${b ? 'removed' : 'added'}`); continue; }
    const { dependencies: bd, ...bRest } = b;
    const { dependencies: ad, ...aRest } = a;
    if (!same(bRest, aRest)) problems.push(`${here} changed`);
    compareLegacy(bd || {}, ad || {}, name, `${here} > `, problems);
  }
}

/**
 * Accept the bump only if nothing but `name` moved.
 * @returns {{ ok: boolean, problems: string[], changed: string[] }}
 */
export function verifyNpmBump({ before, after, name, fromVersion, toVersion, mode }) {
  const problems = [];
  let bPkg, aPkg, bLock, aLock;
  try {
    bPkg = JSON.parse(before.packageJson); aPkg = JSON.parse(after.packageJson);
    bLock = JSON.parse(before.packageLock); aLock = JSON.parse(after.packageLock);
  } catch (e) {
    return { ok: false, problems: [`a manifest is not valid JSON: ${e.message}`], changed: [] };
  }

  if (mode === 'transitive') {
    if (before.packageJson !== after.packageJson) problems.push('package.json changed for a transitive dependency');
  } else {
    const sec = sectionOf(bPkg, name);
    if (!sec || sectionOf(aPkg, name) !== sec) problems.push(`${name} moved out of package.json ${sec || 'dependencies'}`);
    if (!same(withoutTarget(bPkg, name), withoutTarget(aPkg, name))) problems.push('package.json changed beyond the range of ' + name);
  }

  const { packages: bp = {}, dependencies: bd, ...bTop } = bLock;
  const { packages: ap = {}, dependencies: ad, ...aTop } = aLock;
  if (!same(bTop, aTop)) problems.push('package-lock.json top-level fields changed (lockfileVersion, name or requires)');

  const changed = [];
  for (const key of new Set([...Object.keys(bp), ...Object.keys(ap)])) {
    const b = bp[key];
    const a = ap[key];
    if (key !== '' && isTargetPath(key, name)) {
      if (!b || !a) { problems.push(`${key} was ${b ? 'removed' : 'added'}`); continue; }
      if (!same(b, a)) changed.push(key);
      continue;
    }
    if (key === '' && mode === 'direct') {
      if (!same(withoutTarget(b, name), withoutTarget(a, name))) problems.push('the lockfile root changed beyond the range of ' + name);
      continue;
    }
    if (!b || !a) { problems.push(`${key || '(root)'} was ${b ? 'removed' : 'added'}: an unrelated dependency moved`); continue; }
    if (!same(b, a)) problems.push(`${key || '(root)'} changed: an unrelated dependency moved`);
  }
  if (bd || ad) compareLegacy(bd || {}, ad || {}, name, '', problems);

  const targets = Object.entries(ap).filter(([k]) => k !== '' && isTargetPath(k, name));
  if (targets.some(([, v]) => v.version === fromVersion)) problems.push(`${name}@${fromVersion} is still in the lockfile`);
  if (!targets.some(([, v]) => v.version === toVersion)) problems.push(`${name}@${toVersion} is not in the lockfile`);
  for (const k of changed) {
    if (ap[k].version !== toVersion) problems.push(`${k} moved to ${ap[k].version}, not ${toVersion}`);
    if (typeof ap[k].resolved === 'string' && !ap[k].resolved.startsWith(NPM_REGISTRY)) problems.push(`${k} resolves outside the public registry`);
  }
  if (changed.length === 0) problems.push('nothing changed');
  return { ok: problems.length === 0, problems, changed };
}
