import { execFileSync } from 'child_process';
import { readFileSync } from 'fs';
import { join } from 'path';

export function versionAtRef(ref, cwd) {
  if (!/^[A-Za-z0-9._/^~][A-Za-z0-9._/^~-]{0,199}$/.test(ref)) throw new Error(`refusing unsafe ref: ${ref}`);
  let raw;
  try {
    raw = execFileSync('git', ['show', `${ref}:package.json`], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    throw new Error(`cannot read package.json at ${ref} (${String(err.stderr || err.message).trim()}); run \`git fetch origin\` first`);
  }
  return JSON.parse(raw).version;
}

export function localVersion(cwd) {
  return JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8')).version;
}

export function releaseNoteKeys(cwd) {
  return Object.keys(JSON.parse(readFileSync(join(cwd, 'release-notes.json'), 'utf8')));
}

export function argValue(argv, name, fallback) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
}
