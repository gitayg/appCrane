// Usage: npm run version:next [-- --base <ref>] [--minor] [--write]
// Prints the next release number above max(<ref> version, local version).
// Fetches nothing: run `git fetch origin` first so <ref> (default origin/main) is current.
// --write sets it in package.json and package-lock.json, and refuses unless
// release-notes.json already has the notes for that number.
import { execFileSync } from 'child_process';
import { nextVersion } from './lib/version-guard.mjs';
import { versionAtRef, localVersion, releaseNoteKeys, argValue } from './lib/git-version.mjs';

const argv = process.argv.slice(2);
const cwd = process.cwd();
const ref = argValue(argv, '--base', 'origin/main');
const kind = argv.includes('--minor') ? 'minor' : 'patch';

let base;
try {
  base = versionAtRef(ref, cwd);
} catch (err) {
  console.error(`next-version: ${err.message}`);
  process.exit(1);
}
const local = localVersion(cwd);
const next = nextVersion({ base, local, kind });
const hasNotes = releaseNoteKeys(cwd).includes(next);

console.error(`next-version: ${ref} is at ${base}, this checkout is at ${local}; next ${kind} is ${next}`);

if (!argv.includes('--write')) {
  if (!hasNotes) console.error(`next-version: release-notes.json needs a "${next}" key before --write`);
  console.log(next);
  process.exit(0);
}

if (!hasNotes) {
  const old = releaseNoteKeys(cwd).includes(local) ? ` (rename the "${local}" entry if it describes this change)` : '';
  console.error(`next-version: refusing to set ${next}: release-notes.json has no "${next}" key. Add the user-facing notes first${old}.`);
  process.exit(1);
}

execFileSync('npm', ['version', next, '--no-git-tag-version', '--allow-same-version'], { cwd, stdio: ['ignore', 'ignore', 'inherit'] });
console.log(next);
