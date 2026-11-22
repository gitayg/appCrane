// Usage: node scripts/check-version-bump.mjs --base <ref> [--label <name>]
// Fails unless this checkout's package.json version is strictly greater than the
// version at <ref> and release-notes.json has a key for it. Used by
// .github/workflows/version-guard.yml on pull requests, merge queues and pushes to main.
import { versionProblem } from './lib/version-guard.mjs';
import { versionAtRef, localVersion, releaseNoteKeys, argValue } from './lib/git-version.mjs';

const argv = process.argv.slice(2);
const cwd = process.cwd();
const ref = argValue(argv, '--base', 'origin/main');
const baseLabel = argValue(argv, '--label', ref);

let problem;
try {
  problem = versionProblem({
    head: localVersion(cwd),
    base: versionAtRef(ref, cwd),
    baseLabel,
    notesKeys: releaseNoteKeys(cwd),
  });
} catch (err) {
  problem = err.message;
}

if (problem) {
  console.error(process.env.GITHUB_ACTIONS ? `::error title=Version guard::${problem}` : `version guard: ${problem}`);
  process.exit(1);
}
console.log(`version guard: ${localVersion(cwd)} is above ${baseLabel} and has release notes`);
