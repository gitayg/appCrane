export const FIX_HINT = 'run `git fetch origin && npm run version:next -- --write` (add `--minor` for a feature release)';

export function parseVersion(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(v ?? '').trim());
  return m ? m.slice(1).map(Number) : null;
}

export function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) throw new Error(`not an X.Y.Z version: ${pa ? b : a}`);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

export function maxVersion(a, b) {
  return compareVersions(a, b) >= 0 ? a : b;
}

export function nextVersion({ base, local, kind = 'patch' }) {
  const [major, minor, patch] = parseVersion(maxVersion(base, local));
  if (kind === 'minor') return `${major}.${minor + 1}.0`;
  if (kind === 'patch') return `${major}.${minor}.${patch + 1}`;
  throw new Error(`unknown bump kind: ${kind}`);
}

export function versionProblem({ head, base, baseLabel, notesKeys }) {
  if (!parseVersion(head)) return `package.json version "${head}" is not X.Y.Z.`;
  if (!parseVersion(base)) return `${baseLabel} package.json version "${base}" is not X.Y.Z.`;
  if (compareVersions(head, base) <= 0) {
    return `package.json is at ${head} but ${baseLabel} is already at ${base}; ` +
      `the version must be strictly greater. Another change probably took this number: ${FIX_HINT}.`;
  }
  if (!notesKeys.includes(head)) {
    return `release-notes.json has no "${head}" key; add the user-facing notes for ${head} ` +
      `(or rename the entry you wrote under the old number).`;
  }
  return null;
}
