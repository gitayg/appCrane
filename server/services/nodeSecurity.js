// Is the Node.js runtime AppCrane itself runs on patched?
//
// NODE_FLOOR (server/index.js) is a major-version floor: below it, dependencies
// cannot run. This is the other question: a supported major can still carry a
// remote-code-execution flaw fixed in a later patch release. Each advisory names
// the first fixed release on every line Node still supports;
// a major that is not listed (23, 25: end of life) gets no fix and is reported
// unsupported. Majors newer than every listed one were released after the fix.
//
// Script mode, for scripts/safe-boot.sh: `node nodeSecurity.js` prints the
// verdict (ok | vulnerable | unsupported) for the Node running it; with
// --message it prints the explanation instead.

import { readFileSync } from 'fs';
import { pathToFileURL } from 'url';

// One source with the hosted-app runtime check: the Node entries of
// autoPatch/runtime-advisories.json. Each `fixed` event names the first fixed
// release of its line; its major is a line that gets the fix.
function loadAdvisories() {
  const data = JSON.parse(readFileSync(new URL('./autoPatch/runtime-advisories.json', import.meta.url), 'utf8'));
  return Object.freeze((data.advisories || []).filter((a) => a.runtime === 'node').map((a) => Object.freeze({
    id: a.id,
    name: a.campaign || a.id,
    summary: a.summary || '',
    fixed: Object.freeze(Object.fromEntries((a.events || []).filter((e) => e.fixed).map((e) => [Number(e.fixed.split('.')[0]), e.fixed]))),
    source: (a.sources || [])[0] || null,
  })));
}

export const NODE_SECURITY_ADVISORIES = loadAdvisories();

function parse(v) {
  const m = String(v || '').trim().match(/^v?(\d+)\.(\d+)\.(\d+)/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function below(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
}

/** The lowest release on `major` that fixes every listed advisory, or null when the line gets no fix. */
export function securityMinimum(major, advisories = NODE_SECURITY_ADVISORIES) {
  let min = null;
  for (const a of advisories) {
    const majors = Object.keys(a.fixed).map(Number);
    if (major > Math.max(...majors)) continue;
    const f = a.fixed[major];
    if (!f) return null;
    if (!min || below(parse(min), parse(f))) min = f;
  }
  return min || `${major}.0.0`;
}

/** Releases a person can move to: the fixed release of every supported line. */
function supportedTargets(advisories) {
  const majors = [...new Set(advisories.flatMap((a) => Object.keys(a.fixed).map(Number)))].sort((x, y) => x - y);
  return majors.map((m) => securityMinimum(m, advisories)).filter(Boolean);
}

/**
 * { status: 'ok'|'vulnerable'|'unsupported', version, major, minimum, advisories, message }.
 * `minimum` is the release to upgrade to on this major (null when the line gets no fix).
 */
export function nodeSecurityStatus(version = process.versions.node, advisories = NODE_SECURITY_ADVISORIES) {
  const v = parse(version);
  if (!v) return { status: 'unknown', version, major: null, minimum: null, advisories: [], message: `cannot read Node version ${version}` };
  const major = v[0];
  const ids = advisories.map((a) => a.id).join(', ');
  const minimum = securityMinimum(major, advisories);
  if (!minimum) {
    const targets = supportedTargets(advisories).map((t) => `${t}+`).join(', ');
    return {
      status: 'unsupported', version, major, minimum: null, advisories: advisories.map((a) => a.id),
      message: `Node ${version} is on a release line that gets no security fix for ${ids}; it is unsupported. Upgrade to ${targets}.`,
    };
  }
  const open = advisories.filter((a) => {
    const f = a.fixed[major];
    return f && below(v, parse(f));
  });
  if (!open.length) return { status: 'ok', version, major, minimum, advisories: [], message: `Node ${version} has the fixes for ${ids}.` };
  return {
    status: 'vulnerable', version, major, minimum, advisories: open.map((a) => a.id),
    message: `Node ${version} is affected by ${open.map((a) => `${a.id} (${a.name}: ${a.summary})`).join('; ')}. Upgrade to ${minimum} or later.`,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const s = nodeSecurityStatus();
  process.stdout.write(`${process.argv[2] === '--message' ? s.message : s.status}\n`);
}
