// The version to ship when the lowest fixed version is deprecated on npm: the
// lowest release in the same major that is at or above the fix, not
// deprecated, has no advisory of its own on OSV, and is past the cooldown.
// The maintainer's deprecation message may name another version; it is not
// followed, because only OSV says whether that version is still vulnerable.

import { compareVersions } from '../appScan.js';

const MAX_CANDIDATES = 50;
const STABLE = /^(\d+)\.\d+\.\d+$/;
const majorOf = (v) => STABLE.exec(String(v))?.[1] ?? null;

/**
 * @returns {Promise<{ ok: true, version: string, published: Date, skipped: string[] }
 *   | { ok: false, kind: 'person'|'defer', reason: string, retryAfterMs?: number }>}
 */
export async function pickReplacementVersion({ name, fixed, deprecated, versions, queryOsv, cooldownMs, now }) {
  const major = majorOf(fixed);
  const why = `${name}@${fixed} is deprecated on npm ("${deprecated}")`;
  if (major === null) return { ok: false, kind: 'person', reason: `${why}; a person must choose the version.` };
  const candidates = versions
    .filter((v) => v.version !== fixed && majorOf(v.version) === major && !v.deprecated && v.published)
    .filter((v) => { try { return compareVersions(v.version, fixed) > 0; } catch { return false; } })
    .sort((a, b) => compareVersions(a.version, b.version))
    .slice(0, MAX_CANDIDATES);
  if (!candidates.length) return { ok: false, kind: 'person', reason: `${why} and no later ${major}.x release is free of a deprecation; a person must choose the version.` };

  const q = await queryOsv(candidates.map((c) => ({ name, version: c.version, ecosystem: 'npm' })));
  if (!q.ok) return { ok: false, kind: 'defer', reason: `OSV could not be asked about the ${major}.x releases after ${name}@${fixed}; will retry` };
  const flagged = new Map();
  for (const f of q.findings) if (f.name === name) flagged.set(f.version, [...(flagged.get(f.version) || []), ...(f.ids || [])]);

  const skipped = [];
  let waiting = null;
  for (const c of candidates) {
    if (flagged.has(c.version)) { skipped.push(`${c.version} (advisories ${flagged.get(c.version).join(', ')})`); continue; }
    const readyAt = c.published.getTime() + cooldownMs;
    if (now < readyAt) {
      skipped.push(`${c.version} (published ${c.published.toISOString()}, inside the cooldown)`);
      if (!waiting || readyAt < waiting.readyAt) waiting = { version: c.version, readyAt };
      continue;
    }
    return { ok: true, version: c.version, published: c.published, skipped };
  }
  if (waiting) {
    return { ok: false, kind: 'defer', reason: `${why}; ${name}@${waiting.version} is the first clean ${major}.x release and the policy waits ${cooldownMs / 3600_000}h, so it is applied after ${new Date(waiting.readyAt).toISOString()}.`, retryAfterMs: waiting.readyAt - now };
  }
  return { ok: false, kind: 'person', reason: `${why} and every later ${major}.x release is deprecated or has advisories of its own (${skipped.slice(0, 5).join('; ')}); a person must choose the version.` };
}
