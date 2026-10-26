// When was this version published? The npm registry's packument carries a
// `time` map of version -> ISO timestamp. The abbreviated document
// (application/vnd.npm.install-v1+json) does not, so the full one is read.

import { NPM_REGISTRY } from './npmBump.js';

const TIMEOUT_MS = 20_000;

export function packumentUrl(name) {
  return `${NPM_REGISTRY}${name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name)}`;
}

/**
 * @returns {Promise<{ published: Date, deprecated: string|null }>} throws when
 * the registry does not say when it was published. `deprecated` is the
 * maintainer's deprecation message for that version ("Bad release. Please use
 * ..."), which OSV does not carry.
 */
async function packument(name) {
  const res = await fetch(packumentUrl(name), {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`the npm registry returned HTTP ${res.status} for ${name}`);
  return res.json();
}

const deprecation = (v) => (typeof v?.deprecated === 'string' && v.deprecated.trim() ? v.deprecated.trim().slice(0, 300) : null);

export async function npmVersionInfo(name, version) {
  const doc = await packument(name);
  if (doc?.versions && !doc.versions[version]) throw new Error(`${name}@${version} is not on the npm registry (unpublished?)`);
  const t = doc?.time?.[version];
  const d = typeof t === 'string' ? new Date(t) : null;
  if (!d || Number.isNaN(d.getTime())) throw new Error(`the npm registry has no publish time for ${name}@${version}`);
  return { published: d, deprecated: deprecation(doc?.versions?.[version]) };
}

/** Every published version: [{ version, published: Date|null, deprecated: string|null }]. */
export async function npmVersionList(name) {
  const doc = await packument(name);
  return Object.entries(doc?.versions || {}).map(([version, v]) => {
    const t = doc?.time?.[version];
    const d = typeof t === 'string' ? new Date(t) : null;
    return { version, published: d && !Number.isNaN(d.getTime()) ? d : null, deprecated: deprecation(v) };
  });
}
