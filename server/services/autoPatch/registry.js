// When was this version published? The npm registry's packument carries a
// `time` map of version -> ISO timestamp. The abbreviated document
// (application/vnd.npm.install-v1+json) does not, so the full one is read.

import { NPM_REGISTRY } from './npmBump.js';

const TIMEOUT_MS = 20_000;

export function packumentUrl(name) {
  return `${NPM_REGISTRY}${name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name)}`;
}

/** @returns {Promise<Date>} throws when the registry does not say. */
export async function npmPublishedAt(name, version) {
  const res = await fetch(packumentUrl(name), {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`the npm registry returned HTTP ${res.status} for ${name}`);
  const doc = await res.json();
  if (doc?.versions && !doc.versions[version]) throw new Error(`${name}@${version} is not on the npm registry (unpublished?)`);
  const t = doc?.time?.[version];
  const d = typeof t === 'string' ? new Date(t) : null;
  if (!d || Number.isNaN(d.getTime())) throw new Error(`the npm registry has no publish time for ${name}@${version}`);
  return d;
}
