// What digest does a base tag point at on its registry right now?
//
// Docker Hub only. The flow is the registry token spec's
// ("https://auth.docker.io/token?service=registry.docker.io&scope=repository:samalba/my-app:pull,push")
// followed by `HEAD /v2/<name>/manifests/<reference>`, whose 200 response
// carries `Docker-Content-Digest` (distribution spec). HEAD is used on purpose:
// Docker's pull-limit page says "Using GET emulates a real pull and counts
// towards the limit. Using HEAD won't." (measured: ratelimit-remaining stayed
// at 100 after the HEAD.) The Accept list asks for the multi-platform index
// first, which is the digest `docker pull` records in RepoDigests (measured:
// php:8.3-apache HEAD and RepoDigests both sha256:1b8b5b0f31cc...).

import { normalizeRef } from './runtimeImages.js';

const TIMEOUT_MS = 20_000;
const ACCEPT = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.docker.distribution.manifest.v2+json',
  'application/vnd.oci.image.manifest.v1+json',
].join(', ');

export class UnsupportedRegistry extends Error {}

/** The registry's current digest for `ref` (Docker Hub). Throws UnsupportedRegistry for any other registry. */
export async function currentDigest(ref, fetchFn = fetch) {
  const n = normalizeRef(ref);
  if (n.registry !== 'docker.io') throw new UnsupportedRegistry(`${ref} is not on Docker Hub; only Docker Hub bases are checked for a newer image`);
  if (n.digest && !n.tag) throw new UnsupportedRegistry(`${ref} is pinned to a digest, so it never gets a newer image`);
  const tokRes = await fetchFn(`https://auth.docker.io/token?service=registry.docker.io&scope=${encodeURIComponent(`repository:${n.repo}:pull`)}`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!tokRes.ok) throw new Error(`Docker Hub token request returned HTTP ${tokRes.status}`);
  const { token } = await tokRes.json();
  const res = await fetchFn(`https://registry-1.docker.io/v2/${n.repo}/manifests/${encodeURIComponent(n.tag)}`, {
    method: 'HEAD', headers: { Authorization: `Bearer ${token}`, Accept: ACCEPT }, signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`Docker Hub returned HTTP ${res.status} for ${ref}`);
  const digest = res.headers.get('docker-content-digest');
  if (!/^sha256:[0-9a-f]{64}$/.test(String(digest || ''))) throw new Error(`Docker Hub sent no digest for ${ref}`);
  return digest;
}
