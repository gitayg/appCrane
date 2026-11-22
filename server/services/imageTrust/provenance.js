// in-toto Statement v1 carrying SLSA Provenance v1 (https://slsa.dev/spec/v1.1/provenance)
// for one image, plus the statement that attests its SBOM.
//
// SLSA v1.1: Build L1 is "provenance exists"; L2 adds that the hosted build
// platform "generates and signs" it. AppCrane is that platform here: it builds
// the image on its own host, writes this statement itself (never from anything
// the app supplied) and signs it with a key the app never sees. Build L3 also
// needs the signing secret kept out of reach of user-defined build steps and
// isolated runs; app builds here run on the same Docker daemon as the platform,
// so no L3 claim is made.

import { STATEMENT_TYPE } from './envelope.js';

export const SLSA_PREDICATE = 'https://slsa.dev/provenance/v1';
export const CYCLONEDX_PREDICATE = 'https://cyclonedx.org/bom';
export const BUILD_TYPES = {
  build: 'https://appcrane.dev/buildtypes/docker-build/v1',
  pull: 'https://appcrane.dev/buildtypes/image-pull/v1',
  backfill: 'https://appcrane.dev/buildtypes/running-image/v1',
};

/** A repository URL with any userinfo removed, or null. */
export function publicRepoUri(url) {
  if (!url) return null;
  try {
    const u = new URL(String(url));
    u.username = '';
    u.password = '';
    return u.toString();
  } catch {
    return null;
  }
}

/** `name` without a tag or digest, the docker-reference a signature is bound to. */
export function repositoryOf(ref) {
  const s = String(ref || '');
  const at = s.indexOf('@');
  const noDigest = at >= 0 ? s.slice(0, at) : s;
  const slash = noDigest.lastIndexOf('/');
  const colon = noDigest.lastIndexOf(':');
  return colon > slash ? noDigest.slice(0, colon) : noDigest;
}

function subjectFor(imageRef, imageId) {
  return [{ name: repositoryOf(imageRef), digest: { sha256: String(imageId).replace(/^sha256:/, '') } }];
}

/**
 * @param {{ builderId: string, appcraneVersion: string, kind: 'build'|'pull'|'backfill',
 *           app: object, env: string, deploymentId: number|null, imageRef: string, imageId: string,
 *           repoDigest?: string|null, commitSha?: string|null, branch?: string|null,
 *           baseImage?: string|null, baseDigest?: string|null, lockfile?: { name: string, sha256: string|null }|null,
 *           builder?: string|null, startedOn?: string|null, finishedOn: string,
 *           sbom?: { sha256: string, name: string }|null }} ctx
 */
export function provenanceStatement(ctx) {
  const repo = publicRepoUri(ctx.app.github_url);
  const source = repo || (ctx.app.source_type ? `appcrane:${ctx.app.source_type}:${ctx.app.slug}` : `appcrane:${ctx.app.slug}`);
  const resolved = [];
  if (ctx.commitSha) resolved.push({ uri: `git+${source}${ctx.branch ? `@refs/heads/${ctx.branch}` : ''}`, digest: { gitCommit: ctx.commitSha } });
  if (ctx.baseImage) {
    const d = ctx.baseDigest && /^sha256:[a-f0-9]{64}$/.test(ctx.baseDigest) ? { sha256: ctx.baseDigest.slice(7) } : {};
    resolved.push({ uri: `pkg:docker/${ctx.baseImage}`, name: 'base image', digest: d, annotations: d.sha256 ? {} : { digest: 'unknown' } });
  }
  if (ctx.kind === 'pull' && ctx.repoDigest) {
    resolved.push({ uri: `pkg:docker/${repositoryOf(ctx.imageRef)}`, name: 'pulled image', digest: { sha256: ctx.repoDigest.replace(/^.*sha256:/, '') } });
  }
  if (ctx.lockfile?.sha256) resolved.push({ name: ctx.lockfile.name, digest: { sha256: ctx.lockfile.sha256 } });
  const invocation = ctx.deploymentId != null
    ? `${ctx.builderId.replace(/#.*$/, '')}/api/apps/${ctx.app.slug}/deployments/${ctx.env}/${ctx.deploymentId}`
    : `${ctx.builderId.replace(/#.*$/, '')}/api/image-trust/backfill/${ctx.app.slug}/${ctx.env}`;
  return {
    _type: STATEMENT_TYPE,
    subject: subjectFor(ctx.imageRef, ctx.imageId),
    predicateType: SLSA_PREDICATE,
    predicate: {
      buildDefinition: {
        buildType: BUILD_TYPES[ctx.kind],
        externalParameters: {
          app: ctx.app.slug,
          env: ctx.env,
          source: { uri: source, ...(ctx.branch ? { ref: ctx.branch } : {}), ...(ctx.commitSha ? { commit: ctx.commitSha } : {}) },
          ...(ctx.kind === 'pull' ? { image: ctx.imageRef } : {}),
        },
        internalParameters: { builder: ctx.builder || null, image_ref: ctx.imageRef },
        resolvedDependencies: resolved,
      },
      runDetails: {
        builder: { id: ctx.builderId, version: { appcrane: ctx.appcraneVersion } },
        metadata: {
          invocationId: invocation,
          ...(ctx.startedOn ? { startedOn: ctx.startedOn } : {}),
          finishedOn: ctx.finishedOn,
        },
        byproducts: ctx.sbom ? [{ name: ctx.sbom.name, digest: { sha256: ctx.sbom.sha256 }, mediaType: 'application/vnd.cyclonedx+json' }] : [],
      },
    },
  };
}

/** The statement attesting the SBOM: the SBOM itself is the predicate, as `cosign attest --type cyclonedx` writes it. */
export function sbomStatement({ imageRef, imageId, sbom }) {
  return { _type: STATEMENT_TYPE, subject: subjectFor(imageRef, imageId), predicateType: CYCLONEDX_PREDICATE, predicate: sbom };
}
