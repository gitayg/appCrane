// Produce and sign the supply-chain evidence for the image a deploy is about to
// run: SBOM, SLSA provenance, and a signature over the image id. Never throws:
// a failure is recorded on the row and returned, and verify-before-run decides
// what that means under the platform mode.

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import log from '../../utils/logger.js';
import { getSigningKey } from './signingKey.js';
import { signStatement, simpleSigningPayload, signBytes } from './envelope.js';
import { runSbomTool, enrichSbom, sbomCoverage, describedImageId } from './sbom.js';
import { provenanceStatement, sbomStatement, repositoryOf } from './provenance.js';
import { licensePolicyCheck } from './licensePolicy.js';
import { getLicensePolicy, getTrustMode } from './policy.js';
import { inspectImage } from './dockerImage.js';
import { FILES, dirFor, writeDoc, insertPending, finishRow, pruneOrphanAttestations, signedRowFor, signedRowForRef } from './store.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
let version = null;
export function appcraneVersion() {
  if (!version) {
    try { version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version || 'unknown'; } catch { version = 'unknown'; }
  }
  return version;
}

export function instanceOrigin() {
  return process.env.CRANE_DOMAIN ? `https://${process.env.CRANE_DOMAIN}` : `http://localhost:${process.env.PORT || 5001}`;
}

export function builderId() { return `${instanceOrigin()}/appcrane/builder`; }

function isoFromSqlite(t) {
  if (!t) return null;
  const d = new Date(String(t).includes('T') ? t : `${String(t).replace(' ', 'T')}Z`);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/**
 * @param {{ db: object, app: object, env: string, deploymentId: number|null, image: string,
 *           imageId?: string, origin?: 'deploy'|'backfill', kind?: 'build'|'pull'|'backfill', commitSha?: string|null,
 *           builder?: string|null, appendLog?: (line: string) => void, allowPull?: boolean }} ctx
 * @returns {Promise<{ id: number|null, status: 'signed'|'error', error?: string, imageId?: string, sbomStatus?: string }>}
 */
export async function attestImage(ctx) {
  const { db, app, env, image } = ctx;
  const appendLog = ctx.appendLog || (() => {});
  const origin = ctx.origin || 'deploy';
  const kind = ctx.kind || (app.source_type === 'image' ? 'pull' : 'build');
  let id = null;
  try {
    id = insertPending(db, { deploymentId: ctx.deploymentId ?? null, appId: app.id, env, origin, imageRef: image });
    const fail = (error) => {
      finishRow(db, id, { status: 'error', error });
      appendLog(`Supply chain: not signed — ${error}`);
      return { id, status: 'error', error };
    };

    const info = await inspectImage(ctx.imageId || image);
    if (info.error) return fail(info.error);
    if (ctx.imageId && info.id !== ctx.imageId) return fail(`image ${ctx.imageId} resolved to ${info.id}`);

    let key;
    try { key = getSigningKey(db); } catch (e) { return fail(e.message); }

    const dep = ctx.deploymentId != null
      ? db.prepare('SELECT started_at, commit_sha, commit_hash, base_image, base_digest, lockfile_name, lockfile_sha256 FROM deployments WHERE id = ?').get(ctx.deploymentId) || {}
      : {};
    const commitSha = ctx.commitSha || dep.commit_sha || (/^[0-9a-f]{7,40}$/i.test(dep.commit_hash || '') ? dep.commit_hash : null);
    const lockfile = dep.lockfile_name ? { name: dep.lockfile_name, sha256: dep.lockfile_sha256 || null } : null;
    const repoDigest = info.repoDigests.find((d) => image.includes('@') && d.endsWith(image.slice(image.indexOf('@') + 1))) || info.repoDigests[0] || null;
    const dir = dirFor(app.slug, env, id);

    // allowPull: a deploy obtains the scanner only when the platform requires
    // the SBOM attestation to start (enforce); otherwise the nightly scan does.
    const allowPull = ctx.allowPull ?? (getTrustMode(db) === 'enforce');
    const tool = await runSbomTool(info.id, { allowPull });
    let sbom = null;
    let sbomBytes = null;
    let sbomError = null;
    let coverage = null;
    let licenseCheck = null;
    if (!tool.ok) {
      sbomError = tool.error;
    } else if (describedImageId(tool.bom) && describedImageId(tool.bom) !== info.id) {
      sbomError = `the SBOM tool described ${describedImageId(tool.bom)}, not ${info.id}`;
    } else {
      sbom = enrichSbom(tool.bom, {
        author: `AppCrane (${instanceOrigin().replace(/^https?:\/\//, '')})`,
        appcraneVersion: appcraneVersion(), app, env, deploymentId: ctx.deploymentId ?? null,
        imageRef: image, imageId: info.id, repoDigest, commitSha, lockfile, origin,
      });
      sbomBytes = Buffer.from(JSON.stringify(sbom, null, 2));
      coverage = sbomCoverage(sbom);
      licenseCheck = licensePolicyCheck(app, sbom, getLicensePolicy(db));
    }

    const finishedOn = new Date().toISOString();
    const provenance = provenanceStatement({
      builderId: builderId(), appcraneVersion: appcraneVersion(), kind, app, env,
      deploymentId: ctx.deploymentId ?? null, imageRef: image, imageId: info.id, repoDigest,
      commitSha, branch: app.branch || null, baseImage: dep.base_image || null, baseDigest: dep.base_digest || null,
      lockfile, builder: ctx.builder || null, startedOn: isoFromSqlite(dep.started_at), finishedOn,
      sbom: sbomBytes ? { name: FILES.sbom, sha256: sha256(sbomBytes) } : null,
    });
    const provenanceEnv = Buffer.from(JSON.stringify(signStatement(provenance, key)));
    const payload = simpleSigningPayload({
      repository: repositoryOf(image),
      digest: info.id,
      annotations: {
        'dev.appcrane.app': app.slug,
        'dev.appcrane.env': env,
        ...(ctx.deploymentId != null ? { 'dev.appcrane.deployment': String(ctx.deploymentId) } : {}),
        'dev.appcrane.origin': origin,
        'dev.appcrane.provenance.sha256': sha256(provenanceEnv),
      },
    });

    writeDoc(dir, FILES.provenance, provenanceEnv);
    if (sbomBytes) {
      writeDoc(dir, FILES.sbom, sbomBytes);
      writeDoc(dir, FILES.sbomAttestation, JSON.stringify(signStatement(sbomStatement({ imageRef: image, imageId: info.id, sbom }), key)));
    }
    writeDoc(dir, FILES.signaturePayload, payload);
    writeDoc(dir, FILES.signature, signBytes(payload, key.privateKey));

    finishRow(db, id, {
      status: 'signed', image_id: info.id, key_id: key.keyId, dir,
      sbom_status: sbomBytes ? 'ok' : 'missing', sbom_error: sbomError,
      sbom_sha256: sbomBytes ? sha256(sbomBytes) : null,
      sbom_components: coverage?.components ?? null,
      sbom_hash_coverage: coverage?.withHash ?? null,
      sbom_license_coverage: coverage?.withLicense ?? null,
      license_check_json: licenseCheck ? JSON.stringify(licenseCheck) : null,
    });

    appendLog(`Supply chain: signed image ${info.id.slice(0, 19)}… with key ${key.keyId.slice(0, 12)}… (SLSA v1 provenance, cosign-compatible signature).`);
    if (coverage) {
      const algs = Object.entries(coverage.hashAlgorithms).map(([a, n]) => `${a} ${n}`).join(', ') || 'none';
      appendLog(`Supply chain: CycloneDX ${sbom.specVersion} SBOM, ${coverage.components} component(s); hash ${coverage.withHash}/${coverage.components} (${algs}), license ${coverage.withLicense}/${coverage.components}.`);
      appendLog(`License policy: ${licenseCheck.status} — ${licenseCheck.reasons[0]}`);
    } else {
      appendLog(`Supply chain: no SBOM attestation — ${sbomError}`);
    }
    try { pruneOrphanAttestations(db); } catch (e) { log.warn(`attestation prune failed: ${e.message}`); }
    return { id, status: 'signed', imageId: info.id, sbomStatus: sbomBytes ? 'ok' : 'missing' };
  } catch (e) {
    log.warn(`attestation for ${app.slug}/${env} failed: ${e.message}`);
    if (id) { try { finishRow(db, id, { status: 'error', error: e.message }); } catch { /* row write failed too */ } }
    appendLog(`Supply chain: not signed — ${e.message}`);
    return { id, status: 'error', error: e.message };
  }
}

/**
 * The deploy's entry point. An image this deploy built or pulled is signed.
 * A CACHED image (the tag already existed, nothing was built) is never signed
 * on the strength of its tag alone, because whatever retagged it would then be
 * signed too: the deploy reuses the signature this instance already made for
 * those exact bytes, and refuses to sign when this instance signed different
 * bytes under that name. A cached image with no signature history at all (built
 * before signing existed) is signed as a backfill, trust on first use.
 */
export async function attestDeployImage(ctx) {
  if (ctx.fresh) return attestImage(ctx);
  const { db, app, env, image } = ctx;
  const appendLog = ctx.appendLog || (() => {});
  const info = await inspectImage(image);
  if (info.error) {
    appendLog(`Supply chain: not signed — ${info.error}`);
    return { id: null, status: 'error', error: info.error };
  }
  const prior = signedRowFor(db, app.id, env, info.id);
  if (prior) {
    const id = insertPending(db, { deploymentId: ctx.deploymentId ?? null, appId: app.id, env, origin: prior.origin, imageRef: image });
    const keep = ['image_id', 'key_id', 'dir', 'sbom_status', 'sbom_error', 'sbom_sha256', 'sbom_components', 'sbom_hash_coverage', 'sbom_license_coverage', 'license_check_json'];
    finishRow(db, id, { ...Object.fromEntries(keep.map((k) => [k, prior[k]])), status: 'signed' });
    appendLog(`Supply chain: cached image ${info.id.slice(0, 19)}… reuses this instance's signature from attestation #${prior.id}.`);
    return { id, status: 'signed', imageId: info.id, reused: prior.id };
  }
  const other = signedRowForRef(db, app.id, env, image);
  if (other) {
    const error = `cached image ${image} now points at ${info.id}, but this instance signed ${other.image_id} under that name; not signing it`;
    appendLog(`Supply chain: not signed — ${error}`);
    return { id: null, status: 'error', error };
  }
  return attestImage({ ...ctx, imageId: info.id, origin: 'backfill', kind: 'backfill' });
}
