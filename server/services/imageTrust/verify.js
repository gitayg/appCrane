// Verify-before-run: the image about to be started must carry a valid
// signature from THIS instance's key over its exact image id, plus signed
// provenance and SBOM attestations naming that id. Like a Kyverno verifyImages
// rule, the check is on the digest, never the tag: a tag moved to other bytes
// is refused as tampered.
//
// Mode (platform setting image_trust_mode): off | warn | enforce. warn logs the
// problem and starts; enforce refuses with IMAGE_UNTRUSTED before anything is
// stopped by the caller that asked.

import crypto from 'node:crypto';
import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { AppError } from '../../utils/errors.js';
import { getPublicKey } from './signingKey.js';
import { verifyEnvelope, statementCovers, verifyBytes, SIMPLE_SIGNING_TYPE } from './envelope.js';
import { SLSA_PREDICATE, CYCLONEDX_PREDICATE } from './provenance.js';
import { getTrustMode } from './policy.js';
import { inspectImage } from './dockerImage.js';
import { readDoc, signedRowFor, signedRowForRef } from './store.js';

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/**
 * Check one attestation row's documents against the image id. Pure apart from
 * reading the row's files.
 * @returns {string[]} problems; empty means verified
 */
export function verifyRowDocuments(row, imageId, key) {
  const problems = [];
  if (!key) return ['this instance has no signing key, so nothing it runs can be verified'];
  if (row.key_id !== key.keyId) problems.push(`signed by key ${String(row.key_id).slice(0, 12)}…, not this instance's key ${key.keyId.slice(0, 12)}…`);
  const hex = String(imageId).replace(/^sha256:/, '');

  const payload = readDoc(row, 'signaturePayload');
  const sig = readDoc(row, 'signature');
  let signedPayload = null;
  if (!payload || !sig) problems.push('the image signature is missing');
  else if (!verifyBytes(payload, sig.toString('utf8').trim(), key.publicKey)) problems.push('the image signature does not verify');
  else {
    try { signedPayload = JSON.parse(payload.toString('utf8')); } catch { problems.push('the signed payload is not JSON'); }
    if (signedPayload) {
      if (signedPayload?.critical?.type !== SIMPLE_SIGNING_TYPE) problems.push('the signed payload is not a cosign image signature');
      const signedDigest = signedPayload?.critical?.image?.['docker-manifest-digest'];
      if (signedDigest !== imageId) problems.push(`the signature is for ${signedDigest}, not ${imageId}`);
    }
  }

  const prov = readDoc(row, 'provenance');
  let provStatement = null;
  if (!prov) problems.push('the provenance attestation is missing');
  else {
    let env = null;
    try { env = JSON.parse(prov.toString('utf8')); } catch { problems.push('the provenance attestation is not JSON'); }
    if (env) {
      const v = verifyEnvelope(env, key.publicKey);
      if (!v.ok) problems.push(`provenance: ${v.reason}`);
      else if (v.statement.predicateType !== SLSA_PREDICATE) problems.push('provenance is not SLSA v1');
      else if (!statementCovers(v.statement, hex)) problems.push('provenance does not name this image');
      else provStatement = v.statement;
    }
    const pinned = signedPayload?.optional?.['dev.appcrane.provenance.sha256'];
    if (signedPayload && pinned !== sha256(prov)) problems.push('the provenance file is not the one the image signature names');
  }

  if (row.sbom_status !== 'ok') problems.push(`no SBOM attestation (${row.sbom_error || 'not generated'})`);
  else {
    const att = readDoc(row, 'sbomAttestation');
    const file = readDoc(row, 'sbom');
    if (!att || !file) problems.push('the SBOM attestation or SBOM file is missing');
    else {
      let env = null;
      try { env = JSON.parse(att.toString('utf8')); } catch { problems.push('the SBOM attestation is not JSON'); }
      if (env) {
        const v = verifyEnvelope(env, key.publicKey);
        if (!v.ok) problems.push(`SBOM attestation: ${v.reason}`);
        else if (v.statement.predicateType !== CYCLONEDX_PREDICATE) problems.push('the SBOM attestation is not CycloneDX');
        else if (!statementCovers(v.statement, hex)) problems.push('the SBOM attestation does not name this image');
      }
      const fileHash = sha256(file);
      const byproduct = provStatement?.predicate?.runDetails?.byproducts?.find((b) => b?.mediaType === 'application/vnd.cyclonedx+json');
      if (fileHash !== row.sbom_sha256 || (provStatement && byproduct?.digest?.sha256 !== fileHash)) problems.push('the SBOM file does not match the signed provenance');
    }
  }
  return problems;
}

/**
 * @param {{ db?: object, slug: string, env: string, image?: string, imageId?: string }} q
 * @returns {Promise<{ ok: boolean, mode: string, imageId: string|null, reason: string|null, attestationId: number|null }>}
 */
export async function verifyImageForRun(q) {
  const db = q.db || getDb();
  const mode = getTrustMode(db);
  if (mode === 'off') return { ok: true, mode, imageId: null, reason: null, attestationId: null, skipped: true };
  const app = db.prepare('SELECT id, slug FROM apps WHERE slug = ?').get(q.slug);
  let imageId = q.imageId || null;
  if (!imageId) {
    const info = await inspectImage(q.image);
    if (info.error) return { ok: false, mode, imageId: null, reason: info.error, attestationId: null };
    imageId = info.id;
  }
  const what = `${q.image || imageId} (${imageId})`;
  if (!app) return { ok: false, mode, imageId, reason: `no app ${q.slug} to verify ${what} against`, attestationId: null };
  const row = signedRowFor(db, app.id, q.env, imageId);
  if (!row) {
    const byRef = q.image ? signedRowForRef(db, app.id, q.env, q.image) : null;
    const reason = byRef
      ? `TAMPERED: ${q.image} now points at ${imageId}, but this instance signed ${byRef.image_id} under that name`
      : `UNSIGNED: no signature from this instance for ${what}`;
    return { ok: false, mode, imageId, reason, attestationId: null };
  }
  const problems = verifyRowDocuments(row, imageId, getPublicKey(db));
  return { ok: problems.length === 0, mode, imageId, reason: problems.length ? `INVALID: ${problems.join('; ')}` : null, attestationId: row.id };
}

/**
 * Verify, then act on the mode. Throws AppError IMAGE_UNTRUSTED in enforce.
 * @param {{ db?: object, slug: string, env: string, image?: string, imageId?: string, onLog?: (l: string) => void, what?: string }} q
 */
export async function enforceImageTrust(q) {
  const r = await verifyImageForRun(q);
  if (r.skipped || r.ok) {
    if (r.ok && !r.skipped) q.onLog?.(`Image trust: ${r.imageId.slice(0, 19)}… verified (signature, provenance and SBOM attestation from this instance).`);
    return r;
  }
  const where = `${q.slug}/${q.env}${q.what ? ` ${q.what}` : ''}`;
  if (r.mode === 'enforce') {
    const msg = `IMAGE_UNTRUSTED: refusing to start ${where}: ${r.reason}. Image trust is in enforce mode; redeploy to build and sign the image, or have a platform admin sign the running images (POST /api/image-trust/sign-current) or switch the mode to warn.`;
    q.onLog?.(msg);
    log.warn(msg);
    throw new AppError(msg, 409, 'IMAGE_UNTRUSTED');
  }
  const msg = `⚠ Image trust (warn mode): ${where}: ${r.reason}. Started anyway; enforce mode would refuse this.`;
  q.onLog?.(msg);
  log.warn(msg);
  return r;
}
