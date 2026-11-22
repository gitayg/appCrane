// Where a deploy's attestation documents live, and the row that indexes them.
//
// DATA_DIR/attestations/<slug>/<env>/<attestation id>/
//   sbom.cdx.json              the enriched CycloneDX SBOM (downloadable)
//   sbom.intoto.json           DSSE envelope, predicate = that SBOM
//   provenance.intoto.json     DSSE envelope, SLSA v1 provenance
//   image.sig.payload.json     cosign simple-signing payload for the image id
//   image.sig                  its signature, base64
//
// Retention follows deploy history: deployment rows are kept for the life of
// the app (deployLogRetention.js prunes only log text), so a row's documents
// are kept while its deployment row and app exist, and pruneOrphanAttestations
// removes the directories of apps or deployments that are gone.

import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';

export const FILES = Object.freeze({
  sbom: 'sbom.cdx.json',
  sbomAttestation: 'sbom.intoto.json',
  provenance: 'provenance.intoto.json',
  signaturePayload: 'image.sig.payload.json',
  signature: 'image.sig',
});

export function attestationsRoot() {
  return join(resolve(process.env.DATA_DIR || './data'), 'attestations');
}

const SAFE = /^[a-z0-9][a-z0-9-]{0,62}$/;

export function dirFor(slug, env, id) {
  if (!SAFE.test(String(slug)) || !['production', 'sandbox'].includes(env) || !Number.isInteger(Number(id))) {
    throw new Error('attestation path refused: unexpected slug, env or id');
  }
  return join(attestationsRoot(), String(slug), env, String(Number(id)));
}

export function writeDoc(dir, name, content) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), content);
}

/** The bytes of one document of a row, or null. Only names in FILES, only under the row's own dir. */
export function readDoc(row, key) {
  const name = FILES[key];
  if (!name || !row?.dir) return null;
  const root = attestationsRoot();
  const dir = resolve(row.dir);
  if (!dir.startsWith(root + '/')) return null;
  const p = join(dir, name);
  return existsSync(p) ? readFileSync(p) : null;
}

export function insertPending(db, { deploymentId, appId, env, origin, imageRef }) {
  return Number(db.prepare(`INSERT INTO deploy_attestations (deployment_id, app_id, env, origin, image_ref, status)
    VALUES (?, ?, ?, ?, ?, 'pending')`).run(deploymentId ?? null, appId, env, origin, imageRef).lastInsertRowid);
}

export function finishRow(db, id, fields) {
  const cols = Object.keys(fields);
  db.prepare(`UPDATE deploy_attestations SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`)
    .run(...cols.map((c) => fields[c]), id);
}

/** The newest signed row for exactly this image on this app/env. */
export function signedRowFor(db, appId, env, imageId) {
  return db.prepare(`SELECT * FROM deploy_attestations WHERE app_id = ? AND env = ? AND image_id = ? AND status = 'signed'
    ORDER BY id DESC LIMIT 1`).get(appId, env, imageId) || null;
}

/** The newest signed row for this image REFERENCE, whatever bytes it named. */
export function signedRowForRef(db, appId, env, imageRef) {
  return db.prepare(`SELECT * FROM deploy_attestations WHERE app_id = ? AND env = ? AND image_ref = ? AND status = 'signed'
    ORDER BY id DESC LIMIT 1`).get(appId, env, imageRef) || null;
}

export function rowForDeployment(db, appId, deploymentId) {
  return db.prepare('SELECT * FROM deploy_attestations WHERE app_id = ? AND deployment_id = ? ORDER BY id DESC LIMIT 1')
    .get(appId, deploymentId) || null;
}

/** The parsed SBOM a deployment recorded, or null (the release-check input). */
export function sbomForDeployment(db, appId, deploymentId) {
  const row = rowForDeployment(db, appId, deploymentId);
  const bytes = row?.status === 'signed' ? readDoc(row, 'sbom') : null;
  if (!bytes) return null;
  try { return JSON.parse(bytes.toString('utf8')); } catch { return null; }
}

/** Remove attestation directories whose row is gone (the row cascades with its deployment and app). */
export function pruneOrphanAttestations(db) {
  const root = attestationsRoot();
  if (!existsSync(root)) return 0;
  const live = new Set(db.prepare('SELECT dir FROM deploy_attestations WHERE dir IS NOT NULL').all().map((r) => resolve(r.dir)));
  let removed = 0;
  for (const slug of readdirSync(root)) {
    for (const env of ['production', 'sandbox']) {
      const envDir = join(root, slug, env);
      if (!existsSync(envDir)) continue;
      for (const id of readdirSync(envDir)) {
        const d = resolve(join(envDir, id));
        if (!live.has(d)) { rmSync(d, { recursive: true, force: true }); removed += 1; }
      }
    }
  }
  return removed;
}
