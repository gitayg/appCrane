import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import { getPublicKey } from '../services/imageTrust/signingKey.js';
import { getTrustMode, getLicensePolicy, setTrustPolicy, MODES } from '../services/imageTrust/policy.js';
import { readDoc, rowForDeployment, FILES } from '../services/imageTrust/store.js';
import { verifyRowDocuments } from '../services/imageTrust/verify.js';
import { signCurrentImages } from '../services/imageTrust/backfill.js';
import { backfillDiskImages } from '../services/imageTrust/diskBackfill.js';
import { enforceReadiness, REFUSED_STATES } from '../services/imageTrust/readiness.js';
import { openTrustEvents } from '../services/imageTrust/events.js';

const router = Router();

// Per-deploy SBOM, provenance and image signature (services/imageTrust).
// Mounted at /api; auth is per route. Nothing here ever reads the private key.

const DOCS = {
  sbom: { key: 'sbom', type: 'application/vnd.cyclonedx+json' },
  'sbom-attestation': { key: 'sbomAttestation', type: 'application/vnd.dsse.envelope.v1+json' },
  provenance: { key: 'provenance', type: 'application/vnd.dsse.envelope.v1+json' },
  'signature-payload': { key: 'signaturePayload', type: 'application/json' },
  signature: { key: 'signature', type: 'text/plain' },
};

function deploymentId(req) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) throw new AppError('id must be a positive integer', 400, 'VALIDATION');
  return id;
}

export function summarize(db, row) {
  if (!row) return null;
  const key = getPublicKey(db);
  const problems = row.status === 'signed' ? verifyRowDocuments(row, row.image_id, key) : [row.error || 'not signed'];
  let license = null;
  try { license = row.license_check_json ? JSON.parse(row.license_check_json) : null; } catch { license = null; }
  return {
    id: row.id,
    deployment_id: row.deployment_id,
    env: row.env,
    origin: row.origin,
    image_ref: row.image_ref,
    image_id: row.image_id,
    status: row.status,
    error: row.error,
    key_id: row.key_id,
    verified: row.status === 'signed' && problems.length === 0,
    problems,
    sbom: {
      status: row.sbom_status,
      error: row.sbom_error,
      sha256: row.sbom_sha256,
      components: row.sbom_components,
      with_hash: row.sbom_hash_coverage,
      with_license: row.sbom_license_coverage,
    },
    license_check: license,
    documents: row.status === 'signed'
      ? Object.entries(DOCS).filter(([, d]) => readDoc(row, d.key)).map(([name]) => name)
      : [],
    created_at: row.created_at,
  };
}

/** GET /api/apps/:slug/attestations — the newest attestations of this app, newest first. */
router.get('/apps/:slug/attestations', requireAuth, requireAppAccess, (req, res) => {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM deploy_attestations WHERE app_id = ? ORDER BY id DESC LIMIT 50').all(req.app.id);
  res.json({ mode: getTrustMode(db), attestations: rows.map((r) => summarize(db, r)), trust_events: openTrustEvents(db, { appId: req.app.id }) });
});

/** GET /api/apps/:slug/deployments/:id/attestation — signature status of one deploy. */
router.get('/apps/:slug/deployments/:id/attestation', requireAuth, requireAppAccess, (req, res) => {
  const db = getDb();
  const row = rowForDeployment(db, req.app.id, deploymentId(req));
  if (!row) throw new AppError('No attestation recorded for this deployment', 404, 'NOT_FOUND');
  res.json({ mode: getTrustMode(db), attestation: summarize(db, row) });
});

/** GET /api/apps/:slug/deployments/:id/attestation/:doc — one document (sbom, provenance, signature, …) as stored. */
router.get('/apps/:slug/deployments/:id/attestation/:doc', requireAuth, requireAppAccess, (req, res) => {
  const doc = DOCS[req.params.doc];
  if (!doc) throw new AppError(`doc must be one of ${Object.keys(DOCS).join(', ')}`, 400, 'VALIDATION');
  const db = getDb();
  const row = rowForDeployment(db, req.app.id, deploymentId(req));
  const bytes = row ? readDoc(row, doc.key) : null;
  if (!bytes) throw new AppError('That document does not exist for this deployment', 404, 'NOT_FOUND');
  res.setHeader('Content-Type', doc.type);
  res.setHeader('Content-Disposition', `attachment; filename="${req.app.slug}-${row.env}-${row.deployment_id}-${FILES[doc.key]}"`);
  res.send(bytes);
});

/** GET /api/image-trust/public-key — the verifying key, PEM, for auditors (`cosign verify-blob --key`). */
router.get('/image-trust/public-key', requireAuth, (req, res) => {
  const key = getPublicKey(getDb());
  if (!key) throw new AppError('This instance has not signed anything yet, so it has no signing key', 404, 'NOT_FOUND');
  res.setHeader('X-Key-Id', key.keyId);
  res.type('application/x-pem-file').send(key.publicKeyPem);
});

/** GET /api/image-trust/policy — mode, license lists and key id (platform admin). */
router.get('/image-trust/policy', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  res.json({ mode: getTrustMode(db), modes: MODES, ...getLicensePolicy(db), key_id: getPublicKey(db)?.keyId || null });
});

/**
 * PUT /api/image-trust/policy — { mode?, denied?, flagged?, acknowledge_unsigned? } (platform admin).
 * Switching to enforce while running images are unsigned is refused with 409
 * IMAGE_TRUST_NOT_READY listing them (each would have its next restart refused),
 * unless acknowledge_unsigned is true; the override is audited with the list.
 */
router.put('/image-trust/policy', requireAuth, requirePlatformAdmin, async (req, res) => {
  const db = getDb();
  const body = req.body || {};
  let readiness = null;
  if (body.mode === 'enforce' && getTrustMode(db) !== 'enforce') {
    readiness = await enforceReadiness(db);
    if (!readiness.ready && body.acknowledge_unsigned !== true) {
      const w = readiness.would_refuse;
      const err = new AppError(
        `${w.total} running image(s) are not signed by this instance, signed without an SBOM, or whose signature does not verify (${w.unsigned} unsigned, ${w.sbom_missing} without an SBOM, ${w.invalid} not verifying). Under enforce, each of those apps would have its next restart (health auto-restart, restart, recovery) refused. Sign the unsigned and SBOM-less ones first (POST /api/image-trust/sign-current; an image whose signature does not verify is never re-signed and is listed on the census), or send acknowledge_unsigned: true to switch anyway.`,
        409, 'IMAGE_TRUST_NOT_READY');
      err.publicDetails = { running_unsigned: readiness.running_unsigned, would_refuse: w, on_disk_unsigned: readiness.on_disk_unsigned };
      throw err;
    }
  }
  let policy;
  try {
    policy = setTrustPolicy(db, req.body || {}, req.user.id);
  } catch (e) {
    throw new AppError(e.message, e.status || 400, 'VALIDATION');
  }
  logAudit(req.user.id, null, 'image-trust-policy-set', {
    mode: policy.mode, denied: policy.denied.length, flagged: policy.flagged.length,
    ...(readiness && !readiness.ready ? { acknowledged_unsigned: readiness.running_unsigned.map((e) => `${e.app}/${e.env} ${e.image_id}`) } : {}),
  });
  res.json({ ...policy, key_id: getPublicKey(db)?.keyId || null });
});

/**
 * GET /api/image-trust/census — per live app/env, whether its running image is signed;
 * whether enforce can be turned on; unsigned images on disk; warn/refusal events
 * of images still unsigned. Signs nothing.
 */
router.get('/image-trust/census', requireAuth, requirePlatformAdmin, async (req, res) => {
  const db = getDb();
  const envs = await signCurrentImages({ db, dryRun: true });
  const disk = await backfillDiskImages({ db, dryRun: true });
  res.json({
    mode: getTrustMode(db),
    envs,
    enforce_ready: !envs.some((e) => REFUSED_STATES.has(e.state)),
    on_disk: disk.images,
    ...(disk.error ? { on_disk_error: disk.error } : {}),
    events: openTrustEvents(db),
  });
});

/** POST /api/image-trust/sign-current — sign every live app/env's running image (trust on first use). */
router.post('/image-trust/sign-current', requireAuth, requirePlatformAdmin, async (req, res) => {
  const envs = await signCurrentImages({});
  logAudit(req.user.id, null, 'image-trust-backfill', { backfilled: envs.filter((e) => e.state === 'backfilled').length, errors: envs.filter((e) => e.state === 'error').length });
  res.json({ envs });
});

/** POST /api/image-trust/backfill-disk — sign every on-disk image a live or rolled-back deployment of its app names (trust on first use); lists the rest. */
router.post('/image-trust/backfill-disk', requireAuth, requirePlatformAdmin, async (req, res) => {
  const r = await backfillDiskImages({});
  logAudit(req.user.id, null, 'image-trust-backfill-disk', {
    backfilled: r.images.filter((i) => i.state === 'backfilled').map((i) => `${i.app}/${i.env} ${i.image_ref} ${i.image_id}`),
    errors: r.images.filter((i) => i.state === 'error').length,
    unprovable: r.images.filter((i) => i.state === 'unprovable').length,
  });
  res.json(r);
});

export default router;
