import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { getDb } from '../db.js';
import { getLicensePolicy } from '../services/imageTrust/policy.js';
import { licenseFindings } from '../services/imageTrust/licenseFindings.js';

const router = Router();

// License-policy findings counted once per (app, component, version, license),
// from each app/env's newest signed attestation. Mounted at /api.

/** GET /api/apps/:slug/license-findings — this app's unique findings (members). */
router.get('/apps/:slug/license-findings', requireAuth, requireAppAccess, (req, res) => {
  const db = getDb();
  res.json({ policy: getLicensePolicy(db), ...licenseFindings(db, { appId: req.app.id }) });
});

/** GET /api/image-trust/license-findings — every app's unique findings (platform admin). */
router.get('/image-trust/license-findings', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  res.json({ policy: getLicensePolicy(db), ...licenseFindings(db) });
});

export default router;
