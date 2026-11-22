import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { appSecretPrefix, appSecretRoot, appSecretsAvailable, providerConfig } from '../services/secretsProvider/index.js';

const router = Router();

router.use(requireAuth, requirePlatformAdmin);

function appPrefix() {
  try { return appSecretPrefix(); } catch (_) { return null; }
}

// Status only: read from configuration, with no AWS call and no secret names.
router.get('/', (req, res) => {
  const config = providerConfig();
  res.json({
    active: config !== null,
    provider: config?.provider ?? null,
    region: config?.region ?? null,
    platform_secret_configured: Boolean(config?.secretId),
    app_prefix: appSecretsAvailable() ? appPrefix() : null,
    app_secrets: appSecretsAvailable(),
  });
});

// The path of one app's secrets: it is random, so an operator seeding or cleaning
// up a secret in AWS cannot work it out. A name in AWS, never a value or an AWS call.
router.get('/app-path/:slug', (req, res) => {
  const row = getDb().prepare('SELECT slug, secrets_namespace FROM apps WHERE slug = ?').get(req.params.slug);
  if (!row) throw new AppError('App not found', 404, 'NOT_FOUND');
  res.json({ slug: row.slug, path_prefix: `${appSecretRoot(row.secrets_namespace)}/` });
});

export default router;
