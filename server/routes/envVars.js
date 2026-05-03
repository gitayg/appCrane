import { Router } from 'express';
import { getDb } from '../db.js';
// requireAppUser: assigned app users only — admins are explicitly NOT
// granted access to env-var values (the comment on requireAppUser in
// middleware/auth.js codifies this rule). The previous use of
// requireAppUser silently let admin read every app's env via
// ?reveal=true (security review v1.27.34 H4).
import { requireAuth, requireAppUser } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { encrypt, decrypt } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';

const router = Router();

router.use(requireAuth);

/**
 * GET /api/apps/:slug/env/:env - List env vars
 * Assigned app users only — admins do NOT see plaintext values, even
 * with ?reveal=true. If admins need a one-time read for incident
 * response, add a separate audited break-glass endpoint.
 */
router.get('/:slug/env/:env', requireAppUser, (req, res) => {
  const { env } = req.params;
  // Express 5: req.query may be a getter; access safely
  const url = new URL(req.url, `http://${req.headers.host}`);
  const showValues = url.searchParams.get('reveal') === 'true';
  const db = getDb();

  const vars = db.prepare(
    'SELECT id, key, value_encrypted, updated_at FROM env_vars WHERE app_id = ? AND env = ? ORDER BY key'
  ).all(req.app.id, env);

  const result = vars.map(v => ({
    id: v.id,
    key: v.key,
    value: showValues ? decrypt(v.value_encrypted) : '********',
    updated_at: v.updated_at,
  }));

  // Check for matching values across envs (safety warning)
  const warnings = [];
  if (env === 'sandbox') {
    const prodVars = db.prepare(
      'SELECT key, value_encrypted FROM env_vars WHERE app_id = ? AND env = ?'
    ).all(req.app.id, 'production');

    const prodMap = new Map(prodVars.map(v => [v.key, v.value_encrypted]));
    for (const v of vars) {
      if (prodMap.has(v.key) && prodMap.get(v.key) === v.value_encrypted) {
        warnings.push(`WARNING: ${v.key} has the same value in production and sandbox!`);
      }
    }
  }

  res.json({ env, vars: result, warnings });
});

/**
 * PUT /api/apps/:slug/env/:env - Set env vars (bulk)
 * Body: { "vars": { "KEY1": "value1", "KEY2": "value2" } }
 */
router.put('/:slug/env/:env', requireAppUser, auditMiddleware('env-set'), (req, res) => {
  const { env } = req.params;
  const { vars } = req.body;

  if (!vars || typeof vars !== 'object') {
    throw new AppError('Body must contain { vars: { KEY: "value" } }', 400, 'VALIDATION');
  }

  const db = getDb();
  const upsert = db.prepare(`
    INSERT INTO env_vars (app_id, env, key, value_encrypted, updated_by, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(app_id, env, key) DO UPDATE SET
      value_encrypted = excluded.value_encrypted,
      updated_by = excluded.updated_by,
      updated_at = excluded.updated_at
  `);

  const results = [];
  db.transaction(() => {
    for (const [key, value] of Object.entries(vars)) {
      if (!key.match(/^[A-Z_][A-Z0-9_]*$/i)) {
        throw new AppError(`Invalid env var key: ${key}`, 400, 'VALIDATION');
      }
      const encrypted = encrypt(String(value));
      upsert.run(req.app.id, env, key, encrypted, req.user.id);
      results.push(key);
    }
  })();

  res.json({ message: `Set ${results.length} env var(s) for ${env}`, keys: results });
});

/**
 * DELETE /api/apps/:slug/env/:env/:key - Delete single env var
 */
router.delete('/:slug/env/:env/:key', requireAppUser, auditMiddleware('env-delete'), (req, res) => {
  const { env, key } = req.params;
  const db = getDb();

  const result = db.prepare(
    'DELETE FROM env_vars WHERE app_id = ? AND env = ? AND key = ?'
  ).run(req.app.id, env, key);

  if (result.changes === 0) {
    throw new AppError(`Env var '${key}' not found in ${env}`, 404, 'NOT_FOUND');
  }

  res.json({ message: `Deleted ${key} from ${env}` });
});

export default router;
