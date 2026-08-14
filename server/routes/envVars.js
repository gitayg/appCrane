import { Router } from 'express';
import { getDb } from '../db.js';
// requireAppUser: assigned app users only — a global role, on its own, grants
// no access to env-var values (middleware/auth.js codifies the rule).
//
// v1.27.34 H4 established that for `admin`. It did NOT hold for
// `platform_admin`, which returned early from requireAppUser with no assignment
// check at all, so ?reveal=true handed a platform admin the plaintext of every
// app on the box. Closed in v2.39.0 — assignment is now authoritative for every
// role, and an admin who needs access assigns themselves, which is auditable.
import { requireAuth, requireAppUser } from '../middleware/auth.js';
import { auditMiddleware, logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';
import { encrypt, decrypt } from '../services/encryption.js';
import { userHasAppPermission } from '../services/permissions.js';
import { notifySecretReveal } from '../services/emailService.js';
import { AppError } from '../utils/errors.js';

const router = Router();

router.use(requireAuth);

// ── Plaintext-reveal throttle (v2.44.0) ──────────────────────────────────────
//
// Both numbers are set against the ACTUAL client, not a guess. The admin SPA
// (studio-web AppManager) loads the Environment tab with ?reveal=true and calls
// load() again after every set and every delete, so one honest sitting — open
// the tab, add half a dozen variables, delete a stale one, switch between the
// sandbox and production tabs — is on the order of 15-20 reveals in a few
// minutes. 30 per 10 minutes clears that with room to spare, which is the point:
// a throttle that fires during real incident response is a throttle an operator
// will demand be removed, and then there is none.
//
// Above that line there is no human workflow left. 30 full-environment dumps in
// 10 minutes is a script, and the caller gets 429 rather than the plaintext.
//
// Budget is counted per (user, app) across BOTH envs and across BOTH doors —
// this route's `env-reveal` and the MCP tool's `secret-reveal` — so a caller
// cannot get a fresh allowance by switching from HTTP to MCP or from sandbox to
// production. It is read from the audit log rather than process memory so a
// restart does not hand an attacker a clean budget.
const REVEAL_WINDOW_MIN = 10;
const REVEAL_MAX_PER_WINDOW = 30;

// Coalescing window for the owner notification. Same reasoning inverted: with
// the SPA re-revealing after every mutation, mailing on each event would put ~15
// identical notices in an owner's inbox for one editing session, and the third
// one teaches them to filter the rest. One notice per person per app per 30
// minutes keeps the signal; the audit log keeps the complete record.
const REVEAL_NOTICE_COOLDOWN_MIN = 30;

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

  // v2.42.1: a plaintext read is an event worth recording. Writes were audited
  // (env-set, env-delete) and reads were not, so the log could tell you who
  // CHANGED a secret but not who took a copy of one — backwards for incident
  // response, where the question is always "who saw this". The MCP path already
  // logs secret-reveal; this is the same operation through the other door.
  //
  // Only the reveal. The masked list is the ordinary UI render on every visit to
  // the Environment tab, and logging that would bury the reads that matter.
  // Keys only — the values are the thing being protected.
  if (showValues && vars.length) {
    // Both counts are taken BEFORE this reveal is logged, so "recent" and
    // "notified" mean strictly prior events and the arithmetic is unambiguous.
    const countReveals = (minutes) => db.prepare(`
      SELECT COUNT(*) AS n FROM audit_log
      WHERE user_id = ? AND app_id = ? AND action IN ('env-reveal', 'secret-reveal')
        AND created_at >= datetime('now', ?)
    `).get(req.user.id, req.app.id, `-${minutes} minutes`).n;

    if (countReveals(REVEAL_WINDOW_MIN) >= REVEAL_MAX_PER_WINDOW) {
      // Logged at error: hitting this ceiling is never routine use.
      log.error(`SECRET REVEAL THROTTLED ${req.app.slug}/${env} — user ${req.user.id} exceeded ${REVEAL_MAX_PER_WINDOW} reveals in ${REVEAL_WINDOW_MIN}m`);
      throw new AppError(
        `Too many secret reveals for this app (${REVEAL_MAX_PER_WINDOW} per ${REVEAL_WINDOW_MIN} minutes). Wait and retry, or ask a platform admin.`,
        429, 'REVEAL_THROTTLED'
      );
    }

    const alreadyNotified = countReveals(REVEAL_NOTICE_COOLDOWN_MIN) > 0;

    logAudit(req.user.id, req.app.id, 'env-reveal', { env, keys: vars.map(v => v.key) });
    log.warn(`SECRET REVEAL ${req.app.slug}/${env} (${vars.length} key(s)) by user ${req.user.id}`);

    if (!alreadyNotified) {
      // Fire-and-forget: the reveal must not block on SMTP, and a mail
      // transport that is down must not turn a valid read into a 500.
      notifySecretReveal(req.app, env, req.user, vars.map(v => v.key))
        .catch(e => log.error(`Secret-reveal notification failed for ${req.app.slug}/${env}: ${e.message}`));
    }
  }

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

  // Configurable RBAC: production env writes gated by env.write.production
  if (env === 'production' && !userHasAppPermission(req.user, req.app, 'env.write.production')) {
    throw new AppError('Writing production env vars is not permitted by your role on this app', 403, 'FORBIDDEN');
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
