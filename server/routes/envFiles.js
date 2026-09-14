/**
 * Stored .env files of a Crane-hosted app (app_env_files, envFileStore.js).
 *
 *   GET    /api/apps/:slug/env-files                       metadata, never content
 *   GET    /api/apps/:slug/env-files/content?env=&path=    plaintext, throttled + audited + owners notified
 *   PUT    /api/apps/:slug/env-files      { env, path, content, encoding? }   create or replace
 *   DELETE /api/apps/:slug/env-files?env=&path=
 *
 * Authorization, in this order, on every route:
 *   1. requireAppUser — the caller is ASSIGNED to this app. Same gate as the
 *      env-var routes and their ?reveal=true: since v2.39.0 assignment is
 *      authoritative for every role, platform_admin included, because a global
 *      role alone must not reach an app's secrets. These files are the same
 *      secrets in another shape.
 *   2. owner of THIS app (app_user_roles.app_role = 'owner'), or a global
 *      admin / platform_admin who passed step 1. Narrower than env vars (any
 *      assigned user may write a sandbox var): replacing a whole file can drop
 *      every key an app has, and there is no matrix permission for it yet.
 *   3. the app is Crane-hosted (managedRepo.usesLocalRepo) — else 409.
 *
 * Nothing here logs, audits or returns content except the reveal route's body.
 * Changes take effect on the app's next deploy of that environment.
 */

import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requireAppUser } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';
import { AppError } from '../utils/errors.js';
import { roleForUserOnApp } from '../services/permissions.js';
import { usesLocalRepo } from '../services/managedRepo.js';
import { notifySecretReveal } from '../services/emailService.js';
import {
  ENVS, assertEnvRelPath, deleteStoredEnvFile, listStoredEnvFiles, putStoredEnvFile, readStoredEnvFile,
} from '../services/envFileStore.js';

const router = Router();
router.use(requireAuth);

// The env-var reveal route's numbers (routes/envVars.js), and one shared budget:
// these reveals count against env-reveal / secret-reveal and vice versa.
const REVEAL_WINDOW_MIN = 10;
const REVEAL_MAX_PER_WINDOW = 30;
const REVEAL_NOTICE_COOLDOWN_MIN = 30;
const TAKES_EFFECT = 'Takes effect on the next deploy of this environment.';

function requireOwner(req, _res, next) {
  const globalAdmin = req.user.role === 'admin' || req.user.role === 'platform_admin';
  if (globalAdmin || roleForUserOnApp(req.user, req.app) === 'owner') return next();
  return next(new AppError('Managing stored .env files requires the owner role on this app', 403, 'FORBIDDEN'));
}

function requireCraneHosted(req, _res, next) {
  let local = false;
  try { local = usesLocalRepo(req.app); } catch (_) { local = false; }
  if (local) return next();
  return next(new AppError(
    `'${req.app.slug}' is not Crane-hosted; stored .env files exist only for apps whose repository is hosted on AppCrane. Use environment variables.`,
    409, 'NOT_CRANE_HOSTED'));
}

function envAndPath(src) {
  const env = src?.env;
  const path = src?.path;
  if (!ENVS.includes(env)) throw new AppError(`env must be one of ${ENVS.join(', ')}`, 400, 'VALIDATION');
  try {
    assertEnvRelPath(path);
  } catch (e) {
    throw new AppError(e.message, 400, e.code || 'VALIDATION');
  }
  return { env, path };
}

function query(req) {
  const url = new URL(req.url, 'http://localhost');
  return { env: url.searchParams.get('env'), path: url.searchParams.get('path') };
}

router.get('/:slug/env-files', requireAppUser, requireOwner, requireCraneHosted, (req, res) => {
  const files = listStoredEnvFiles(getDb(), req.app.id).map((f) => ({
    env: f.env, path: f.path, mode: `0${(f.mode & 0o777).toString(8)}`, bytes: f.bytes, source: f.source, updated_at: f.updated_at,
  }));
  res.json({ app: req.app.slug, files });
});

router.get('/:slug/env-files/content', requireAppUser, requireOwner, requireCraneHosted, (req, res) => {
  const { env, path } = envAndPath(query(req));
  const db = getDb();
  const countReveals = (minutes) => db.prepare(`
    SELECT COUNT(*) AS n FROM audit_log
    WHERE user_id = ? AND app_id = ? AND action IN ('env-reveal', 'secret-reveal', 'env_file.reveal')
      AND created_at >= datetime('now', ?)
  `).get(req.user.id, req.app.id, `-${minutes} minutes`).n;

  if (countReveals(REVEAL_WINDOW_MIN) >= REVEAL_MAX_PER_WINDOW) {
    log.error(`SECRET REVEAL THROTTLED ${req.app.slug}/${env} (.env file) — user ${req.user.id} exceeded ${REVEAL_MAX_PER_WINDOW} reveals in ${REVEAL_WINDOW_MIN}m`);
    throw new AppError(
      `Too many secret reveals for this app (${REVEAL_MAX_PER_WINDOW} per ${REVEAL_WINDOW_MIN} minutes). Wait and retry, or ask a platform admin.`,
      429, 'REVEAL_THROTTLED');
  }

  const file = readStoredEnvFile(db, req.app.id, env, path);
  if (!file) throw new AppError(`No stored .env file ${JSON.stringify(path)} in ${env}`, 404, 'NOT_FOUND');

  const alreadyNotified = countReveals(REVEAL_NOTICE_COOLDOWN_MIN) > 0;
  logAudit(req.user.id, req.app.id, 'env_file.reveal', { env, path });
  log.warn(`SECRET REVEAL ${req.app.slug}/${env} stored .env file ${JSON.stringify(path)} by user ${req.user.id}`);
  if (!alreadyNotified) {
    notifySecretReveal(req.app, env, req.user, [`stored .env file ${path}`])
      .catch((e) => log.error(`Secret-reveal notification failed for ${req.app.slug}/${env}: ${e.message}`));
  }

  res.json({
    env, path, mode: `0${(file.mode & 0o777).toString(8)}`, bytes: file.bytes, updated_at: file.updated_at,
    content: file.content.toString('utf8'),
  });
});

router.put('/:slug/env-files', requireAppUser, requireOwner, requireCraneHosted, (req, res) => {
  const { env, path } = envAndPath(req.body);
  const { content, encoding = 'utf-8' } = req.body || {};
  if (encoding !== 'utf-8' && encoding !== 'base64') throw new AppError("encoding must be 'utf-8' or 'base64'", 400, 'VALIDATION');
  if (typeof content !== 'string') throw new AppError('content must be a string', 400, 'VALIDATION');
  let input = content;
  if (encoding === 'base64') {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(content) || content.length % 4 !== 0) throw new AppError('content is not valid base64', 400, 'VALIDATION');
    input = Buffer.from(content, 'base64');
  }
  let result;
  try {
    result = putStoredEnvFile(getDb(), req.app.id, env, path, input);
  } catch (e) {
    if (e.code === 'ENV_FILE_CONTENT_REFUSED') throw new AppError(e.message, e.status || 400, e.code);
    throw e;
  }
  logAudit(req.user.id, req.app.id, 'env_file.replace', { env, path, created: result.created });
  log.info(`Stored .env file ${JSON.stringify(path)} ${result.created ? 'created' : 'replaced'} on ${req.app.slug}/${env} by user ${req.user.id}`);
  res.status(result.created ? 201 : 200).json({
    env, path, created: result.created, mode: `0${(result.mode & 0o777).toString(8)}`, bytes: result.bytes, updated_at: result.updated_at,
    message: `${result.created ? 'Created' : 'Replaced'} ${path} for ${env}. ${TAKES_EFFECT}`,
  });
});

router.delete('/:slug/env-files', requireAppUser, requireOwner, requireCraneHosted, (req, res) => {
  const { env, path } = envAndPath(query(req));
  if (!deleteStoredEnvFile(getDb(), req.app.id, env, path)) {
    throw new AppError(`No stored .env file ${JSON.stringify(path)} in ${env}`, 404, 'NOT_FOUND');
  }
  logAudit(req.user.id, req.app.id, 'env_file.delete', { env, path });
  log.info(`Stored .env file ${JSON.stringify(path)} deleted from ${req.app.slug}/${env} by user ${req.user.id}`);
  res.json({ env, path, deleted: true, message: `Deleted ${path} from ${env}. ${TAKES_EFFECT}` });
});

export default router;
