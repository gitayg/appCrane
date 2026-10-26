// Platform setting for fresh base images on app-owned Dockerfiles, and the
// admin view the runtime patch card reads.
//
// Generated Dockerfiles always pull their base: AppCrane chose the tag
// (php:<minor>-apache, node:<major>-alpine) precisely so it moves to the latest
// patch. An app's own Dockerfile is pulled too unless a platform admin turns it
// off (`pull_base_images_app_dockerfiles`, default on): a floating tag the
// author wrote (php:8.3-apache, node:22) means "the latest patch of this line"
// as well, and a cached copy silently freezes it; a pinned tag or digest pulls
// to the same bytes, so pinning authors see no change.

import { AppError } from '../../utils/errors.js';
import { isPlatformAdmin } from '../../utils/roles.js';
import { logAudit } from '../../middleware/audit.js';
import { APP_DOCKERFILE_PULL_KEY, pullForAppDockerfiles } from './runtimeImages.js';
import { getPolicy } from './policy.js';

export function getRuntimePolicy(db) {
  const p = getPolicy(db);
  return { auto_patch_enabled: p.enabled, policy: p.name, pull_app_dockerfiles: pullForAppDockerfiles(db), pull_generated_dockerfiles: true };
}

export function setRuntimePolicy(db, patch, user) {
  if (!isPlatformAdmin(user)) throw new AppError('Only a platform admin can change this setting', 403, 'FORBIDDEN');
  if (typeof patch?.pull_app_dockerfiles !== 'boolean') throw new AppError('pull_app_dockerfiles must be true or false', 400, 'VALIDATION');
  const before = getRuntimePolicy(db);
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(APP_DOCKERFILE_PULL_KEY, patch.pull_app_dockerfiles ? 'true' : 'false', user.id);
  const after = getRuntimePolicy(db);
  logAudit(user.id, null, 'runtime-patch-policy-change', { before, after });
  return after;
}

/** Recent runtime patch runs, newest first. */
export function recentRuntimeRuns(db, limit = 20) {
  return db.prepare(`SELECT p.id, a.slug AS app_slug, p.runtime, p.advisory_key, p.from_version, p.to_version, p.status, p.reason,
    p.sandbox_deployment_id, p.production_deployment_id, p.started_at, p.finished_at
    FROM runtime_patch_runs p JOIN apps a ON a.id = p.app_id WHERE p.status != 'ineligible' ORDER BY p.id DESC LIMIT ?`).all(limit);
}
