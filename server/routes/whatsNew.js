/**
 * "What's New" per-user, per-app dialog state (v2.3.4+).
 *
 *   GET  /api/apps/:slug/whats-new
 *     Returns { current_version, changes, first_time }.
 *     - first_time=true  → user has never opened this app; no dialog.
 *       Server has already recorded the current version as seen, so the
 *       next visit will only show diffs.
 *     - changes=[]       → user is up to date; no dialog.
 *     - changes=[{...}]  → show dialog. Each entry: { version, commit_hash,
 *       commit_message, finished_at }. Newest first.
 *
 *   POST /api/apps/:slug/whats-new/seen
 *     Marks the current live production version as seen by the caller.
 *     Idempotent. The frontend hits this when the dialog is dismissed.
 *
 * Source of truth for "changes" is the deployments table — each
 * production deploy that hit `live` since the user's last_seen_at
 * timestamp, grouped by `version` (so a same-version redeploy doesn't
 * appear twice). commit_message provides the human-readable line.
 *
 * Auth: any authenticated user with access to the app (requireAppAccess
 * — admins, owners, assigned users; portal/public users who have access
 * via app_users rows go through the same gate).
 */

import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';

const router = Router();

router.use(requireAuth);

/**
 * Latest live production deployment for an app — the "current version"
 * the user is being shown when they open the frame.
 */
function latestLive(db, appId) {
  return db.prepare(`
    SELECT id, version, commit_hash, commit_message, finished_at
    FROM deployments
    WHERE app_id = ? AND env = 'production' AND status = 'live'
    ORDER BY finished_at DESC
    LIMIT 1
  `).get(appId);
}

router.get('/:slug/whats-new', requireAppAccess, (req, res) => {
  const db = getDb();
  const app = req.app;
  const live = latestLive(db, app.id);
  const currentVersion = live?.version || null;

  // No live deployment yet → nothing to show; don't write a seen-row
  // either, so the first real release gets recorded correctly when the
  // user comes back.
  if (!live) {
    return res.json({ current_version: null, changes: [], first_time: false });
  }

  const seen = db.prepare(
    'SELECT last_seen_version, last_seen_at FROM user_app_seen WHERE user_id = ? AND app_id = ?'
  ).get(req.user.id, app.id);

  if (!seen) {
    // First-ever visit. Silently record the current version so the next
    // open shows only changes since now. Avoids dumping months of
    // history on a brand-new account or a freshly-assigned user.
    db.prepare(`
      INSERT INTO user_app_seen (user_id, app_id, last_seen_version, last_seen_at)
      VALUES (?, ?, ?, datetime('now'))
    `).run(req.user.id, app.id, currentVersion);
    return res.json({ current_version: currentVersion, changes: [], first_time: true });
  }

  // Already up-to-date → no dialog. Compare by version string first
  // (cheaper, exact match) then fall back to timestamp window so a
  // re-deploy at the same version doesn't fire the modal.
  if (seen.last_seen_version === currentVersion) {
    return res.json({ current_version: currentVersion, changes: [], first_time: false });
  }

  // Pull every production live deploy strictly after the user's last
  // seen timestamp, grouped by version (latest of each), newest first.
  const rows = db.prepare(`
    SELECT version, commit_hash, commit_message,
           MAX(finished_at) AS finished_at
    FROM deployments
    WHERE app_id = ?
      AND env = 'production'
      AND status = 'live'
      AND finished_at > ?
    GROUP BY version
    ORDER BY finished_at DESC
    LIMIT 50
  `).all(app.id, seen.last_seen_at);

  res.json({
    current_version: currentVersion,
    changes: rows,
    first_time: false,
  });
});

router.post('/:slug/whats-new/seen', requireAppAccess, (req, res) => {
  const db = getDb();
  const app = req.app;
  const live = latestLive(db, app.id);
  const currentVersion = live?.version || null;

  db.prepare(`
    INSERT INTO user_app_seen (user_id, app_id, last_seen_version, last_seen_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, app_id) DO UPDATE SET
      last_seen_version = excluded.last_seen_version,
      last_seen_at      = excluded.last_seen_at
  `).run(req.user.id, app.id, currentVersion);

  res.json({ ok: true, last_seen_version: currentVersion });
});

export default router;
