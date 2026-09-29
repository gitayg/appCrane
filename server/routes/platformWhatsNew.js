/**
 * Platform "What's New" (v2.13.0). Shows platform-admins what changed in
 * AppCrane itself when the running version is newer than the one they last
 * saw — surfaced post-login by the dashboard.
 *
 *   GET  /api/whats-new/platform
 *     → { current_version, changes, first_time }. first_time records the
 *       current version silently (no dialog) so a fresh admin doesn't get
 *       dumped the whole history. changes=[] when up to date.
 *   POST /api/whats-new/platform/seen
 *     → marks the running version seen for the caller. Idempotent.
 *
 * Change notes are AppCrane's own commit subjects, written as user-facing
 * release notes ("vX.Y.Z: …"), read from this install's git checkout after a
 * fetch of origin (services/releaseNotes.js). Those between the caller's
 * last-seen version and the running version are returned.
 */

import { Router } from 'express';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { getVersionNotes } from '../services/releaseNotes.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8')).version;

const router = Router();

// Semver compare: 1 if a > b, -1 if a < b, 0 if equal.
function cmp(a, b) {
  const pa = (a || '0').split('.').map(Number);
  const pb = (b || '0').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
  }
  return 0;
}

router.use(requireAuth, requirePlatformAdmin);

router.get('/platform', async (req, res) => {
  const db = getDb();
  const current = VERSION;

  // Explicit version range (e.g. the upgrade preview: from=current running
  // version, to=latest available). Read-only — does not touch seen-state.
  const fromQ = typeof req.query.from === 'string' ? req.query.from : null;
  const toQ   = typeof req.query.to   === 'string' ? req.query.to   : null;
  if (fromQ && toQ) {
    const notes = await getVersionNotes();
    const changes = notes
      .filter(c => cmp(c.version, fromQ) > 0 && cmp(c.version, toQ) <= 0)
      .slice(0, 25);
    return res.json({ current_version: toQ, changes, first_time: false });
  }

  const row = db.prepare('SELECT last_seen_version FROM platform_whats_new_seen WHERE user_id = ?').get(req.user.id);

  if (!row) {
    // First sighting — record silently, show nothing.
    db.prepare(
      "INSERT OR REPLACE INTO platform_whats_new_seen (user_id, last_seen_version, last_seen_at) VALUES (?, ?, datetime('now'))"
    ).run(req.user.id, current);
    return res.json({ current_version: current, changes: [], first_time: true });
  }

  if (!row.last_seen_version || row.last_seen_version === current || cmp(current, row.last_seen_version) <= 0) {
    return res.json({ current_version: current, changes: [], first_time: false });
  }

  const notes = await getVersionNotes();
  const changes = notes
    .filter(c => cmp(c.version, row.last_seen_version) > 0 && cmp(c.version, current) <= 0)
    .slice(0, 25);
  res.json({ current_version: current, changes, first_time: false });
});

router.post('/platform/seen', (req, res) => {
  const db = getDb();
  db.prepare(
    "INSERT OR REPLACE INTO platform_whats_new_seen (user_id, last_seen_version, last_seen_at) VALUES (?, ?, datetime('now'))"
  ).run(req.user.id, VERSION);
  res.json({ ok: true });
});

export default router;
