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
 * Change notes come from GitHub: AppCrane's own commit subjects on
 * gitayg/appCrane are written as user-facing release notes ("vX.Y.Z: …"),
 * so we parse the version-tagged commits and return those between the
 * caller's last-seen version and the running version. Public-repo API, no
 * token; cached 5 min to stay well under the unauthenticated rate limit.
 */

import { Router } from 'express';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';

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

let _commitsCache = null;
let _commitsCacheAt = 0;
async function fetchVersionCommits() {
  const now = Date.now();
  if (_commitsCache && now - _commitsCacheAt < 5 * 60 * 1000) return _commitsCache;
  try {
    const r = await fetch('https://api.github.com/repos/gitayg/appCrane/commits?per_page=50', {
      headers: { 'User-Agent': 'AppCrane', 'Accept': 'application/vnd.github+json' },
      signal: AbortSignal.timeout(6000),
    });
    if (!r.ok) return _commitsCache || [];
    const data = await r.json();
    const parsed = [];
    for (const c of Array.isArray(data) ? data : []) {
      const firstLine = String(c.commit?.message || '').split('\n')[0];
      const m = firstLine.match(/^v(\d+\.\d+\.\d+)[:\s-]\s*(.*)$/);
      if (!m) continue;
      parsed.push({
        version: m[1],
        commit_message: (m[2] || '').trim() || firstLine,
        commit_hash: c.sha || null,
        finished_at: c.commit?.author?.date || c.commit?.committer?.date || null,
      });
    }
    _commitsCache = parsed;
    _commitsCacheAt = now;
    return parsed;
  } catch (_) {
    return _commitsCache || [];
  }
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
    const commits = await fetchVersionCommits();
    const changes = commits
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

  const commits = await fetchVersionCommits();
  const changes = commits
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
