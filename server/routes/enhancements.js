import { Router } from 'express';
import { getDb } from '../db.js';
import { hashApiKey } from '../services/encryption.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { mirrorRequest, closeRequest, getAppForMirror } from '../services/github/issuesMirror.js';
import {
  listComments, createComment, setStatus as setCommentStatus,
  deleteComment, getComment,
} from '../services/enhancementComments.js';
import { BUCKETS, bucketize, applyBucket } from '../services/requestStatus.js';
import { userHasAppPermission } from '../services/permissions.js';
import { notifyRequesterFulfilled, notifyAppAdminsOfNewRequest, notifyPlatformAdminsOfPlatformRequest } from '../services/requestNotify.js';

const router = Router();

const VALID_STATUSES = ['new', 'selected', 'planning', 'in_progress', 'done', 'no_changes_needed'];

/**
 * Resolve an identity Bearer token to a user row.
 * Returns null if invalid/expired.
 */
function getUserFromBearer(token) {
  if (!token) return null;
  const db = getDb();
  const tokenHash = hashApiKey(token);
  const session = db.prepare(`
    SELECT s.*, u.id as user_id, u.name, u.email, u.username, u.role
    FROM identity_sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
  `).get(tokenHash);
  return session || null;
}

/**
 * POST /api/enhancements
 * Submit an enhancement request. Requires identity Bearer token.
 * Body: { message: "...", app_slug: "..." (optional) }
 */
router.post('/', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const session = getUserFromBearer(token);

  // Fall back to API key auth (for admin dashboard submissions)
  let userId, userName, userRole;
  if (session) {
    userId = session.user_id;
    userName = session.name;
    userRole = session.role;
  } else {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');
    const db2 = getDb();
    const user = db2.prepare('SELECT * FROM users WHERE api_key_hash = ?').get(hashApiKey(apiKey));
    if (!user) throw new AppError('Invalid API key', 401, 'UNAUTHORIZED');
    userId = user.id;
    userName = user.name;
    userRole = user.role;
  }

  const { message, app_slug } = req.body || {};
  if (!message || !message.trim()) {
    throw new AppError('message is required', 400, 'VALIDATION');
  }

  const db = getDb();
  const { lastInsertRowid } = db.prepare(`
    INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status)
    VALUES (?, ?, ?, ?, 'new')
  `).run(app_slug || null, userId, userName, message.trim());

  // v2: requests land in 'triage' for human/MCP-agent pickup. We no longer
  // auto-queue an AppStudio plan job — that whole pipeline (Anthropic API
  // calls + container-based code generation) was deprecated when AppCrane
  // pivoted to "AI is the user's tool, MCP is the integration." Letting an
  // invalid ANTHROPIC_API_KEY produce a noisy 401 on every request submission
  // (the user-reported bug) is exactly the noise this removal eliminates.
  // The request is now just a tracked work item; agents call appcrane_list_requests
  // to pick it up via local Claude Code / Cursor / any MCP-capable client.

  res.json({ message: 'Enhancement request submitted. Thank you!', enhancement_id: lastInsertRowid });

  // v2.21.5: '_platform' is a reserved slug for requests against AppCrane
  // itself — no GitHub mirror, notify platform admins instead of app admins.
  if (app_slug === '_platform') {
    notifyPlatformAdminsOfPlatformRequest(lastInsertRowid);
  } else if (app_slug) {
    const app = getAppForMirror(app_slug);
    if (app?.github_url) {
      const row = db.prepare('SELECT id, message, user_name, status, created_at FROM enhancement_requests WHERE id = ?').get(lastInsertRowid);
      mirrorRequest(app, row).catch(() => {});
    }
    // v2.14.1/3: email the app's owners/admins on any new request (access or feature).
    notifyAppAdminsOfNewRequest(lastInsertRowid);
  }
});

/**
 * GET /api/enhancements/my
 * Get the current user's own enhancement requests. Requires Bearer token.
 */
router.get('/my', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const session = getUserFromBearer(token);
  if (!session) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');

  const db = getDb();
  const rows = db.prepare(`
    SELECT id, app_slug, message, created_at, status
    FROM enhancement_requests
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(session.user_id);
  res.json({ requests: rows });
});

/**
 * GET /api/enhancements/owned
 * List enhancement requests filed against apps the caller may view requests
 * for — gated by the configurable `request.view_app` permission (per-app
 * role × the role_permissions matrix at /settings#roles). Default: owners
 * only; an operator can flip Admin or User on to widen the triage view.
 * Mirrors the rich shape of the admin /api/enhancements endpoint (bucket
 * label + latest job info) so the page renders identically without the
 * caller being a global admin. Users with no viewable app get [] (sidebar
 * then hides the Requests item entirely).
 *
 * Out of scope: requests the caller personally submitted on apps they have
 * no role on (that's /api/enhancements/my, kept separate so this view stays
 * an app-triage list rather than mixing two mental models).
 */
router.get('/owned', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const session = getUserFromBearer(token);
  if (!session) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');

  const db = getDb();
  // Resolve the apps this caller may view requests for through the matrix
  // rather than hardcoding roles — so /settings#roles drives who sees what.
  // The candidate set is every app the caller has any per-app relationship
  // with (a role row or a bare assignment); userHasAppPermission then
  // applies the matrix (and the global-admin escape hatch) per app.
  // userHasAppPermission reads user.id (per-app role lookup) + user.role
  // (global-admin escape hatch). The session row's own `id` is the session
  // id, not the user id — normalize so roleForUserOnApp queries correctly.
  const principal = { id: session.user_id, role: session.role };
  const candidateApps = db.prepare(`
    SELECT DISTINCT a.id, a.slug FROM apps a
    WHERE a.id IN (SELECT app_id FROM app_user_roles WHERE user_id = ?)
       OR a.id IN (SELECT app_id FROM app_users      WHERE user_id = ?)
  `).all(session.user_id, session.user_id);
  const viewableSlugs = candidateApps
    .filter(a => userHasAppPermission(principal, a, 'request.view_app'))
    .map(a => a.slug);

  if (viewableSlugs.length === 0) return res.json({ requests: [] });

  const includeDone = req.query.include_done === '1' || req.query.include_done === 'true';
  const placeholders = viewableSlugs.map(() => '?').join(', ');
  const where = includeDone ? '' : "AND (er.status != 'done' OR er.status IS NULL)";
  const rows = db.prepare(`
    SELECT
      er.id, er.app_slug, er.user_name, er.message, er.created_at, er.status,
      er.fix_version, er.cost_tokens, er.cost_usd_cents, er.branch_name, er.pr_url,
      er.validated_at, er.validated_by,
      j.id        AS latest_job_id,
      j.phase     AS latest_job_phase,
      j.status    AS latest_job_status,
      j.error_message AS latest_job_error,
      j.cost_tokens   AS latest_job_tokens,
      j.cost_usd_cents AS latest_job_cents
    FROM enhancement_requests er
    LEFT JOIN enhancement_jobs j ON j.id = (
      SELECT id FROM enhancement_jobs WHERE enhancement_id = er.id ORDER BY id DESC LIMIT 1
    )
    WHERE er.app_slug IN (${placeholders}) ${where}
    ORDER BY er.created_at DESC
  `).all(...viewableSlugs);
  const enriched = rows.map(r => ({ ...r, bucket: bucketize(r.status, r.validated_at) }));
  res.json({ requests: enriched });
});

/**
 * GET /api/enhancements
 * List all enhancement requests. Requires admin API key.
 */
router.get('/', requireAuth, requireAdmin, (req, res) => {
  const db = getDb();
  // By default hide requests the user marked as done — they're cleanup
  // clutter on the active list. ?include_done=1 shows everything.
  const includeDone = req.query.include_done === '1' || req.query.include_done === 'true';
  const conds = [];
  if (!includeDone) conds.push("(er.status != 'done' OR er.status IS NULL)");
  // v2.21.5: platform requests ('_platform') are visible only to platform
  // admins. Tier-2 admins and everyone else never see them in the triage list.
  if (req.user.role !== 'platform_admin') conds.push("(er.app_slug IS NULL OR er.app_slug != '_platform')");
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const rows = db.prepare(`
    SELECT
      er.id, er.app_slug, er.user_name, er.message, er.created_at, er.status,
      er.fix_version, er.cost_tokens, er.cost_usd_cents, er.branch_name, er.pr_url,
      er.validated_at, er.validated_by,
      j.id        AS latest_job_id,
      j.phase     AS latest_job_phase,
      j.status    AS latest_job_status,
      j.error_message AS latest_job_error,
      j.cost_tokens   AS latest_job_tokens,
      j.cost_usd_cents AS latest_job_cents
    FROM enhancement_requests er
    LEFT JOIN enhancement_jobs j ON j.id = (
      SELECT id FROM enhancement_jobs WHERE enhancement_id = er.id ORDER BY id DESC LIMIT 1
    )
    ${where}
    ORDER BY er.created_at DESC
  `).all();
  // Add bucket label so the UI doesn't have to compute it
  const enriched = rows.map(r => ({ ...r, bucket: bucketize(r.status, r.validated_at) }));
  res.json({ requests: enriched });
});

/**
 * PUT /api/enhancements/:id/bucket
 * Move a request through the simplified lifecycle:
 *   triage → in_progress → shipped → validated
 * Body: { bucket: 'triage' | 'in_progress' | 'shipped' | 'validated' }
 *
 * App-admins or AppCrane admins only. Mirrors back to GitHub on shipped.
 */
router.put('/:id/bucket', requireAuth, (req, res) => {
  const { bucket } = req.body || {};
  if (!BUCKETS.includes(bucket)) {
    throw new AppError(`bucket must be one of: ${BUCKETS.join(', ')}`, 400, 'VALIDATION');
  }
  const db = getDb();
  const id = parseInt(req.params.id, 10);
  const row = db.prepare(
    'SELECT id, app_slug, message, user_name, pr_url, status, validated_at FROM enhancement_requests WHERE id = ?'
  ).get(id);
  if (!row) throw new AppError('Not found', 404, 'NOT_FOUND');

  if (req.user.role !== 'admin' && req.user.role !== 'platform_admin') {
    if (!row.app_slug) throw new AppError('Forbidden', 403, 'FORBIDDEN');
    const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(row.app_slug);
    const ar = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app?.id, req.user.id);
    // Admin/owner of app: most transitions allowed. The 'shipped' transition
    // is configurable via the request.ship permission.
    const hasAppRole = ar?.app_role === 'admin' || ar?.app_role === 'owner';
    if (!hasAppRole) throw new AppError('Forbidden', 403, 'FORBIDDEN');
    if (bucket === 'shipped' && !userHasAppPermission(req.user, app, 'request.ship')) {
      throw new AppError('Marking shipped is not permitted by your role on this app', 403, 'FORBIDDEN');
    }
  }

  applyBucket(db, id, bucket, req.user.id);
  res.json({ bucket });

  if (bucket === 'shipped' && row.app_slug) {
    const app = getAppForMirror(row.app_slug);
    if (app?.github_url) {
      closeRequest(app, { ...row, status: 'done' }, { resolution: 'Shipped via AppCrane.', prUrl: row.pr_url || null }).catch(() => {});
    }
  }
});

/**
 * POST /api/enhancements/:id/set-status
 * Set status for an enhancement request. Requires admin.
 * Body: { status: 'consideration' | 'in_progress' | 'done' }
 */
router.post('/:id/set-status', requireAuth, requireAdmin, (req, res) => {
  const { status } = req.body || {};
  if (!VALID_STATUSES.includes(status)) {
    throw new AppError(`status must be one of: ${VALID_STATUSES.join(', ')}`, 400, 'VALIDATION');
  }
  const db = getDb();
  const id = parseInt(req.params.id, 10);
  const row = db.prepare('SELECT id, app_slug, message, user_name, pr_url, status FROM enhancement_requests WHERE id = ?').get(id);
  if (!row) throw new AppError('Not found', 404, 'NOT_FOUND');
  db.prepare('UPDATE enhancement_requests SET status = ? WHERE id = ?').run(status, id);
  res.json({ status });

  // v2.14.1/2: on first transition to a terminal state (done or won't-do),
  // email the requester + platform admins and close the mirrored GitHub issue.
  const terminal = status === 'done' || status === 'no_changes_needed';
  if (terminal && row.status !== status) {
    notifyRequesterFulfilled(id, req.user.id);
    if (row.app_slug) {
      const app = getAppForMirror(row.app_slug);
      if (app?.github_url) {
        const resolution = status === 'no_changes_needed' ? "Closed as won't-do in AppCrane." : 'Marked done in AppCrane.';
        closeRequest(app, { ...row, status }, { resolution, prUrl: row.pr_url || null }).catch(() => {});
      }
    }
  }
});

/**
 * GET /api/enhancements/portal
 * List all enhancement requests for the admin portal view.
 * Auth: Authorization: Bearer TOKEN (admin only)
 */
router.get('/portal', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const session = getUserFromBearer(token);
  if (!session) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');
  if (session.role !== 'admin' && session.role !== 'platform_admin') throw new AppError('Admin access required', 403, 'FORBIDDEN');

  const db = getDb();
  const rows = db.prepare(`
    SELECT
      er.id, er.app_slug, er.user_name, er.message, er.created_at, er.status,
      er.fix_version,
      j.status AS latest_job_status
    FROM enhancement_requests er
    LEFT JOIN enhancement_jobs j ON j.id = (
      SELECT id FROM enhancement_jobs WHERE enhancement_id = er.id ORDER BY id DESC LIMIT 1
    )
    ORDER BY er.created_at DESC
  `).all();
  res.json({ requests: rows });
});

/**
 * POST /api/enhancements/:id/delete
 * Delete an enhancement request. Admins can delete any request; regular
 * users can delete requests they submitted themselves. Refuses to delete
 * while a job is actively running.
 */
router.post('/:id/delete', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const session = getUserFromBearer(token);

  let userId, userRole;
  if (session) {
    userId = session.user_id;
    userRole = session.role;
  } else {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');
    const db2 = getDb();
    const user = db2.prepare('SELECT * FROM users WHERE api_key_hash = ?').get(hashApiKey(apiKey));
    if (!user) throw new AppError('Invalid API key', 401, 'UNAUTHORIZED');
    userId = user.id;
    userRole = user.role;
  }

  const db = getDb();
  const id = parseInt(req.params.id, 10);
  const row = db.prepare('SELECT id, user_id FROM enhancement_requests WHERE id = ?').get(id);
  if (!row) throw new AppError('Not found', 404, 'NOT_FOUND');

  const isAdmin = userRole === 'admin' || userRole === 'platform_admin';
  const isOwner = row.user_id && row.user_id === userId;
  if (!isAdmin && !isOwner) throw new AppError('You can only delete your own requests', 403, 'FORBIDDEN');

  const active = db.prepare("SELECT 1 FROM enhancement_jobs WHERE enhancement_id = ? AND status IN ('queued', 'running') LIMIT 1").get(id);
  if (active) throw new AppError('Cannot delete a request with an active job — wait for it to finish first', 409, 'JOB_ACTIVE');

  db.transaction(() => {
    db.prepare('DELETE FROM enhancement_jobs WHERE enhancement_id = ?').run(id);
    db.prepare('DELETE FROM enhancement_requests WHERE id = ?').run(id);
  })();
  res.json({ message: 'Deleted' });
});

// ── Comments thread (bugs / notes / reviews) ───────────────────────────
//
// Authenticates with the same Bearer-or-API-key pattern as the rest of
// this file. Read access for any authenticated user; write access for
// the request submitter or any admin (admins own the triage queue).

function resolveAuthOrThrow(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const session = getUserFromBearer(token);
  if (session) return { userId: session.user_id, userName: session.name, role: session.role };

  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE api_key_hash = ?').get(hashApiKey(apiKey));
    if (user) return { userId: user.id, userName: user.name, role: user.role };
  }
  throw new AppError('Authentication required', 401, 'UNAUTHORIZED');
}

function loadEnhOr404(id) {
  // SECURITY (v1.27.34 C3): pull app_slug too so the per-route access
  // check below knows which app gates this enhancement.
  const enh = getDb().prepare('SELECT id, user_id, app_slug FROM enhancement_requests WHERE id = ?').get(id);
  if (!enh) throw new AppError('Enhancement not found', 404, 'NOT_FOUND');
  return enh;
}

/**
 * Refuse access if the caller isn't admin and isn't assigned to enh.app_slug.
 * Mirror of appstudio.js ensureAppAccessForEnh (kept local here to avoid an
 * import cycle between routes files).
 */
function ensureAppAccessForEnh(auth, enh) {
  if (auth?.role === 'admin' || auth?.role === 'platform_admin') return;
  if (!enh?.app_slug) throw new AppError('Forbidden', 403, 'FORBIDDEN');
  const db = getDb();
  const app = db.prepare('SELECT id FROM apps WHERE slug = ?').get(enh.app_slug);
  if (!app) throw new AppError('Forbidden', 403, 'FORBIDDEN');
  const ok = db.prepare('SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?').get(app.id, auth.userId)
          || db.prepare('SELECT 1 FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, auth.userId);
  if (!ok) throw new AppError('Forbidden', 403, 'FORBIDDEN');
}

router.get('/:id/comments', (req, res) => {
  const auth = resolveAuthOrThrow(req);
  const enh = loadEnhOr404(parseInt(req.params.id, 10));
  ensureAppAccessForEnh(auth, enh);
  res.json({ comments: listComments(parseInt(req.params.id, 10)) });
});

router.post('/:id/comments', (req, res) => {
  const auth = resolveAuthOrThrow(req);
  const enhId = parseInt(req.params.id, 10);
  const enh = loadEnhOr404(enhId);
  ensureAppAccessForEnh(auth, enh);
  const { type, body } = req.body || {};
  try {
    const c = createComment(enhId, {
      type: type || 'note',
      body,
      authorUserId: auth.userId,
      authorName:   auth.userName,
    });
    res.status(201).json({ comment: c });
  } catch (e) {
    throw new AppError(e.message, 400, 'VALIDATION');
  }
});

router.patch('/:id/comments/:cid', (req, res) => {
  const auth = resolveAuthOrThrow(req);
  const enhId = parseInt(req.params.id, 10);
  const cid   = parseInt(req.params.cid, 10);
  const enh = loadEnhOr404(enhId);
  ensureAppAccessForEnh(auth, enh);
  const { status } = req.body || {};
  try {
    const c = setCommentStatus(enhId, cid, status, auth.userId);
    res.json({ comment: c });
  } catch (e) {
    if (e.message === 'comment not found') throw new AppError(e.message, 404, 'NOT_FOUND');
    throw new AppError(e.message, 400, 'VALIDATION');
  }
});

router.delete('/:id/comments/:cid', (req, res) => {
  const auth = resolveAuthOrThrow(req);
  const enhId = parseInt(req.params.id, 10);
  const cid   = parseInt(req.params.cid, 10);
  const enh = loadEnhOr404(enhId);
  ensureAppAccessForEnh(auth, enh);
  const existing = getComment(enhId, cid);
  if (!existing) throw new AppError('comment not found', 404, 'NOT_FOUND');
  // Author can delete their own; admins (admin or platform_admin) can delete anyone's.
  const isAuthor = existing.author_user_id === auth.userId;
  if (!isAuthor && auth.role !== 'admin' && auth.role !== 'platform_admin') {
    throw new AppError('Forbidden', 403, 'FORBIDDEN');
  }
  deleteComment(enhId, cid);
  res.json({ deleted: true });
});

export default router;
