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

const router = Router();

const VALID_STATUSES = ['new', 'selected', 'planning', 'in_progress', 'done'];

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

  if (process.env.ANTHROPIC_API_KEY) {
    if (userRole === 'admin') {
      db.prepare("UPDATE enhancement_requests SET mode = 'auto', status = 'planning' WHERE id = ?").run(lastInsertRowid);
    } else {
      db.prepare("UPDATE enhancement_requests SET status = 'planning' WHERE id = ?").run(lastInsertRowid);
    }
    db.prepare('INSERT INTO enhancement_jobs (enhancement_id, phase) VALUES (?, ?)').run(lastInsertRowid, 'plan');
  } else {
    // Surface the missing-key state instead of silently leaving the request
    // stuck on 'new' with no job — the dashboard would otherwise show a
    // forever-spinner. The job's failed status + error_message is what the
    // /api/enhancements list response renders.
    db.prepare(
      "INSERT INTO enhancement_jobs (enhancement_id, phase, status, error_message, finished_at) VALUES (?, 'plan', 'failed', ?, datetime('now'))"
    ).run(lastInsertRowid, 'ANTHROPIC_API_KEY not configured');
  }

  res.json({ message: 'Enhancement request submitted. Thank you!', enhancement_id: lastInsertRowid });

  if (app_slug) {
    const app = getAppForMirror(app_slug);
    if (app?.github_url) {
      const row = db.prepare('SELECT id, message, user_name, status, created_at FROM enhancement_requests WHERE id = ?').get(lastInsertRowid);
      mirrorRequest(app, row).catch(() => {});
    }
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
 * GET /api/enhancements
 * List all enhancement requests. Requires admin API key.
 */
router.get('/', requireAuth, requireAdmin, (req, res) => {
  const db = getDb();
  const rows = db.prepare(`
    SELECT
      er.id, er.app_slug, er.user_name, er.message, er.created_at, er.status,
      er.fix_version, er.cost_tokens, er.cost_usd_cents, er.branch_name, er.pr_url,
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
    ORDER BY er.created_at DESC
  `).all();
  res.json({ requests: rows });
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
  const row = db.prepare('SELECT id, app_slug, message, user_name, pr_url FROM enhancement_requests WHERE id = ?').get(id);
  if (!row) throw new AppError('Not found', 404, 'NOT_FOUND');
  db.prepare('UPDATE enhancement_requests SET status = ? WHERE id = ?').run(status, id);
  res.json({ status });

  if (status === 'done' && row.app_slug) {
    const app = getAppForMirror(row.app_slug);
    if (app?.github_url) {
      closeRequest(app, { ...row, status }, { resolution: 'Marked done in AppCrane.', prUrl: row.pr_url || null }).catch(() => {});
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
  if (session.role !== 'admin') throw new AppError('Admin access required', 403, 'FORBIDDEN');

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

  const isAdmin = userRole === 'admin';
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
  if (auth?.role === 'admin') return;
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
  // Author can delete their own; admins can delete anyone's.
  const isAuthor = existing.author_user_id === auth.userId;
  if (!isAuthor && auth.role !== 'admin') {
    throw new AppError('Forbidden', 403, 'FORBIDDEN');
  }
  deleteComment(enhId, cid);
  res.json({ deleted: true });
});

export default router;
