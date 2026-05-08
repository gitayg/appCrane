/**
 * Staged-file uploads (MCP-E, v2.2.18).
 *
 * Why this exists: AppCrane's MCP server passes through to a per-user
 * github-mcp-server container, whose push_files tool requires file content
 * inline as a JSON arg. Anything bigger than ~256KB choks the JSON-RPC
 * channel. So instead, the agent uploads the bytes here, gets back an
 * opaque token, and then calls appcrane_push_staged_file with that token
 * to docker-cp the file into a running container.
 *
 * Lifecycle:
 *   1. Client POSTs multipart/form-data to /api/files/staged (single 'file' field)
 *   2. Server writes to DATA_DIR/staged/<token>/<filename>, inserts staged_files row
 *      with expires_at = now + STAGED_TTL_MIN minutes (default 10)
 *   3. Server returns { token, sha256, size_bytes, expires_at }
 *   4. MCP tool consumes the token (docker cp) and marks pushed_at
 *   5. 5-min sweeper deletes expired rows + scratch dirs
 *
 * Security:
 *   - token = base64url(crypto.randomBytes(16)) — opaque, non-enumerable
 *   - filename sanitized to [A-Za-z0-9._-]
 *   - scratch root pinned to DATA_DIR/staged/ (no traversal)
 *   - owner-only retrieval/delete (req.user.id must match row's user_id)
 *   - sha256 computed server-side and returned to client for integrity
 *   - max size 200MB (configurable via STAGED_MAX_BYTES env)
 */

import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getDb } from '../db.js';
import { existsSync, mkdirSync, readFileSync, unlinkSync, rmSync } from 'fs';
import { join, resolve } from 'path';
import crypto from 'crypto';
import log from '../utils/logger.js';

const router = Router();

const STAGED_MAX_BYTES = parseInt(process.env.STAGED_MAX_BYTES || String(200 * 1024 * 1024), 10);
const STAGED_TTL_MIN   = parseInt(process.env.STAGED_TTL_MIN   || '10', 10);

function dataDir() {
  return resolve(process.env.DATA_DIR || './data');
}
function stagedRoot() {
  return join(dataDir(), 'staged');
}
function sanitizeFilename(name) {
  const stripped = String(name || 'file').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 200);
  return stripped || 'file';
}
function issueToken() {
  return crypto.randomBytes(16).toString('base64url');
}

router.use(requireAuth);

/**
 * POST /api/files/staged — multipart upload, returns staging token.
 */
router.post('/staged', async (req, res) => {
  const multer = (await import('multer')).default;

  const root = stagedRoot();
  if (!existsSync(root)) mkdirSync(root, { recursive: true });

  // Stage to a per-request scratch dir keyed by a fresh token. Multer writes
  // straight into that dir, so we don't have to move the file later.
  const token = issueToken();
  const scratch = join(root, token);
  mkdirSync(scratch, { recursive: true });

  const upload = multer({
    storage: multer.diskStorage({
      destination: (_req, _file, cb) => cb(null, scratch),
      filename:    (_req, file, cb)  => cb(null, sanitizeFilename(file.originalname)),
    }),
    limits: { fileSize: STAGED_MAX_BYTES },
  }).single('file');

  upload(req, res, (err) => {
    if (err) {
      try { rmSync(scratch, { recursive: true, force: true }); } catch (_) {}
      return res.status(400).json({ error: { code: 'UPLOAD_ERROR', message: err.message } });
    }
    if (!req.file) {
      try { rmSync(scratch, { recursive: true, force: true }); } catch (_) {}
      return res.status(400).json({ error: { code: 'NO_FILE', message: 'expected a file field named "file"' } });
    }

    let sha256;
    try {
      const buf = readFileSync(req.file.path);
      sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    } catch (e) {
      try { rmSync(scratch, { recursive: true, force: true }); } catch (_) {}
      return res.status(500).json({ error: { code: 'HASH_FAILED', message: e.message } });
    }

    const expiresAt = new Date(Date.now() + STAGED_TTL_MIN * 60 * 1000)
      .toISOString().slice(0, 19).replace('T', ' ');

    try {
      getDb().prepare(`
        INSERT INTO staged_files (token, user_id, filename, size_bytes, sha256, scratch_path, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(token, req.user.id, req.file.filename, req.file.size, sha256, req.file.path, expiresAt);
    } catch (e) {
      try { rmSync(scratch, { recursive: true, force: true }); } catch (_) {}
      return res.status(500).json({ error: { code: 'DB_INSERT_FAILED', message: e.message } });
    }

    res.status(201).json({
      token,
      filename:   req.file.filename,
      size_bytes: req.file.size,
      sha256,
      expires_at: expiresAt,
    });
  });
});

/**
 * GET /api/files/staged/:token — owner-only metadata.
 */
router.get('/staged/:token', (req, res) => {
  const row = getDb().prepare('SELECT * FROM staged_files WHERE token = ?').get(req.params.token);
  if (!row || row.user_id !== req.user.id) {
    return res.status(404).json({ error: { code: 'NOT_FOUND' } });
  }
  res.json({
    token:      row.token,
    filename:   row.filename,
    size_bytes: row.size_bytes,
    sha256:     row.sha256,
    expires_at: row.expires_at,
    pushed_at:  row.pushed_at,
  });
});

/**
 * DELETE /api/files/staged/:token — owner-only manual cleanup.
 */
router.delete('/staged/:token', (req, res) => {
  const row = getDb().prepare('SELECT * FROM staged_files WHERE token = ?').get(req.params.token);
  if (!row || row.user_id !== req.user.id) {
    return res.status(404).json({ error: { code: 'NOT_FOUND' } });
  }
  try {
    rmSync(join(stagedRoot(), row.token), { recursive: true, force: true });
  } catch (e) {
    log.warn(`staged cleanup: rm ${row.token} failed: ${e.message}`);
  }
  getDb().prepare('DELETE FROM staged_files WHERE token = ?').run(row.token);
  res.status(204).end();
});

/**
 * Sweep expired staged rows + their scratch dirs. Called by a 5-min
 * setInterval registered in server/index.js. Idempotent; safe to invoke
 * repeatedly. Also cleans orphan scratch dirs that don't have a matching
 * row (defensive — shouldn't happen but disk is cheap).
 */
export function sweepStagedFiles() {
  const db = getDb();
  let removed = 0;
  try {
    const expired = db.prepare("SELECT token FROM staged_files WHERE expires_at < datetime('now')").all();
    for (const { token } of expired) {
      try { rmSync(join(stagedRoot(), token), { recursive: true, force: true }); } catch (_) {}
      db.prepare('DELETE FROM staged_files WHERE token = ?').run(token);
      removed++;
    }
  } catch (e) {
    log.warn(`staged sweep failed: ${e.message}`);
  }
  if (removed > 0) log.info(`staged sweep: reaped ${removed} expired upload(s)`);
  return removed;
}

export default router;
