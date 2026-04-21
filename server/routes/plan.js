import { Router } from 'express';
import { getDb } from '../db.js';
import { hashApiKey } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';

const router = Router();

function resolveUser(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (token) {
    const db = getDb();
    const session = db.prepare(`
      SELECT s.*, u.id as user_id, u.name, u.role
      FROM identity_sessions s JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ? AND s.expires_at > datetime('now')
    `).get(hashApiKey(token));
    if (session) return { userId: session.user_id, userName: session.name, role: session.role };
  }
  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE api_key_hash = ?').get(hashApiKey(apiKey));
    if (user && user.active) return { userId: user.id, userName: user.name, role: user.role };
  }
  return null;
}

function getEnhancement(id, user) {
  const db = getDb();
  const enh = db.prepare('SELECT * FROM enhancement_requests WHERE id = ?').get(id);
  if (!enh) throw new AppError('Enhancement not found', 404, 'NOT_FOUND');
  if (enh.user_id !== user.userId && user.role !== 'admin') throw new AppError('Access denied', 403, 'FORBIDDEN');
  return enh;
}

// GET /api/plan/:enhancementId — get current plan status
router.get('/:enhancementId', (req, res) => {
  const user = resolveUser(req);
  if (!user) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');
  const id = parseInt(req.params.enhancementId, 10);
  if (isNaN(id)) throw new AppError('Invalid enhancement id', 400, 'VALIDATION');

  const enh = getEnhancement(id, user);
  const db = getDb();
  const job = db.prepare(`
    SELECT id, phase, status, output_json, error_message, created_at
    FROM enhancement_jobs
    WHERE enhancement_id = ? AND phase IN ('plan', 'revise_plan')
    ORDER BY id DESC LIMIT 1
  `).get(id);

  let jobOutput = null;
  if (job?.output_json) { try { jobOutput = JSON.parse(job.output_json); } catch (_) {} }

  res.json({
    id: enh.id,
    status: enh.status,
    message: enh.message,
    plan: enh.ai_plan_json ? (() => { try { return JSON.parse(enh.ai_plan_json); } catch (_) { return null; } })() : null,
    job: job ? { id: job.id, phase: job.phase, status: job.status, output: jobOutput, error: job.error_message } : null,
  });
});

// GET /api/plan/:enhancementId/stream — SSE stream of plan job progress
router.get('/:enhancementId/stream', (req, res) => {
  const user = resolveUser(req);
  if (!user) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');
  const id = parseInt(req.params.enhancementId, 10);
  if (isNaN(id)) throw new AppError('Invalid enhancement id', 400, 'VALIDATION');

  getEnhancement(id, user); // access check only

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.write(': connected\n\n');

  let lastText = '';
  let lastJobId = null;
  let done = false;

  const keepalive = setInterval(() => { try { res.write(': ping\n\n'); } catch (_) {} }, 20000);

  const poll = setInterval(() => {
    if (done) return;
    try {
      const db = getDb();
      const job = db.prepare(`
        SELECT id, status, output_json, error_message
        FROM enhancement_jobs WHERE enhancement_id = ? AND phase IN ('plan', 'revise_plan')
        ORDER BY id DESC LIMIT 1
      `).get(id);

      if (!job) return;

      if (lastJobId !== null && job.id !== lastJobId) lastText = '';
      lastJobId = job.id;

      if (job.status === 'queued') return;

      if (job.status === 'running') {
        let output = null;
        try { output = job.output_json ? JSON.parse(job.output_json) : null; } catch (_) {}
        if (output?.streaming && output.text && output.text !== lastText) {
          lastText = output.text;
          res.write(`data: ${JSON.stringify({ type: 'progress', text: output.text })}\n\n`);
        }
        return;
      }

      done = true;
      clearInterval(poll);
      clearInterval(keepalive);

      if (job.status === 'done') {
        const enh = db.prepare('SELECT ai_plan_json FROM enhancement_requests WHERE id = ?').get(id);
        let plan = null;
        try { plan = enh?.ai_plan_json ? JSON.parse(enh.ai_plan_json) : null; } catch (_) {}
        res.write(`data: ${JSON.stringify({ type: 'plan', plan })}\n\n`);
      } else {
        res.write(`data: ${JSON.stringify({ type: 'error', message: job.error_message || 'Planning failed' })}\n\n`);
      }
      res.end();
    } catch (err) {
      log.error(`Plan stream poll error: ${err.message}`);
    }
  }, 2000);

  req.on('close', () => {
    done = true;
    clearInterval(poll);
    clearInterval(keepalive);
  });
});

// POST /api/plan/:enhancementId/feedback — send refinement feedback, re-queue plan
router.post('/:enhancementId/feedback', (req, res) => {
  const user = resolveUser(req);
  if (!user) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');
  const id = parseInt(req.params.enhancementId, 10);
  if (isNaN(id)) throw new AppError('Invalid enhancement id', 400, 'VALIDATION');

  const enh = getEnhancement(id, user);
  const { comment } = req.body || {};
  if (!comment?.trim()) throw new AppError('comment is required', 400, 'VALIDATION');

  const db = getDb();
  const field = user.role === 'admin' ? 'admin_comments' : 'user_comments';
  const existing = enh[field] || '';
  const updated = existing + `\n[${new Date().toISOString()}] ${comment.trim()}`;

  db.prepare(`UPDATE enhancement_requests SET ${field} = ?, status = 'planning' WHERE id = ?`).run(updated, id);
  db.prepare('INSERT INTO enhancement_jobs (enhancement_id, phase) VALUES (?, ?)').run(id, 'revise_plan');

  res.json({ message: 'Feedback submitted, re-planning queued' });
});

// POST /api/plan/:enhancementId/build — approve plan and trigger build
router.post('/:enhancementId/build', (req, res) => {
  const user = resolveUser(req);
  if (!user) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');
  const id = parseInt(req.params.enhancementId, 10);
  if (isNaN(id)) throw new AppError('Invalid enhancement id', 400, 'VALIDATION');

  const enh = getEnhancement(id, user);
  if (!enh.ai_plan_json) throw new AppError('No plan available to build', 400, 'NO_PLAN');

  const db = getDb();

  if (user.role === 'admin') {
    db.prepare("UPDATE enhancement_requests SET status = 'plan_approved' WHERE id = ?").run(id);
    db.prepare('INSERT INTO enhancement_jobs (enhancement_id, phase) VALUES (?, ?)').run(id, 'code');
    res.json({ message: 'Build queued', auto: true });
  } else {
    db.prepare("UPDATE enhancement_requests SET status = 'selected' WHERE id = ?").run(id);
    res.json({ message: 'Plan submitted for admin approval', auto: false });
  }
});

export default router;
