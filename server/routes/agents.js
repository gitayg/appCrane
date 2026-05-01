/**
 * AIDE-compatible /api/agents surface backed by AppCrane coder sessions.
 * Clients that speak the AIDE wire format work against this backend unchanged
 * (only base-URL and auth headers differ).
 *
 * Mapping: AIDE "agent" = AppCrane coder_session
 *   agent.id   = session.id  (UUID)
 *   agent.name = app.name
 *   agent.dir  = session.workspace_dir
 */
import { Router } from 'express';
import { execFileSync } from 'child_process';
import { getDb } from '../db.js';
import { hashApiKey } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';
import { auditMiddleware } from '../middleware/audit.js';
import { commitAndPush } from '../services/builder/gitOps.js';
import {
  createSession,
  resumeSession,
  dispatch,
  stopDispatch,
  subscribe,
  getInMemorySession,
} from '../services/builder/builderSession.js';
import log from '../utils/logger.js';

const router = Router();

// ── Auth (identical to coder.js — Bearer or X-API-Key or query params for SSE) ──

router.use((req, res, next) => {
  const db = getDb();
  if (req.query.api_key && !req.headers['x-api-key']) req.headers['x-api-key'] = req.query.api_key;
  if (req.query.token && !req.headers.authorization) req.headers.authorization = `Bearer ${req.query.token}`;

  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const user = db.prepare('SELECT * FROM users WHERE api_key_hash = ?').get(hashApiKey(apiKey));
    if (user?.active) { req.user = user; return next(); }
  }

  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (token) {
    const session = db.prepare(`
      SELECT s.*, u.id as id, u.name, u.email, u.username, u.role, u.active
      FROM identity_sessions s JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ? AND s.expires_at > datetime('now')
    `).get(hashApiKey(token));
    if (session?.active) { req.user = session; return next(); }
  }

  return next(new AppError('Authentication required', 401, 'UNAUTHORIZED'));
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function getDbSession(id) {
  const db = getDb();
  const s = db.prepare('SELECT * FROM coder_sessions WHERE id = ?').get(id);
  if (!s) throw new AppError('Session not found', 404, 'NOT_FOUND');
  return s;
}

function getAppForSlug(slug) {
  const db = getDb();
  return db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
}

function requireAppAccess(app, user) {
  if (!app) throw new AppError('App not found', 404, 'NOT_FOUND');
  if (user.role === 'admin') return;
  const db = getDb();
  const row = db.prepare('SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?').get(app.id, user.id);
  if (!row) throw new AppError('You do not have access to this app', 403, 'FORBIDDEN');
}

function sessionToAgent(session, app) {
  return {
    id: session.id,
    name: app?.name || session.app_slug,
    tags: [session.app_slug],
    dir: session.workspace_dir || '',
    githubTokenName: '',
    claudeProfile: '',
    claudeModel: process.env.APPSTUDIO_CODER_MODEL || 'claude-sonnet-4-6',
    claudeArgs: '',
    autoGitPull: false,
    gitUseAideToken: false,
    tasks: [],
    notes: '',
    permissionsAlwaysAllow: {},
    env: {},
    useMCP: false,
    claudeSessionId: session.claude_session_id || null,
    manuallyFlagged: false,
    // AppCrane extensions
    appSlug: session.app_slug,
    branchName: session.branch_name,
    sessionStatus: session.status,
    costTokens: session.cost_tokens,
    costUsdCents: session.cost_usd_cents,
    createdAt: session.created_at,
    shippedAt: session.shipped_at,
  };
}

function rowToMessage(row) {
  if (row.role === 'system') return null;
  return {
    id: String(row.id),
    role: row.role === 'assistant' ? 'agent' : 'user',
    text: row.content,
    ts: Math.floor(new Date(row.created_at + 'Z').getTime()),
    tokens: row.tokens || undefined,
  };
}

// In-memory streaming text accumulator (sessionId → { text, messageId })
const _streaming = new Map();

function buildMessages(sessionId) {
  const db = getDb();
  const rows = db.prepare(
    "SELECT * FROM coder_session_messages WHERE session_id = ? AND role IN ('user','assistant') ORDER BY id ASC"
  ).all(sessionId);
  const msgs = rows.map(rowToMessage).filter(Boolean);

  const s = _streaming.get(sessionId);
  if (s?.text) {
    msgs.push({ id: s.messageId, role: 'agent', text: s.text, ts: Date.now(), streaming: true });
  }
  return msgs;
}

function buildStatus(sessionId, lastError = null) {
  const inMem = getInMemorySession(sessionId);
  const isStreaming = !!(inMem?.runner?.isActive?.());
  const workspaceDir = inMem?.workspaceDir;

  let hasUncommittedChanges = false, uncommittedCount = 0;
  if (workspaceDir) {
    try {
      const out = execFileSync('git', [
        '-c', `safe.directory=${workspaceDir}`, '-C', workspaceDir, 'status', '--short',
      ], { stdio: 'pipe', timeout: 5000 }).toString().trim();
      const lines = out ? out.split('\n').filter(Boolean) : [];
      hasUncommittedChanges = lines.length > 0;
      uncommittedCount = lines.length;
    } catch (_) {}
  }

  return { isStreaming, queuedTasks: [], hasUncommittedChanges, uncommittedCount, lastError };
}

// ── GET /api/agents — list sessions user can access ───────────────────────────

router.get('/', (req, res) => {
  const db = getDb();
  let rows;
  if (req.user.role === 'admin') {
    rows = db.prepare(`
      SELECT cs.*, a.name as app_name FROM coder_sessions cs
      LEFT JOIN apps a ON a.slug = cs.app_slug
      WHERE cs.status NOT IN ('error') ORDER BY cs.created_at DESC LIMIT 50
    `).all();
  } else {
    rows = db.prepare(`
      SELECT cs.*, a.name as app_name FROM coder_sessions cs
      LEFT JOIN apps a ON a.slug = cs.app_slug
      LEFT JOIN app_users au ON au.app_id = a.id AND au.user_id = ?
      WHERE cs.user_id = ? OR au.user_id = ?
      AND cs.status NOT IN ('error') ORDER BY cs.created_at DESC LIMIT 50
    `).all(req.user.id, req.user.id, req.user.id);
  }
  res.json(rows.map(r => sessionToAgent(r, { name: r.app_name, slug: r.app_slug })));
});

// ── GET /api/health ───────────────────────────────────────────────────────────

router.get('/health', (req, res) => {
  res.json({ ok: true, version: process.env.npm_package_version || '1.x' });
});

// ── GET /api/agents/apps — apps with embedded session + health context ────────

router.get('/apps', (req, res) => {
  const db = getDb();
  let apps;
  if (req.user.role === 'admin') {
    apps = db.prepare('SELECT * FROM apps ORDER BY name ASC').all();
  } else {
    apps = db.prepare(`
      SELECT a.* FROM apps a
      WHERE a.id IN (SELECT app_id FROM app_users WHERE user_id = ?)
      ORDER BY a.name ASC
    `).all(req.user.id);
  }

  const enriched = apps.map(app => {
    const session = db.prepare(
      "SELECT id, status, branch_name, created_at, shipped_at FROM coder_sessions " +
      "WHERE app_slug = ? AND status NOT IN ('error') ORDER BY created_at DESC LIMIT 1"
    ).get(app.slug);

    const healthProd = db.prepare('SELECT is_down, last_status FROM health_state WHERE app_id = ? AND env = ?').get(app.id, 'production');
    const healthSand = db.prepare('SELECT is_down, last_status FROM health_state WHERE app_id = ? AND env = ?').get(app.id, 'sandbox');

    const lastDeployProd = db.prepare(
      'SELECT version, status, finished_at FROM deployments WHERE app_id = ? AND env = ? ORDER BY started_at DESC LIMIT 1'
    ).get(app.id, 'production');

    const healthLabel = (h) => !h ? 'unknown' : h.is_down ? 'down' : h.last_status === 200 ? 'healthy' : 'unknown';

    return {
      id: app.id,
      name: app.name,
      slug: app.slug,
      description: app.description || null,
      github_url: app.github_url || null,
      source_type: app.source_type || 'github',
      category: app.category || null,
      production: {
        health: { status: healthLabel(healthProd) },
        deploy: lastDeployProd || null,
      },
      sandbox: {
        health: { status: healthLabel(healthSand) },
      },
      currentSession: session ? {
        id: session.id,
        status: session.status,
        branchName: session.branch_name,
        createdAt: session.created_at,
        shippedAt: session.shipped_at,
      } : null,
    };
  });

  res.json(enriched);
});

// ── POST /api/agents — create session for an app ─────────────────────────────

router.post('/', auditMiddleware('agents.create'), async (req, res) => {
  const { name: appSlug } = req.body || {};
  if (!appSlug?.trim()) throw new AppError('name (app slug) is required', 400, 'VALIDATION');
  if (!process.env.ANTHROPIC_API_KEY) throw new AppError('ANTHROPIC_API_KEY not configured', 503, 'NOT_CONFIGURED');

  const app = getAppForSlug(appSlug.trim());
  requireAppAccess(app, req.user);
  if (!app.github_url) throw new AppError('App must have a GitHub URL to use Studio', 400, 'NO_GITHUB');

  const logs = [];
  const sessionId = await createSession(app, req.user.id, (msg) => { logs.push(msg); log.info(`[studio] ${msg}`); });

  const db = getDb();
  const session = db.prepare('SELECT * FROM coder_sessions WHERE id = ?').get(sessionId);
  res.status(201).json(sessionToAgent(session, app));
});

// ── GET /api/agents/:id ───────────────────────────────────────────────────────

router.get('/:id', (req, res) => {
  const session = getDbSession(req.params.id);
  const app = getAppForSlug(session.app_slug);
  requireAppAccess(app, req.user);
  res.json(sessionToAgent(session, app));
});

// ── PATCH /api/agents/:id ─────────────────────────────────────────────────────

router.patch('/:id', (req, res) => {
  const session = getDbSession(req.params.id);
  requireAppAccess(getAppForSlug(session.app_slug), req.user);
  // notes is the only meaningful AIDE field to persist
  if (typeof req.body.notes === 'string') {
    getDb().prepare('UPDATE coder_sessions SET last_activity_at = datetime("now") WHERE id = ?').run(session.id);
  }
  const updated = getDb().prepare('SELECT * FROM coder_sessions WHERE id = ?').get(session.id);
  res.json(sessionToAgent(updated, getAppForSlug(session.app_slug)));
});

// ── DELETE /api/agents/:id ────────────────────────────────────────────────────

router.delete('/:id', auditMiddleware('agents.delete'), (req, res) => {
  const session = getDbSession(req.params.id);
  requireAppAccess(getAppForSlug(session.app_slug), req.user);
  stopDispatch(session.id);
  getDb().prepare("UPDATE coder_sessions SET status = 'paused', container_id = NULL WHERE id = ?").run(session.id);
  res.sendStatus(204);
});

// ── GET /api/agents/:id/messages ──────────────────────────────────────────────

router.get('/:id/messages', (req, res) => {
  const session = getDbSession(req.params.id);
  requireAppAccess(getAppForSlug(session.app_slug), req.user);
  res.json(buildMessages(session.id));
});

// ── POST /api/agents/:id/dispatch ────────────────────────────────────────────

router.post('/:id/dispatch', async (req, res) => {
  const session = getDbSession(req.params.id);
  requireAppAccess(getAppForSlug(session.app_slug), req.user);
  if (!['idle', 'paused'].includes(session.status) && session.status !== 'active') {
    throw new AppError(`Session is '${session.status}'`, 400, 'WRONG_STATUS');
  }

  const { text, planMode } = req.body || {};
  if (!text?.trim()) throw new AppError('text is required', 400, 'VALIDATION');

  await dispatch(session.id, text.trim());
  res.json({ queued: false });
});

// ── POST /api/agents/:id/stop ─────────────────────────────────────────────────

router.post('/:id/stop', (req, res) => {
  const session = getDbSession(req.params.id);
  requireAppAccess(getAppForSlug(session.app_slug), req.user);
  stopDispatch(session.id);
  res.sendStatus(204);
});

// ── POST /api/agents/:id/resume ───────────────────────────────────────────────

router.post('/:id/resume', auditMiddleware('agents.resume'), async (req, res) => {
  const session = getDbSession(req.params.id);
  requireAppAccess(getAppForSlug(session.app_slug), req.user);
  if (session.status !== 'paused') throw new AppError(`Session is '${session.status}', must be paused`, 400, 'WRONG_STATUS');
  await resumeSession(session.id, (msg) => log.info(`[studio:resume] ${msg}`));
  const updated = getDb().prepare('SELECT * FROM coder_sessions WHERE id = ?').get(session.id);
  res.json(sessionToAgent(updated, getAppForSlug(session.app_slug)));
});

// ── POST /api/agents/:id/ship-sandbox ────────────────────────────────────────

router.post('/:id/ship-sandbox', auditMiddleware('agents.ship'), async (req, res) => {
  const session = getDbSession(req.params.id);
  const app = getAppForSlug(session.app_slug);
  requireAppAccess(app, req.user);
  if (!['idle', 'paused'].includes(session.status)) {
    throw new AppError('Stop the current run before shipping', 400, 'WRONG_STATUS');
  }
  if (!session.workspace_dir) throw new AppError('Workspace not available', 400, 'NO_WORKSPACE');

  const summaryMsg = req.body?.message?.trim() || `studio session ${session.id.slice(0, 8)}`;
  const logs = [];
  const onLog = (m) => { logs.push(m); log.info(`[studio:ship] ${m}`); };

  const { pushed, reason } = await commitAndPush({
    workspaceDir: session.workspace_dir,
    branchName: session.branch_name,
    commitMsg: `studio: ${summaryMsg.slice(0, 72)}`,
    onLog,
  });

  if (!pushed) return res.json({ message: `Nothing to ship (${reason})`, deployed: false });

  const db = getDb();
  const { getPortsForSlot } = await import('../services/portAllocator.js');
  const { deployApp } = await import('../services/deployer.js');

  const deployRow = db.prepare(
    "INSERT INTO deployments (app_id, env, status, log) VALUES (?, 'sandbox', 'pending', ?) RETURNING id"
  ).get(app.id, `Studio ship: ${summaryMsg}`);

  db.prepare("UPDATE coder_sessions SET status = 'shipped', shipped_at = datetime('now') WHERE id = ?")
    .run(session.id);

  deployApp(deployRow.id, app, 'sandbox', getPortsForSlot(app.slot), { preExtractedDir: session.workspace_dir })
    .catch(err => log.error(`Studio ship deploy failed for ${app.slug}: ${err.message}`));

  res.json({ message: 'Shipped to sandbox', deploy_id: deployRow.id, branch: session.branch_name, log: logs });
});

// ── POST /api/agents/:id/promote-prod ────────────────────────────────────────

router.post('/:id/promote-prod', auditMiddleware('agents.promote'), async (req, res) => {
  const session = getDbSession(req.params.id);
  const app = getAppForSlug(session.app_slug);
  requireAppAccess(app, req.user);
  if (!session.workspace_dir) throw new AppError('Workspace not available', 400, 'NO_WORKSPACE');

  const db = getDb();
  const { getPortsForSlot } = await import('../services/portAllocator.js');
  const { deployApp } = await import('../services/deployer.js');

  const deployRow = db.prepare(
    "INSERT INTO deployments (app_id, env, status, log) VALUES (?, 'production', 'pending', ?) RETURNING id"
  ).get(app.id, `Studio promote from session ${session.id.slice(0, 8)}`);

  deployApp(deployRow.id, app, 'production', getPortsForSlot(app.slot), { preExtractedDir: session.workspace_dir })
    .catch(err => log.error(`Studio promote failed for ${app.slug}: ${err.message}`));

  res.json({ message: 'Production deploy started', deploy_id: deployRow.id });
});

// ── GET /api/agents/:id/git/status ───────────────────────────────────────────

router.get('/:id/git/status', (req, res) => {
  const session = getDbSession(req.params.id);
  requireAppAccess(getAppForSlug(session.app_slug), req.user);
  const workspaceDir = session.workspace_dir;
  if (!workspaceDir) return res.json({ uncommitted: [], branch: session.branch_name, ahead: 0, behind: 0 });

  try {
    const git = (args) => execFileSync('git',
      ['-c', `safe.directory=${workspaceDir}`, '-C', workspaceDir, ...args],
      { stdio: 'pipe', timeout: 10000 }).toString().trim();

    const branch  = (() => { try { return git(['branch', '--show-current']); } catch (_) { return session.branch_name; } })();
    const statusOut = (() => { try { return git(['status', '--short']); } catch (_) { return ''; } })();
    const uncommitted = statusOut ? statusOut.split('\n').filter(Boolean) : [];

    let ahead = 0, behind = 0;
    try {
      const rev = git(['rev-list', '--count', '--left-right', 'HEAD...@{u}']);
      const parts = rev.split('\t').map(Number);
      ahead = parts[0] || 0; behind = parts[1] || 0;
    } catch (_) {}

    res.json({ uncommitted, branch, ahead, behind });
  } catch (err) {
    res.json({ uncommitted: [], branch: session.branch_name, ahead: 0, behind: 0, error: err.message });
  }
});

// ── GET /api/agents/:id/git/diff ─────────────────────────────────────────────

router.get('/:id/git/diff', (req, res) => {
  const session = getDbSession(req.params.id);
  requireAppAccess(getAppForSlug(session.app_slug), req.user);
  if (!session.workspace_dir) return res.type('text/plain').send('');

  try {
    const diff = execFileSync('git',
      ['-c', `safe.directory=${session.workspace_dir}`, '-C', session.workspace_dir,
       'diff', 'HEAD'],
      { stdio: 'pipe', timeout: 15000 }).toString();
    res.type('text/plain').send(diff);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/agents/:id/events — SSE (AIDE named-event format) ───────────────

router.get('/:id/events', (req, res) => {
  const session = getDbSession(req.params.id);
  requireAppAccess(getAppForSlug(session.app_slug), req.user);

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const sid = session.id;
  const send = (eventName, data) => {
    try { res.write(`event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`); } catch (_) {}
  };

  // Initial state
  send('messages', buildMessages(sid));
  send('status', buildStatus(sid));

  const unsub = subscribe(sid, (ev) => {
    if (ev.type === 'stream' && ev.event?.type === 'text') {
      const s = _streaming.get(sid) || { text: '', messageId: `s-${Date.now()}` };
      s.text += ev.event.text;
      _streaming.set(sid, s);
      send('messages', buildMessages(sid));
    } else if (ev.type === 'status') {
      if (ev.status === 'idle') {
        _streaming.delete(sid);
        send('messages', buildMessages(sid));
      }
      send('status', buildStatus(sid, ev.lastError));
    } else if (ev.type === 'error') {
      _streaming.delete(sid);
      send('messages', buildMessages(sid));
      send('status', buildStatus(sid, ev.message));
    }
  });

  const heartbeat = setInterval(() => { try { res.write(': heartbeat\n\n'); } catch (_) {} }, 25000);
  req.on('close', () => { clearInterval(heartbeat); unsub(); });
});

// ── Misc (tools / tokens / master-claude — stubs for API compat) ──────────────

router.get('/tools', (req, res) => res.json([]));
router.get('/tokens', (req, res) => res.json({ names: [] }));
router.get('/master-claude', (req, res) => res.json({ content: '' }));
router.put('/master-claude', (req, res) => res.json({ ok: true }));

export default router;
