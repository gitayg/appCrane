import { Router } from 'express';
import { getDb } from '../db.js';
import { hashApiKey } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';
import { auditMiddleware } from '../middleware/audit.js';
import {
  commitAndPush,
  listWorkspaceChanges,
  readWorkspaceFileForRelease,
  markReleasedInWorkspace,
} from '../services/builder/gitOps.js';
import {
  createSession,
  resumeSession,
  dispatch,
  stopDispatch,
  subscribe,
  evictApp,
} from '../services/builder/builderSession.js';
import { getContainer } from '../services/builder/appContainer.js';
import { agentCredentialKind, NO_CREDENTIAL_MESSAGE } from '../services/llm/runAgent.js';
import { usesLocalRepo, pushFilesToManagedRepo } from '../services/managedRepo.js';
import { getQueueState, subscribeQueue } from '../services/builder/appQueue.js';
import { fetchReleasesAndChangelog, renderReleasesPage } from '../services/github/releases.js';
import log from '../utils/logger.js';

const router = Router();

// Auth: accepts X-API-Key header, Bearer identity token, or query-param equivalents
// (query params used by SSE because EventSource cannot send custom headers).
router.use((req, res, next) => {
  const db = getDb();
  // A credential in the query string is written to the proxy access log, kept in
  // browser history, and sent in the Referer of anything the page then loads.
  // EventSource cannot set headers, so for SSE there is no alternative — but
  // that argument covers exactly one endpoint per router, and this promotion
  // used to run for all of them, including POSTs that ship code and evict
  // containers. Those are called with fetch(), which sets headers fine.
  const isSseRequest = req.method === 'GET' && /\/events\/?$/.test(req.path);
  if (isSseRequest) {
    if (req.query.api_key && !req.headers['x-api-key']) req.headers['x-api-key'] = req.query.api_key;
    if (req.query.token && !req.headers.authorization) req.headers.authorization = `Bearer ${req.query.token}`;
  }

  // Try X-API-Key first
  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const user = db.prepare('SELECT * FROM users WHERE api_key_hash = ?').get(hashApiKey(apiKey));
    if (user?.active) { req.user = user; return next(); }
  }

  // Try Bearer (identity session)
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (token) {
    const session = db.prepare(`
      SELECT s.*, u.id as id, u.name, u.email, u.username, u.role, u.active
      FROM identity_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
    `).get(hashApiKey(token));
    if (session?.active) { req.user = session; return next(); }
  }

  return next(new AppError('Authentication required', 401, 'UNAUTHORIZED'));
});

function getApp(slug, user) {
  const db = getDb();
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  if (!app) throw new AppError(`App '${slug}' not found`, 404, 'NOT_FOUND');
  if (user.role !== 'admin' && user.role !== 'platform_admin') {
    const assigned = db.prepare('SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?').get(app.id, user.id);
    if (!assigned) throw new AppError('You do not have access to this app', 403, 'FORBIDDEN');
  }
  return app;
}

// Builder needs a source repository it can clone. There are exactly two:
// a connected GitHub repo, or a Crane-hosted (managed, repo_backend='local')
// repo on this host. The second has github_url NULL by design, so a bare
// `!app.github_url` check refused it -- that check was the whole reason
// Builder was unavailable for Crane-hosted apps.
function assertHasSource(app) {
  if (app.github_url || usesLocalRepo(app)) return;
  throw new AppError(
    'Builder needs source code to work on: connect a GitHub repository to this app, or use a Crane-hosted app.',
    400,
    'NO_REPO',
  );
}

function getSession(sessionId, slug) {
  const db = getDb();
  const s = db.prepare('SELECT * FROM coder_sessions WHERE id = ?').get(sessionId);
  if (!s) throw new AppError('Session not found', 404, 'NOT_FOUND');
  if (s.app_slug !== slug) throw new AppError('Session does not belong to this app', 403, 'FORBIDDEN');
  return s;
}

// ── POST /api/coder/:slug/session — start a new session ─────────────────

router.post('/:slug/session', auditMiddleware('coder.start'), async (req, res) => {
  const app = getApp(req.params.slug, req.user);
  // A dispatch needs exactly ONE credential and there are three sources:
  // the caller's own Claude subscription token, the app's uploaded
  // credentials.json, or the platform ANTHROPIC_API_KEY. This used to gate on
  // the platform key alone, which refused callers who had one of the other two.
  if (agentCredentialKind({ actingUserId: req.user.id, appSlug: app.slug }) === 'none') {
    throw new AppError(NO_CREDENTIAL_MESSAGE, 503, 'NOT_CONFIGURED');
  }
  assertHasSource(app);

  const logs = [];
  const onLog = (msg) => {
    logs.push(msg);
    log.info(`[builder:${app.slug}] ${msg}`);
  };

  try {
    const sessionId = await createSession(app, req.user.id, onLog);
    res.status(201).json({ session_id: sessionId, log: logs });
  } catch (err) {
    if (err.code === 'BUILDER_OCCUPIED') {
      throw new AppError(err.message, 409, 'BUILDER_OCCUPIED');
    }
    throw err;
  }
});

// ── GET /api/coder/:slug/session — get active/latest session ─────────────

router.get('/:slug/session', (req, res) => {
  getApp(req.params.slug, req.user);
  const db = getDb();
  const session = db.prepare(`
    SELECT * FROM coder_sessions WHERE app_slug = ? ORDER BY created_at DESC LIMIT 1
  `).get(req.params.slug);
  if (!session) return res.json({ session: null });
  res.json({ session });
});

// ── GET /api/coder/:slug/session/:id — get specific session ──────────────

router.get('/:slug/session/:id', (req, res) => {
  // v2.27.0 SECURITY: getSession only proves the session belongs to this slug —
  // it says nothing about whether the CALLER may see that app. Without this
  // getApp() call (which every sibling route makes) any authenticated user
  // could read another app's coder transcript, i.e. its source-code
  // conversation. Cross-tenant reads on :slug routes are the exact bug class
  // behind the 2026 self-hosted-PaaS disclosure wave.
  getApp(req.params.slug, req.user);
  const session = getSession(req.params.id, req.params.slug);
  const db = getDb();
  const messages = db.prepare(
    "SELECT * FROM coder_session_messages WHERE session_id = ? AND role IN ('user','assistant') ORDER BY id DESC LIMIT 100"
  ).all(session.id).reverse();
  res.json({ session, messages });
});

// ── POST /api/coder/:slug/session/:id/dispatch — send a message ──────────

router.post('/:slug/session/:id/dispatch', async (req, res) => {
  getApp(req.params.slug, req.user);
  const session = getSession(req.params.id, req.params.slug);
  if (!['idle', 'active'].includes(session.status)) {
    throw new AppError(`Session is '${session.status}', must be idle to dispatch`, 400, 'WRONG_STATUS');
  }

  const { prompt } = req.body || {};
  if (!prompt?.trim()) throw new AppError('prompt is required', 400, 'VALIDATION');

  await dispatch(req.params.id, prompt.trim());
  res.json({ message: 'Dispatch started' });
});

// ── POST /api/coder/:slug/session/:id/stop — stop current dispatch ───────

router.post('/:slug/session/:id/stop', (req, res) => {
  getApp(req.params.slug, req.user);
  getSession(req.params.id, req.params.slug);
  stopDispatch(req.params.id);
  res.json({ message: 'Stopped' });
});

// ── POST /api/coder/:slug/session/:id/resume — re-start evicted session ──

router.post('/:slug/session/:id/resume', auditMiddleware('coder.resume'), async (req, res) => {
  getApp(req.params.slug, req.user);
  const session = getSession(req.params.id, req.params.slug);
  if (session.status !== 'paused') {
    throw new AppError(`Session is '${session.status}', must be paused to resume`, 400, 'WRONG_STATUS');
  }

  const logs = [];
  try {
    await resumeSession(req.params.id, (msg) => { logs.push(msg); log.info(`[builder:resume] ${msg}`); });
  } catch (err) {
    if (err.code === 'BUILDER_OCCUPIED') {
      throw new AppError(err.message, 409, 'BUILDER_OCCUPIED');
    }
    throw err;
  }
  res.json({ message: 'Session resumed', log: logs });
});

// ── POST /api/coder/:slug/session/:id/ship — commit, push, deploy sandbox

router.post('/:slug/session/:id/ship', auditMiddleware('coder.ship'), async (req, res) => {
  const app = getApp(req.params.slug, req.user);
  const session = getSession(req.params.id, req.params.slug);
  if (!['idle', 'paused'].includes(session.status)) {
    throw new AppError(`Session is '${session.status}', stop the current run before shipping`, 400, 'WRONG_STATUS');
  }
  if (!session.workspace_dir) {
    throw new AppError('Workspace not found — session may have been evicted', 400, 'NO_WORKSPACE');
  }

  const db = getDb();
  const { getPortsForSlot } = await import('../services/portAllocator.js');
  const { deployApp } = await import('../services/deployer.js');

  const summaryMsg = req.body?.message?.trim() || `coder session ${session.id.slice(0, 8)}`;
  const commitMsg  = `coder: ${summaryMsg.slice(0, 72)}`;

  const logs = [];
  const onLog = (msg) => { logs.push(msg); log.info(`[builder:ship] ${msg}`); };

  const { pushed, reason } = await commitAndPush({
    workspaceDir: session.workspace_dir,
    branchName: session.branch_name,
    commitMsg,
    onLog,
  });

  if (!pushed) {
    return res.json({ message: `Nothing to ship (${reason})`, deployed: false });
  }

  const deployRow = db.prepare(
    "INSERT INTO deployments (app_id, env, status, log) VALUES (?, 'sandbox', 'pending', ?) RETURNING id"
  ).get(app.id, `Coder ship: ${summaryMsg}`);

  const ports = getPortsForSlot(app.slot);

  db.prepare("UPDATE coder_sessions SET status = 'shipped', shipped_at = datetime('now') WHERE id = ?")
    .run(session.id);

  deployApp(deployRow.id, app, 'sandbox', ports, { preExtractedDir: session.workspace_dir })
    .catch(err => log.error(`Coder ship deploy failed for ${app.slug}: ${err.message}`));

  res.json({ message: 'Shipped to sandbox', deploy_id: deployRow.id, branch: session.branch_name });
});

// ── GET /api/coder/:slug/session/:id/changes — what the agent changed ────
//
// Working-tree changes in the session workspace against its base commit
// (HEAD), untracked files included. This is the menu POST .../release picks
// from: a path it does not list is refused there.

router.get('/:slug/session/:id/changes', (req, res) => {
  getApp(req.params.slug, req.user);
  const session = getSession(req.params.id, req.params.slug);
  if (!session.workspace_dir) {
    throw new AppError('Workspace not found — session may have been evicted', 400, 'NO_WORKSPACE');
  }
  res.json({ files: listWorkspaceChanges(session.workspace_dir) });
});

// ── POST /api/coder/:slug/session/:id/release — release selected changes ─
//
// The Crane-hosted counterpart of /ship. /ship pushes a branch to a GitHub
// remote and then deploys FROM THE WORKSPACE (preExtractedDir), so the
// deployed tree and the repository can differ. A Crane-hosted app has no
// remote at all, and its source of truth is the managed repository — so this
// route commits the selected files THROUGH that repository and lets the
// existing deploy-on-push (deployTrigger.deployAfterLocalPush, reached from
// managedRepo.pushFilesToManagedRepo) start the sandbox deploy. No deployments
// row is written here and deployApp is never called from here: one push, one
// commit, one deploy, all through the path every other managed push takes.

/**
 * The bar appcrane_push_to_managed_app enforces (mcpTools.isAppAdmin): an
 * AppCrane admin, or admin/owner on this app. Deliberately stricter than the
 * getApp() assignment check the chat routes use — being able to talk to the
 * agent is not being able to commit its work and start a deploy.
 */
function requireAppAdmin(app, user, action) {
  if (user.role === 'admin' || user.role === 'platform_admin') return;
  const row = getDb()
    .prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?')
    .get(app.id, user.id);
  if (row?.app_role === 'admin' || row?.app_role === 'owner') return;
  throw new AppError(
    `Forbidden: ${action} requires admin or app-admin role on '${app.slug}'`,
    403,
    'FORBIDDEN',
  );
}

router.post('/:slug/session/:id/release', auditMiddleware('coder.release'), async (req, res) => {
  const app = getApp(req.params.slug, req.user);
  requireAppAdmin(app, req.user, 'releasing changes');
  if (!usesLocalRepo(app)) {
    throw new AppError(
      `'${app.slug}' is not a Crane-hosted app: its source lives on GitHub, so there is no managed repository to release into. Use /ship.`,
      400,
      'NOT_CRANE_HOSTED',
    );
  }

  const session = getSession(req.params.id, req.params.slug);
  if (!['idle', 'paused'].includes(session.status)) {
    throw new AppError(`Session is '${session.status}', stop the current run before releasing`, 400, 'WRONG_STATUS');
  }
  if (!session.workspace_dir) {
    throw new AppError('Workspace not found — session may have been evicted', 400, 'NO_WORKSPACE');
  }

  const paths = req.body?.paths;
  if (!Array.isArray(paths) || paths.length === 0 || paths.some((p) => typeof p !== 'string' || !p)) {
    throw new AppError('paths must be a non-empty array of repo-relative path strings', 400, 'VALIDATION');
  }
  const duplicates = [...new Set(paths.filter((p, i) => paths.indexOf(p) !== i))];
  if (duplicates.length) {
    throw new AppError(`duplicate path(s): ${duplicates.map((p) => JSON.stringify(p)).join(', ')}`, 400, 'VALIDATION');
  }

  // The change set is authority for what MAY be released. A path outside it is
  // a caller working from a stale listing (or naming a file the agent never
  // touched), and committing it would ship something nobody chose.
  const changes = listWorkspaceChanges(session.workspace_dir);
  const byPath = new Map(changes.map((c) => [c.path, c]));
  const unknown = paths.filter((p) => !byPath.has(p));
  if (unknown.length) {
    throw new AppError(
      `not in this session's change set: ${unknown.map((p) => JSON.stringify(p)).join(', ')}. Nothing was released. GET .../changes lists what can be.`,
      400,
      'NOT_CHANGED',
    );
  }

  const summaryMsg = req.body?.message?.trim() || `coder session ${session.id.slice(0, 8)}`;
  const commitMsg = `coder: ${summaryMsg.slice(0, 72)}`;

  const files = [];
  const deletions = [];
  try {
    for (const p of paths) {
      if (byPath.get(p).status === 'deleted') deletions.push(p);
      else files.push(readWorkspaceFileForRelease(session.workspace_dir, p));
    }
  } catch (err) {
    throw new AppError(`${err.message} Nothing was released.`, 400, 'UNREADABLE_CHANGE');
  }

  let result;
  try {
    result = await pushFilesToManagedRepo(app, files, {
      deletions,
      message: commitMsg,
      actorId: req.user.id,
    });
  } catch (err) {
    // The push refuses for reasons the caller can act on and names them: a
    // .env path (ENV_FILE_IN_PUSH, 422), a deleted path that is not on the
    // branch (DELETE_PATH_NOT_FOUND, 404), an empty resulting tree
    // (EMPTY_TREE, 422). Those carry their own status/code and must reach the
    // caller as themselves rather than as a 500. Everything else the push
    // validates is a refusal too, so it becomes a 400 rather than an
    // "internal error" the caller cannot read.
    if (err.status) throw err;
    throw new AppError(err.message, 400, 'RELEASE_REFUSED');
  }

  markReleasedInWorkspace(session.workspace_dir, paths, commitMsg);
  log.info(`Coder release: ${app.slug} ${result.commit.sha.slice(0, 12)} (${files.length} file(s), ${deletions.length} deletion(s))`);

  res.json({
    commit: { sha: result.commit.sha },
    released: files.map((f) => f.path),
    deleted: [...deletions],
    deploy: result.auto_deploy ?? null,
  });
});

// ── POST /api/coder/:slug/evict — manual app-container teardown ──────────
//
// Kills the shared container for this app, deletes its workspace, and pauses
// every in-memory session bound to it. Anyone in the chat will get a
// `status=paused` event and can resume on the next dispatch.
router.post('/:slug/evict', auditMiddleware('coder.evict'), (req, res) => {
  getApp(req.params.slug, req.user);
  const evicted = evictApp(req.params.slug, `manual:${req.user.id}`);
  res.json({ evicted, message: evicted ? 'Container evicted' : 'No live container for this app' });
});

// ── GET /api/coder/:slug/container — current per-app container state ─────
router.get('/:slug/container', (req, res) => {
  getApp(req.params.slug, req.user);
  const c = getContainer(req.params.slug);
  if (!c) return res.json({ live: false });
  res.json({
    live: true,
    container_id: c.containerId,
    workspace_dir: c.workspaceDir,
    branch_name: c.branchName,
    busy: c.busy,
    last_activity_at: new Date(c.lastActivityAt).toISOString(),
    claude_session_id: c.claudeSessionId || null,
  });
});

// The release feed a Crane-hosted app has: none. Same shape
// fetchReleasesAndChangelog returns, so both the JSON consumer and
// renderReleasesPage (which already handles zero releases and an `error`
// banner) need no special case.
function craneHostedReleaseFeed() {
  return {
    repo: null,
    releases: [],
    changelog: null,
    fetchedAt: new Date().toISOString(),
    error: 'This app is Crane-hosted — its source lives on AppCrane, not GitHub, so there are no GitHub releases to show.',
  };
}

// ── GET /api/coder/:slug/releases — JSON release feed ───────────────────
//
// Returns { repo, releases, changelog, fetchedAt }. Pulls GitHub Releases
// API + raw CHANGELOG.md from the default branch on every call. The token
// stays on the host; the agent never sees it.
router.get('/:slug/releases', async (req, res, next) => {
  try {
    const app = getApp(req.params.slug, req.user);
    if (!app.github_url && !usesLocalRepo(app)) {
      return res.status(400).json({ error: 'App has no GitHub repository connected.' });
    }
    // A Crane-hosted app has no GitHub releases to fetch, and asking GitHub
    // about a repo that is not there is a request with no possible answer.
    // An empty feed says so without turning the panel into an error.
    const data = usesLocalRepo(app) ? craneHostedReleaseFeed() : await fetchReleasesAndChangelog(app);
    res.json({ ...data, app: { slug: app.slug, name: app.name, github_url: app.github_url } });
  } catch (err) { next(err); }
});

// ── GET /api/coder/:slug/releases/view — sandboxed HTML release viewer ──
//
// Returns a self-contained HTML page (CSP locked: no scripts) intended
// to be loaded inside an iframe with sandbox="allow-popups". Renders
// the release notes as markdown via a tiny in-tree renderer.
router.get('/:slug/releases/view', async (req, res, next) => {
  try {
    const app = getApp(req.params.slug, req.user);
    if (!app.github_url && !usesLocalRepo(app)) {
      res.set('Content-Type', 'text/html; charset=utf-8');
      return res.status(400).send('<p style="color:#fca5a5;font-family:sans-serif;padding:20px">App has no GitHub repository connected.</p>');
    }
    const data = usesLocalRepo(app) ? craneHostedReleaseFeed() : await fetchReleasesAndChangelog(app);
    const html = renderReleasesPage({ app, ...data });
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; font-src https: data:");
    res.send(html);
  } catch (err) { next(err); }
});

// ── GET /api/coder/:slug/queue — current per-app FIFO queue ──────────────
//
// Returns { depth, running, items[] } where running/items expose
// { id, priority, sourceType, sourceId, label, enqueuedAt }. Improve = 1,
// Builder = 2 (lower drains first; FIFO within same priority).
router.get('/:slug/queue', (req, res) => {
  getApp(req.params.slug, req.user);
  res.json(getQueueState(req.params.slug));
});

// ── GET /api/coder/:slug/session/:id/events — SSE stream ─────────────────

router.get('/:slug/session/:id/events', (req, res) => {
  getApp(req.params.slug, req.user);
  const session = getSession(req.params.id, req.params.slug);

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = (obj) => {
    res.write(`data: ${JSON.stringify(obj)}\n\n`);
  };

  // Replay recent messages from DB
  const afterId = parseInt(req.query.after || '0', 10);
  const db = getDb();
  const recent = db.prepare(
    "SELECT * FROM coder_session_messages WHERE session_id = ? AND id > ? AND role = 'system' ORDER BY id ASC LIMIT 200"
  ).all(session.id, afterId);
  for (const row of recent) {
    try { send(JSON.parse(row.content)); } catch (_) {}
  }

  // Send current status
  send({ type: 'status', status: session.status });

  const unsub = subscribe(req.params.id, send);

  req.on('close', unsub);
});

export default router;
