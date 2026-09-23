import { Router } from 'express';
import { getDb } from '../db.js';
import { hashApiKey } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';
import { auditMiddleware } from '../middleware/audit.js';
import {
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
  listFollowups,
  cancelFollowup,
} from '../services/builder/builderSession.js';
import { getContainer } from '../services/builder/appContainer.js';
import { agentCredentialKind, NO_CREDENTIAL_MESSAGE } from '../services/llm/runAgent.js';
import {
  coderModelChoices,
  defaultCoderModel,
  isAllowedCoderModel,
} from '../services/llm/coderModels.js';
import { usesLocalRepo, pushFilesToManagedRepo } from '../services/managedRepo.js';
import { getQueueState } from '../services/builder/appQueue.js';
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

// The coder works on Crane-hosted apps only: source_type='managed' with
// repo_backend='local', i.e. a bare repo on this host.
//
// v2.80.0 widened this to "a GitHub URL OR a Crane-hosted app" so a managed app
// (github_url NULL by design) would stop being refused. That let a GitHub-backed
// app in as well, and the only thing it could then do with its work was
// `git push` to a remote — the path /changes + /release replaced. A session
// whose release path does not exist is worse than a refusal, so the gate is the
// same shape as /release's: Crane-hosted, or a named reason.
//
// The two refusals are kept apart on purpose. NO_REPO means "there is no source
// at all, connect one"; NOT_CRANE_HOSTED means "there is source, it is just not
// somewhere this tool works" — different problems with different fixes, and a
// UI that wants to offer a migration can branch on the second.
/**
 * Every reason the coder is unavailable for THIS user on THIS app, all at once.
 *
 * The UI used to hide the Coder button unless the app was Crane-hosted, so a
 * user on any other app never learned the feature existed, let alone what it
 * would take. And the gates below report the FIRST failure only: fix the
 * source and you meet the credential gap next, one refusal at a time.
 *
 * So this returns the whole list, from the same predicates the gates use. The
 * test in test/coder-availability.test.js pins that the two cannot disagree:
 * availability says unavailable exactly when session start refuses.
 *
 * `fix` is written for the person reading it, not for the code that raised it.
 */
export function coderGaps(app, user) {
  const gaps = [];
  const source = String(app.source_type || '');

  // repoBackendOf throws on a value it does not recognise, rather than guess
  // where the source lives. Correct for a write path; wrong here, where the
  // contract is "always answerable". A corrupt row becomes a gap the user can
  // report, not a 500 that hides the Coder button's explanation entirely.
  let hosted;
  try {
    hosted = usesLocalRepo(app);
  } catch (err) {
    gaps.push({
      code: 'UNKNOWN_SOURCE',
      title: "AppCrane can't tell where this app's code lives",
      detail: err.message,
      fix: 'Ask a platform admin to correct the app\'s repository settings.',
    });
    hosted = true; // the source question is answered (badly); still check the credential
  }

  if (!hosted) {
    if (source === 'managed') {
      gaps.push({
        code: 'REPO_NOT_MIGRATED',
        title: "This app's repository hasn't moved onto AppCrane yet",
        detail: 'AppCrane moves managed repositories onto this server automatically when it starts. '
          + 'This one was left on GitHub — usually because a branch or tag did not match exactly.',
        fix: 'Ask a platform admin to check the repository migration report, resolve the mismatch, '
          + 'and restart AppCrane so the migration runs again.',
      });
    } else if (source === 'upload' || source === 'managed_legacy') {
      gaps.push({
        code: 'NOT_CONVERTED',
        title: 'This app is still an uploaded archive',
        detail: 'AppCrane converts uploaded apps into repositories it hosts when it starts. '
          + (app.github_url
            ? 'This one names a GitHub repository, so which source it should use is left to its owner.'
            : 'This one was skipped.'),
        fix: 'Ask a platform admin to check the upload conversion report and restart AppCrane once it is resolved.',
      });
    } else if (source === 'image') {
      gaps.push({
        code: 'NO_SOURCE',
        title: 'This app runs from a container image',
        detail: 'It is deployed from a published image, so there is no source code behind it for the coder to edit.',
        fix: 'Create a Crane-hosted app from its source code to use the coder.',
      });
    } else if (app.github_url) {
      gaps.push({
        code: 'NOT_CRANE_HOSTED',
        title: "This app's code lives in your GitHub repository",
        detail: 'The coder edits code AppCrane hosts itself, so it can release changes straight to sandbox. '
          + 'It cannot edit a repository on GitHub.',
        fix: 'Create a Crane-hosted app to use the coder. Keep working on this one with your own tools.',
      });
    } else {
      gaps.push({
        code: 'NO_REPO',
        title: 'This app has no source code yet',
        detail: 'There is no repository behind it for the coder to edit.',
        fix: 'Create a Crane-hosted app to use the coder.',
      });
    }
  }

  if (agentCredentialKind({ actingUserId: user.id, appSlug: app.slug }) === 'none') {
    gaps.push({
      code: 'NO_CREDENTIAL',
      title: "You haven't connected a Claude account",
      detail: "The coder runs on your own Claude subscription, this app's stored credentials, or a platform-wide "
        + 'key. None of them is set up for you.',
      fix: 'Run `claude setup-token` and save the token in Settings → Account — or ask a platform admin to set a platform key.',
      href: '/settings#account',
    });
  }

  return gaps;
}

/** Whether `user` may release on `app` — the predicate requireAppAdmin enforces. */
function canReleaseOn(app, user) {
  if (user.role === 'admin' || user.role === 'platform_admin') return true;
  const row = getDb()
    .prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?')
    .get(app.id, user.id);
  return row?.app_role === 'admin' || row?.app_role === 'owner';
}

function assertCraneHosted(app) {
  if (usesLocalRepo(app)) return;
  if (!app.github_url) {
    throw new AppError(
      'Builder needs source code to work on: this app has none. Create a Crane-hosted app.',
      400,
      'NO_REPO',
    );
  }
  throw new AppError(
    `'${app.slug}' keeps its source on GitHub. Builder works on Crane-hosted apps only — apps whose repository lives on AppCrane itself.`,
    400,
    'NOT_CRANE_HOSTED',
  );
}

function getSession(sessionId, slug) {
  const db = getDb();
  const s = db.prepare('SELECT * FROM coder_sessions WHERE id = ?').get(sessionId);
  if (!s) throw new AppError('Session not found', 404, 'NOT_FOUND');
  if (s.app_slug !== slug) throw new AppError('Session does not belong to this app', 403, 'FORBIDDEN');
  return s;
}

// ── GET /api/coder/models — what a dispatch may ask for ──────────────────
//
// The list is served rather than hardcoded in the SPA because the two would
// drift, and they would drift ASYMMETRICALLY: a picker offering a value the
// allowlist rejects is a 400 on send, and a picker missing the value an
// operator configured hides the only model the deployment actually runs. Same
// array here and in the validator below, by construction.
//
// Declared before any '/:slug' route: Express matches in order, and a bare
// GET '/models' must not be read as a slug named "models".
router.get('/models', (req, res) => {
  res.json({ models: coderModelChoices(), default: defaultCoderModel() });
});

// ── GET /api/coder/:slug/availability — can this user use the coder here? ──
//
// Always answerable, never a refusal: the point is that a user on an app where
// the coder does not work still learns what it would take. can_release is
// reported too, so the UI can say "you can chat, but not release" up front
// rather than hiding a button that would 403.
router.get('/:slug/availability', (req, res) => {
  const app = getApp(req.params.slug, req.user);
  const gaps = coderGaps(app, req.user);
  res.json({ available: gaps.length === 0, can_release: canReleaseOn(app, req.user), gaps });
});

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
  assertCraneHosted(app);

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
  // Pending follow-ups ride along with the transcript: this is the call the
  // chat makes on every (re)connect, so it is what makes a typed-ahead message
  // survive F5.
  res.json({ session, messages, followups: listFollowups(session.id) });
});

// ── POST /api/coder/:slug/session/:id/dispatch — send a message ──────────

router.post('/:slug/session/:id/dispatch', async (req, res) => {
  getApp(req.params.slug, req.user);
  const session = getSession(req.params.id, req.params.slug);
  // 'active' and 'queued' are accepted because a message typed while a turn is
  // running is queued as a follow-up rather than refused (v2.85.0).
  // A paused session gets its own code so the panel can resume and retry the
  // same message, rather than show an error next to a pill that says idle.
  if (session.status === 'paused') {
    throw new AppError('This session is paused (its container was stopped). Resume it to continue.', 409, 'SESSION_PAUSED');
  }
  if (!['idle', 'active', 'queued'].includes(session.status)) {
    throw new AppError(`Session is '${session.status}', must be idle to dispatch`, 400, 'WRONG_STATUS');
  }

  const { prompt, model } = req.body || {};
  if (!prompt?.trim()) throw new AppError('prompt is required', 400, 'VALIDATION');

  // SECURITY — the whole reason this field is dangerous: `model` ends up in a
  // shell string built for `sh -c` inside the app container (runAgent.js
  // buildClaudeCmd). An ALLOWLIST OF EXACT STRINGS, not a pattern over
  // characters that look harmless: `sonnet; touch /tmp/pwned` passes any
  // "reasonable" regex someone writes six months from now. The quoting in
  // buildClaudeCmd is the second, independent defence.
  if (model !== undefined && model !== null && model !== '' && !isAllowedCoderModel(model)) {
    throw new AppError(
      `Unsupported model. GET /api/coder/models lists what this deployment accepts.`,
      400,
      'VALIDATION',
    );
  }

  let r;
  try {
    r = await dispatch(req.params.id, prompt.trim(), { model, userId: req.user.id });
  } catch (err) {
    if (err.code === 'SESSION_PAUSED') throw new AppError(err.message, 409, 'SESSION_PAUSED');
    throw err;
  }
  if (r?.queued) {
    return res.json({ message: 'Queued as a follow-up', queued: true, followup: r.followup });
  }
  res.json({ message: 'Dispatch started', queued: false });
});

// ── follow-up queue (typed-ahead messages for THIS session) ──────────────
//
// Distinct from GET /:slug/queue, which is the per-APP work queue (Improve
// jobs and builder turns competing for one container). These are messages the
// user typed while their own turn was still running; none of them has been
// sent to the model.

router.get('/:slug/session/:id/followups', (req, res) => {
  getApp(req.params.slug, req.user);
  getSession(req.params.id, req.params.slug);
  res.json({ followups: listFollowups(req.params.id) });
});

router.delete('/:slug/session/:id/followups/:followupId', (req, res) => {
  getApp(req.params.slug, req.user);
  getSession(req.params.id, req.params.slug);
  const id = Number(req.params.followupId);
  if (!Number.isInteger(id)) throw new AppError('followupId must be an integer', 400, 'VALIDATION');
  const cancelled = cancelFollowup(req.params.id, id);
  if (!cancelled) {
    throw new AppError('No pending follow-up with that id — it may have already started', 404, 'NOT_FOUND');
  }
  res.json({ cancelled: true, followups: listFollowups(req.params.id) });
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
  // Gated for the same reason /session is, and it is the door that was left
  // open: resume needs only a row in status 'paused', and builderSession's
  // restart recovery pauses every live session. So a row left behind by the
  // retired /api/agents -- or by /api/coder before v2.82.0 narrowed its gate --
  // could resume a GitHub-backed app into a clone path this tool no longer
  // supports, and the session would have no way to release its work.
  const app = getApp(req.params.slug, req.user);
  assertCraneHosted(app);
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

// POST /:slug/session/:id/ship is GONE (Crane-hosted-only coder).
//
// It committed the workspace and `git push`ed it to a GitHub remote, then
// deployed from the workspace. Every app this router now serves is Crane-hosted
// and has no remote, so the route could only ever answer 400. /changes +
// /release replaced it: selected
// files, committed THROUGH the managed repository, deploy started by the same
// deploy-on-push every other managed push goes through.
//
// Removed rather than left to 400, because a mounted route is code that gets
// maintained and security-patched, and this one still carried a real defect
// (it read `git status` with the default core.fileMode, so a chmod-777
// workspace made every ship commit a whole-repo mode flip).
//
// v2.83.0: the GitHub ship path is gone entirely. /api/agents — the second,
// GitHub-only coder surface that was its last reachable caller — was retired,
// and gitOps.commitAndPush went with it.

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
  send({ type: 'followups', items: listFollowups(session.id) });

  const unsub = subscribe(req.params.id, send);

  req.on('close', unsub);
});

export default router;
