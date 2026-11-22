import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { clientIp } from '../utils/clientIp.js';
import { assertSlug, localRepoExists } from '../services/localGit.js';
import { GIT_HTTP_LIMITS, plain, serveReceivePack, serveUploadPack } from '../services/gitHttp.js';
import { isAdmin } from '../utils/roles.js';
import { roleForUserOnApp } from '../services/permissions.js';
import { viewAsRefusalMessage } from '../services/viewAs.js';
import { getDb } from '../db.js';
import log from '../utils/logger.js';

// git clone/fetch/push over HTTPS for Crane-hosted apps (managed + repo_backend
// 'local'). Clone and fetch need app access; push needs the bar every other
// commit path holds (mcpTools.isAppAdmin, coder.js requireAppAdmin): platform
// admin, or admin/owner on this app. What a push may change (fast-forward
// only, no deletions, no tag moves) is enforced in services/gitHttp.js.
// Mounted in server/index.js BEFORE express.json(), which would consume the
// binary request body.
//
// Auth is HTTP Basic because that is what git speaks: the password is the
// caller's AppCrane API key, handed to the same requireAuth the REST API uses
// (deactivated users, dhk_mcp_ scope and removed dhk_app_ keys are refused
// there). The username is ignored. Crew agent tokens are not user keys and do
// not resolve.
//
// Not found, not Crane-hosted and not yours are one indistinguishable 404, so
// the endpoint does not tell anyone which slugs exist.

const pushForbidden = (slug) => `Forbidden: pushing to '${slug}' requires admin or owner role on it (or platform admin)`;
const FAILED_AUTH_LIMIT = 30;
const FAILED_AUTH_WINDOW_MS = 15 * 60_000;

export function createGitHttpRouter({ limits = GIT_HTTP_LIMITS } = {}) {
  const router = Router();
  const failures = new Map();

  const challenge = (res, msg = 'Authentication required: username anything, password = your AppCrane API key') =>
    plain(res, 401, msg, { 'WWW-Authenticate': 'Basic realm="AppCrane", charset="UTF-8"' });
  const notFound = (res) => plain(res, 404, 'Repository not found');

  function throttled(ip) {
    const rec = failures.get(ip);
    if (!rec) return false;
    if (Date.now() > rec.resetAt) { failures.delete(ip); return false; }
    return rec.count >= FAILED_AUTH_LIMIT;
  }
  function recordFailure(ip) {
    const now = Date.now();
    const rec = failures.get(ip);
    if (!rec || now > rec.resetAt) failures.set(ip, { count: 1, resetAt: now + FAILED_AUTH_WINDOW_MS });
    else rec.count++;
    if (failures.size > 10_000) for (const [k, r] of failures) if (now > r.resetAt) failures.delete(k);
  }

  function authenticate(req, res, next) {
    const m = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(req.headers.authorization || '');
    if (!m) return challenge(res);
    const decoded = Buffer.from(m[1], 'base64').toString('utf8');
    const colon = decoded.indexOf(':');
    const key = colon >= 0 ? decoded.slice(colon + 1) : '';
    if (!key) return challenge(res);
    const ip = clientIp(req);
    if (throttled(ip)) return plain(res, 429, 'Too many failed sign-in attempts; try again later', { 'Retry-After': '900' });
    delete req.headers['x-github-token'];
    req.headers['x-api-key'] = key;
    requireAuth(req, res, (err) => {
      delete req.headers['x-api-key'];
      if (!err) return next();
      if (err.status === 401) { recordFailure(ip); return challenge(res, 'Invalid AppCrane API key'); }
      return plain(res, 403, err.message);
    });
  }

  function authorizeRepo(req, res, next) {
    const m = /^(.+)\.git$/.exec(req.params.repo || '');
    let slug = null;
    try { slug = m ? assertSlug(m[1]) : null; } catch (_) { slug = null; }
    if (!slug) return notFound(res);
    req.params.slug = slug;
    // requireAppAccess leaves the app row on req.app, which is Express's own
    // handle (req.ip reads settings through it); put that back.
    const expressApp = req.app;
    requireAppAccess(req, res, (err) => {
      const app = req.app;
      req.app = expressApp;
      if (err) return notFound(res);
      if (app.source_type !== 'managed' || app.repo_backend !== 'local' || !localRepoExists(slug)) return notFound(res);
      req.gitRepo = { slug, app };
      next();
    });
  }

  const canChangeCode = (user, app) => isAdmin(user) || ['admin', 'owner'].includes(roleForUserOnApp(user, app));

  function pushAudit(req, action, extra) {
    const { slug, app } = req.gitRepo;
    try {
      logAudit(req.user.id, app.id, action, { slug, transport: 'smart-http', ip: clientIp(req), ...extra });
    } catch (_) { /* auditing must never break a push */ }
  }

  // A member who can clone but not push gets 403 (they can see the repo); a
  // credential viewing as another role changes nothing, as on /api.
  function authorizePush(req, res, next) {
    const { slug, app } = req.gitRepo;
    if (req.view_as) {
      pushAudit(req, 'git-push-refused', { reason: 'view-as', refs: [] });
      return plain(res, 403, viewAsRefusalMessage(req.view_as));
    }
    if (!canChangeCode(req.user, app)) {
      pushAudit(req, 'git-push-refused', { reason: 'forbidden', refs: [] });
      return plain(res, 403, pushForbidden(slug));
    }
    next();
  }

  router.get('/:repo/info/refs', (req, res, next) => {
    const service = req.query.service;
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      return plain(res, 403, 'Only git smart-HTTP clone, fetch and push are served here');
    }
    next();
  }, authenticate, authorizeRepo, (req, res, next) => {
    if (req.query.service !== 'git-receive-pack') return next();
    authorizePush(req, res, () => {
      serveReceivePack(req, res, { slug: req.gitRepo.slug, userId: req.user.id, advertise: true, limits });
    });
  }, (req, res) => {
    const { slug, app } = req.gitRepo;
    try {
      logAudit(req.user.id, app.id, 'git-fetch', { slug, transport: 'smart-http', ip: clientIp(req) });
    } catch (_) { /* auditing must never break a fetch */ }
    serveUploadPack(req, res, { slug, userId: req.user.id, advertise: true, limits });
  });

  router.post('/:repo/git-upload-pack', authenticate, authorizeRepo, (req, res) => {
    if (req.headers['content-type'] !== 'application/x-git-upload-pack-request') {
      return plain(res, 415, 'Expected Content-Type application/x-git-upload-pack-request');
    }
    const { slug, app } = req.gitRepo;
    // A POST carrying a known SHA returns a pack without GET info/refs, so it needs
    // a row of its own. A clone can POST several times, hence not 'git-fetch'.
    try {
      logAudit(req.user.id, app.id, 'git-upload-pack', { slug, transport: 'smart-http', ip: clientIp(req) });
    } catch (_) { /* auditing must never break a fetch */ }
    serveUploadPack(req, res, { slug, userId: req.user.id, advertise: false, limits });
  });

  router.post('/:repo/git-receive-pack', authenticate, authorizeRepo, authorizePush, (req, res) => {
    if (req.headers['content-type'] !== 'application/x-git-receive-pack-request') {
      return plain(res, 415, 'Expected Content-Type application/x-git-receive-pack-request');
    }
    const { slug } = req.gitRepo;
    serveReceivePack(req, res, {
      slug, userId: req.user.id, advertise: false, limits,
      onDone: ({ status, reason, refs, bytes, updated = [] }) => {
        if (status === 'empty') return;
        // The same record every AppCrane managed push writes (managedRepo.js,
        // mcpTools.js), so the next deploy's supply-chain verify accepts this
        // commit. Only for the branch that deploy clones, and only once git has
        // moved it; nothing is deployed from here.
        const deployRef = `refs/heads/${req.gitRepo.app.branch || 'main'}`;
        const landed = updated.find((u) => u.ref === deployRef && /^[0-9a-f]{40}$/.test(u.sha));
        if (landed) {
          try {
            getDb().prepare('UPDATE apps SET last_managed_push_sha = ? WHERE id = ?').run(landed.sha, req.gitRepo.app.id);
          } catch (e) { log.warn(`git push to ${slug}: recording the pushed commit failed: ${e.message}`); }
        }
        pushAudit(req, status === 'updated' ? 'git-push' : 'git-push-refused', {
          outcome: status, ...(reason ? { reason } : {}), refs, bytes, ...(landed ? { recorded_push_sha: landed.sha.slice(0, 12) } : {}),
        });
      },
    });
  });

  router.use((req, res) => notFound(res));
  return router;
}

export default createGitHttpRouter();
