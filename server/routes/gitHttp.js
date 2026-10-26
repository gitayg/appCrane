import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { clientIp } from '../utils/clientIp.js';
import { assertSlug, localRepoExists } from '../services/localGit.js';
import { GIT_HTTP_LIMITS, plain, serveUploadPack } from '../services/gitHttp.js';

// git clone/fetch over HTTPS for Crane-hosted apps (managed + repo_backend
// 'local'). Read-only: pushes go through AppCrane (coder release, MCP push).
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

const PUSH_REFUSED = 'AppCrane does not accept git push. Release changes through the coder\'s Changes tab or the appcrane_push_to_managed_app MCP tool.';
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

  router.get('/:repo/info/refs', (req, res, next) => {
    const service = req.query.service;
    if (service === 'git-receive-pack') return plain(res, 403, PUSH_REFUSED);
    if (service !== 'git-upload-pack') return plain(res, 403, 'Only git smart-HTTP clone and fetch (git-upload-pack) are served here');
    next();
  }, authenticate, authorizeRepo, (req, res) => {
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
    serveUploadPack(req, res, { slug: req.gitRepo.slug, userId: req.user.id, advertise: false, limits });
  });

  router.post('/:repo/git-receive-pack', (req, res) => plain(res, 403, PUSH_REFUSED));

  router.use((req, res) => notFound(res));
  return router;
}

export default createGitHttpRouter();
