import { Router } from 'express';
import crypto from 'crypto';
import { getDb } from '../db.js';
import { requireAuth, requireAdmin, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware, logAudit } from '../middleware/audit.js';
import { getNextSlot, getPortsForSlot } from '../services/portAllocator.js';
import { encrypt, generateApiKey, hashApiKey } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';
import { resolveSafe } from '../utils/paths.js';
import { reloadCaddy } from '../services/caddy.js';
import { validateBypassPaths } from '../utils/authBypassPaths.js';
import { userHasAppPermission, userHasPlatformPermission, roleForUserOnApp } from '../services/permissions.js';
import { isAdmin } from '../utils/roles.js';
import log from '../utils/logger.js';
import { existsSync, mkdirSync, renameSync, unlinkSync } from 'fs';
import { join } from 'path';
import { reconcileOrphanedApps } from '../services/reconcile.js';

const router = Router();

// Owners we know can't be real GitHub accounts. Catches the placeholder
// patterns (e.g. github.com/local/foo) the 2026-05-02 triage flagged on
// `healthchampion`.
const PLACEHOLDER_GH_OWNERS = new Set([
  'local', 'localhost', 'example', 'test', 'placeholder', 'todo', 'tbd', 'unknown',
]);

function validateGithubUrl(url) {
  if (!/^https:\/\//.test(url)) {
    throw new AppError('github_url must use HTTPS', 400, 'VALIDATION');
  }
  const m = url.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+?)(\.git)?\/?$/);
  if (!m) {
    throw new AppError('github_url must look like https://github.com/owner/repo[.git]', 400, 'VALIDATION');
  }
  if (PLACEHOLDER_GH_OWNERS.has(m[1].toLowerCase())) {
    throw new AppError(
      `github_url owner "${m[1]}" looks like a placeholder — use the real GitHub repo URL`,
      400, 'VALIDATION',
    );
  }
}

/**
 * Returns a list of apps whose github_url is missing, malformed, or uses a
 * known placeholder owner. Used by the admin triage page to surface rows
 * that slipped past validation in earlier versions of this service.
 */
function listSuspiciousGithubUrls() {
  const db = getDb();
  const rows = db.prepare('SELECT id, slug, name, github_url FROM apps').all();
  return rows.filter(r => {
    const u = r.github_url;
    if (!u) return false; // empty is OK — app simply has no repo
    try { validateGithubUrl(u); return false; } catch { return true; }
  });
}

const ICON_EXTS = ['png', 'jpg', 'jpeg', 'webp', 'gif', 'svg'];
function hasIconFile(slug) {
  const dir = join(process.env.DATA_DIR || './data', 'apps', slug);
  return ICON_EXTS.some(ext => existsSync(join(dir, `icon.${ext}`)));
}

router.use(requireAuth);

/**
 * GET /api/apps - List apps.
 *
 * v2.6.7: visibility rules:
 *   - admin / platform_admin → every app
 *   - other authed users     → every app EXCEPT visibility='hidden'.
 *                              That's both the apps they have a role on
 *                              and the ones they don't — the latter
 *                              render as "Request access" tiles in the
 *                              Launcher. Public apps openable for all,
 *                              private apps openable only if the user
 *                              has an explicit role row
 *
 * The previous query only returned assigned apps, which meant a brand-
 * new user with no assignments saw an empty Launcher and no way to
 * discover what was available. Per the user direction: "if user is
 * able to access the system he should see discoverable apps (to request
 * access), public apps, private apps that he is user or an admin."
 *
 * Hidden apps still stay invisible to non-admins.
 */
router.get('/', (req, res) => {
  const db = getDb();
  let apps;

  if (isAdmin(req.user)) {
    apps = db.prepare('SELECT * FROM apps ORDER BY created_at DESC').all();
  } else {
    apps = db.prepare(`
      SELECT a.* FROM apps a
      WHERE a.visibility != 'hidden'
      ORDER BY a.created_at DESC
    `).all();
  }

  // v2.6.7: per-user role on every returned app, so the Launcher can
  // decide whether the user can open the app or needs to request
  // access. Batch-fetched up front to avoid N+1 query per app row.
  // For admins, role is implicitly 'admin' on every app via the global
  // gate — we still surface it so the SPA doesn't have to special-case.
  const userRolesBySlug = new Map();
  if (!isAdmin(req.user)) {
    const rows = db.prepare(`
      SELECT a.slug, aur.app_role
      FROM app_user_roles aur
      JOIN apps a ON a.id = aur.app_id
      WHERE aur.user_id = ?
    `).all(req.user.id);
    for (const r of rows) userRolesBySlug.set(r.slug, r.app_role);
  }
  function userAppRole(app) {
    if (isAdmin(req.user)) return 'admin';                       // global admins everywhere
    const explicit = userRolesBySlug.get(app.slug);
    if (explicit && explicit !== 'none') return explicit;         // 'user' / 'admin' / 'owner'
    if (app.visibility === 'public') return 'viewer';             // public apps openable by anyone
    return 'none';                                                 // discoverable: needs request access
  }

  // Enrich with ports and health status
  const enriched = apps.map(app => {
    const ports = getPortsForSlot(app.slot);

    const healthProd = db.prepare('SELECT * FROM health_state WHERE app_id = ? AND env = ?').get(app.id, 'production');
    const healthSand = db.prepare('SELECT * FROM health_state WHERE app_id = ? AND env = ?').get(app.id, 'sandbox');

    const lastDeployProd = db.prepare(
      'SELECT version, status, finished_at FROM deployments WHERE app_id = ? AND env = ? ORDER BY started_at DESC LIMIT 1'
    ).get(app.id, 'production');
    const lastDeploySand = db.prepare(
      'SELECT version, status, finished_at FROM deployments WHERE app_id = ? AND env = ? ORDER BY started_at DESC LIMIT 1'
    ).get(app.id, 'sandbox');

    // Get assigned users
    const users = db.prepare(`
      SELECT u.id, u.name, u.email FROM users u
      JOIN app_users au ON u.id = au.user_id
      WHERE au.app_id = ?
    `).all(app.id);

    // The owner of the app — single row from app_user_roles (multiple owners
    // shouldn't exist by design, but if they do we surface the first by id).
    // null when the owner record was never created (e.g. apps from before
    // migration 048 fixed the latent CHECK bug, or apps whose creator was
    // deleted leaving created_by NULL).
    const ownerRow = db.prepare(`
      SELECT u.id, u.name, u.email FROM users u
      JOIN app_user_roles aur ON aur.user_id = u.id
      WHERE aur.app_id = ? AND aur.app_role = 'owner'
      ORDER BY u.id LIMIT 1
    `).get(app.id);

    const craneDomain = process.env.CRANE_DOMAIN;
    const urls = craneDomain ? {
      production: `https://${craneDomain}/${app.slug}`,
      sandbox: `https://${craneDomain}/${app.slug}-sandbox`,
    } : null;

    return {
      ...app,
      resource_limits: JSON.parse(app.resource_limits || '{}'),
      has_icon: hasIconFile(app.slug),
      // Boolean flags derived from secret-bearing columns so the UI can
      // show "this app has its own X" without ever shipping the secret.
      has_claude_credentials: !!app.claude_credentials_encrypted,
      has_github_token:       !!app.github_token_encrypted,
      // v2.6.7: per-user role on this app from the caller's perspective.
      // 'admin' / 'owner' / 'user' / 'viewer' / 'none'.
      app_role: userAppRole(app),
      ...(isAdmin(req.user) ? { ports } : {}),
      owner: ownerRow || null,
      urls,
      base_path: { production: `/${app.slug}/`, sandbox: `/${app.slug}-sandbox/` },
      production: {
        health: healthProd ? { status: healthProd.is_down ? 'down' : (healthProd.last_status === 200 ? 'healthy' : 'unknown'), last_check: healthProd.last_check_at, response_ms: healthProd.last_response_ms } : { status: 'unknown' },
        deploy: lastDeployProd || null,
      },
      sandbox: {
        health: healthSand ? { status: healthSand.is_down ? 'down' : (healthSand.last_status === 200 ? 'healthy' : 'unknown'), last_check: healthSand.last_check_at, response_ms: healthSand.last_response_ms } : { status: 'unknown' },
        deploy: lastDeploySand || null,
      },
      users,
    };
  });

  res.json({ apps: enriched });
});

/**
 * POST /api/apps - Create app (any authenticated user, auto-assigns creator)
 */
router.post('/', requireAuth, auditMiddleware('app-create'), async (req, res) => {
  // v2.7.0: app creation is gated by the configurable platform.create_app
  // permission instead of plain requireAuth. Global admins always pass;
  // plain users pass only if a platform admin granted the `user` tier at
  // /settings#roles. Closes the old gap where any authenticated key could
  // create apps via the API while the dashboard button was admin-only.
  if (!userHasPlatformPermission(req.user, 'platform.create_app')) {
    throw new AppError('You do not have permission to create apps.', 403, 'FORBIDDEN');
  }

  const { name, slug, domain, description, category, source_type, github_url, branch, github_token, max_ram_mb, max_cpu_percent } = req.body;

  if (!name || !slug) throw new AppError('Name and slug are required', 400, 'VALIDATION');
  if (!/^[a-z0-9][a-z0-9-]*$/.test(slug)) throw new AppError('Slug must be lowercase alphanumeric with dashes', 400, 'VALIDATION');
  if (github_url) validateGithubUrl(github_url);
  // SECURITY: same regex as PUT — branch flows into `sh -c` calls.
  if (branch && !/^[A-Za-z0-9._/\-]{1,200}$/.test(branch)) {
    throw new AppError('branch must be alphanumeric with . _ / - (max 200 chars)', 400, 'VALIDATION');
  }
  // v2.3.1: 'upload' is dead. Only 'github' (user/external repo) and
  // 'managed' (service-account-owned repo) are valid for new apps.
  // 'managed_legacy' is the deprecation marker for existing upload apps;
  // it can't be set via API.
  const VALID_SOURCE_TYPES = new Set(['github', 'managed']);
  if (source_type && !VALID_SOURCE_TYPES.has(source_type)) {
    throw new AppError(
      `source_type must be 'github' or 'managed' — '${source_type}' is no longer supported`,
      400, 'VALIDATION',
    );
  }

  const db = getDb();

  // Check uniqueness
  if (db.prepare('SELECT id FROM apps WHERE slug = ?').get(slug)) {
    throw new AppError(`App slug '${slug}' already exists`, 409, 'DUPLICATE');
  }

  const slot = getNextSlot(db);
  const ports = getPortsForSlot(slot);
  const resourceLimits = JSON.stringify({
    max_ram_mb: max_ram_mb || 512,
    max_cpu_percent: max_cpu_percent || 50,
  });

  const tokenEncrypted = github_token ? encrypt(github_token) : null;

  // domain is a custom override only — routing uses CRANE_DOMAIN/slug by default
  const appDomain = domain || null;

  const result = db.prepare(`
    INSERT INTO apps (name, slug, slot, domain, description, category, source_type, github_url, branch, github_token_encrypted, resource_limits, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(name, slug, slot, appDomain, description || null, category || null, source_type || 'github', github_url || null, branch || 'main', tokenEncrypted, resourceLimits, req.user.id);

  const appId = result.lastInsertRowid;

  // Create health configs for both envs
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO health_configs (app_id, env) VALUES (?, ?)').run(appId, env);
    db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(appId, env);
  }

  // Auto-assign creator to the app — both as a member (app_users) and as
  // the owner (app_user_roles). Two tables because they predate each other:
  // - app_users: bare "this user has access" rows
  // - app_user_roles: per-app role (none/user/admin/owner)
  // Forgetting the second was the v2.5.12 "⚠ No owner" bug — apps would
  // be created without anyone to administer them per-app, and only global
  // admins could touch them. Both inserts are idempotent (INSERT OR IGNORE
  // / ON CONFLICT) so re-running this code path is safe.
  db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)').run(appId, req.user.id);
  db.prepare(`
    INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')
    ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = 'owner'
  `).run(appId, req.user.id);

  // Create webhook config
  const webhookToken = crypto.randomBytes(16).toString('hex');
  const webhookSecret = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO webhook_configs (app_id, token, secret) VALUES (?, ?, ?)').run(appId, webhookToken, webhookSecret);

  // Create app directories
  const dataDir = process.env.DATA_DIR || './data';
  const appDir = join(dataDir, 'apps', slug);
  for (const env of ['production', 'sandbox']) {
    const envDir = join(appDir, env);
    mkdirSync(join(envDir, 'releases'), { recursive: true });
    mkdirSync(join(envDir, 'shared', 'data'), { recursive: true });
  }

  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);

  // Update Caddy reverse proxy config
  const caddyResult = await reloadCaddy();
  if (!caddyResult.success) {
    log.warn(`Caddy reload failed after app create: ${caddyResult.error}`);
  }

  // Start health checks for the new app
  try {
    const { refreshAppChecks } = await import('../services/healthChecker.js');
    refreshAppChecks(appId);
  } catch (e) {}

  const craneDomain = process.env.CRANE_DOMAIN;
  const urls = craneDomain ? {
    production: `https://${craneDomain}/${slug}`,
    sandbox: `https://${craneDomain}/${slug}-sandbox`,
  } : null;

  res.status(201).json({
    app: { ...app, resource_limits: JSON.parse(app.resource_limits) },
    urls,
    base_path: { production: `/${slug}/`, sandbox: `/${slug}-sandbox/` },
    webhook_url: `/api/webhooks/${webhookToken}`,
    message: `App '${name}' created. Assign users with PUT /api/apps/${slug}/users`,
  });
});

/**
 * GET /api/apps/:slug - App detail
 */
router.get('/:slug', requireAppAccess, (req, res) => {
  const db = getDb();
  const app = req.app;
  const ports = getPortsForSlot(app.slot);

  const users = db.prepare(`
    SELECT u.id, u.name, u.email FROM users u
    JOIN app_users au ON u.id = au.user_id WHERE au.app_id = ?
  `).all(app.id);

  const deployments = db.prepare(
    'SELECT id, env, version, status, commit_hash, started_at, finished_at FROM deployments WHERE app_id = ? ORDER BY started_at DESC LIMIT 10'
  ).all(app.id);

  const healthProd = db.prepare('SELECT * FROM health_state WHERE app_id = ? AND env = ?').get(app.id, 'production');
  const healthSand = db.prepare('SELECT * FROM health_state WHERE app_id = ? AND env = ?').get(app.id, 'sandbox');
  const healthConfigProd = db.prepare('SELECT * FROM health_configs WHERE app_id = ? AND env = ?').get(app.id, 'production');
  const healthConfigSand = db.prepare('SELECT * FROM health_configs WHERE app_id = ? AND env = ?').get(app.id, 'sandbox');

  const webhook = db.prepare('SELECT token, auto_deploy_sandbox, auto_deploy_prod, branch_filter FROM webhook_configs WHERE app_id = ?').get(app.id);

  const craneDomainDetail = process.env.CRANE_DOMAIN;
  const urlsDetail = craneDomainDetail ? {
    production: `https://${craneDomainDetail}/${app.slug}`,
    sandbox: `https://${craneDomainDetail}/${app.slug}-sandbox`,
  } : null;

  res.json({
    app: { ...app, resource_limits: JSON.parse(app.resource_limits || '{}') },
    urls: urlsDetail,
    base_path: { production: `/${app.slug}/`, sandbox: `/${app.slug}-sandbox/` },
    ...(isAdmin(req.user) ? { ports } : {}),
    users,
    deployments,
    health: {
      production: { config: healthConfigProd, state: healthProd },
      sandbox: { config: healthConfigSand, state: healthSand },
    },
    webhook: webhook ? { ...webhook, url: `/api/webhooks/${webhook.token}` } : null,
  });
});

/**
 * PUT /api/apps/:slug - Update app (admin or assigned user)
 */
router.put('/:slug', requireAppAccess, auditMiddleware('app-update'), async (req, res) => {
  const db = getDb();
  const app = req.app;
  const { name, domain, description, category, source_type, github_url, branch, github_token, max_ram_mb, max_cpu_percent, public_access, visibility, image_retention, frame_ancestors, auth_mode, auth_bypass_paths, email_enabled, email_from_name } = req.body;

  // Configurable RBAC: changes to repo-related fields gated by code.modify_repo_settings.
  // Other fields (name, description, category, visibility, etc.) stay open to any
  // app-assigned user via requireAppAccess.
  const repoFieldChanged =
    github_url !== undefined ||
    branch !== undefined ||
    github_token !== undefined ||
    source_type !== undefined;
  if (repoFieldChanged && !userHasAppPermission(req.user, app, 'code.modify_repo_settings')) {
    throw new AppError('Modifying repo settings is not permitted by your role on this app', 403, 'FORBIDDEN');
  }

  // v2.3.1: same allowlist as POST. Editing an app's source_type to
  // 'upload' is no longer permitted; the only legal targets are 'github'
  // and 'managed'. Existing 'managed_legacy' apps can stay or be promoted
  // to 'github' / 'managed' once their files are pushed to a real repo.
  if (source_type !== undefined) {
    const VALID_SOURCE_TYPES = new Set(['github', 'managed']);
    if (!VALID_SOURCE_TYPES.has(source_type)) {
      throw new AppError(
        `source_type must be 'github' or 'managed' — '${source_type}' is no longer supported`,
        400, 'VALIDATION',
      );
    }
  }

  // v2.7.6: category changes are owner/admin-only, and only global admins may
  // CREATE a new category. Owners pick from the existing set; plain app 'user'
  // members can't change the category at all. (Other open fields below stay
  // editable by any app-assigned user via requireAppAccess.)
  if (category !== undefined) {
    const newCat = category ? String(category).trim() : null;
    const curCat = app.category || null;
    if (newCat !== curCat) {
      const globalAdmin = isAdmin(req.user);
      const isOwner = roleForUserOnApp(req.user, app) === 'owner';
      if (!globalAdmin && !isOwner) {
        throw new AppError('Only the app owner can change the category.', 403, 'FORBIDDEN');
      }
      // Owners may only assign an existing category; creating new categories
      // is reserved for global admins. v2.7.8: scope the "does this category
      // exist" check to apps the owner can actually see (public, or apps
      // they're assigned to) — matches the Launcher dropdown and avoids a
      // cross-app oracle that would reveal categories used by apps hidden
      // from this user.
      if (!globalAdmin && newCat) {
        const exists = db.prepare(`
          SELECT 1 FROM apps a
          WHERE a.category = ? AND a.category IS NOT NULL AND a.category != ''
            AND (
              a.visibility = 'public'
              OR EXISTS (SELECT 1 FROM app_users au WHERE au.app_id = a.id AND au.user_id = ?)
              OR EXISTS (SELECT 1 FROM app_user_roles aur WHERE aur.app_id = a.id AND aur.user_id = ?)
            )
          LIMIT 1
        `).get(newCat, req.user.id, req.user.id);
        if (!exists) {
          throw new AppError('Only admins can create new categories — pick an existing one.', 403, 'NEW_CATEGORY_FORBIDDEN');
        }
      }
    }
  }

  const updates = {};
  if (name !== undefined) updates.name = name;
  if (domain !== undefined) updates.domain = domain;
  if (description !== undefined) updates.description = description;
  if (category !== undefined) updates.category = category ? String(category).trim() : null;
  if (source_type !== undefined) updates.source_type = source_type;
  if (github_url !== undefined) {
    if (github_url) validateGithubUrl(github_url);
    updates.github_url = github_url;
  }
  if (branch !== undefined) {
    // SECURITY: branch flows into `sh -c` arguments inside container start
    // commands (askClaude.js, generator.js). Validate at the write boundary
    // so a future inline interpolation can't be exploited via this column.
    // Regex matches the chars git accepts in a ref name plus '/' for paths.
    if (branch && !/^[A-Za-z0-9._/\-]{1,200}$/.test(branch)) {
      throw new AppError('branch must be alphanumeric with . _ / - (max 200 chars)', 400, 'VALIDATION');
    }
    updates.branch = branch;
  }
  if (visibility !== undefined) {
    if (!['hidden', 'private', 'public'].includes(visibility)) {
      throw new AppError('visibility must be one of: hidden, private, public', 400, 'VALIDATION');
    }
    // v2.7.9: visibility changes are owner/admin-only (it controls public
    // exposure). Plain app 'user' members can't flip it.
    if (visibility !== (app.visibility || 'hidden')) {
      const globalAdmin = isAdmin(req.user);
      const isOwner = roleForUserOnApp(req.user, app) === 'owner';
      if (!globalAdmin && !isOwner) {
        throw new AppError('Only the app owner can change visibility.', 403, 'FORBIDDEN');
      }
    }
    updates.visibility = visibility;
    updates.public_access = visibility === 'public' ? 1 : 0;
  } else if (public_access !== undefined) {
    updates.public_access = public_access ? 1 : 0;
    updates.visibility = public_access ? 'public' : 'private';
  }
  if (github_token !== undefined) updates.github_token_encrypted = encrypt(github_token);
  if (image_retention !== undefined) {
    if (!isAdmin(req.user)) {
      throw new AppError('Only admins can change image retention', 403, 'FORBIDDEN');
    }
    const ret = Number(image_retention);
    if (!Number.isFinite(ret) || ret < 0 || ret > 50 || !Number.isInteger(ret)) {
      throw new AppError('image_retention must be an integer between 0 and 50', 400, 'VALIDATION');
    }
    updates.image_retention = ret;
  }
  if (max_ram_mb !== undefined || max_cpu_percent !== undefined) {
    if (!isAdmin(req.user)) {
      throw new AppError('Only admins can change resource limits', 403, 'FORBIDDEN');
    }
    const ram = max_ram_mb !== undefined ? Number(max_ram_mb) : null;
    const cpu = max_cpu_percent !== undefined ? Number(max_cpu_percent) : null;
    if (ram !== null && (!Number.isFinite(ram) || ram < 64 || ram > 16384)) {
      throw new AppError('max_ram_mb must be between 64 and 16384', 400, 'VALIDATION');
    }
    if (cpu !== null && (!Number.isFinite(cpu) || cpu < 5 || cpu > 800)) {
      throw new AppError('max_cpu_percent must be between 5 and 800', 400, 'VALIDATION');
    }
    const current = JSON.parse(app.resource_limits || '{}');
    updates.resource_limits = JSON.stringify({
      max_ram_mb: ram ?? current.max_ram_mb ?? 512,
      max_cpu_percent: cpu ?? current.max_cpu_percent ?? 50,
    });
  }

  if (frame_ancestors !== undefined) {
    // SECURITY: changing frame_ancestors lets the app be embedded in
    // arbitrary origins → clickjacking on /login (which strips
    // X-Frame-Options for that slug's redirect). Restrict to admin so an
    // app-assigned user can't open the door (security review v1.27.34 H3).
    if (!isAdmin(req.user)) {
      throw new AppError('Only admins can change frame_ancestors', 403, 'FORBIDDEN');
    }
    if (frame_ancestors === null || frame_ancestors === '') {
      updates.frame_ancestors = null;
    } else {
      // Validate CSP source-list syntax: tokens separated by spaces, each
      // either 'self' / 'none' (with quotes) or a scheme://host[:port]
      // (optional wildcards in subdomain only). Reject anything containing
      // ;, newlines, double-quotes, or other CSP-injection characters.
      const v = String(frame_ancestors).trim();
      if (!/^[A-Za-z0-9 _.\-:/'*]+$/.test(v))     throw new AppError("frame_ancestors contains invalid characters", 400, 'VALIDATION');
      if (v.length > 512)                          throw new AppError("frame_ancestors too long (max 512 chars)", 400, 'VALIDATION');
      const tokens = v.split(/\s+/).filter(Boolean);
      const TOKEN_RE = /^('self'|'none'|https?:\/\/(\*\.)?[a-z0-9.\-]+(:\d+)?)$/i;
      const bad = tokens.find(t => !TOKEN_RE.test(t));
      if (bad) throw new AppError(`frame_ancestors token "${bad}" is not a valid CSP source`, 400, 'VALIDATION');
      updates.frame_ancestors = tokens.join(' ');
    }
  }

  // v2.7.27: auth_bypass_paths. Per-path bypass of forward_auth — narrower
  // than headless mode (which removes SSO from the entire app). Same exposure
  // class as auth_mode, so same gate: owner-or-admin. Validated centrally in
  // utils/authBypassPaths.js so the API write path AND the Caddy generator
  // read-back share one set of rules. Stored as JSON; Caddy emits one inner
  // `handle` block per entry, BEFORE the forward_auth'd parent block.
  if (auth_bypass_paths !== undefined) {
    const globalAdmin = isAdmin(req.user);
    const isOwner = roleForUserOnApp(req.user, app) === 'owner';
    if (!globalAdmin && !isOwner) {
      throw new AppError('Only the app owner can change auth_bypass_paths.', 403, 'FORBIDDEN');
    }
    let parsed;
    try { parsed = validateBypassPaths(auth_bypass_paths); }
    catch (e) { throw new AppError(e.message, 400, 'VALIDATION'); }
    updates.auth_bypass_paths = parsed && parsed.length > 0 ? JSON.stringify(parsed) : null;
  }

  // v2.7.22: auth_mode. 'headless' bypasses forward_auth entirely and exposes
  // the app to unauthenticated traffic. Owner-or-admin only, same gate as
  // visibility/category (it's an exposure change).
  if (auth_mode !== undefined) {
    if (!['authenticated', 'headless'].includes(auth_mode)) {
      throw new AppError("auth_mode must be 'authenticated' or 'headless'", 400, 'VALIDATION');
    }
    if (auth_mode !== (app.auth_mode || 'authenticated')) {
      const globalAdmin = isAdmin(req.user);
      const isOwner = roleForUserOnApp(req.user, app) === 'owner';
      if (!globalAdmin && !isOwner) {
        throw new AppError('Only the app owner can change auth_mode.', 403, 'FORBIDDEN');
      }
    }
    updates.auth_mode = auth_mode;
  }

  // v2.8.0: email service enablement (owner-or-admin, same exposure gate).
  // Enabling provisions a service token if the app doesn't have one yet; the
  // token + reachability env only land in the container on the next deploy.
  let emailJustEnabled = false;
  if (email_enabled !== undefined) {
    const globalAdmin = isAdmin(req.user);
    const isOwner = roleForUserOnApp(req.user, app) === 'owner';
    if (!globalAdmin && !isOwner) {
      throw new AppError('Only the app owner can change email_enabled.', 403, 'FORBIDDEN');
    }
    const next = email_enabled ? 1 : 0;
    updates.email_enabled = next;
    if (next === 1 && !app.service_token_hash) {
      const { issueServiceToken } = await import('../services/appServiceToken.js');
      issueServiceToken(app.id);
      emailJustEnabled = true;
    }
  }
  if (email_from_name !== undefined) {
    updates.email_from_name = email_from_name ? String(email_from_name).slice(0, 100) : null;
  }

  if (Object.keys(updates).length === 0) {
    return res.json({ app, message: 'No changes' });
  }

  const ALLOWED_APP_COLS = new Set(['name','domain','description','category','source_type','github_url','branch','public_access','visibility','github_token_encrypted','resource_limits','runtime','image_retention','frame_ancestors','auth_mode','auth_bypass_paths','email_enabled','email_from_name']);
  const invalidKey = Object.keys(updates).find(k => !ALLOWED_APP_COLS.has(k));
  if (invalidKey) throw new AppError(`Invalid field: ${invalidKey}`, 400, 'VALIDATION');

  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = Object.values(updates);

  db.prepare(`UPDATE apps SET ${setClauses} WHERE id = ?`).run(...values, app.id);

  // frame_ancestors and auth_mode change the per-app Caddyfile block — reload to apply.
  // auth_mode flips whether forward_auth runs at all; without a reload the new
  // setting wouldn't take effect on the live proxy.
  if ('frame_ancestors' in updates || 'auth_mode' in updates || 'auth_bypass_paths' in updates) {
    await reloadCaddy().catch(e => log.warn(`Caddy reload after app meta update: ${e.message}`));
  }

  const updated = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  res.json({
    app: { ...updated, resource_limits: JSON.parse(updated.resource_limits || '{}') },
    ...(emailJustEnabled && { message: 'Email enabled and a service token was provisioned. Redeploy the app so the token (APPCRANE_SERVICE_TOKEN) is injected into the container.' }),
  });
});

/**
 * DELETE /api/apps/:slug - Delete app
 * Configurable RBAC: gated by app.delete permission. AppCrane global admin
 * always allowed; per-app deletion follows the role_permissions matrix
 * (default: Owner only). Requires ?confirm=true.
 */
router.delete('/:slug', requireAppAccess, auditMiddleware('app-delete'), async (req, res) => {
  if (!userHasAppPermission(req.user, req.app, 'app.delete')) {
    throw new AppError('Deleting this app is not permitted by your role', 403, 'FORBIDDEN');
  }
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.searchParams.get('confirm') !== 'true') {
    throw new AppError('Add ?confirm=true to delete', 400, 'CONFIRMATION_REQUIRED');
  }

  const db = getDb();
  const slug = req.app.slug;

  // Stop containers
  try {
    const { stopApp } = await import('../services/docker.js');
    await stopApp(slug, 'production').catch(() => {});
    await stopApp(slug, 'sandbox').catch(() => {});
  } catch (e) {}

  // Delete related records first to avoid FK constraint failures
  const appId = req.app.id;
  db.transaction(() => {
    db.prepare('DELETE FROM app_users WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM app_user_roles WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM deployments WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM env_vars WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM health_configs WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM health_state WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM webhook_configs WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM backups WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM notification_configs WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM identity_sessions WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM audit_log WHERE app_id = ?').run(appId);
    db.prepare('DELETE FROM apps WHERE id = ?').run(appId);
  })();

  // Update Caddy config (removes app routes)
  await reloadCaddy().catch(e => log.warn(`Caddy reload after delete: ${e.message}`));

  res.json({ message: `App '${slug}' deleted` });
});

/**
 * POST /api/apps/:slug/rename - Rename app slug (admin only)
 * Stops containers, renames data dir, updates DB, reloads Caddy, redeploys.
 */
router.post('/:slug/rename', requireAdmin, requireAppAccess, auditMiddleware('app-rename'), async (req, res) => {
  const { new_slug, redirect = true } = req.body;

  if (!new_slug) throw new AppError('new_slug is required', 400, 'VALIDATION');
  if (!/^[a-z0-9][a-z0-9-]*$/.test(new_slug)) {
    throw new AppError('Slug must be lowercase alphanumeric with dashes', 400, 'VALIDATION');
  }

  const db = getDb();
  const app = req.app;
  const oldSlug = app.slug;

  if (new_slug === oldSlug) throw new AppError('New slug is the same as current slug', 400, 'VALIDATION');
  if (db.prepare('SELECT id FROM apps WHERE slug = ?').get(new_slug)) {
    throw new AppError(`Slug '${new_slug}' is already in use`, 409, 'DUPLICATE');
  }

  // Stop old containers
  try {
    const { stopApp } = await import('../services/docker.js');
    await stopApp(oldSlug, 'production').catch(() => {});
    await stopApp(oldSlug, 'sandbox').catch(() => {});
  } catch (_) {}

  // Rename data directory
  const dataDir = process.env.DATA_DIR || './data';
  const appsBase = join(dataDir, 'apps');
  const oldDir = resolveSafe(appsBase, oldSlug);
  const newDir = resolveSafe(appsBase, new_slug);
  if (existsSync(oldDir)) {
    renameSync(oldDir, newDir);
  }

  // Build updated slug_aliases (append old slug for redirect)
  let aliases = [];
  try { aliases = JSON.parse(app.slug_aliases || '[]'); } catch (_) {}
  if (redirect && !aliases.includes(oldSlug)) aliases.push(oldSlug);

  // Update DB
  db.prepare('UPDATE apps SET slug = ?, slug_aliases = ? WHERE id = ?')
    .run(new_slug, aliases.length ? JSON.stringify(aliases) : null, app.id);

  // Reload Caddy with new routes (+ redirect if requested)
  await reloadCaddy().catch(e => log.warn(`Caddy reload after rename: ${e.message}`));

  // Redeploy live environments so containers get the updated APP_BASE_PATH and new name
  const liveEnvs = db.prepare("SELECT env FROM deployments WHERE app_id = ? AND status = 'live'").all(app.id);
  const updatedApp = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  const ports = getPortsForSlot(updatedApp.slot);

  for (const { env } of liveEnvs) {
    try {
      const result = db.prepare(
        "INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, ?, 'pending', ?)"
      ).run(app.id, env, req.user.id);
      const { deployApp } = await import('../services/deployer.js');
      deployApp(result.lastInsertRowid, updatedApp, env, ports).catch(err => {
        log.error(`Rename redeploy failed (${env}): ${err.message}`);
      });
    } catch (e) {
      log.warn(`Could not queue rename redeploy for ${env}: ${e.message}`);
    }
  }

  res.json({
    message: `App renamed from '${oldSlug}' to '${new_slug}'`,
    old_slug: oldSlug,
    new_slug,
    redirect,
    redeploying: liveEnvs.map(r => r.env),
  });
});

/**
 * PUT /api/apps/:slug/users - Assign users to app (admin or assigned user)
 */
router.put('/:slug/users', requireAppAccess, auditMiddleware('app-assign-users'), (req, res) => {
  const { user_ids, user_emails } = req.body;
  const db = getDb();
  const appId = req.app.id;

  let ids = user_ids || [];

  // Resolve emails to IDs
  if (user_emails && user_emails.length) {
    for (const email of user_emails) {
      const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      if (!user) throw new AppError(`User with email '${email}' not found`, 404, 'NOT_FOUND');
      ids.push(user.id);
    }
  }

  // Replace all assignments
  db.transaction(() => {
    db.prepare('DELETE FROM app_users WHERE app_id = ?').run(appId);
    const insert = db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)');
    for (const uid of ids) {
      insert.run(appId, uid);
    }
  })();

  const users = db.prepare(`
    SELECT u.id, u.name, u.email FROM users u
    JOIN app_users au ON u.id = au.user_id WHERE au.app_id = ?
  `).all(appId);

  res.json({ app: req.app.slug, users });
});

/*
 * Retired in v2.6.0: POST /api/apps/:slug/deployment-key (+ /recycle).
 *
 * These endpoints minted per-app `user_<random>` REST keys for an
 * X-Deployment-Key flow that duplicated MCP. AppCrane is MCP-only for
 * agents now (see appcrane_get_guide topic="operations"); per-app
 * access lives in app_user_roles, not in paste-key headers.
 *
 * Existing keys keep authenticating until v3.0; no new ones are issued.
 */
router.post('/:slug/deployment-key', requireAuth, (_req, res) => {
  res.status(410).json({
    error: {
      code: 'GONE',
      message: 'Deployment keys are retired (v2.6.0). Agents authenticate via MCP; use appcrane_grant_app_access for per-app access.',
    },
  });
});

/* Recycle path also retired — same rationale as above. */
router.post('/:slug/deployment-key/recycle', requireAuth, (_req, res) => {
  res.status(410).json({
    error: {
      code: 'GONE',
      message: 'Deployment keys are retired (v2.6.0). Use appcrane_grant_app_access for per-app access.',
    },
  });
});

/**
 * POST /api/apps/:slug/icon - Upload app icon SVG (admin or assigned app user)
 */
router.post('/:slug/icon', requireAuth, requireAppAccess, async (req, res) => {
  const app = req.app;  // set by requireAppAccess

  const multer = (await import('multer')).default;
  const dataDir = process.env.DATA_DIR || './data';
  const tmpDir = join(dataDir, 'tmp');
  mkdirSync(tmpDir, { recursive: true });

  const ALLOWED_ICON_MIMES = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'image/gif': 'gif' };
  const upload = multer({
    dest: tmpDir,
    limits: { fileSize: 500 * 1024 },
    fileFilter: (_req, file, cb) => {
      if (ALLOWED_ICON_MIMES[file.mimetype]) {
        cb(null, true);
      } else {
        cb(new AppError('Only PNG, JPEG, WEBP, and GIF icons are accepted', 400, 'INVALID_FILE'));
      }
    },
  }).single('icon');

  upload(req, res, (err) => {
    if (err) return res.status(400).json({ error: { code: 'UPLOAD_ERROR', message: err.message } });
    if (!req.file) return res.status(400).json({ error: { code: 'NO_FILE', message: 'No icon file uploaded' } });
    const ext = ALLOWED_ICON_MIMES[req.file.mimetype] || 'png';
    const appIconDir = join(dataDir, 'apps', app.slug);
    // App dir might not exist yet (rare — app created but never deployed).
    mkdirSync(appIconDir, { recursive: true });
    // Wipe any prior icons with a different extension so the GET endpoint
    // (which scans ICON_EXTS in order) doesn't keep serving the stale one.
    // Without this, uploading a JPG over an existing PNG silently kept
    // returning the PNG forever.
    for (const oldExt of ICON_EXTS) {
      if (oldExt === ext) continue;
      const oldPath = join(appIconDir, `icon.${oldExt}`);
      if (existsSync(oldPath)) {
        try { unlinkSync(oldPath); } catch (_) {}
      }
    }
    const iconPath = join(appIconDir, `icon.${ext}`);
    renameSync(req.file.path, iconPath);
    res.json({ message: 'Icon uploaded', url: `/api/apps/${app.slug}/icon` });
  });
});

/**
 * POST /api/reconcile - Register orphaned filesystem apps into the DB and reload Caddy
 */
router.post('/reconcile', requireAdmin, async (req, res) => {
  const dryRun = req.query.dry_run === '1' || req.body?.dry_run === true;
  const result = await reconcileOrphanedApps({ dryRun });
  res.json({ ...result, dry_run: dryRun });
});

/**
 * GET /api/apps/suspicious-github-urls — admin-only triage list of apps
 * whose github_url is malformed or uses a placeholder owner. Backstop
 * for rows that slipped past validation in earlier service versions.
 */
router.get('/suspicious-github-urls', requireAdmin, (req, res) => {
  res.json({ apps: listSuspiciousGithubUrls() });
});

// ── Per-app Claude Code OAuth credentials ──────────────────────────────
//
// Operators upload a credentials.json (the file `claude login` writes)
// scoped to a specific app. AppCrane mounts it into that app's CLI
// containers so the agent authenticates as the operator's Claude.ai
// subscription instead of charging the global ANTHROPIC_API_KEY wallet.
// Stored encrypted on the app row; never returned in plaintext.

/**
 * GET /api/apps/:slug/claude-credentials — public summary of what's stored.
 * Never returns the raw tokens — just `{ present, expiresAt, accountUuid,
 * accessTokenTail }` so the UI can show a "configured" state without leaking.
 */
router.get('/:slug/claude-credentials', requireAppAccess, async (req, res) => {
  const { credentialsInfo } = await import('../services/claudeCredentials.js');
  res.json(credentialsInfo(req.params.slug));
});

/**
 * PUT /api/apps/:slug/claude-credentials — upload/replace the stored creds.
 * Body: { credentials: <full JSON object> }  OR  raw JSON body that itself
 * is the credentials.json contents. Either shape is accepted to keep the
 * UI form simple (just FileReader → fetch).
 *
 * SECURITY: admin only. An app-assigned (non-admin) user must not be able
 * to overwrite the operator's billing credentials with their own — see
 * the v1.27.34 security review (H2).
 */
router.put('/:slug/claude-credentials', requireAdmin, requireAppAccess, auditMiddleware('app-claude-credentials'), async (req, res) => {
  const body = req.body || {};
  const payload = body.credentials && typeof body.credentials === 'object'
    ? body.credentials
    : body;
  const { setCredentials, validateCredentials } = await import('../services/claudeCredentials.js');
  try {
    validateCredentials(payload);
    setCredentials(req.params.slug, payload);
    // Long-lived per-app builder containers mount credentials.json at
    // start-time only. If one is running, evict it so the next Build/
    // Code dispatch starts a fresh container with the new creds —
    // otherwise the user uploads new creds and the container keeps
    // using the stale (or absent) mount, surfacing as "Not logged in"
    // or "Credit balance is too low" depending on auth precedence.
    try {
      const { evict } = await import('../services/builder/appContainer.js');
      evict(req.params.slug, 'credentials-changed');
    } catch (_) {}
    // Return the fresh summary so the UI can update without a second fetch.
    const { credentialsInfo } = await import('../services/claudeCredentials.js');
    res.json(credentialsInfo(req.params.slug));
  } catch (e) {
    throw new AppError(`invalid credentials: ${e.message}`, 400, 'VALIDATION');
  }
});

/**
 * DELETE /api/apps/:slug/claude-credentials — clear stored creds. The next
 * dispatch falls back to the global ANTHROPIC_API_KEY.
 *
 * SECURITY: admin only. Same reasoning as PUT.
 */
router.delete('/:slug/claude-credentials', requireAdmin, requireAppAccess, auditMiddleware('app-claude-credentials'), async (req, res) => {
  const { clearCredentials } = await import('../services/claudeCredentials.js');
  clearCredentials(req.params.slug);
  // Same reasoning as PUT — evict the running builder so it stops
  // mounting the (now-deleted) creds and falls back to API key auth
  // on the next dispatch.
  try {
    const { evict } = await import('../services/builder/appContainer.js');
    evict(req.params.slug, 'credentials-cleared');
  } catch (_) {}
  res.json({ present: false });
});

export default router;
