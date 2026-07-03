import { getDb } from '../db.js';
import { decrypt, encrypt } from './encryption.js';
import { BUCKETS, bucketize, applyBucket } from './requestStatus.js';
import { userHasAppPermission, userHasPlatformPermission, roleForUserOnApp } from './permissions.js';
import { isAdmin } from '../utils/roles.js';
import log from '../utils/logger.js';
import { validateBypassPaths } from '../utils/authBypassPaths.js';
import { resolveVisibility } from '../utils/appVisibility.js';
import { mkdirSync } from 'fs';
import { join } from 'path';
import crypto from 'crypto';

/**
 * MCP tool registry. Each tool:
 *   - name, description, inputSchema (read by the LLM via tools/list)
 *   - requiredRole — 'admin' (any AppCrane admin), 'app_admin' (admin OR per-app
 *     admin role), 'app_access' (any user with access to the app), 'any'
 *   - handler(user, args) → arbitrary JSON returned to the agent
 *
 * v1 surface (5 tools): list apps, read env, deploy, list requests, read logs.
 * Keep this small and well-described — descriptions are how the LLM picks tools.
 */

/**
 * If users.mcp_app_scope is set on the calling key, MCP is restricted to
 * those slugs regardless of role — including AppCrane admins. Returns null
 * (no restriction) if unset, an array of slugs if set, or [] to lock out.
 */
function mcpScope(user) {
  const raw = user.mcp_app_scope;
  if (raw == null || raw === '') return null;
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.map(String) : null;
  } catch (_) {
    return null;
  }
}

function isInMcpScope(user, slug) {
  const scope = mcpScope(user);
  if (scope === null) return null; // no opinion — fall through to role checks
  return scope.includes(slug);
}

function accessibleSlugsForUser(user) {
  // Personal MCP key — dynamically resolves to apps where the user has access.
  // AppCrane global admins (admin OR platform_admin) see every app; everyone
  // else sees apps they own. Role changes take effect on the next call.
  // (App-scoped keys removed in v2.2.12 — per-app scoping comes from the
  // user's app_user_roles assignments, not from a separate key type.)
  if (user._mcpUserKey) {
    const db = getDb();
    if (isAdmin(user)) {
      return db.prepare('SELECT slug FROM apps').all().map(r => r.slug);
    }
    return db.prepare(`
      SELECT DISTINCT a.slug
      FROM apps a
      JOIN app_user_roles aur ON aur.app_id = a.id
      WHERE aur.user_id = ? AND aur.app_role = 'owner'
    `).all(user.id).map(r => r.slug);
  }

  const scope = mcpScope(user);
  if (scope) return scope; // explicit scope wins over role
  const db = getDb();
  if (isAdmin(user)) {
    return db.prepare('SELECT slug FROM apps').all().map(r => r.slug);
  }
  return db
    .prepare(
      `SELECT DISTINCT a.slug
       FROM apps a
       LEFT JOIN app_users au ON au.app_id = a.id AND au.user_id = ?
       LEFT JOIN app_user_roles aur ON aur.app_id = a.id AND aur.user_id = ?
       WHERE au.user_id IS NOT NULL OR aur.user_id IS NOT NULL`
    )
    .all(user.id, user.id)
    .map(r => r.slug);
}

function getAppForUser(user, slug) {
  const db = getDb();
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  if (!app) throw new Error(`App not found: ${slug}`);

  // Personal MCP key locks scope to apps the user has access to. AppCrane
  // global admins (admin OR platform_admin) keep their global access;
  // everyone else is restricted to apps where they're explicitly Owner.
  if (user._mcpUserKey) {
    if (isAdmin(user)) return app;
    const owns = db.prepare(
      "SELECT 1 FROM app_user_roles WHERE app_id = ? AND user_id = ? AND app_role = 'owner'"
    ).get(app.id, user.id);
    if (!owns) throw new Error(`Forbidden: this personal MCP key only covers apps you own; ${slug} is not one`);
    return app;
  }

  // Explicit MCP scope (if set) trumps role
  const inScope = isInMcpScope(user, slug);
  if (inScope === false) throw new Error(`Forbidden: app ${slug} is outside this key's MCP scope`);
  if (inScope === true) return app;

  // No explicit scope: fall back to role/assignment check
  if (isAdmin(user)) return app;
  const hasAccess =
    db.prepare('SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?').get(app.id, user.id) ||
    db.prepare('SELECT 1 FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, user.id);
  if (!hasAccess) throw new Error(`Forbidden: no access to app ${slug}`);
  return app;
}

function isAppAdmin(user, app) {
  // MCP scope only restricts WHICH apps; if the user has the slug in scope
  // and is a global admin (admin or platform_admin), they're still an
  // app-admin for it.
  if (isAdmin(user)) return true;
  const db = getDb();
  const row = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, user.id);
  // v2.7.0: owner is the highest per-app tier (none < user < admin < owner),
  // so it must satisfy admin-level write gates. The canUseTool 'app_admin'
  // visibility check already includes owner; this handler-side check omitted
  // it, so an owner who created an app saw write tools (set_env, etc.) but
  // got "Forbidden" on call. Matters for non-admin onboarding: the app
  // creator is auto-assigned owner.
  return row?.app_role === 'admin' || row?.app_role === 'owner';
}

/**
 * Whitelist for container exec paths. Only /app and /data are reachable —
 * everything else (/etc, /root, /proc, the host bind-mounts) is off-limits
 * for read tools so a curious agent can't grep secrets out of the OS image.
 * `..` traversal is rejected even after the prefix check.
 */
function validateContainerPath(p) {
  const path = String(p == null ? '' : p).trim();
  if (!path) throw new Error('path is required');
  if (!path.startsWith('/')) throw new Error('path must be absolute');
  if (path.includes('..')) throw new Error('path must not contain ".."');
  if (path !== '/app' && path !== '/data' &&
      !path.startsWith('/app/') && !path.startsWith('/data/')) {
    throw new Error('path must be under /app or /data');
  }
  return path;
}

function auditMcpCall(user, toolName, args, error) {
  try {
    const db = getDb();
    const slug = args && typeof args.slug === 'string' ? args.slug : null;
    const appId = slug
      ? db.prepare('SELECT id FROM apps WHERE slug = ?').get(slug)?.id ?? null
      : null;
    const detail = JSON.stringify({
      tool: toolName,
      args: args || {},
      ok: !error,
      error: error ? String(error.message || error) : null,
    });
    db.prepare(
      'INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (?, ?, ?, ?)'
    ).run(user.id, appId, `mcp.${toolName}`, detail);
  } catch (e) {
    log.warn(`MCP audit log failed: ${e.message}`);
    // Compliance/regulated installs can flip this to fail-closed: any audit
    // write failure (table locked, schema drift, disk full) refuses the call
    // rather than letting the action proceed without a trail.
    if (process.env.APPCRANE_AUDIT_REQUIRED === '1') {
      throw new Error(`Audit log unavailable — refusing to proceed (APPCRANE_AUDIT_REQUIRED=1): ${e.message}`);
    }
  }
}

/**
 * Augment an app row with the canonical URLs (production + sandbox) and
 * the most recent live deployment version for each environment. Used by
 * appcrane_list_apps and appcrane_get_app so an agent can answer
 * "what's deployed and where" without a follow-up call.
 *
 * `app` must include `id`, `slug`, and `domain`.
 */
function enrichAppRow(db, app) {
  const craneDomain = process.env.CRANE_DOMAIN;
  const urls = craneDomain
    ? {
        production: app.domain ? `https://${app.domain}` : `https://${craneDomain}/${app.slug}`,
        sandbox: `https://${craneDomain}/${app.slug}-sandbox`,
      }
    : null;

  const lastLiveProd = db
    .prepare(
      "SELECT version, finished_at FROM deployments WHERE app_id = ? AND env = 'production' AND status = 'live' ORDER BY started_at DESC LIMIT 1"
    )
    .get(app.id);
  const lastLiveSand = db
    .prepare(
      "SELECT version, finished_at FROM deployments WHERE app_id = ? AND env = 'sandbox' AND status = 'live' ORDER BY started_at DESC LIMIT 1"
    )
    .get(app.id);

  return {
    slug: app.slug,
    name: app.name,
    description: app.description ?? null,
    domain: app.domain ?? null,
    urls,
    versions: {
      production: lastLiveProd?.version ?? null,
      sandbox: lastLiveSand?.version ?? null,
    },
    last_deploy: {
      production: lastLiveProd?.finished_at ?? null,
      sandbox: lastLiveSand?.finished_at ?? null,
    },
  };
}

const TOOLS = [
  {
    name: 'appcrane_list_apps',
    description:
      'List all AppCrane apps the current user has access to. Each app includes slug, name, description, ' +
      'urls (production + sandbox), and the version currently live in each environment. ' +
      'Call this first when the user asks about "my apps", "what apps exist", or before doing anything app-specific. ' +
      'Non-admin users see only their assigned apps; admins (admin or platform_admin) see everything.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user) => {
      const db = getDb();
      const slugs = accessibleSlugsForUser(user);
      if (!slugs.length) return { apps: [], count: 0 };
      const placeholders = slugs.map(() => '?').join(',');
      const apps = db
        .prepare(
          `SELECT id, slug, name, description, domain FROM apps WHERE slug IN (${placeholders}) ORDER BY name`
        )
        .all(...slugs)
        .map(a => enrichAppRow(db, a));
      return { apps, count: apps.length };
    },
  },

  {
    name: 'appcrane_get_app',
    description:
      'Get detailed info for a single app: URLs, current versions per environment, recent deployments, and ' +
      'health state. Use this when the user asks "what\'s the status of <app>", "is <app> deployed", or after a ' +
      'deploy to confirm what landed. Returns 404-equivalent error if the slug doesn\'t exist or the caller has no access.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string', description: 'App slug, e.g. "mysite"' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const app = getAppForUser(user, args.slug);
      const db = getDb();
      const enriched = enrichAppRow(db, app);

      const recentDeploys = db
        .prepare(
          `SELECT id, env, version, status, commit_hash, started_at, finished_at, frontend_assets
           FROM deployments WHERE app_id = ?
           ORDER BY started_at DESC LIMIT 6`
        )
        .all(app.id);

      const healthProd = db
        .prepare('SELECT last_check_at, last_status, last_response_ms, is_down FROM health_state WHERE app_id = ? AND env = ?')
        .get(app.id, 'production');
      const healthSand = db
        .prepare('SELECT last_check_at, last_status, last_response_ms, is_down FROM health_state WHERE app_id = ? AND env = ?')
        .get(app.id, 'sandbox');

      // v2.5.2: surface the mutable config fields so agents can see what's
      // actually stored before calling appcrane_update_app to patch one.
      // Token field is intentionally a boolean (`token_set`) — never the
      // plaintext, never the encrypted blob.
      let resourceLimits = null;
      try { resourceLimits = app.resource_limits ? JSON.parse(app.resource_limits) : null; } catch (_) {}

      return {
        ...enriched,
        recent_deployments: recentDeploys,
        health: {
          production: healthProd
            ? {
                status: healthProd.is_down ? 'down' : (healthProd.last_status === 200 ? 'healthy' : 'unknown'),
                last_check: healthProd.last_check_at,
                response_ms: healthProd.last_response_ms,
              }
            : { status: 'unknown' },
          sandbox: healthSand
            ? {
                status: healthSand.is_down ? 'down' : (healthSand.last_status === 200 ? 'healthy' : 'unknown'),
                last_check: healthSand.last_check_at,
                response_ms: healthSand.last_response_ms,
              }
            : { status: 'unknown' },
        },
        config: {
          source_type:    app.source_type,
          github_url:     app.github_url,
          branch:         app.branch,
          token_set:      !!app.github_token_encrypted,
          domain:         app.domain,
          category:       app.category,
          visibility:     app.visibility,
          public_access:  app.public_access,
          image_retention: app.image_retention,
          frame_ancestors: app.frame_ancestors,
          max_ram_mb:      resourceLimits?.max_ram_mb      ?? null,
          max_cpu_percent: resourceLimits?.max_cpu_percent ?? null,
        },
      };
    },
  },

  {
    name: 'appcrane_top_apps',
    description:
      'Top apps by distinct active users in a lookback window. Useful for "which apps are getting the most use this week" or "what should I deprecate" type questions. Sourced from app_visits which is recorded on every Caddy forward_auth (one row per user/app/day). Returns rows ordered by user count descending. Admin only.',
    inputSchema: {
      type: 'object',
      properties: {
        days: { type: 'integer', minimum: 1, maximum: 90, default: 7,  description: 'Lookback window. Default 7, max 90.' },
        top:  { type: 'integer', minimum: 1, maximum: 50, default: 10, description: 'How many rows. Default 10, max 50.' },
      },
      additionalProperties: false,
    },
    requiredRole: 'admin',
    handler: async (_user, args) => {
      const days = Math.min(Math.max(parseInt(args.days, 10) || 7, 1), 90);
      const top  = Math.min(Math.max(parseInt(args.top,  10) || 10, 1), 50);
      const db = getDb();
      const rows = db.prepare(`
        SELECT a.slug, a.name,
               COUNT(DISTINCT v.user_id) AS users,
               COUNT(*) AS visit_days
        FROM app_visits v
        JOIN apps a ON a.id = v.app_id
        WHERE v.day >= date('now', '-' || ? || ' days')
        GROUP BY a.slug, a.name
        ORDER BY users DESC, visit_days DESC, a.name ASC
        LIMIT ?
      `).all(days, top);
      return { days, top, apps: rows };
    },
  },

  {
    name: 'appcrane_top_users',
    description:
      'Top users by distinct apps opened in a lookback window. Surfaces who the heaviest cross-app users are — handy for finding power users to interview, or spotting churn risk (a user who used 10 apps last month and 0 this week). Sourced from app_visits. Active users only. Admin only.',
    inputSchema: {
      type: 'object',
      properties: {
        days: { type: 'integer', minimum: 1, maximum: 90, default: 7,  description: 'Lookback window. Default 7, max 90.' },
        top:  { type: 'integer', minimum: 1, maximum: 50, default: 10, description: 'How many rows. Default 10, max 50.' },
      },
      additionalProperties: false,
    },
    requiredRole: 'admin',
    handler: async (_user, args) => {
      const days = Math.min(Math.max(parseInt(args.days, 10) || 7, 1), 90);
      const top  = Math.min(Math.max(parseInt(args.top,  10) || 10, 1), 50);
      const db = getDb();
      const rows = db.prepare(`
        SELECT u.id, u.name, u.email,
               COUNT(DISTINCT v.app_id) AS apps,
               COUNT(*) AS visit_days
        FROM app_visits v
        JOIN users u ON u.id = v.user_id
        WHERE v.day >= date('now', '-' || ? || ' days')
          AND u.active = 1
        GROUP BY u.id, u.name, u.email
        ORDER BY apps DESC, visit_days DESC, u.name ASC
        LIMIT ?
      `).all(days, top);
      return { days, top, users: rows };
    },
  },

  {
    name: 'appcrane_get_health',
    description:
      'Fetch the deployed app\'s health endpoint server-side, bypassing AppCrane\'s auth proxy. Use this to validate ' +
      'that a deploy actually landed the expected version, or to check if the app is responding. AppCrane hits the ' +
      'app\'s configured health endpoint (default /api/health) on the internal port directly — no Caddy, no SSO ' +
      'redirect — and returns the response status + body. ' +
      'Defaults to sandbox; pass stage="production" only when the user asks about prod.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string', description: 'App slug, e.g. "mysite"' },
        env:  { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      const { getPortsForSlot } = await import('./portAllocator.js');
      const ports = getPortsForSlot(app.slot);
      const port = env === 'production' ? ports.prod_be : ports.sand_be;

      const db = getDb();
      const cfg = db
        .prepare('SELECT endpoint FROM health_configs WHERE app_id = ? AND env = ?')
        .get(app.id, env);
      const path = cfg?.endpoint || '/api/health';
      const url = `http://127.0.0.1:${port}${path}`;

      try {
        const r = await fetch(url, { signal: AbortSignal.timeout(5000) });
        const text = await r.text();
        let body;
        try { body = JSON.parse(text); } catch { body = text.slice(0, 4096); }
        return {
          app: app.slug,
          env,
          url,
          status: r.status,
          ok: r.ok,
          body,
        };
      } catch (e) {
        return {
          app: app.slug,
          env,
          url,
          ok: false,
          error: e.message || String(e),
        };
      }
    },
  },

  {
    name: 'appcrane_get_secret',
    description:
      'Get all secrets (the app\'s encrypted environment variables) for an app, decrypted. Use this when the user asks about config, secrets, ' +
      'or when you need to verify what env vars are set. ' +
      'Defaults to sandbox; pass stage="production" only when the user explicitly says production. ' +
      'Requires app-admin or AppCrane admin role — non-admin users get a permission error.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string', description: 'App slug, e.g. "mysite"' },
        env: { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'app_admin', // also gated per-slug inside handler
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      if (!isAppAdmin(user, app)) throw new Error('Forbidden: env vars require admin or app-admin role');

      const db = getDb();
      const rows = db
        .prepare('SELECT key, value_encrypted FROM env_vars WHERE app_id = ? AND env = ? ORDER BY key')
        .all(app.id, env);
      const vars = {};
      for (const r of rows) {
        try {
          vars[r.key] = decrypt(r.value_encrypted);
        } catch (_) {
          vars[r.key] = '<<decrypt error>>';
        }
      }
      log.info(`MCP: env vars read for ${app.slug}/${env} by user ${user.id}`);
      return { app: app.slug, env, vars, count: rows.length };
    },
  },

  {
    name: 'appcrane_deploy',
    description:
      'Trigger a deployment — this IS how you "update an env to the latest". For github and managed apps it ' +
      'pulls the latest commit from the app\'s configured branch on GitHub (server-side, using the app\'s stored ' +
      'credentials — you do NOT need your own github token or to push/upload anything), builds a fresh Docker ' +
      'image, and swaps in a new container. Use it whenever the user says things like "update sandbox to the ' +
      'latest", "deploy the newest version", "pull my latest github changes", or "redeploy". Returns a ' +
      'deployment ID; use appcrane_get_logs to monitor progress. ' +
      'Defaults to sandbox; production requires explicit confirmation from the user.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string', description: 'App slug to deploy' },
        env: { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'any', // gated by app-access
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      // v2.7.11: production deploys require the deploy.production permission —
      // mirrors POST /api/apps/:slug/deploy/:env. Was missing here, so an
      // app-access key could ship to prod via MCP without the permission.
      if (env === 'production' && !userHasAppPermission(user, app, 'deploy.production')) {
        throw new Error('Forbidden: deploying to production requires the deploy.production permission for this app.');
      }
      const db = getDb();

      // v2.7.31: deploy-storm guard — refuse a new deploy when one is already
      // in flight for this app+env, so an agent loop calling appcrane_deploy
      // can't spawn unbounded concurrent builds. Mirrors POST /deploy/:env.
      const { getPortsForSlot } = await import('./portAllocator.js');
      const { deployApp, assertNoInflightDeploy } = await import('./deployer.js');
      assertNoInflightDeploy(db, app.id, env, app.slug);

      const result = db
        .prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, ?, 'pending', ?)")
        .run(app.id, env, user.id);
      const deployId = result.lastInsertRowid;

      const ports = getPortsForSlot(app.slot);

      // Fire-and-forget — agent monitors via logs
      deployApp(deployId, app, env, ports).catch((err) => {
        log.error(`MCP deploy ${deployId} failed: ${err.message}`);
      });

      log.info(`MCP: deploy queued for ${app.slug}/${env} (id=${deployId}) by user ${user.id}`);
      return {
        deployment_id: deployId,
        app: app.slug,
        env,
        status: 'pending',
        next: `Use appcrane_get_logs with slug="${app.slug}" env="${env}" to monitor.`,
      };
    },
  },

  {
    name: 'appcrane_list_releases',
    description:
      'List the deploy/release history for an app + env, newest first — each release is id, version, commit, status (live / rolled_back / failed / pending), who deployed it, and when. Use this to see what is live and to pick a target for appcrane_rollback. App access required.',
    inputSchema: {
      type: 'object',
      properties: {
        slug:  { type: 'string' },
        env:   { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
        limit: { type: 'integer', minimum: 1, maximum: 50, description: 'Max rows (default 10).' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'any', // gated by app-access via getAppForUser
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      const limit = Math.min(Math.max(parseInt(args.limit, 10) || 10, 1), 50);
      const db = getDb();
      const releases = db.prepare(`
        SELECT d.id, d.version, d.commit_hash, d.status, d.started_at, d.finished_at,
          u.name AS deployed_by_name,
          CASE WHEN d.release_path IS NOT NULL AND d.release_path != '' THEN 1 ELSE 0 END AS rollbackable
        FROM deployments d
        LEFT JOIN users u ON d.deployed_by = u.id
        WHERE d.app_id = ? AND d.env = ?
        ORDER BY d.started_at DESC
        LIMIT ?
      `).all(app.id, env, limit);
      return { app: app.slug, env, releases };
    },
  },

  {
    name: 'appcrane_rollback',
    description:
      'Roll an env back to a prior release. Pass deployment_id (from appcrane_list_releases) to target a specific release, or omit it to roll back to the immediately previous one. Re-runs that release from its recorded build (re-uses the cached per-commit image — no rebuild when it is still retained) and health-checks it. Records a NEW deployment and marks the previous live one rolled_back. Owner-only (or global admin).',
    inputSchema: {
      type: 'object',
      properties: {
        slug:          { type: 'string' },
        env:           { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
        deployment_id: { type: 'integer', description: 'Target release id. Omit to roll back to the previous release.' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'any', // gated per-slug in handler (owner of the app, or global admin)
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      // v2.7.13: rollback is owner-only (or global admin), same gate as promote.
      if (!isAdmin(user) && roleForUserOnApp(user, app) !== 'owner') {
        throw new Error('Forbidden: only the app owner can roll back this app.');
      }
      const { rollbackApp } = await import('./deployer.js');
      const r = await rollbackApp(app, env, args.deployment_id, user.id);
      return {
        app: app.slug,
        env,
        deployment_id: r.deployment_id,
        rolled_back_to: r.rollback_to,
        version: r.version,
        commit_hash: r.commit_hash,
        next: `Use appcrane_get_logs slug="${app.slug}" env="${env}" to confirm the rolled-back release is healthy.`,
      };
    },
  },

  {
    name: 'appcrane_promote',
    description:
      'Promote the current live SANDBOX release to production — the gated sandbox→prod path. Refuses unless sandbox is live AND currently healthy (you do not ship a broken sandbox to prod), and the promoted prod release is health-checked with auto-revert. For github apps this rebuilds production from the EXACT sandbox commit; for managed/upload apps it copies the exact tested sandbox release. Owner-only (or global admin).',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'any', // gated per-slug in handler (owner of the app, or global admin)
    handler: async (user, args) => {
      const app = getAppForUser(user, args.slug);
      // v2.7.12: promotion is owner-only (or global admin).
      if (!isAdmin(user) && roleForUserOnApp(user, app) !== 'owner') {
        throw new Error('Forbidden: only the app owner can promote to production.');
      }
      const { promoteApp } = await import('./deployer.js');
      const r = await promoteApp(app, user.id);
      return {
        app: app.slug,
        deployment_id: r.deployment_id,
        from_sandbox: r.from_sandbox,
        version: r.version,
        mode: r.mode,
        status: r.status,
        next: `Use appcrane_get_logs slug="${app.slug}" stage="production" to monitor the promotion.`,
      };
    },
  },

  {
    name: 'appcrane_list_requests',
    description:
      'List enhancement requests filed against an app via the AppCrane intake form. ' +
      'Use this when the user asks "what should I work on?", "what\'s queued for X?", or wants to pick up tickets. ' +
      'Returns id, message, app_slug, submitter, and bucket. Buckets: triage (unclaimed), in_progress (someone is working on it), shipped (merged + deployed), validated (requester confirmed). ' +
      'Filter by bucket="triage" to find work to pick up.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string', description: 'Filter by app slug. Omit to see across all accessible apps.' },
        bucket: {
          type: 'string',
          enum: ['triage', 'in_progress', 'shipped', 'validated'],
          description: 'Filter to one bucket. Most useful: "triage" for unclaimed work.',
        },
        limit: { type: 'number', default: 20, minimum: 1, maximum: 100 },
      },
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const db = getDb();
      const limit = Math.min(args.limit || 20, 100);
      const where = [];
      const params = [];
      if (args.slug) {
        // Verify the explicit slug is in the user's MCP scope
        const inScope = isInMcpScope(user, args.slug);
        if (inScope === false) throw new Error(`Forbidden: app ${args.slug} is outside this key's MCP scope`);
        where.push('app_slug = ?');
        params.push(args.slug);
      }
      // Always restrict to what this key can see (admin + scope-set fold to one set)
      const accessibleSlugs = accessibleSlugsForUser(user);
      if (!accessibleSlugs.length) return { requests: [], count: 0 };
      where.push(`app_slug IN (${accessibleSlugs.map(() => '?').join(',')})`);
      params.push(...accessibleSlugs);
      const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';
      params.push(limit);
      const rows = db
        .prepare(
          `SELECT id, message, app_slug, status, validated_at, user_name, created_at, branch_name, pr_url, fix_version, cost_usd_cents
           FROM enhancement_requests ${whereClause}
           ORDER BY id DESC LIMIT ?`
        )
        .all(...params);
      let requests = rows.map(r => ({ ...r, bucket: bucketize(r.status, r.validated_at) }));
      if (args.bucket) requests = requests.filter(r => r.bucket === args.bucket);
      return { requests, count: requests.length };
    },
  },

  {
    name: 'appcrane_set_request_status',
    description:
      'Move a request through the lifecycle: triage → in_progress → shipped → validated. ' +
      'Use this when the user says "I\'ll take #42" (set to in_progress), after merging a PR (set to shipped), ' +
      'or after confirming a fix works (set to validated). Validated requests are considered closed. ' +
      'Requires app-admin or AppCrane admin role.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Request id (the # column).' },
        bucket: {
          type: 'string',
          enum: ['triage', 'in_progress', 'shipped', 'validated'],
          description: 'Target bucket.',
        },
      },
      required: ['id', 'bucket'],
      additionalProperties: false,
    },
    requiredRole: 'app_admin',
    handler: async (user, args) => {
      if (!BUCKETS.includes(args.bucket)) throw new Error(`Unknown bucket: ${args.bucket}`);
      const db = getDb();
      const row = db.prepare(
        'SELECT id, app_slug, status, validated_at FROM enhancement_requests WHERE id = ?'
      ).get(args.id);
      if (!row) throw new Error(`Request ${args.id} not found`);

      // Authz: AppCrane admin OR per-app admin OR per-app owner.
      // The 'shipped' transition is gated by the configurable role_permissions
      // matrix (request.ship permission) so the matrix change applies to MCP
      // and REST identically.
      let appRow = null;
      if (!isAdmin(user)) {
        if (!row.app_slug) throw new Error('Forbidden: only AppCrane admin can move requests with no app');
        appRow = db.prepare('SELECT * FROM apps WHERE slug = ?').get(row.app_slug);
        const ar = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(appRow?.id, user.id);
        const hasAppRole = ar?.app_role === 'admin' || ar?.app_role === 'owner';
        if (!hasAppRole) throw new Error(`Forbidden: not an admin or owner of ${row.app_slug}`);
        if (args.bucket === 'shipped') {
          if (!userHasAppPermission(user, appRow, 'request.ship')) {
            throw new Error(`Forbidden: marking shipped is not permitted by your role on ${row.app_slug}`);
          }
        }
      }

      applyBucket(db, args.id, args.bucket, user.id);
      log.info(`MCP: request ${args.id} → bucket=${args.bucket} (user ${user.id})`);
      return { id: args.id, bucket: args.bucket };
    },
  },

  {
    name: 'appcrane_ls',
    description:
      'List files inside a running app container at a specific path. Use to verify what actually got built / what files made it into the deployed image. Read-only; bound to safe roots (/app and /data only). Returns the directory listing as text.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string' },
        env: { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
        path: { type: 'string', description: 'Absolute path inside the container, must start with /app or /data', default: '/app' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      const safePath = validateContainerPath(args.path || '/app');
      const { execFileSync } = await import('child_process');
      const containerName = `appcrane-${app.slug}-${env}`;
      try {
        const out = execFileSync('docker', ['exec', containerName, 'ls', '-la', '--', safePath], {
          stdio: 'pipe',
          timeout: 5000,
        }).toString();
        return { app: app.slug, env, path: safePath, listing: out };
      } catch (e) {
        const detail = e.stderr?.toString().trim() || e.message;
        throw new Error(`ls failed in ${containerName}:${safePath}: ${detail}`);
      }
    },
  },

  {
    name: 'appcrane_cat',
    description:
      'Print the contents of a file inside a running app container. Read-only; bound to safe roots (/app and /data only). Refuses files larger than 256KB; truncate by reading the first N bytes via path tricks if you need a tail.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string' },
        env: { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
        path: { type: 'string', description: 'Absolute path inside the container, must start with /app or /data' },
      },
      required: ['slug', 'path'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      const safePath = validateContainerPath(args.path);
      const { execFileSync } = await import('child_process');
      const containerName = `appcrane-${app.slug}-${env}`;
      const MAX_BYTES = 256 * 1024;
      // Probe size first so we don't pull a multi-MB file into the response.
      let size;
      try {
        const sizeOut = execFileSync('docker', ['exec', containerName, 'stat', '-c', '%s', '--', safePath], {
          stdio: 'pipe',
          timeout: 5000,
        }).toString().trim();
        size = parseInt(sizeOut, 10);
      } catch (e) {
        const detail = e.stderr?.toString().trim() || e.message;
        throw new Error(`stat failed in ${containerName}:${safePath}: ${detail}`);
      }
      if (Number.isFinite(size) && size > MAX_BYTES) {
        throw new Error(`File too large (${size} bytes > ${MAX_BYTES} cap). Use a tail/head invocation outside this tool, or read a specific range.`);
      }
      try {
        const out = execFileSync('docker', ['exec', containerName, 'cat', '--', safePath], {
          stdio: 'pipe',
          timeout: 5000,
          maxBuffer: MAX_BYTES + 1024,
        }).toString();
        return { app: app.slug, env, path: safePath, size, content: out };
      } catch (e) {
        const detail = e.stderr?.toString().trim() || e.message;
        throw new Error(`cat failed in ${containerName}:${safePath}: ${detail}`);
      }
    },
  },

  {
    name: 'appcrane_push_staged_file',
    description:
      'Move a previously-staged file into a running container at a path under /app or /data. THE WAY TO GET LARGE BINARIES (DMGs, datasets, bundles) into a container when they\'re too big to inline through appcrane_cp. ' +
      'Two steps: (1) upload the bytes with a plain multipart POST to ' + '`' + 'curl -F file=@local.dmg -H "X-API-Key: <your dhk_mcp_ key>" https://<host>/api/files/staged' + '`' + ' — your MCP key IS allowed on this endpoint (v2.10.6+); it returns { token, sha256, size_bytes }. (2) Call this tool with that token and a dest path. ' +
      'The container must be running. Path is validated (no "..", must start with /app or /data). The staged blob is deleted on success.',
    inputSchema: {
      type: 'object',
      properties: {
        slug:  { type: 'string', description: 'Target app slug' },
        env:   { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
        token: { type: 'string', description: 'Token returned by POST /api/files/staged' },
        dest:  { type: 'string', description: 'Absolute container path under /app or /data — destination file or directory' },
      },
      required: ['slug', 'token', 'dest'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      const safeDest = validateContainerPath(args.dest);

      const db = getDb();
      const row = db.prepare('SELECT * FROM staged_files WHERE token = ?').get(args.token);
      if (!row)                       throw new Error('staged file not found (token unknown or already swept)');
      if (row.user_id !== user.id)    throw new Error('staged file is owned by a different user');
      if (row.pushed_at)              throw new Error('staged file was already consumed');
      const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
      if (row.expires_at < now)       throw new Error(`staged file expired at ${row.expires_at}`);

      const { execFileSync } = await import('child_process');
      const containerName = `appcrane-${app.slug}-${env}`;
      const cpSpec = `${containerName}:${safeDest}`;
      try {
        execFileSync('docker', ['cp', row.scratch_path, cpSpec], {
          stdio: 'pipe',
          timeout: 30000,
        });
      } catch (e) {
        const detail = e.stderr?.toString().trim() || e.message;
        throw new Error(`docker cp into ${cpSpec} failed: ${detail}`);
      }

      // Mark consumed and reap the scratch dir. The 5-min sweeper would
      // catch this at expires_at anyway, but freeing disk immediately is
      // friendlier on busy boxes.
      try {
        const { rmSync } = await import('fs');
        const { dirname } = await import('path');
        rmSync(dirname(row.scratch_path), { recursive: true, force: true });
      } catch (_) { /* sweeper will retry */ }
      db.prepare("UPDATE staged_files SET pushed_at = datetime('now') WHERE token = ?").run(row.token);

      return {
        app: app.slug,
        env,
        container: containerName,
        dest: safeDest,
        size_bytes: row.size_bytes,
        sha256: row.sha256,
      };
    },
  },

  {
    name: 'appcrane_wait_deploy',
    description:
      'Block until a deployment reaches a terminal state (live / failed / rolled_back), then return its final status. ' +
      'Use after appcrane_deploy instead of polling appcrane_get_logs in a loop. Returns immediately if the deployment ' +
      'is already terminal. Defaults to 180s timeout, hard-capped at 600s. On timeout, returns { status: "pending", ' +
      'timed_out: true } so the caller can decide whether to keep waiting.',
    inputSchema: {
      type: 'object',
      properties: {
        deployment_id: { type: 'number', description: 'Deployment id from appcrane_deploy' },
        timeout_sec:   { type: 'number', description: 'How long to wait. Default 180s, max 600s.', default: 180 },
      },
      required: ['deployment_id'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const id = parseInt(args.deployment_id, 10);
      if (!Number.isFinite(id) || id <= 0) throw new Error('deployment_id must be a positive integer');
      const timeoutSec = Math.min(Math.max(parseInt(args.timeout_sec, 10) || 180, 1), 600);
      const TERMINAL = new Set(['live', 'failed', 'rolled_back']);

      const db = getDb();
      // Verify the caller can see this deployment's app — same accessibility
      // as appcrane_get_app would enforce. Resolves the slug from the row.
      const initial = db
        .prepare(
          `SELECT d.id, d.app_id, d.env, d.status, d.version, d.commit_hash, d.started_at, d.finished_at, d.frontend_assets,
                  a.slug AS app_slug
           FROM deployments d JOIN apps a ON a.id = d.app_id
           WHERE d.id = ?`
        )
        .get(id);
      if (!initial) throw new Error(`Deployment #${id} not found`);
      // getAppForUser throws Forbidden if the caller can't see the app.
      getAppForUser(user, initial.app_slug);

      // Already terminal? Return immediately.
      if (TERMINAL.has(initial.status)) {
        return {
          deployment_id: id,
          app: initial.app_slug,
          env: initial.env,
          status: initial.status,
          version: initial.version,
          commit_hash: initial.commit_hash,
          started_at: initial.started_at,
          finished_at: initial.finished_at,
          frontend_assets: initial.frontend_assets,
          timed_out: false,
          waited_ms: 0,
        };
      }

      // Poll once per 2s until terminal or timeout. setInterval-style with
      // setTimeout so we can cancel cleanly. No DB load to speak of —
      // single primary-key lookup per tick.
      const start = Date.now();
      const deadline = start + timeoutSec * 1000;
      const stmt = db.prepare(
        `SELECT id, status, version, commit_hash, started_at, finished_at, frontend_assets
         FROM deployments WHERE id = ?`
      );
      while (Date.now() < deadline) {
        const remaining = deadline - Date.now();
        await new Promise(r => setTimeout(r, Math.min(2000, remaining)));
        const row = stmt.get(id);
        if (!row) {
          // Deleted under us — extremely unusual. Return a synthetic gone status.
          return {
            deployment_id: id,
            app: initial.app_slug,
            env: initial.env,
            status: 'gone',
            timed_out: false,
            waited_ms: Date.now() - start,
          };
        }
        if (TERMINAL.has(row.status)) {
          return {
            deployment_id: id,
            app: initial.app_slug,
            env: initial.env,
            status: row.status,
            version: row.version,
            commit_hash: row.commit_hash,
            started_at: row.started_at,
            finished_at: row.finished_at,
            frontend_assets: row.frontend_assets,
            timed_out: false,
            waited_ms: Date.now() - start,
          };
        }
      }

      // Timed out — give the caller back the latest known state.
      const last = stmt.get(id) || initial;
      return {
        deployment_id: id,
        app: initial.app_slug,
        env: initial.env,
        status: last.status,
        version: last.version,
        commit_hash: last.commit_hash,
        started_at: last.started_at,
        finished_at: last.finished_at,
        frontend_assets: last.frontend_assets,
        timed_out: true,
        waited_ms: Date.now() - start,
        next: `Deployment still ${last.status} after ${timeoutSec}s. Call appcrane_wait_deploy again or use appcrane_get_logs to see what's happening.`,
      };
    },
  },

  {
    name: 'appcrane_get_deploy_log',
    description:
      'Read the deploy/build log for a specific deployment — the output that came out of clone / npm install / docker build / health-validate, BEFORE the container started running. This is what you want when a deploy fails fast (1-2 second failures are almost always pre-build errors that never reach the runtime container, so appcrane_get_logs has nothing to show). Pass a deployment_id from appcrane_deploy / appcrane_get_app.recent_deployments, OR omit it and pass slug+env to get the latest deployment\'s log.',
    inputSchema: {
      type: 'object',
      properties: {
        deployment_id: { type: 'integer', description: 'Specific deployment id. Preferred — unambiguous.' },
        slug:          { type: 'string',  description: 'App slug. Required when deployment_id is not given.' },
        env:           { type: 'string',  enum: ['sandbox', 'production'], description: 'Required when deployment_id is not given.' },
        tail:          { type: 'integer', minimum: 1, maximum: 5000, default: 500, description: 'Return only the last N lines. Defaults to 500; full log can be many KB on a long build.' },
      },
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const db = getDb();
      let row;
      if (args.deployment_id) {
        row = db.prepare(`
          SELECT d.*, a.slug AS app_slug
          FROM deployments d JOIN apps a ON a.id = d.app_id
          WHERE d.id = ?
        `).get(args.deployment_id);
        if (!row) throw new Error(`Deployment ${args.deployment_id} not found`);
        // Authz: caller must have access to the deployment's app.
        getAppForUser(user, row.app_slug);
      } else {
        if (!args.slug || !args.env) {
          throw new Error('Either deployment_id, or both slug and env, must be provided');
        }
        const app = getAppForUser(user, args.slug);
        row = db.prepare(`
          SELECT * FROM deployments
          WHERE app_id = ? AND env = ?
          ORDER BY started_at DESC
          LIMIT 1
        `).get(app.id, args.env);
        if (!row) throw new Error(`No deployments found for ${args.slug} (${args.env})`);
        row.app_slug = app.slug;
      }

      const fullLog = row.log || '';
      const tail = Math.min(parseInt(args.tail, 10) || 500, 5000);
      const lines = fullLog.split('\n');
      const trimmed = lines.length > tail ? lines.slice(-tail) : lines;
      const truncated = lines.length > tail;

      return {
        deployment_id:   row.id,
        app:             row.app_slug,
        env:             row.env,
        status:          row.status,
        version:         row.version,
        commit_hash:     row.commit_hash,
        commit_message:  row.commit_message,
        started_at:      row.started_at,
        finished_at:     row.finished_at,
        duration_seconds: row.finished_at && row.started_at
          ? Math.round((new Date(row.finished_at).getTime() - new Date(row.started_at).getTime()) / 1000)
          : null,
        log:             trimmed.join('\n'),
        line_count:      trimmed.length,
        truncated,
        original_line_count: lines.length,
      };
    },
  },

  {
    name: 'appcrane_get_logs',
    description:
      'Get recent runtime logs from a running app container (docker logs). Use this for runtime issues — once the container is up. ' +
      'Returns the most recent N lines (default 100, max 1000). Pass search to filter to lines containing a substring (case-insensitive). ' +
      'NOT the right tool for fast deploy failures (1-2 second exits, "no such container" errors): those happen during clone / npm install / docker build / health-validate, BEFORE any container exists. Use appcrane_get_deploy_log for that.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string' },
        env: { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
        lines: { type: 'number', default: 100, minimum: 1, maximum: 1000 },
        search: { type: 'string', description: 'Filter to lines containing this substring (case-insensitive)' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      const lines = Math.min(args.lines || 100, 1000);
      const { getAppLogs } = await import('./docker.js');
      const logLines = await getAppLogs(app.slug, env, lines, args.search || '');
      return { app: app.slug, env, lines: logLines, count: logLines.length };
    },
  },

  {
    name: 'appcrane_create_app',
    description:
      'Register a new app in AppCrane from a GitHub repository. Use this only after the user has explicitly ' +
      'confirmed they want to onboard a new app and provided a real github URL. ' +
      'Allocates ports, creates the data directories, configures Caddy routing, and starts health checks. ' +
      'After this returns, call appcrane_set_secret to set any required secrets, then appcrane_deploy to ship the first build. ' +
      'Requires the create-apps permission (global admins, or any role a platform admin granted at Settings → Roles).',
    inputSchema: {
      type: 'object',
      properties: {
        name:        { type: 'string', description: 'Display name (shown in dashboard)' },
        slug:        { type: 'string', description: 'URL-safe identifier — lowercase letters, digits, dashes; must start with a letter or digit. Lives at /<slug>/.' },
        github_url:  { type: 'string', description: 'GitHub repo URL, e.g. https://github.com/me/mysite' },
        branch:      { type: 'string', description: 'Branch to track. Default: main', default: 'main' },
        description: { type: 'string' },
        domain:      { type: 'string', description: 'Optional custom domain. If omitted, the app lives under CRANE_DOMAIN/<slug>/.' },
        github_token:    { type: 'string', description: 'GitHub PAT for private repos. Stored encrypted; only used to clone.' },
        max_ram_mb:      { type: 'number', description: 'Per-container memory cap. Default: 512.' },
        max_cpu_percent: { type: 'number', description: 'Per-container CPU cap. Default: 50.' },
      },
      required: ['name', 'slug', 'github_url'],
      additionalProperties: false,
    },
    requiredRole: 'create_app',
    handler: async (user, args) => {
      // Mirror server/routes/apps.js POST / validation rules
      const { name, slug, github_url } = args;
      if (!name || !slug) throw new Error('name and slug are required');
      if (!/^[a-z0-9][a-z0-9-]*$/.test(slug)) throw new Error('slug must be lowercase alphanumeric with dashes');
      if (args.branch && !/^[A-Za-z0-9._/\-]{1,200}$/.test(args.branch)) {
        throw new Error('branch must be alphanumeric with . _ / - (max 200 chars)');
      }
      if (!/^https?:\/\/(www\.)?github\.com\/[A-Za-z0-9_.\-]+\/[A-Za-z0-9_.\-]+(\.git)?\/?$/.test(github_url)) {
        throw new Error('github_url must be a valid github.com URL');
      }

      const db = getDb();
      if (db.prepare('SELECT id FROM apps WHERE slug = ?').get(slug)) {
        throw new Error(`App slug '${slug}' already exists`);
      }

      const { getNextSlot, getPortsForSlot } = await import('./portAllocator.js');
      const { reloadCaddy } = await import('./caddy.js');

      const slot = getNextSlot(db);
      const ports = getPortsForSlot(slot);
      // v2.21.5: only platform admins choose CPU/memory; others get defaults.
      const platAdmin = user.role === 'platform_admin';
      const resourceLimits = JSON.stringify({
        max_ram_mb:      (platAdmin && args.max_ram_mb)      || 512,
        max_cpu_percent: (platAdmin && args.max_cpu_percent) || 50,
      });
      const tokenEncrypted = args.github_token ? encrypt(args.github_token) : null;
      const branch = args.branch || 'main';

      const result = db.prepare(`
        INSERT INTO apps (name, slug, slot, domain, description, category, source_type, github_url, branch, github_token_encrypted, resource_limits, created_by)
        VALUES (?, ?, ?, ?, ?, ?, 'github', ?, ?, ?, ?, ?)
      `).run(name, slug, slot, args.domain || null, args.description || null, null, github_url, branch, tokenEncrypted, resourceLimits, user.id);
      const appId = result.lastInsertRowid;

      for (const env of ['production', 'sandbox']) {
        db.prepare('INSERT INTO health_configs (app_id, env) VALUES (?, ?)').run(appId, env);
        db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(appId, env);
      }
      // Auto-assign creator as both member and owner. The app_user_roles
      // owner row is what makes "⚠ No owner" go away on /applications and
      // gives this user per-app authz boundaries (e.g. the appcrane_*
      // access-management tools). Forgetting it was the v2.5.12 bug.
      db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)').run(appId, user.id);
      db.prepare(`
        INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')
        ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = 'owner'
      `).run(appId, user.id);

      const webhookToken = crypto.randomBytes(16).toString('hex');
      const webhookSecret = crypto.randomBytes(32).toString('hex');
      db.prepare('INSERT INTO webhook_configs (app_id, token, secret) VALUES (?, ?, ?)').run(appId, webhookToken, webhookSecret);

      const dataDir = process.env.DATA_DIR || './data';
      const appDir = join(dataDir, 'apps', slug);
      for (const env of ['production', 'sandbox']) {
        const envDir = join(appDir, env);
        mkdirSync(join(envDir, 'releases'), { recursive: true });
        mkdirSync(join(envDir, 'shared', 'data'), { recursive: true });
      }

      try { await reloadCaddy(); } catch (_) {}
      try {
        const { refreshAppChecks } = await import('./healthChecker.js');
        refreshAppChecks(appId);
      } catch (_) {}

      log.info(`MCP: app '${slug}' created by user ${user.id}`);
      const craneDomain = process.env.CRANE_DOMAIN;
      const urls = craneDomain ? {
        production: `https://${craneDomain}/${slug}`,
        sandbox:    `https://${craneDomain}/${slug}-sandbox`,
      } : null;
      return {
        app: { slug, name, github_url, branch },
        ports,
        urls,
        next: `Set secrets with appcrane_set_secret, then deploy with appcrane_deploy slug="${slug}" stage="sandbox".`,
      };
    },
  },

  {
    name: 'appcrane_update_app',
    description:
      'Patch fields on an existing app. Use this to fix a missing github_url after the fact, change branch, rotate the github_token, retag with category/visibility, or adjust resource limits — anything you would otherwise need direct DB access for. Only includes fields you pass; omitted fields are left alone. To clear a string field pass an empty string. Returns the same shape as appcrane_get_app.',
    inputSchema: {
      type: 'object',
      properties: {
        slug:           { type: 'string', description: 'App slug to update.' },
        name:           { type: 'string' },
        description:    { type: 'string' },
        category:       { type: 'string' },
        domain:         { type: 'string' },
        source_type:    { type: 'string', enum: ['github', 'managed', 'managed_legacy'] },
        github_url:     { type: 'string', description: 'github.com URL of the source repo. Pass empty string to clear.' },
        branch:         { type: 'string' },
        github_token:   { type: 'string', description: 'PAT for private clones. Stored encrypted (AES-256-GCM). Omit to leave the existing token alone; pass empty string to clear it; pass a value to rotate.' },
        visibility:     { type: 'string', enum: ['public', 'private', 'hidden'] },
        public_access:  { type: 'integer', enum: [0, 1] },
        image_retention: { type: 'integer', minimum: 0, maximum: 50 },
        frame_ancestors: { type: 'string' },
        auth_bypass_paths: {
          type: 'array',
          maxItems: 10,
          items: { type: 'string' },
          description: 'v2.7.27: array of path prefixes (e.g. ["/ws/local-runner"]) that bypass SSO forward_auth on this app. Requests under these prefixes reach the container with NO X-AppCrane-* identity headers — the app authenticates them itself (e.g. token in query string). Caddy suppresses access logging for these paths to prevent token leakage to log storage. Pass [] or null to clear.',
        },
        max_ram_mb:      { type: 'number', description: 'Per-container memory cap.' },
        max_cpu_percent: { type: 'number', description: 'Per-container CPU cap (0-100).' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'admin',
    handler: async (user, args) => {
      const { slug } = args;
      if (!slug || typeof slug !== 'string') throw new Error('slug is required');

      const db = getDb();
      const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
      if (!app) throw new Error(`App not found: ${slug}`);

      // Validate any field that's been passed. Mirrors server/routes/apps.js
      // PUT validation; agents calling this through MCP shouldn't be able
      // to bypass the same checks.
      const updates = {};
      if (args.name        !== undefined) {
        if (!args.name || typeof args.name !== 'string') throw new Error('name must be a non-empty string');
        updates.name = args.name;
      }
      if (args.description !== undefined) updates.description = args.description ? String(args.description) : null;
      if (args.category    !== undefined) updates.category    = args.category    ? String(args.category)    : null;
      if (args.domain      !== undefined) {
        // v2.10.0: custom passthrough domain (served at root, no SSO/topbar).
        const { validateCustomDomain } = await import('../utils/customDomain.js');
        updates.domain = validateCustomDomain(args.domain, process.env.CRANE_DOMAIN);
        if (updates.domain) {
          const clash = db.prepare('SELECT slug FROM apps WHERE lower(domain) = ? AND id != ?').get(updates.domain, app.id);
          if (clash) throw new Error(`Domain "${updates.domain}" is already used by app "${clash.slug}"`);
        }
      }
      if (args.source_type !== undefined) updates.source_type = args.source_type;
      if (args.github_url  !== undefined) {
        if (args.github_url && !/^https?:\/\/(www\.)?github\.com\/[A-Za-z0-9_.\-]+\/[A-Za-z0-9_.\-]+(\.git)?\/?$/.test(args.github_url)) {
          throw new Error('github_url must be a valid github.com URL or empty string to clear');
        }
        updates.github_url = args.github_url || null;
      }
      if (args.branch !== undefined) {
        if (args.branch && !/^[A-Za-z0-9._/\-]{1,200}$/.test(args.branch)) {
          throw new Error('branch must be alphanumeric with . _ / - (max 200 chars)');
        }
        updates.branch = args.branch || null;
      }
      // v2.20.2: visibility + public_access stay in lock-step via the shared
      // resolveVisibility helper (visibility wins if both are passed), so this
      // path can't drift from the REST update. Setting one without the other
      // used to leave an app publicly reachable yet catalog-private, which made
      // the launcher prompt users to "Request access" to an already-open app.
      Object.assign(updates, resolveVisibility({ visibility: args.visibility, public_access: args.public_access }));
      if (args.image_retention !== undefined) {
        const n = parseInt(args.image_retention, 10);
        if (!Number.isFinite(n) || n < 0 || n > 50) throw new Error('image_retention must be 0-50');
        updates.image_retention = n;
      }
      if (args.frame_ancestors !== undefined) updates.frame_ancestors = args.frame_ancestors ? String(args.frame_ancestors) : null;
      if (args.auth_bypass_paths !== undefined) {
        const parsed = validateBypassPaths(args.auth_bypass_paths);
        updates.auth_bypass_paths = parsed && parsed.length > 0 ? JSON.stringify(parsed) : null;
      }

      if (args.github_token !== undefined) {
        // '' clears, undefined leaves alone, anything else rotates
        updates.github_token_encrypted = args.github_token ? encrypt(args.github_token) : null;
      }

      if (args.max_ram_mb !== undefined || args.max_cpu_percent !== undefined) {
        // v2.21.5: CPU/memory limits are platform-admin only.
        if (user.role !== 'platform_admin') {
          throw new Error('Only platform admins can change CPU/memory limits.');
        }
        let limits = {};
        try { limits = app.resource_limits ? JSON.parse(app.resource_limits) : {}; } catch (_) {}
        if (args.max_ram_mb      !== undefined) limits.max_ram_mb      = args.max_ram_mb;
        if (args.max_cpu_percent !== undefined) limits.max_cpu_percent = args.max_cpu_percent;
        updates.resource_limits = JSON.stringify(limits);
      }

      const keys = Object.keys(updates);
      if (keys.length === 0) throw new Error('No fields to update — pass at least one field besides slug.');

      const setClause = keys.map(k => `${k} = ?`).join(', ');
      const values    = keys.map(k => updates[k]);
      db.prepare(`UPDATE apps SET ${setClause} WHERE id = ?`).run(...values, app.id);

      log.info(`MCP: app '${slug}' updated by user ${user.id}; fields=${keys.join(',')}`);

      // frame_ancestors / auth_bypass_paths / domain change the Caddyfile.
      // Reload to apply (a custom domain adds/removes a whole site block).
      if ('frame_ancestors' in updates || 'auth_bypass_paths' in updates || 'domain' in updates) {
        try {
          const { reloadCaddy } = await import('./caddy.js');
          await reloadCaddy();
        } catch (e) { log.warn(`MCP set_app_meta: Caddy reload failed (non-fatal): ${e.message}`); }
      }

      // Return the same shape as appcrane_get_app so the agent can verify
      // what landed without a separate get_app round-trip.
      const fresh = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
      const enriched = enrichAppRow(db, fresh);
      let resourceLimits = null;
      try { resourceLimits = fresh.resource_limits ? JSON.parse(fresh.resource_limits) : null; } catch (_) {}
      return {
        ...enriched,
        updated_fields: keys,
        config: {
          source_type:    fresh.source_type,
          github_url:     fresh.github_url,
          branch:         fresh.branch,
          token_set:      !!fresh.github_token_encrypted,
          domain:         fresh.domain,
          category:       fresh.category,
          visibility:     fresh.visibility,
          public_access:  fresh.public_access,
          image_retention: fresh.image_retention,
          frame_ancestors: fresh.frame_ancestors,
          auth_bypass_paths: (() => { try { return fresh.auth_bypass_paths ? JSON.parse(fresh.auth_bypass_paths) : []; } catch (_) { return []; } })(),
          max_ram_mb:      resourceLimits?.max_ram_mb      ?? null,
          max_cpu_percent: resourceLimits?.max_cpu_percent ?? null,
        },
      };
    },
  },

  {
    name: 'appcrane_set_app_meta',
    description:
      'Set an app\'s category, visibility, auth_mode, and/or auth_bypass_paths — the owner self-service fields (same controls the dashboard Launcher exposes to owners). Owner of the app (or global admin) required. visibility is one of public / private / hidden. auth_mode is `authenticated` (default — all routes go through AppCrane SSO) or `headless` (the app bypasses forward_auth ENTIRELY and is reachable without identity — right tool for telemetry ingest, public webhooks, status pages; the app\'s own server is responsible for any payload-level authn). auth_bypass_paths (v2.7.27+) is an array of path prefixes (e.g. ["/ws/local-runner"]) that bypass SSO on this app only — narrower than headless mode; the app authenticates those paths itself (e.g. token in query string). The platform strips incoming X-AppCrane-* headers on bypass paths (forgery defense intact) and suppresses access logging for them (token-in-query never sits in log storage). Owners may only assign an EXISTING category; creating a brand-new category is reserved for global admins. For powerful fields (github_url, branch, token, source_type, resource limits) use appcrane_update_app (admin only).',
    inputSchema: {
      type: 'object',
      properties: {
        slug:       { type: 'string', description: 'App slug.' },
        category:   { type: 'string', description: 'Category/tag. Owners must pick one already in use; pass empty string to clear.' },
        visibility: { type: 'string', enum: ['public', 'private', 'hidden'], description: 'public = anyone; private = assigned users; hidden = not discoverable.' },
        auth_mode:  { type: 'string', enum: ['authenticated', 'headless'], description: 'authenticated = AppCrane SSO + per-app role checks; headless = NO auth at the proxy (the entire app is reachable by anyone on the internet).' },
        auth_bypass_paths: {
          type: 'array',
          maxItems: 10,
          items: { type: 'string' },
          description: 'v2.7.27: array of path prefixes (e.g. ["/ws/local-runner"]) that bypass SSO forward_auth on this app. Requests under these prefixes reach the container with NO X-AppCrane-* identity headers — the app authenticates them itself. Caddy suppresses access logging for these paths to prevent query-string-token leakage. Pass [] or null to clear.',
        },
        domain: {
          type: 'string',
          description: 'v2.10.0: custom domain (e.g. "raise.glick.run") that serves this app at the ROOT of that domain with NO AppCrane SSO and NO topbar — the app does its own auth. Maps to production. Requires the domain\'s DNS to point at this host (Caddy auto-provisions TLS). Pass "" or null to remove. The /<slug> path under the platform domain stays.',
        },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'any', // handler enforces owner-or-admin per-slug
    handler: async (user, args) => {
      const app = getAppForUser(user, args.slug);
      const globalAdmin = isAdmin(user);
      if (!globalAdmin && roleForUserOnApp(user, app) !== 'owner') {
        throw new Error('Forbidden: only the app owner (or a global admin) can change category/visibility/auth_mode/auth_bypass_paths/domain.');
      }
      if (args.category === undefined && args.visibility === undefined && args.auth_mode === undefined && args.auth_bypass_paths === undefined && args.domain === undefined) {
        throw new Error('Pass at least one of category, visibility, auth_mode, auth_bypass_paths, or domain.');
      }
      const db = getDb();
      const updates = {};

      // v2.20.2: shared invariant helper (see resolveVisibility) — no-op when
      // visibility isn't in the patch.
      Object.assign(updates, resolveVisibility({ visibility: args.visibility }));

      if (args.category !== undefined) {
        const newCat = args.category ? String(args.category).trim() : null;
        // Owners can't create new categories — must already exist on an app
        // they can see (public or assigned). Mirrors POST/PUT /api/apps.
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
          `).get(newCat, user.id, user.id);
          if (!exists) throw new Error('Only admins can create new categories — pick an existing one.');
        }
        updates.category = newCat;
      }

      if (args.auth_mode !== undefined) {
        if (!['authenticated', 'headless'].includes(args.auth_mode)) {
          throw new Error("auth_mode must be 'authenticated' or 'headless'");
        }
        updates.auth_mode = args.auth_mode;
      }

      if (args.auth_bypass_paths !== undefined) {
        const parsed = validateBypassPaths(args.auth_bypass_paths);
        updates.auth_bypass_paths = parsed && parsed.length > 0 ? JSON.stringify(parsed) : null;
      }

      if (args.domain !== undefined) {
        const { validateCustomDomain } = await import('../utils/customDomain.js');
        updates.domain = validateCustomDomain(args.domain, process.env.CRANE_DOMAIN);
        if (updates.domain) {
          const clash = db.prepare('SELECT slug FROM apps WHERE lower(domain) = ? AND id != ?').get(updates.domain, app.id);
          if (clash) throw new Error(`Domain "${updates.domain}" is already used by app "${clash.slug}"`);
        }
      }

      const keys = Object.keys(updates);
      const setClause = keys.map(k => `${k} = ?`).join(', ');
      db.prepare(`UPDATE apps SET ${setClause} WHERE id = ?`).run(...keys.map(k => updates[k]), app.id);

      // v2.7.22: auth_mode flips the Caddy block shape (forward_auth on/off);
      // v2.7.28: auth_bypass_paths emits inner handle blocks; v2.10.0: domain
      // adds/removes a whole custom-domain site. Reload Caddy when any change.
      if ('auth_mode' in updates || 'auth_bypass_paths' in updates || 'domain' in updates) {
        try {
          const { reloadCaddy } = await import('./caddy.js');
          await reloadCaddy();
        } catch (e) { log.warn(`Caddy reload after meta change failed: ${e.message}`); }
      }

      log.info(`MCP: app '${app.slug}' meta updated by user ${user.id}; fields=${keys.join(',')}`);
      const fresh = db.prepare('SELECT category, visibility, public_access, auth_mode, auth_bypass_paths FROM apps WHERE id = ?').get(app.id);
      let bypassPaths = [];
      try { bypassPaths = fresh.auth_bypass_paths ? JSON.parse(fresh.auth_bypass_paths) : []; } catch (_) {}
      return {
        app: app.slug,
        category: fresh.category,
        visibility: fresh.visibility,
        public_access: fresh.public_access,
        auth_mode: fresh.auth_mode,
        auth_bypass_paths: bypassPaths,
        updated_fields: keys,
      };
    },
  },

  {
    name: 'appcrane_list_app_members',
    description:
      'List every user who has access to an app, with their per-app role (owner / admin / user / viewer / none). Use this before granting or revoking to see who is already in. Returns email + name + role for each member. App-admin or owner of the app required (or global admin / platform_admin).',
    inputSchema: {
      type: 'object',
      properties: { slug: { type: 'string' } },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const app = getAppForUser(user, args.slug);
      if (!isAppAdmin(user, app)) {
        // Owners are accepted by isAppAdmin in v2.3.x; this guards against
        // a regular user reading the full member roster.
        const db = getDb();
        const row = db.prepare("SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?").get(app.id, user.id);
        if (row?.app_role !== 'owner') throw new Error('Forbidden: only app admins / owners can list members');
      }
      const db = getDb();
      const rows = db.prepare(`
        SELECT u.id, u.name, u.email, u.username, COALESCE(aur.app_role, 'none') AS role
        FROM users u
        LEFT JOIN app_user_roles aur ON aur.user_id = u.id AND aur.app_id = ?
        WHERE u.active = 1
          AND (aur.app_id IS NOT NULL OR EXISTS (SELECT 1 FROM app_users au WHERE au.app_id = ? AND au.user_id = u.id))
        ORDER BY
          CASE COALESCE(aur.app_role, 'none')
            WHEN 'owner' THEN 0 WHEN 'admin' THEN 1
            WHEN 'user'  THEN 2 WHEN 'viewer' THEN 3 ELSE 4
          END, u.name
      `).all(app.id, app.id);
      return { app: app.slug, members: rows };
    },
  },

  {
    name: 'appcrane_grant_app_access',
    description:
      'Grant a user access to an app at a specific per-app role. `user` accepts a numeric user id, an email, or a username — first match wins. role defaults to "user". Idempotent: existing rows are upgraded/downgraded to the new role. App-admin or owner of the app required (or global admin).',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string' },
        user: { type: 'string', description: 'User id (numeric string), email, or username' },
        role: { type: 'string', enum: ['user', 'admin', 'owner'], default: 'user' },
      },
      required: ['slug', 'user'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const app = getAppForUser(user, args.slug);
      if (!isAppAdmin(user, app)) {
        const db = getDb();
        const r = db.prepare("SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?").get(app.id, user.id);
        if (r?.app_role !== 'owner') throw new Error('Forbidden: only app admins / owners can grant access');
      }
      const role = args.role || 'user';
      if (!['user', 'admin', 'owner'].includes(role)) {
        throw new Error('role must be one of: user, admin, owner');
      }
      const db = getDb();
      const target = db.prepare(`
        SELECT id, name, email, username FROM users
        WHERE active = 1 AND (CAST(id AS TEXT) = ? OR email = ? OR username = ?)
        LIMIT 1
      `).get(args.user, args.user, args.user);
      if (!target) throw new Error(`User not found: ${args.user}`);

      // Both tables: app_users (membership) + app_user_roles (role).
      // getAppForUser walks both, so we keep them in sync.
      db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)').run(app.id, target.id);
      db.prepare(`
        INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)
        ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = excluded.app_role
      `).run(app.id, target.id, role);

      log.info(`MCP: granted ${role} on ${app.slug} to user ${target.id} by ${user.id}`);
      return { app: app.slug, user: { id: target.id, name: target.name, email: target.email }, role };
    },
  },

  {
    name: 'appcrane_revoke_app_access',
    description:
      'Remove a user\'s access from an app entirely. Idempotent: returns ok even if the user had no access. App-admin or owner of the app required (or global admin). Refuses to remove the only remaining owner.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string' },
        user: { type: 'string', description: 'User id, email, or username' },
      },
      required: ['slug', 'user'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const app = getAppForUser(user, args.slug);
      if (!isAppAdmin(user, app)) {
        const db = getDb();
        const r = db.prepare("SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?").get(app.id, user.id);
        if (r?.app_role !== 'owner') throw new Error('Forbidden: only app admins / owners can revoke access');
      }
      const db = getDb();
      const target = db.prepare(`
        SELECT id, name, email FROM users WHERE active = 1
          AND (CAST(id AS TEXT) = ? OR email = ? OR username = ?) LIMIT 1
      `).get(args.user, args.user, args.user);
      if (!target) throw new Error(`User not found: ${args.user}`);

      // Owner-protection: refuse to remove the last owner — would leave
      // the app un-ownable. Caller must promote a different user first.
      const cur = db.prepare("SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?").get(app.id, target.id);
      if (cur?.app_role === 'owner') {
        const ownerCount = db.prepare("SELECT COUNT(*) AS c FROM app_user_roles WHERE app_id = ? AND app_role = 'owner'").get(app.id).c;
        if (ownerCount <= 1) {
          throw new Error(`Refusing to revoke: ${target.email || target.id} is the only owner of ${app.slug}. Promote another user first.`);
        }
      }

      const r1 = db.prepare('DELETE FROM app_user_roles WHERE app_id = ? AND user_id = ?').run(app.id, target.id);
      const r2 = db.prepare('DELETE FROM app_users      WHERE app_id = ? AND user_id = ?').run(app.id, target.id);

      log.info(`MCP: revoked access on ${app.slug} from user ${target.id} by ${user.id}`);
      return { app: app.slug, user: { id: target.id, email: target.email }, removed: { roles: r1.changes, members: r2.changes } };
    },
  },

  {
    name: 'appcrane_list_access_requests',
    description:
      'List pending access requests — enhancement_requests rows whose message starts with "Access request for app …" (the portal\'s Request-access button posts these). With slug, scopes to one app; without, returns access requests across every app the caller can administer. App-admin / owner / global admin required.',
    inputSchema: {
      type: 'object',
      properties: { slug: { type: 'string', description: 'Optional. Limit to one app.' } },
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const db = getDb();
      // Determine which slugs the caller can administer. Global admins get
      // every slug; otherwise only slugs where they are owner / admin.
      let scopedSlugs;
      if (isAdmin(user)) {
        scopedSlugs = null; // null = unrestricted
      } else {
        scopedSlugs = db.prepare(`
          SELECT DISTINCT a.slug FROM apps a
          JOIN app_user_roles aur ON aur.app_id = a.id AND aur.user_id = ?
          WHERE aur.app_role IN ('owner', 'admin')
        `).all(user.id).map(r => r.slug);
        if (scopedSlugs.length === 0) return { requests: [], count: 0 };
      }

      let where = "er.status != 'done' AND er.message LIKE 'Access request for app%'";
      const params = [];
      if (args.slug) {
        where += ' AND er.app_slug = ?';
        params.push(args.slug);
      }
      if (scopedSlugs) {
        const placeholders = scopedSlugs.map(() => '?').join(',');
        where += ` AND er.app_slug IN (${placeholders})`;
        params.push(...scopedSlugs);
      }

      const rows = db.prepare(`
        SELECT er.id, er.app_slug, er.user_id, er.user_name, er.message, er.status, er.created_at
        FROM enhancement_requests er
        WHERE ${where}
        ORDER BY er.created_at DESC
        LIMIT 100
      `).all(...params);

      return { requests: rows, count: rows.length };
    },
  },

  {
    name: 'appcrane_approve_access_request',
    description:
      'Approve a pending access request: grants the requester access to the app at `role` (default "user") and marks the enhancement_request as done. Verifies the request is actually an access request before acting. App-admin / owner / global admin required.',
    inputSchema: {
      type: 'object',
      properties: {
        request_id: { type: 'integer', description: 'enhancement_requests.id from appcrane_list_access_requests' },
        role:       { type: 'string', enum: ['user', 'admin', 'owner'], default: 'user' },
      },
      required: ['request_id'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const db = getDb();
      const req = db.prepare('SELECT * FROM enhancement_requests WHERE id = ?').get(args.request_id);
      if (!req) throw new Error(`Request ${args.request_id} not found`);
      if (!/^Access request for app/i.test(req.message || '')) {
        throw new Error(`Request ${args.request_id} is not an access request — refusing to grant`);
      }
      if (req.status === 'done') throw new Error(`Request ${args.request_id} is already closed`);

      const app = getAppForUser(user, req.app_slug);
      if (!isAppAdmin(user, app)) {
        const r = db.prepare("SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?").get(app.id, user.id);
        if (r?.app_role !== 'owner') throw new Error('Forbidden: only app admins / owners can approve access');
      }

      const role = args.role || 'user';
      db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)').run(app.id, req.user_id);
      db.prepare(`
        INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)
        ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = excluded.app_role
      `).run(app.id, req.user_id, role);
      db.prepare("UPDATE enhancement_requests SET status = 'done' WHERE id = ?").run(req.id);

      log.info(`MCP: approved access request #${req.id} → ${role} on ${app.slug} for user ${req.user_id} by ${user.id}`);
      return {
        request_id: req.id,
        app: app.slug,
        granted_to: { id: req.user_id, name: req.user_name },
        role,
        status: 'approved',
      };
    },
  },

  {
    name: 'appcrane_deny_access_request',
    description:
      'Deny a pending access request: marks the enhancement_request as done WITHOUT granting access. Optionally appends a reason to the original message so the requester (and the audit trail) sees why. App-admin / owner / global admin required.',
    inputSchema: {
      type: 'object',
      properties: {
        request_id: { type: 'integer' },
        reason:     { type: 'string', description: 'Optional. Appended to the request message.' },
      },
      required: ['request_id'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const db = getDb();
      const req = db.prepare('SELECT * FROM enhancement_requests WHERE id = ?').get(args.request_id);
      if (!req) throw new Error(`Request ${args.request_id} not found`);
      if (!/^Access request for app/i.test(req.message || '')) {
        throw new Error(`Request ${args.request_id} is not an access request`);
      }
      if (req.status === 'done') throw new Error(`Request ${args.request_id} is already closed`);

      const app = getAppForUser(user, req.app_slug);
      if (!isAppAdmin(user, app)) {
        const r = db.prepare("SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?").get(app.id, user.id);
        if (r?.app_role !== 'owner') throw new Error('Forbidden: only app admins / owners can deny access');
      }

      const newMessage = args.reason
        ? `${req.message}\n\n[DENIED by ${user.email || user.username || user.id} on ${new Date().toISOString().slice(0, 19).replace('T', ' ')}]\n${args.reason}`
        : req.message;
      db.prepare("UPDATE enhancement_requests SET status = 'done', message = ? WHERE id = ?").run(newMessage, req.id);

      log.info(`MCP: denied access request #${req.id} on ${app.slug} by ${user.id}`);
      return { request_id: req.id, app: app.slug, status: 'denied', reason: args.reason || null };
    },
  },

  {
    name: 'appcrane_set_app_icon',
    description:
      'Set the tile icon for an app (shown on the Dashboard, the Launcher cards, the Manage table, and the frame topbar). Accepts a base64-encoded image in PNG / SVG / WEBP / JPEG / GIF. ' +
      'For repo-tracked icons prefer committing public/icon.png to the repo — AppCrane picks it up automatically on each deploy. Use this MCP tool when the icon needs to change without a redeploy, or when the source isn\'t in the repo. ' +
      'Replaces any existing icon. App-admin or owner required (or global admin).',
    inputSchema: {
      type: 'object',
      properties: {
        slug:    { type: 'string', description: 'App slug.' },
        format:  { type: 'string', enum: ['png', 'svg', 'webp', 'jpg', 'jpeg', 'gif'], description: 'Image format. Determines the on-disk file extension (icon.<format>).' },
        base64:  { type: 'string', description: 'Base64-encoded image payload. May or may not include the data URL prefix (data:image/png;base64,…) — both work. Max 500 KB decoded.' },
      },
      required: ['slug', 'format', 'base64'],
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (user, args) => {
      const app = getAppForUser(user, args.slug);
      if (!isAppAdmin(user, app)) {
        const db = getDb();
        const r = db.prepare("SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?").get(app.id, user.id);
        if (r?.app_role !== 'owner') throw new Error('Forbidden: only app admins / owners can set the app icon');
      }

      const ext = String(args.format || '').toLowerCase();
      const ICON_EXTS = ['png', 'svg', 'webp', 'jpg', 'jpeg', 'gif'];
      if (!ICON_EXTS.includes(ext)) throw new Error(`format must be one of: ${ICON_EXTS.join(', ')}`);

      // Strip an optional data-URL prefix so callers can paste either form.
      let raw = String(args.base64 || '').trim();
      const m = raw.match(/^data:[^;]+;base64,(.+)$/i);
      if (m) raw = m[1];
      if (!raw) throw new Error('base64 payload is empty');

      let buf;
      try { buf = Buffer.from(raw, 'base64'); } catch (e) { throw new Error(`base64 decode failed: ${e.message}`); }
      const MAX_BYTES = 500 * 1024;
      if (buf.length === 0)        throw new Error('decoded payload is empty');
      if (buf.length > MAX_BYTES)  throw new Error(`icon too large (${buf.length} bytes > ${MAX_BYTES} cap)`);

      const { writeFileSync, unlinkSync, existsSync, mkdirSync } = await import('fs');
      const { join } = await import('path');
      const dataDir = process.env.DATA_DIR || './data';
      const appIconDir = join(dataDir, 'apps', app.slug);
      mkdirSync(appIconDir, { recursive: true });

      // Wipe stale-extension siblings so the GET endpoint doesn't keep
      // serving an old icon under a different extension. Mirrors what
      // the POST /api/apps/:slug/icon upload endpoint does.
      for (const oldExt of ICON_EXTS) {
        if (oldExt === ext) continue;
        const oldPath = join(appIconDir, `icon.${oldExt}`);
        if (existsSync(oldPath)) { try { unlinkSync(oldPath); } catch (_) {} }
      }

      const destPath = join(appIconDir, `icon.${ext}`);
      writeFileSync(destPath, buf);

      log.info(`MCP: app icon updated for ${app.slug} (${ext}, ${buf.length} bytes) by user ${user.id}`);
      return {
        app: app.slug,
        format: ext,
        size_bytes: buf.length,
        url: `/api/apps/${app.slug}/icon`,
      };
    },
  },

  {
    name: 'appcrane_get_guide',
    description:
      'Fetch the latest AppCrane playbook on a given topic. Use this at the START of any non-trivial workflow so you operate on the current authoritative guidance, not on whatever you remember from a past session. Topics: "onboarding" = the full new-app onboarding playbook (paths a/b/c/d, health-endpoint contract, common pitfalls). "operations" = the comprehensive agent operations guide (deploy, env, logs, rollback, every appcrane_* tool). "email" = how a hosted app sends email through AppCrane (the /api/service/email endpoint, env vars, recipient rules). Topic defaults to "onboarding" if omitted. Returns markdown.',
    inputSchema: {
      type: 'object',
      properties: {
        topic: {
          type: 'string',
          enum: ['onboarding', 'operations', 'email'],
          description: 'Which guide to fetch. Default: onboarding.',
        },
      },
      additionalProperties: false,
    },
    requiredRole: 'any',
    handler: async (_user, args) => {
      const topic = ['operations', 'email'].includes(args.topic) ? args.topic : 'onboarding';
      const { readFileSync, existsSync } = await import('fs');
      const { join, dirname } = await import('path');
      const { fileURLToPath } = await import('url');
      const __dirname = dirname(fileURLToPath(import.meta.url));

      // v2.5.24: both guides now live in server/services/guides/. The
      // legacy AGENT_GUIDE.md at the repo root was retired along with
      // its REST/curl examples — AppCrane is MCP-only for agents now.
      const path = join(__dirname, 'guides', `${topic}.md`);
      if (!existsSync(path)) throw new Error(`Guide '${topic}' not found on this AppCrane install`);

      let content = readFileSync(path, 'utf8');
      // Substitute {{HOST}} placeholder with the configured CRANE_DOMAIN so
      // the agent sees the right host in its instructions. Falls back to a
      // generic phrasing when CRANE_DOMAIN is unset.
      const host = process.env.CRANE_DOMAIN || 'your AppCrane host';
      content = content.replace(/\{\{HOST\}\}/g, host);

      return {
        topic,
        host,
        markdown: content,
        bytes: Buffer.byteLength(content, 'utf8'),
      };
    },
  },

  {
    name: 'appcrane_create_managed_app',
    description:
      'Create a new app using AppCrane\'s GitHub service-account — the platform creates a repo on the configured org/user, owns it, and the agent works against it through github_* tools without the end user ever needing their own PAT. Use this when the user does not have a GitHub account or does not want to deal with GitHub at all. Requires the platform admin to have configured the service-account in Settings → GitHub. Returns the same shape as appcrane_create_app, plus the auto-created repo metadata. IDEMPOTENT RECOVERY: if the slug already exists as a managed app but its AMC_ repo was never created (a half-created app from an earlier failure — push then returns REPO_NOT_FOUND), calling this again re-provisions the missing repo and returns { repaired: true } instead of erroring. So if a create attempt half-failed, just call it again with the same slug. Owner-or-admin to repair an existing one.',
    inputSchema: {
      type: 'object',
      properties: {
        name:        { type: 'string', description: 'Display name (human-readable)' },
        slug:        { type: 'string', description: 'URL slug, lowercase-alphanumeric-with-dashes. Becomes the repo name.' },
        description: { type: 'string', description: 'Optional. Used as both app description and repo description.' },
        branch:      { type: 'string', description: 'Default branch for the new repo. Defaults to "main".' },
        domain:      { type: 'string', description: 'Optional custom domain.' },
        max_ram_mb:      { type: 'number', description: 'Per-container memory cap. Default: 512.' },
        max_cpu_percent: { type: 'number', description: 'Per-container CPU cap. Default: 50.' },
      },
      required: ['name', 'slug'],
      additionalProperties: false,
    },
    requiredRole: 'create_app',
    handler: async (user, args) => {
      const { name, slug } = args;
      if (!name || !slug) throw new Error('name and slug are required');
      if (!/^[a-z0-9][a-z0-9-]*$/.test(slug)) throw new Error('slug must be lowercase alphanumeric with dashes');
      if (args.branch && !/^[A-Za-z0-9._/\-]{1,200}$/.test(args.branch)) {
        throw new Error('branch must be alphanumeric with . _ / - (max 200 chars)');
      }

      const db = getDb();
      const { createAppRepo, getServiceConfig } = await import('./githubService.js');
      const cfg = getServiceConfig();
      if (!cfg.enabled) throw new Error('GitHub service-account is disabled. Enable it in Settings → GitHub before using managed mode.');
      if (!cfg.configured) throw new Error('GitHub service-account has no token. Configure it in Settings → GitHub before using managed mode.');

      // v2.10.4: self-heal a half-created managed app. If an earlier attempt
      // wrote the app row but never landed the AMC_ repo (e.g. it died on a
      // 401 mid-provision), the app is stuck: create says "slug exists", push
      // says REPO_NOT_FOUND, and there's no MCP delete. Re-calling this tool
      // now RE-PROVISIONS the missing repo instead of erroring — idempotent
      // recovery the agent can drive itself.
      const existing = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
      if (existing) {
        if (existing.source_type !== 'managed') {
          throw new Error(`App slug '${slug}' already exists (source_type='${existing.source_type}'). Pick a different slug.`);
        }
        if (!isAdmin(user) && roleForUserOnApp(user, existing) !== 'owner') {
          throw new Error(`App slug '${slug}' already exists and you are not its owner.`);
        }
        let repaired;
        try {
          repaired = await createAppRepo(slug, { description: args.description || existing.description || '' });
        } catch (e) {
          if (/REPO_EXISTS/.test(e.message)) {
            throw new Error(`App '${slug}' already exists and its AMC_ repo is provisioned — nothing to repair. Use appcrane_push_to_managed_app + appcrane_deploy.`);
          }
          throw new Error(`Failed to re-provision repo for '${slug}': ${e.message}`);
        }
        db.prepare("UPDATE apps SET github_url = ?, branch = COALESCE(NULLIF(branch, ''), ?), source_type = 'managed' WHERE id = ?")
          .run(repaired.html_url, repaired.default_branch || 'main', existing.id);
        log.info(`MCP: repaired half-created managed app '${slug}' — re-provisioned ${repaired.full_name || repaired.name} by user ${user.id}`);
        return {
          app: slug,
          repaired: true,
          repo: { name: repaired.name, html_url: repaired.html_url, default_branch: repaired.default_branch },
          next: `Repo (re)provisioned. Next: appcrane_push_to_managed_app slug="${slug}" files=[…], then appcrane_deploy slug="${slug}" stage="sandbox".`,
        };
      }

      // Create the GitHub repo first — if this fails (token misconfigured,
      // owner is wrong, slug collides), bail before touching the DB so we
      // don't leave half-baked apps behind.

      let repo;
      try {
        repo = await createAppRepo(slug, { description: args.description || '' });
      } catch (e) {
        throw new Error(`Failed to create managed repo for '${slug}': ${e.message}`);
      }

      const { getNextSlot, getPortsForSlot } = await import('./portAllocator.js');
      const { reloadCaddy } = await import('./caddy.js');

      const slot = getNextSlot(db);
      const ports = getPortsForSlot(slot);
      // v2.21.5: only platform admins choose CPU/memory; others get defaults.
      const platAdmin = user.role === 'platform_admin';
      const resourceLimits = JSON.stringify({
        max_ram_mb:      (platAdmin && args.max_ram_mb)      || 512,
        max_cpu_percent: (platAdmin && args.max_cpu_percent) || 50,
      });
      const branch = args.branch || repo.default_branch || 'main';

      const result = db.prepare(`
        INSERT INTO apps (name, slug, slot, domain, description, category, source_type, github_url, branch, github_token_encrypted, resource_limits, created_by)
        VALUES (?, ?, ?, ?, ?, ?, 'managed', ?, ?, NULL, ?, ?)
      `).run(name, slug, slot, args.domain || null, args.description || null, null, repo.html_url, branch, resourceLimits, user.id);
      const appId = result.lastInsertRowid;

      for (const env of ['production', 'sandbox']) {
        db.prepare('INSERT INTO health_configs (app_id, env) VALUES (?, ?)').run(appId, env);
        db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(appId, env);
      }
      // Auto-assign creator as both member and owner. The app_user_roles
      // owner row is what makes "⚠ No owner" go away on /applications and
      // gives this user per-app authz boundaries (e.g. the appcrane_*
      // access-management tools). Forgetting it was the v2.5.12 bug.
      db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)').run(appId, user.id);
      db.prepare(`
        INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')
        ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = 'owner'
      `).run(appId, user.id);

      const webhookToken = crypto.randomBytes(16).toString('hex');
      const webhookSecret = crypto.randomBytes(32).toString('hex');
      db.prepare('INSERT INTO webhook_configs (app_id, token, secret) VALUES (?, ?, ?)').run(appId, webhookToken, webhookSecret);

      const dataDir = process.env.DATA_DIR || './data';
      const appDir = join(dataDir, 'apps', slug);
      for (const env of ['production', 'sandbox']) {
        const envDir = join(appDir, env);
        mkdirSync(join(envDir, 'releases'), { recursive: true });
        mkdirSync(join(envDir, 'shared', 'data'), { recursive: true });
      }

      try { await reloadCaddy(); } catch (_) {}
      try {
        const { refreshAppChecks } = await import('./healthChecker.js');
        refreshAppChecks(appId);
      } catch (_) {}

      log.info(`MCP: managed app '${slug}' created by user ${user.id}; repo=${repo.full_name}`);
      const craneDomain = process.env.CRANE_DOMAIN;
      const urls = craneDomain ? {
        production: `https://${craneDomain}/${slug}`,
        sandbox:    `https://${craneDomain}/${slug}-sandbox`,
      } : null;
      return {
        app: { slug, name, github_url: repo.html_url, branch, source_type: 'managed' },
        repo: {
          full_name:      repo.full_name,
          html_url:       repo.html_url,
          clone_url:      repo.clone_url,
          default_branch: repo.default_branch,
          private:        repo.private,
          owner_type:     repo.owner_type,
        },
        ports,
        urls,
        next: `Push scaffolding via appcrane_push_to_managed_app slug="${slug}" files=[…], then appcrane_deploy slug="${slug}" stage="sandbox". Do NOT use github_push_files for this repo — that's authed with the user's PAT and has zero access to the service account.`,
      };
    },
  },

  {
    name: 'appcrane_push_to_managed_app',
    description:
      'Push a batch of files to a managed app\'s AMC_<slug> repo, authenticated server-side via AppCrane\'s service-account credential. Use this — NOT github_push_files — for managed apps, because github_* tools authenticate with the caller\'s personal PAT, which has zero access to the service account\'s repos. Multiple files become a single commit. files: [{ path, content, encoding? }] where encoding defaults to "utf-8" (use "base64" for binaries like icons). Requires the app to already exist via appcrane_create_managed_app. v2.7.22: response now includes per-file `sha256` (hex) and decoded `bytes` length so you can verify integrity — compute the SHA-256 of the bytes you sent, compare to the server\'s echo, and fail loudly if they differ. Essential for binary files where inline-string truncation or trailing-byte issues would otherwise produce a silently-broken commit. ' +
      'v2.10.7: for a large CODE file, do NOT inline it — upload the bytes over HTTP and commit by token. (1) ' + '`' + 'curl -F file=@big.js -H "X-API-Key: <your dhk_mcp_ key>" https://<host>/api/files/staged' + '`' + ' returns { token, sha256, size_bytes }. (2) Pass that file as { path, staged_token } instead of { path, content }. The server reads the staged bytes and commits them verbatim, so 100+ KB sources push reliably without the model having to emit the content (which is where inline truncation comes from). Per file, provide exactly one of content or staged_token. Staged tokens are owner-scoped and expiring.',
    inputSchema: {
      type: 'object',
      properties: {
        slug:    { type: 'string', description: 'Managed app slug. Repo name resolved as AMC_<slug>.' },
        files:   {
          type: 'array',
          minItems: 1,
          maxItems: 200,
          items: {
            type: 'object',
            properties: {
              path:         { type: 'string', description: 'Repo-relative path (no leading slash, no ..)' },
              content:      { type: 'string', description: 'Inline file content. For binary, base64-encode and set encoding="base64". Omit when using staged_token.' },
              encoding:     { type: 'string', enum: ['utf-8', 'base64'], description: 'Defaults to utf-8. Ignored when staged_token is used (staged bytes are committed as-is).' },
              staged_token: { type: 'string', description: 'Token from POST /api/files/staged. Commits the uploaded bytes verbatim — use instead of content for large code files. Exactly one of content / staged_token per file.' },
            },
            required: ['path'],
            additionalProperties: false,
          },
        },
        message: { type: 'string', description: 'Commit message. Defaults to "chore: scaffolding for <slug>".' },
        branch:  { type: 'string', description: 'Target branch. Defaults to the repo\'s default branch (usually "main").' },
      },
      required: ['slug', 'files'],
      additionalProperties: false,
    },
    // v2.7.0: was 'admin' — that blocked the non-admin path (d) flow, where a
    // user granted platform.create_app calls appcrane_create_managed_app (now
    // create_app-gated), becomes owner, and then needs to push scaffolding.
    // app_admin matches set_env; getAppForUser + isAppAdmin enforce per-slug
    // ownership.
    requiredRole: 'app_admin',
    handler: async (user, args) => {
      const app = getAppForUser(user, args.slug);
      if (!isAppAdmin(user, app)) throw new Error('Forbidden: pushing to a managed repo requires admin or app-admin role');
      if (app.source_type !== 'managed') {
        throw new Error(`App '${app.slug}' is source_type='${app.source_type || 'github'}' — appcrane_push_to_managed_app only works for source_type='managed' apps. For regular GitHub apps, use the github_* MCP tools with your X-Github-Token.`);
      }
      // v2.10.7: a file entry may carry { staged_token } instead of inline
      // { content }. Resolve each token to its HTTP-uploaded bytes (POST
      // /api/files/staged) so large code files commit reliably without the
      // model emitting them verbatim. Same owner/expiry checks as
      // appcrane_push_staged_file; consumed rows are reaped after the commit.
      const db = getDb();
      const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
      const consumedTokens = [];
      let resolvedFiles = args.files;
      if (args.files.some((f) => typeof f.staged_token === 'string' && f.staged_token)) {
        const { readFileSync } = await import('fs');
        resolvedFiles = args.files.map((f) => {
          const hasInline = typeof f.content === 'string';
          const hasStaged = typeof f.staged_token === 'string' && f.staged_token.length > 0;
          if (hasStaged && hasInline) throw new Error(`File '${f.path}': provide either content or staged_token, not both`);
          if (!hasStaged && !hasInline) throw new Error(`File '${f.path}': must provide content or staged_token`);
          if (!hasStaged) return { path: f.path, content: f.content, encoding: f.encoding };

          const row = db.prepare('SELECT * FROM staged_files WHERE token = ?').get(f.staged_token);
          if (!row)                    throw new Error(`File '${f.path}': staged file not found (token unknown or already swept)`);
          if (row.user_id !== user.id) throw new Error(`File '${f.path}': staged file is owned by a different user`);
          if (row.pushed_at)           throw new Error(`File '${f.path}': staged file was already consumed`);
          if (row.expires_at < now)    throw new Error(`File '${f.path}': staged file expired at ${row.expires_at}`);
          let buf;
          try { buf = readFileSync(row.scratch_path); } catch (e) { throw new Error(`File '${f.path}': cannot read staged bytes: ${e.message}`); }
          consumedTokens.push(row);
          return { path: f.path, content: buf.toString('base64'), encoding: 'base64' };
        });
      }

      const { pushFilesToManagedRepo } = await import('./githubService.js');
      const result = await pushFilesToManagedRepo(app.slug, resolvedFiles, {
        message: args.message,
        branch:  args.branch || app.branch,
      });
      // v2.10.2: record the SHA we just authored+pushed so the next deploy's
      // supply-chain verify can compare the clone HEAD to THIS, not to GitHub's
      // lagging branch-API HEAD (read-after-write race on the mirror push).
      if (result?.commit?.sha && /^[0-9a-f]{40}$/.test(result.commit.sha)) {
        db.prepare('UPDATE apps SET last_managed_push_sha = ? WHERE id = ?').run(result.commit.sha, app.id);
      }
      // v2.10.7: mark consumed staged rows + free their scratch dirs now the
      // commit landed (the 5-min sweeper would catch them at expiry anyway).
      if (consumedTokens.length) {
        const { rmSync } = await import('fs');
        const { dirname } = await import('path');
        for (const row of consumedTokens) {
          try { rmSync(dirname(row.scratch_path), { recursive: true, force: true }); } catch (_) { /* sweeper retries */ }
          try { db.prepare("UPDATE staged_files SET pushed_at = datetime('now') WHERE token = ?").run(row.token); } catch (_) {}
        }
      }
      log.info(`MCP: pushed ${result.files.length} file(s) to managed repo AMC_${app.slug} (commit ${result.commit.sha.slice(0, 7)}) by user ${user.id}${consumedTokens.length ? ` [${consumedTokens.length} staged]` : ''}`);
      return {
        app:     app.slug,
        commit:  result.commit,
        branch:  result.branch,
        files:   result.files,
        message: result.message,
        next:    `Files pushed. Next: appcrane_deploy slug="${app.slug}" stage="sandbox" to ship.`,
      };
    },
  },

  {
    name: 'appcrane_set_secret',
    description:
      'Set or update a secret (an encrypted environment variable injected into the app). Encrypted at rest; only the running app process can read the plaintext. ' +
      'Defaults to sandbox; require explicit stage="production" only when the user asks. ' +
      'App-admin or AppCrane admin only. Respects the caller\'s mcp_app_scope.',
    inputSchema: {
      type: 'object',
      properties: {
        slug:  { type: 'string' },
        env:   { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
        key:   { type: 'string', description: 'Env var name. Letters, digits, underscores; must not start with a digit.' },
        value: { type: 'string', description: 'The value to store (will be encrypted server-side).' },
      },
      required: ['slug', 'key', 'value'],
      additionalProperties: false,
    },
    requiredRole: 'app_admin',
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      if (!isAppAdmin(user, app)) throw new Error('Forbidden: setting env vars requires admin or app-admin role');
      if (!/^[A-Z_][A-Z0-9_]*$/i.test(args.key)) {
        throw new Error(`Invalid env var key: ${args.key} (must match /^[A-Z_][A-Z0-9_]*$/i)`);
      }
      const db = getDb();
      const encrypted = encrypt(String(args.value));
      db.prepare(`
        INSERT INTO env_vars (app_id, env, key, value_encrypted, updated_by, updated_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(app_id, env, key) DO UPDATE SET
          value_encrypted = excluded.value_encrypted,
          updated_by = excluded.updated_by,
          updated_at = excluded.updated_at
      `).run(app.id, env, args.key, encrypted, user.id);
      log.info(`MCP: env var ${args.key} set on ${app.slug}/${env} by user ${user.id}`);
      return { app: app.slug, env, key: args.key, ok: true };
    },
  },

  {
    name: 'appcrane_cp',
    description:
      'Copy/upload a file straight into the app\'s persistent /data volume on the host (aliases: appcrane_upload, appcrane_set_data_blob) — single hop, no container round-trip, no GitHub round-trip, no inline size ceiling. The bytes land at /data/apps/<slug>/<env>/shared/data/<path>, which is the SAME path the running container sees mounted as /data/<path>. Right tool for multi-MB datasets, large fixtures, or anything where appcrane_push_to_managed_app\'s tool-arg ceiling would force chunking. Returns the SHA-256 + byte count of what was stored so the caller can verify integrity. App-admin or owner of the app required. NEVER returns secrets in the response. Path must be repo-relative, no `..`, no leading slash.',
    inputSchema: {
      type: 'object',
      properties: {
        slug:     { type: 'string', description: 'App slug.' },
        env:      { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox', description: 'Which env\'s /data volume to write to.' },
        path:     { type: 'string', description: 'Path within /data, e.g. "datasets/threats.json" or "cache/build.tar.gz". No leading slash, no "..".' },
        content:  { type: 'string', description: 'The data to write. utf-8 string or base64-encoded bytes depending on encoding.' },
        encoding: { type: 'string', enum: ['utf-8', 'base64'], default: 'utf-8', description: 'Defaults to utf-8. Use base64 for binary blobs.' },
      },
      required: ['slug', 'path', 'content'],
      additionalProperties: false,
    },
    requiredRole: 'app_admin',
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      if (!isAppAdmin(user, app)) throw new Error('Forbidden: writing to /data requires admin or app-admin role on this app');

      // Path validation — repo-relative, no traversal, no absolute. resolveSafe
      // verifies the final path is within the shared/data root after symlink
      // expansion (same primitive deployer.js uses).
      const rel = String(args.path || '').trim();
      if (!rel) throw new Error('path is required');
      if (rel.startsWith('/')) throw new Error('path must NOT start with "/" — it is relative to /data');
      if (rel.split('/').some(seg => seg === '..' || seg === '.')) {
        throw new Error('path must not contain "." or ".." segments');
      }

      const { mkdirSync, writeFileSync } = await import('fs');
      const { resolve, join, dirname } = await import('path');
      const { createHash } = await import('crypto');

      const dataDir = resolve(process.env.DATA_DIR || './data');
      const sharedRoot = resolve(join(dataDir, 'apps', app.slug, env, 'shared', 'data'));
      const targetPath = resolve(join(sharedRoot, rel));
      if (!targetPath.startsWith(sharedRoot + '/') && targetPath !== sharedRoot) {
        throw new Error('Security: resolved path escapes shared/data');
      }

      // Decode content. utf-8 string passthrough or base64 → buffer.
      const encoding = args.encoding === 'base64' ? 'base64' : 'utf-8';
      const buf = encoding === 'base64'
        ? Buffer.from(String(args.content), 'base64')
        : Buffer.from(String(args.content), 'utf-8');

      mkdirSync(dirname(targetPath), { recursive: true });
      // Atomic write: write to .tmp, rename. Readers never see a partial file.
      const tmpPath = targetPath + '.tmp-' + Date.now();
      writeFileSync(tmpPath, buf);
      const { renameSync } = await import('fs');
      renameSync(tmpPath, targetPath);

      const sha256 = createHash('sha256').update(buf).digest('hex');
      log.info(`MCP: /data write ${app.slug}/${env}/${rel} ← ${buf.length} bytes (sha256=${sha256.slice(0, 12)}) by user ${user.id}`);
      return {
        app: app.slug,
        env,
        path: rel,
        bytes: buf.length,
        sha256,
        encoding,
        container_path: '/data/' + rel,
        host_path: targetPath,
      };
    },
  },

  {
    name: 'appcrane_list_cron',
    description:
      'List the scheduled jobs declared in an app\'s deployhub.json `cron` array (after the most recent deploy). Each entry includes the cron schedule, the command, when it last ran, the exit code, and the tail of the last run\'s stdout/stderr. Use to verify a job was registered, debug a missing run, or read the recent log. App-admin or owner.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string' },
        env:  { type: 'string', enum: ['sandbox', 'production'], description: 'Optional — omit to list both envs.' },
      },
      required: ['slug'],
      additionalProperties: false,
    },
    requiredRole: 'app_admin',
    handler: async (user, args) => {
      const app = getAppForUser(user, args.slug);
      if (!isAppAdmin(user, app)) throw new Error('Forbidden: reading cron jobs requires admin or app-admin role on this app');
      const db = getDb();
      const filters = args.env ? 'AND env = ?' : '';
      const params = args.env ? [app.id, args.env] : [app.id];
      const rows = db.prepare(`
        SELECT id, env, name, schedule, command, enabled, timeout_seconds,
               last_run_at, last_exit_code, last_log
        FROM app_cron_jobs
        WHERE app_id = ? ${filters}
        ORDER BY env, name
      `).all(...params);
      return { app: app.slug, jobs: rows };
    },
  },

  {
    name: 'appcrane_run_cron_now',
    description:
      'Trigger a scheduled cron job RIGHT NOW, regardless of its schedule. Useful for "I want to test my daily rebuild without waiting until midnight" or "rerun yesterday\'s failed job." Runs the same `docker exec` the tick loop would, against the app\'s container; updates last_run_at / last_exit_code / last_log just like a scheduled run. Returns the exit code and last-log tail. App-admin or owner. Idempotent: if the job is already running (mutex held), reports it and skips rather than overlapping.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string' },
        env:  { type: 'string', enum: ['sandbox', 'production'], default: 'sandbox' },
        name: { type: 'string', description: 'Job name from deployhub.json `cron[].name`.' },
      },
      required: ['slug', 'name'],
      additionalProperties: false,
    },
    requiredRole: 'app_admin',
    handler: async (user, args) => {
      const env = args.env === 'production' ? 'production' : 'sandbox';
      const app = getAppForUser(user, args.slug);
      if (!isAppAdmin(user, app)) throw new Error('Forbidden: running cron jobs requires admin or app-admin role on this app');
      const db = getDb();
      const job = db.prepare(`
        SELECT id, app_id, env, name, schedule, command, timeout_seconds
        FROM app_cron_jobs
        WHERE app_id = ? AND env = ? AND name = ?
      `).get(app.id, env, String(args.name));
      if (!job) throw new Error(`No cron job named "${args.name}" on ${app.slug}/${env}. Check deployhub.json or appcrane_list_cron.`);
      const { runCronJob } = await import('./cronScheduler.js');
      const result = await runCronJob(job);
      return { app: app.slug, env, name: job.name, ...result };
    },
  },
];

// v2.11.0: AWS-friendly naming. The catalog the LLM sees presents the
// sandbox/production dimension as `stage` (Copilot/eb vocabulary) instead of
// `env`; callTool bridges `stage` back to the `env` handlers still read, so no
// handler or schema-literal changes are needed. One transform covers all 14
// env-taking tools, keeping the convention consistent from a single place.
function stageifySchema(schema) {
  if (!schema || !schema.properties || !schema.properties.env) return schema;
  const properties = {};
  for (const [k, v] of Object.entries(schema.properties)) {
    if (k === 'env') {
      properties.stage = { ...v, description: `${v.description ? v.description + ' ' : ''}Target stage (legacy alias: env).` };
    } else {
      properties[k] = v;
    }
  }
  const required = Array.isArray(schema.required)
    ? schema.required.map((r) => (r === 'env' ? 'stage' : r))
    : schema.required;
  return { ...schema, properties, required };
}

// Old tool names kept working after the v2.11.0 rename so existing agents and
// saved scripts don't break — accepted on call, no longer advertised.
const TOOL_NAME_ALIASES = {
  appcrane_set_env:       'appcrane_set_secret',
  appcrane_get_env:       'appcrane_get_secret',
  appcrane_set_data_blob: 'appcrane_cp',
  appcrane_upload:        'appcrane_cp',
};

export function listTools(user, userMcpKey = null) {
  // Stash userMcpKey on user so canUseTool's helpers (and future custom checks)
  // can see it.
  const userView = userMcpKey ? { ...user, _mcpUserKey: userMcpKey } : user;
  return TOOLS.filter((t) => canUseTool(userView, t)).map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: stageifySchema(t.inputSchema),
  }));
}

export async function callTool(user, name, args, userMcpKey = null) {
  const canonicalName = TOOL_NAME_ALIASES[name] || name;
  const tool = TOOLS.find((t) => t.name === canonicalName);
  if (!tool) {
    auditMcpCall(user, name, args, new Error('unknown tool'));
    throw new Error(`Unknown tool: ${name}`);
  }
  if (!canUseTool(user, tool)) {
    const err = new Error(`Forbidden: tool ${name} requires ${tool.requiredRole}`);
    auditMcpCall(user, name, args, err);
    throw err;
  }
  // Reject keys with empty MCP scope outright (per-user mcp_scope override)
  const scope = mcpScope(user);
  if (scope && scope.length === 0) {
    const err = new Error('Forbidden: this key has an empty MCP scope (locked out)');
    auditMcpCall(user, name, args, err);
    throw err;
  }
  // Stash auth context on user so helpers (accessibleSlugsForUser,
  // getAppForUser) can constrain output.
  const userWithKey = userMcpKey ? { ...user, _mcpUserKey: userMcpKey } : user;
  // v2.11.0: 'stage' is the canonical sandbox/production param; bridge it to the
  // legacy 'env' the handlers still read (and vice-versa, so both callers work).
  const callArgs = { ...(args || {}) };
  if (callArgs.stage != null && callArgs.env == null) callArgs.env = callArgs.stage;
  else if (callArgs.env != null && callArgs.stage == null) callArgs.stage = callArgs.env;
  try {
    const result = await tool.handler(userWithKey, callArgs);
    auditMcpCall(user, name, args, null);
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    };
  } catch (err) {
    auditMcpCall(user, name, args, err);
    throw err;
  }
}

function canUseTool(user, tool) {
  if (tool.requiredRole === 'admin') return isAdmin(user);
  // v2.7.0: app-creation tools gated by the configurable platform.create_app
  // permission — global admins always, plus any role a platform admin
  // granted at /settings#roles. Mirrors POST /api/apps.
  if (tool.requiredRole === 'create_app') return userHasPlatformPermission(user, 'platform.create_app');
  if (tool.requiredRole === 'app_admin') {
    if (isAdmin(user)) return true;
    // v2.7.1: also surface app_admin tools to anyone who can create apps.
    // Without this, a create_app holder connects owning zero apps → app_admin
    // tools (set_env, push_to_managed_app) are filtered out → they create a
    // managed app and become its owner, but the MCP client cached the tool
    // list at connect (server advertises tools.listChanged=false) and never
    // re-fetches, so the write tools never appear without a reconnect. They
    // WILL own what they create, so showing the tools up front is correct;
    // per-slug ownership is still enforced by getAppForUser/isAppAdmin in
    // each handler, so visibility never widens actual access.
    if (userHasPlatformPermission(user, 'platform.create_app')) return true;
    // Caller must be admin or owner of at least one app for this tool to even appear.
    // Per-slug authz still happens inside the handler when invoked.
    const db = getDb();
    const row = db.prepare(
      `SELECT 1 FROM app_user_roles WHERE user_id = ? AND app_role IN ('admin', 'owner') LIMIT 1`
    ).get(user.id);
    return !!row;
  }
  return true;
}

export function getToolCatalog() {
  // For the admin /mcp page — expose tool metadata without auth filtering
  return TOOLS.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: stageifySchema(t.inputSchema),
    requiredRole: t.requiredRole,
  }));
}
