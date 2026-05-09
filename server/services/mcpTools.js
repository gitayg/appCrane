import { getDb } from '../db.js';
import { decrypt, encrypt } from './encryption.js';
import { BUCKETS, bucketize, applyBucket } from './requestStatus.js';
import { userHasAppPermission } from './permissions.js';
import { isAdmin } from '../utils/roles.js';
import log from '../utils/logger.js';
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
  return row?.app_role === 'admin';
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
    name: 'appcrane_get_health',
    description:
      'Fetch the deployed app\'s health endpoint server-side, bypassing AppCrane\'s auth proxy. Use this to validate ' +
      'that a deploy actually landed the expected version, or to check if the app is responding. AppCrane hits the ' +
      'app\'s configured health endpoint (default /api/health) on the internal port directly — no Caddy, no SSO ' +
      'redirect — and returns the response status + body. ' +
      'Defaults to sandbox; pass env="production" only when the user asks about prod.',
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
    name: 'appcrane_get_env',
    description:
      'Get all environment variables for an app, decrypted. Use this when the user asks about config, secrets, ' +
      'or when you need to verify what env vars are set. ' +
      'Defaults to sandbox; pass env="production" only when the user explicitly says production. ' +
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
      'Trigger a deployment for an app. Pulls latest code from the configured branch, builds the Docker image, ' +
      'and starts a new container. Returns a deployment ID; use appcrane_get_logs to monitor progress. ' +
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
      const db = getDb();
      const result = db
        .prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, ?, 'pending', ?)")
        .run(app.id, env, user.id);
      const deployId = result.lastInsertRowid;

      const { getPortsForSlot } = await import('./portAllocator.js');
      const { deployApp } = await import('./deployer.js');
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
      'Move a previously-staged file (uploaded via POST /api/files/staged) into a running container at a path under /app or /data. ' +
      'Use this when the file is too large to send inline as a JSON arg — upload to the staging endpoint first, then call this with the returned token. ' +
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
    name: 'appcrane_get_logs',
    description:
      'Get recent runtime logs from a running app container. Use this to debug issues, watch a deploy, ' +
      'or verify that a fix worked in production. Returns the most recent N lines (default 100, max 1000). ' +
      'Pass search to filter to lines containing a substring (case-insensitive).',
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
      'After this returns, call appcrane_set_env to set any required env vars, then appcrane_deploy to ship the first build. ' +
      'Admin-only — non-admins cannot create apps.',
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
    requiredRole: 'admin',
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
      const resourceLimits = JSON.stringify({
        max_ram_mb:      args.max_ram_mb      || 512,
        max_cpu_percent: args.max_cpu_percent || 50,
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
      db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)').run(appId, user.id);

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
        next: `Set env vars with appcrane_set_env, then deploy with appcrane_deploy slug="${slug}" env="sandbox".`,
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
      if (args.domain      !== undefined) updates.domain      = args.domain      ? String(args.domain)      : null;
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
      if (args.visibility    !== undefined) updates.visibility    = args.visibility;
      if (args.public_access !== undefined) updates.public_access = args.public_access ? 1 : 0;
      if (args.image_retention !== undefined) {
        const n = parseInt(args.image_retention, 10);
        if (!Number.isFinite(n) || n < 0 || n > 50) throw new Error('image_retention must be 0-50');
        updates.image_retention = n;
      }
      if (args.frame_ancestors !== undefined) updates.frame_ancestors = args.frame_ancestors ? String(args.frame_ancestors) : null;

      if (args.github_token !== undefined) {
        // '' clears, undefined leaves alone, anything else rotates
        updates.github_token_encrypted = args.github_token ? encrypt(args.github_token) : null;
      }

      if (args.max_ram_mb !== undefined || args.max_cpu_percent !== undefined) {
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
          max_ram_mb:      resourceLimits?.max_ram_mb      ?? null,
          max_cpu_percent: resourceLimits?.max_cpu_percent ?? null,
        },
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
    name: 'appcrane_create_managed_app',
    description:
      'Create a new app using AppCrane\'s GitHub service-account — the platform creates a repo on the configured org/user, owns it, and the agent works against it through github_* tools without the end user ever needing their own PAT. Use this when the user does not have a GitHub account or does not want to deal with GitHub at all. Requires the platform admin to have configured the service-account in Settings → GitHub. Returns the same shape as appcrane_create_app, plus the auto-created repo metadata.',
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
    requiredRole: 'admin',
    handler: async (user, args) => {
      const { name, slug } = args;
      if (!name || !slug) throw new Error('name and slug are required');
      if (!/^[a-z0-9][a-z0-9-]*$/.test(slug)) throw new Error('slug must be lowercase alphanumeric with dashes');
      if (args.branch && !/^[A-Za-z0-9._/\-]{1,200}$/.test(args.branch)) {
        throw new Error('branch must be alphanumeric with . _ / - (max 200 chars)');
      }

      const db = getDb();
      if (db.prepare('SELECT id FROM apps WHERE slug = ?').get(slug)) {
        throw new Error(`App slug '${slug}' already exists`);
      }

      // Create the GitHub repo first — if this fails (token misconfigured,
      // owner is wrong, slug collides), bail before touching the DB so we
      // don't leave half-baked apps behind.
      const { createAppRepo, getServiceConfig } = await import('./githubService.js');
      const cfg = getServiceConfig();
      if (!cfg.enabled) throw new Error('GitHub service-account is disabled. Enable it in Settings → GitHub before using managed mode.');
      if (!cfg.configured) throw new Error('GitHub service-account has no token. Configure it in Settings → GitHub before using managed mode.');

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
      const resourceLimits = JSON.stringify({
        max_ram_mb:      args.max_ram_mb      || 512,
        max_cpu_percent: args.max_cpu_percent || 50,
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
      db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)').run(appId, user.id);

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
        next: `Push scaffolding to the repo (the repo is auto-init'd with a README on default branch '${branch}'), then appcrane_deploy slug="${slug}" env="sandbox".`,
      };
    },
  },

  {
    name: 'appcrane_set_env',
    description:
      'Set or update an environment variable on an app. Encrypted at rest; only the running app process can read the plaintext. ' +
      'Defaults to sandbox; require explicit env="production" only when the user asks. ' +
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
];

export function listTools(user, userMcpKey = null) {
  // Stash userMcpKey on user so canUseTool's helpers (and future custom checks)
  // can see it.
  const userView = userMcpKey ? { ...user, _mcpUserKey: userMcpKey } : user;
  return TOOLS.filter((t) => canUseTool(userView, t)).map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  }));
}

export async function callTool(user, name, args, userMcpKey = null) {
  const tool = TOOLS.find((t) => t.name === name);
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
  try {
    const result = await tool.handler(userWithKey, args || {});
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
  if (tool.requiredRole === 'app_admin') {
    if (isAdmin(user)) return true;
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
    inputSchema: t.inputSchema,
    requiredRole: t.requiredRole,
  }));
}
