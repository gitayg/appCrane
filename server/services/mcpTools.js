import { getDb } from '../db.js';
import { decrypt, encrypt } from './encryption.js';
import { BUCKETS, bucketize, applyBucket } from './requestStatus.js';
import { userHasAppPermission } from './permissions.js';
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
  // App-scoped MCP key locks visibility to its single app, regardless of the
  // issuer's other access. (See callTool — we stash appKey on user._mcpAppKey
  // so existing tool handlers see the same restriction.)
  if (user._mcpAppKey) return [user._mcpAppKey.app_slug];

  // Personal MCP key — dynamically resolves to apps where the user has access.
  // AppCrane global admins see every app; everyone else sees apps they own.
  // Role changes take effect on the next call (no key reissue needed).
  if (user._mcpUserKey) {
    const db = getDb();
    if (user.role === 'admin') {
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
  if (user.role === 'admin') {
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
  // global admins keep their global access; everyone else is restricted to
  // apps where they're explicitly Owner.
  if (user._mcpUserKey) {
    if (user.role === 'admin') return app;
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
  if (user.role === 'admin') return app;
  const hasAccess =
    db.prepare('SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?').get(app.id, user.id) ||
    db.prepare('SELECT 1 FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, user.id);
  if (!hasAccess) throw new Error(`Forbidden: no access to app ${slug}`);
  return app;
}

function isAppAdmin(user, app) {
  // MCP scope only restricts WHICH apps; if the user has the slug in scope
  // and is a global admin, they're still an app-admin for it.
  if (user.role === 'admin') return true;
  const db = getDb();
  const row = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, user.id);
  return row?.app_role === 'admin';
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

const TOOLS = [
  {
    name: 'appcrane_list_apps',
    description:
      'List all AppCrane apps the current user has access to. Returns slug, name, description, and domain for each. ' +
      'Call this first when the user asks about "my apps", "what apps exist", or before doing anything app-specific. ' +
      'Non-admin users see only their assigned apps; admins see everything.',
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
          `SELECT slug, name, description, domain FROM apps WHERE slug IN (${placeholders}) ORDER BY name`
        )
        .all(...slugs);
      return { apps, count: apps.length };
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
      if (user.role !== 'admin') {
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
    name: 'appcrane_create_github_repo',
    description:
      'Create a brand new GitHub repository to host an app. Requires the user to provide a GitHub PAT ' +
      'with `repo` scope. Use this BEFORE appcrane_create_app when the user wants to start a fresh project ' +
      '(rather than register an existing repo). Returns the new repo URL — chain it directly into appcrane_create_app. ' +
      'The user is expected to push their actual code afterwards (via local git or Claude Code). ' +
      'Repo is private by default.',
    inputSchema: {
      type: 'object',
      properties: {
        name:         { type: 'string', description: 'Repo name (will live at github.com/<owner>/<name>)' },
        github_token: { type: 'string', description: 'GitHub PAT with `repo` scope. Not stored — only used for this one call.' },
        owner:        { type: 'string', description: 'Org name to create the repo under. Omit to create under the authenticated user.' },
        private:      { type: 'boolean', description: 'Default: true', default: true },
        description:  { type: 'string' },
        auto_init:    { type: 'boolean', description: 'Initialize with a README so the repo has a default branch. Default: true', default: true },
      },
      required: ['name', 'github_token'],
      additionalProperties: false,
    },
    requiredRole: 'admin',
    handler: async (_user, args) => {
      const isPrivate = args.private !== false;
      const autoInit = args.auto_init !== false;
      const url = args.owner
        ? `https://api.github.com/orgs/${encodeURIComponent(args.owner)}/repos`
        : 'https://api.github.com/user/repos';
      const body = {
        name: args.name,
        description: args.description || undefined,
        private: isPrivate,
        auto_init: autoInit,
      };
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': `token ${args.github_token}`,
          'Accept': 'application/vnd.github+json',
          'User-Agent': 'AppCrane-MCP',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = data?.message || `HTTP ${res.status}`;
        throw new Error(`GitHub repo creation failed: ${detail}`);
      }
      return {
        url:            data.html_url,
        clone_url:      data.clone_url,
        owner:          data.owner?.login,
        name:           data.name,
        default_branch: data.default_branch,
        private:        data.private,
        next: `Now call appcrane_create_app with github_url="${data.html_url}" and the same github_token to register the new repo with AppCrane.`,
      };
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

export function listTools(user, appKey = null, userMcpKey = null) {
  // Stash userMcpKey on user so canUseTool's helpers (and future custom checks)
  // can see it. AppKey takes precedence — it's app-scoped, the strictest.
  const userView = userMcpKey && !appKey ? { ...user, _mcpUserKey: userMcpKey } : user;
  return TOOLS.filter((t) => canUseTool(userView, t, appKey)).map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  }));
}

export async function callTool(user, name, args, appKey = null, userMcpKey = null) {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) {
    auditMcpCall(user, name, args, new Error('unknown tool'));
    throw new Error(`Unknown tool: ${name}`);
  }
  if (!canUseTool(user, tool, appKey)) {
    const reason = appKey
      ? `tool ${name} not allowed by app-key scope '${appKey.scope}'`
      : `tool ${name} requires ${tool.requiredRole}`;
    const err = new Error(`Forbidden: ${reason}`);
    auditMcpCall(user, name, args, err);
    throw err;
  }
  // App-scoped keys: bind every per-app call to the key's app
  if (appKey && args && typeof args.slug === 'string' && args.slug !== appKey.app_slug) {
    const err = new Error(`Forbidden: this key is scoped to app '${appKey.app_slug}', not '${args.slug}'`);
    auditMcpCall(user, name, args, err);
    throw err;
  }
  // App-scoped key with no slug arg on a per-app tool: inject the key's app
  if (appKey && args && !args.slug && tool.inputSchema?.required?.includes('slug')) {
    args = { ...args, slug: appKey.app_slug };
  }
  // Reject (user-level) keys with empty MCP scope outright
  const scope = mcpScope(user);
  if (!appKey && scope && scope.length === 0) {
    const err = new Error('Forbidden: this key has an empty MCP scope (locked out)');
    auditMcpCall(user, name, args, err);
    throw err;
  }
  // Stash auth context on user so helpers (accessibleSlugsForUser,
  // getAppForUser) can constrain output. App-key wins if both are set.
  const userWithKey = appKey
    ? { ...user, _mcpAppKey: appKey }
    : userMcpKey
      ? { ...user, _mcpUserKey: userMcpKey }
      : user;
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

/**
 * Allowed tools per app_key scope. App-scoped keys see ONLY these tools
 * via tools/list; calls to other tools are rejected.
 *   read   — discovery + read-only state
 *   deploy — read + deploy + claim/ship requests
 *   full   — deploy + read/write env vars
 */
const APP_KEY_SCOPE_TOOLS = {
  read: new Set([
    'appcrane_list_apps', 'appcrane_get_app', 'appcrane_get_logs',
    'appcrane_list_requests',
  ]),
  deploy: new Set([
    'appcrane_list_apps', 'appcrane_get_app', 'appcrane_get_logs',
    'appcrane_list_requests', 'appcrane_deploy', 'appcrane_set_request_status',
  ]),
  full: new Set([
    'appcrane_list_apps', 'appcrane_get_app', 'appcrane_get_logs',
    'appcrane_list_requests', 'appcrane_deploy', 'appcrane_set_request_status',
    'appcrane_get_env', 'appcrane_set_env',
  ]),
};

function canUseTool(user, tool, appKey) {
  // App-scoped key: scope is the gate, not the user's role
  if (appKey) {
    const allowed = APP_KEY_SCOPE_TOOLS[appKey.scope] || APP_KEY_SCOPE_TOOLS.read;
    return allowed.has(tool.name);
  }
  if (tool.requiredRole === 'admin') return user.role === 'admin';
  if (tool.requiredRole === 'app_admin') {
    if (user.role === 'admin') return true;
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
