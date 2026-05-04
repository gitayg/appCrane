import { getDb } from '../db.js';
import { decrypt } from './encryption.js';
import { BUCKETS, bucketize, applyBucket } from './requestStatus.js';
import log from '../utils/logger.js';

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
    requiredRole: 'any', // gated by app-admin check inside handler
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
    requiredRole: 'any',
    handler: async (user, args) => {
      if (!BUCKETS.includes(args.bucket)) throw new Error(`Unknown bucket: ${args.bucket}`);
      const db = getDb();
      const row = db.prepare(
        'SELECT id, app_slug, status, validated_at FROM enhancement_requests WHERE id = ?'
      ).get(args.id);
      if (!row) throw new Error(`Request ${args.id} not found`);

      // Authz: AppCrane admin or per-app admin
      if (user.role !== 'admin') {
        if (!row.app_slug) throw new Error('Forbidden: only AppCrane admin can move requests with no app');
        const app = db.prepare('SELECT id FROM apps WHERE slug = ?').get(row.app_slug);
        const ar = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app?.id, user.id);
        if (ar?.app_role !== 'admin') throw new Error(`Forbidden: not an admin of ${row.app_slug}`);
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
];

export function listTools(user) {
  return TOOLS.filter((t) => canUseTool(user, t)).map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  }));
}

export async function callTool(user, name, args) {
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
  // Reject keys with empty MCP scope outright
  const scope = mcpScope(user);
  if (scope && scope.length === 0) {
    const err = new Error('Forbidden: this key has an empty MCP scope (locked out)');
    auditMcpCall(user, name, args, err);
    throw err;
  }
  try {
    const result = await tool.handler(user, args || {});
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
  if (tool.requiredRole === 'admin') return user.role === 'admin';
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
