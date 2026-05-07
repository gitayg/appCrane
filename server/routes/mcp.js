import { Router } from 'express';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { listTools, callTool, getToolCatalog } from '../services/mcpTools.js';
import { getDb } from '../db.js';
import {
  listToolsForUser as ghListTools,
  callToolForUser as ghCallTool,
  listActive as ghListActive,
  killUserContainer as ghKill,
} from '../services/githubMcpContainers.js';
import log from '../utils/logger.js';

const router = Router();

const SERVER_INFO = {
  name: 'appcrane',
  version: '1.0.0',
};

const SERVER_INSTRUCTIONS = `
AppCrane is a deploy and lifecycle platform for AI-built apps. This single
MCP connection exposes BOTH lifecycle and source-code tooling:

  appcrane_*  — AppCrane-native lifecycle operations:
    appcrane_list_apps             — discovery
    appcrane_get_app               — health, deploys, recent activity
    appcrane_get_env               — read env vars (admin / app-admin)
    appcrane_set_env               — write env vars (admin / app-admin)
    appcrane_deploy                — trigger deploy (defaults to sandbox)
    appcrane_get_logs              — runtime logs
    appcrane_list_requests         — intake-form queue (filter by bucket)
    appcrane_set_request_status    — move requests through the lifecycle
    appcrane_create_app            — register an app with AppCrane

  github_*    — GitHub passthrough (file contents, PRs, issues, branches,
                code search, Actions, releases). These appear in tools/list
                ONLY when the connection has the X-Github-Token header set.
                AppCrane lazy-spawns a per-user GitHub MCP container and
                forwards calls to it; you do not need to install or
                configure a separate GitHub MCP server. The user's PAT was
                provided once at \`claude mcp add\` time and is reused for
                every github_* call until they update or revoke it.

If you do not see github_* tools in tools/list, the user did not include
X-Github-Token in their AppCrane MCP setup. Either ask them to add it
(\`claude mcp add --transport http appcrane <url> --header "X-API-Key: ..." --header
"X-Github-Token: ghp_..."\`) or fall back to the gh / git CLI on their
machine for code-level operations.

A typical end-to-end app onboarding (no second MCP needed):
  1. github_create_repository(...) — create the repo via GitHub passthrough
     (requires X-Github-Token to be configured)
  2. github_push_files / github_create_or_update_file — scaffold via the
     same connection
  3. appcrane_create_app(...)         — register with AppCrane
  4. appcrane_set_env(...)            — encrypted env vars
  5. appcrane_deploy(slug, "sandbox") — first deploy
  6. appcrane_get_logs(slug, "sandbox") — verify health

Defaults & conventions:
- Prefer sandbox over production unless the user explicitly asks for production
- When the user asks "what should I work on?", call appcrane_list_requests
- Use github_* tools (not gh/git CLI) when X-Github-Token is configured —
  works in any environment, no shell access needed
- When opening a PR for a request, include "Closes appcrane#<id>" in the
  body so AppCrane can auto-link it on the next status sync

Auth: every call uses the caller's AppCrane API key. Tools requiring admin or
app-admin role are filtered out of tools/list when the caller doesn't have the
permission, so you won't see them at all if you can't use them.

Multi-identity hint: a single user may register this URL multiple times under
different names (e.g. appcrane-readonly, appcrane-app1, appcrane-app2), each
with its own API key. Tools are namespaced per registration. If the user asks
you to "use the X key" or operates against a specific app, prefer the matching
registration.
`.trim();

/**
 * MCP HTTP transport. JSON-RPC 2.0 over POST /api/mcp.
 * Implements: initialize, tools/list, tools/call, ping.
 */
router.post('/', requireAuth, async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};
  if (jsonrpc !== '2.0') {
    return res.json({ jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid request — expected jsonrpc 2.0' } });
  }

  try {
    let result;
    switch (method) {
      case 'initialize':
        result = {
          protocolVersion: '2024-11-05',
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
          instructions: SERVER_INSTRUCTIONS,
        };
        break;
      case 'tools/list': {
        const appcraneTools = listTools(req.user, req.app_key, req.user_mcp_key);
        // Append github_* tools if the caller provided X-Github-Token. Lazy-
        // spawns a container; idle-reaped after settings.github_mcp_idle_timeout.
        let githubTools = [];
        if (req.github_token) {
          try {
            githubTools = await ghListTools(req.user.id, req.github_token);
          } catch (e) {
            log.warn(`MCP tools/list: github fetch failed for user ${req.user.id}: ${e.message}`);
          }
        }
        result = { tools: [...appcraneTools, ...githubTools] };
        break;
      }
      case 'tools/call':
        if (!params?.name) {
          return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'Missing tool name' } });
        }
        log.info(
          `MCP: tools/call name=${params.name} user=${req.user.id}` +
          (req.app_key ? ` app_key=${req.app_key.id}/${req.app_key.app_slug}` : '') +
          (req.user_mcp_key ? ` user_mcp_key=${req.user_mcp_key.id}` : '')
        );
        // Route by namespace ownership:
        //   - appcrane_* (and mcp__appcrane__*) → local AppCrane handler
        //   - everything else → user's GitHub MCP container
        // Note: github-mcp-server's tools are mostly UNPREFIXED (get_me,
        // create_issue, list_pull_requests, etc.), so we can't match by
        // a `github_*` prefix. We own the `appcrane_*` namespace; anything
        // outside it belongs to the upstream GitHub MCP.
        {
          const isAppCraneTool =
            params.name.startsWith('appcrane_') ||
            params.name.startsWith('mcp__appcrane__');
          const stripPrefix = (name, prefix) =>
            name.startsWith(prefix) ? name.slice(prefix.length) : name;

          if (isAppCraneTool) {
            const upstreamName = stripPrefix(params.name, 'mcp__appcrane__');
            result = await callTool(req.user, upstreamName, params.arguments, req.app_key, req.user_mcp_key);
          } else {
            if (!req.github_token) {
              return res.json({
                jsonrpc: '2.0', id,
                error: {
                  code: -32000,
                  message: `Tool '${params.name}' is not an AppCrane tool. To call GitHub MCP tools, add --header "X-Github-Token: ghp_..." to your AppCrane MCP setup command, then retry.`,
                },
              });
            }
            const upstreamName = stripPrefix(params.name, 'mcp__github__');
            result = await ghCallTool(req.user.id, req.github_token, upstreamName, params.arguments);
          }
        }
        break;
      case 'ping':
        result = {};
        break;
      default:
        return res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
    }
    res.json({ jsonrpc: '2.0', id, result });
  } catch (err) {
    log.warn(`MCP ${method} error: ${err.message}`);
    res.json({ jsonrpc: '2.0', id, error: { code: -32000, message: err.message } });
  }
});

/**
 * GET /api/mcp/github/containers — admin-only. Live roster of per-user
 * GitHub MCP containers. POST /api/mcp/github/containers/:user_id/kill
 * force-stops one (e.g. if a PAT got revoked and a container is hung).
 */
router.get('/github/containers', requireAuth, requireAdmin, (req, res) => {
  res.json({ active: ghListActive() });
});
router.post('/github/containers/:user_id/kill', requireAuth, requireAdmin, (req, res) => {
  const userId = parseInt(req.params.user_id, 10);
  const ok = ghKill(userId);
  res.json({ ok, user_id: userId });
});

/**
 * GET /api/mcp/recent-activity — admin-only. Returns app slugs that had a
 * mcp.* audit entry in the last N minutes (default 5). Used by the
 * /applications page to badge live agent traffic.
 */
router.get('/recent-activity', requireAuth, requireAdmin, (req, res) => {
  const minutes = Math.min(Math.max(parseInt(req.query.minutes) || 5, 1), 60);
  const db = getDb();
  const rows = db.prepare(`
    SELECT a.slug AS slug, MAX(al.created_at) AS last_at, COUNT(*) AS calls
    FROM audit_log al
    JOIN apps a ON a.id = al.app_id
    WHERE al.action LIKE 'mcp.%'
      AND al.created_at >= datetime('now', '-' || ? || ' minutes')
    GROUP BY a.slug
    ORDER BY last_at DESC
  `).all(minutes);
  res.json({ active: rows });
});

/**
 * GET /api/mcp/connection — connection info available to any authed user.
 * Returns endpoint + transport + server name/version. No tool descriptions
 * (those are admin-only via /catalog because they reveal internal surface).
 */
router.get('/connection', requireAuth, (req, res) => {
  res.json({
    server: SERVER_INFO,
    endpoint: '/api/mcp',
    transport: 'http',
    auth: 'X-API-Key header',
  });
});

/**
 * GET /api/mcp/catalog — admin-only, used by the /mcp settings page to render
 * the tool list with role badges. Not part of the JSON-RPC surface.
 */
router.get('/catalog', requireAuth, requireAdmin, (req, res) => {
  res.json({
    server: SERVER_INFO,
    instructions: SERVER_INSTRUCTIONS,
    tools: getToolCatalog(),
    endpoint: '/api/mcp',
  });
});

export default router;
