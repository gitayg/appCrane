import { Router } from 'express';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { listTools, callTool, getToolCatalog } from '../services/mcpTools.js';
import log from '../utils/logger.js';

const router = Router();

const SERVER_INFO = {
  name: 'appcrane',
  version: '1.0.0',
};

const SERVER_INSTRUCTIONS = `
AppCrane is a deploy and lifecycle platform for AI-built apps.

This MCP exposes APPCRANE-SPECIFIC operations:
  - appcrane_list_apps       — discovery
  - appcrane_get_app         — health, deploys, recent activity
  - appcrane_get_env         — read env vars (admin / app-admin)
  - appcrane_set_env         — write env vars (admin / app-admin)
  - appcrane_deploy          — trigger deploy (defaults to sandbox)
  - appcrane_get_logs        — runtime logs
  - appcrane_list_requests   — intake-form queue (filter by bucket)
  - appcrane_set_request_status — move requests through the lifecycle
  - appcrane_create_github_repo — bootstrap a new repo for an app
  - appcrane_create_app      — register an app with AppCrane

Code-level operations (file contents, PRs, issues, branches, code search,
GitHub Actions, releases) live in the OFFICIAL GITHUB MCP SERVER, not here.
You should normally have BOTH MCPs configured side-by-side. AppCrane mediates
deploys/env/lifecycle; GitHub MCP mediates source code.

A typical end-to-end app onboarding:
  1. appcrane_create_github_repo(...) — create the repo
  2. <push scaffold via GitHub MCP or local git>
  3. appcrane_create_app(...)         — register with AppCrane
  4. appcrane_set_env(...)            — encrypted env vars
  5. appcrane_deploy(slug, "sandbox") — first deploy
  6. appcrane_get_logs(slug, "sandbox") — verify health

Defaults & conventions:
- Prefer sandbox over production unless the user explicitly asks for production
- When the user asks "what should I work on?", call appcrane_list_requests
- For code reading / PRs / issues, route through GitHub MCP, not AppCrane
- When opening a PR for a request via GitHub MCP, include "Closes appcrane#<id>"
  in the body so AppCrane can auto-link it on the next status sync

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
      case 'tools/list':
        result = { tools: listTools(req.user, req.app_key) };
        break;
      case 'tools/call':
        if (!params?.name) {
          return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'Missing tool name' } });
        }
        log.info(`MCP: tools/call name=${params.name} user=${req.user.id}${req.app_key ? ` app_key=${req.app_key.id}/${req.app_key.app_slug}` : ''}`);
        result = await callTool(req.user, params.name, params.arguments, req.app_key);
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
