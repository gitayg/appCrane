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

Use these tools to:
- Discover apps the user has access to (appcrane_list_apps)
- Read environment variables (appcrane_get_env) — admin or app-admin only
- Trigger deployments (appcrane_deploy) — defaults to sandbox
- Pick up enhancement requests from the intake form (appcrane_list_requests)
- Read runtime logs to debug or watch deploys (appcrane_get_logs)

Defaults:
- Prefer sandbox over production unless the user explicitly asks for production
- When the user asks "what should I work on?", call appcrane_list_requests
- Always call appcrane_list_apps first to discover what's available

Auth: every call requires the user's AppCrane API key. Admin-only tools return
a permission error for non-admin users.
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
        result = { tools: listTools(req.user) };
        break;
      case 'tools/call':
        if (!params?.name) {
          return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'Missing tool name' } });
        }
        log.info(`MCP: tools/call name=${params.name} user=${req.user.id}`);
        result = await callTool(req.user, params.name, params.arguments);
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
