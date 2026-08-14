import { Router } from 'express';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { listTools, callTool, getToolCatalog, isMcpLockedOut } from '../services/mcpTools.js';
import { noteMcpStart, noteMcpEnd } from '../services/mcpActivity.js';
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

/**
 * Supported MCP protocol revisions, newest first (v2.28.1).
 *
 * The server previously answered `initialize` with a hardcoded '2024-11-05' —
 * the original revision, four behind current. `2026-07-28` is a breaking
 * revision: it drops the `initialize` handshake and `Mcp-Session-Id` entirely
 * (the protocol is stateless), adds a mandatory `server/discover`, and removes
 * `ping`.
 *
 * We NEGOTIATE rather than flip. A hard cutover would disconnect every client
 * still speaking an older revision — which, for a self-hosted platform whose
 * users point long-lived agents at it, means breaking work already in flight.
 * So: echo back whichever supported revision the client asks for, keep
 * `initialize`/`ping` answering for older clients, and serve `server/discover`
 * for new ones. Both shapes are correct simultaneously because AppCrane's
 * surface is tools-only — no sessions, subscriptions, sampling or roots, which
 * is where the breaking changes actually bite.
 */
const PROTOCOL_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const LATEST_PROTOCOL = PROTOCOL_VERSIONS[0];
const DEFAULT_LEGACY_PROTOCOL = '2024-11-05';
const PROTOCOL_META_KEY = 'io.modelcontextprotocol/protocolVersion';

const SERVER_CAPABILITIES = { tools: { listChanged: false } };

/**
 * Resolve which revision to speak for a request. Order of evidence:
 *   1. `params.protocolVersion` (initialize, older clients)
 *   2. `params._meta['io.modelcontextprotocol/protocolVersion']` (2026-07-28,
 *      which carries the version on every request instead of a handshake)
 *   3. the `MCP-Protocol-Version` header
 * Unknown/absent → the legacy default, so a client that never states a version
 * keeps getting exactly what it got before this change.
 */
function negotiateProtocol(req, params) {
  const asked =
    params?.protocolVersion ||
    params?._meta?.[PROTOCOL_META_KEY] ||
    req.get('MCP-Protocol-Version');
  if (asked && PROTOCOL_VERSIONS.includes(asked)) return asked;
  // A client asking for something newer than we know gets our newest, per the
  // spec's negotiation rule (offer the closest supported). Revisions are ISO
  // dates, so lexicographic comparison is chronological.
  if (asked && asked > LATEST_PROTOCOL) return LATEST_PROTOCOL;
  // Absent, or a version we don't recognise: fall back to the legacy default,
  // so a client that never states one keeps getting exactly what it got before
  // negotiation existed.
  return DEFAULT_LEGACY_PROTOCOL;
}

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
 *
 * Implements: server/discover (2026-07-28), initialize + ping (pre-2026-07-28,
 * kept for compatibility), tools/list, tools/call.
 *
 * Protocol revision is negotiated per request (see negotiateProtocol) and
 * echoed in the MCP-Protocol-Version response header, so old and new clients
 * can both talk to the same endpoint.
 */
router.post('/', requireAuth, async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};
  if (jsonrpc !== '2.0') {
    return res.json({ jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid request — expected jsonrpc 2.0' } });
  }

  // Negotiate once per request and reuse — the header and the handshake
  // responses must agree, and re-deriving it per case invites them to drift.
  // Harmless to clients that ignore the header; required reading for
  // 2026-07-28 ones.
  const protocolVersion = negotiateProtocol(req, params);
  res.set('MCP-Protocol-Version', protocolVersion);

  // Mark this MCP request in-flight so a concurrent self-update waits for it
  // to finish before restarting. noteMcpEnd() runs in finally, even on early
  // return or throw below.
  noteMcpStart();
  try {
    let result;
    switch (method) {
      case 'initialize':
        // Retained for pre-2026-07-28 clients. The handshake is gone in the
        // current revision, but answering it costs nothing and is the only
        // thing keeping existing agents connected.
        result = {
          protocolVersion,
          capabilities: SERVER_CAPABILITIES,
          serverInfo: SERVER_INFO,
          instructions: SERVER_INSTRUCTIONS,
        };
        break;
      // v2.28.1: `server/discover` is the stateless replacement for the
      // initialize handshake in MCP 2026-07-28 — the client asks what the
      // server is and can do, without establishing any session.
      case 'server/discover':
        result = {
          protocolVersion,
          capabilities: SERVER_CAPABILITIES,
          serverInfo: SERVER_INFO,
          instructions: SERVER_INSTRUCTIONS,
        };
        break;
      case 'tools/list': {
        const appcraneTools = listTools(req.user, req.user_mcp_key);
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
            result = await callTool(req.user, upstreamName, params.arguments, req.user_mcp_key);
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
            // v2.42.1 SECURITY: the empty-scope lockout lives inside callTool,
            // which this branch never enters — so a key the operator had locked
            // out of MCP could still drive the GitHub passthrough and make
            // AppCrane `docker run` a github-mcp-server container on the host.
            if (isMcpLockedOut(req.user)) {
              return res.json({
                jsonrpc: '2.0', id,
                error: { code: -32000, message: 'Forbidden: this key has an empty MCP scope (locked out)' },
              });
            }
            const upstreamName = stripPrefix(params.name, 'mcp__github__');
            result = await ghCallTool(req.user.id, req.github_token, upstreamName, params.arguments);
          }
        }
        break;
      // Removed in 2026-07-28, still answered: a client that pings and gets
      // "method not found" concludes the server is broken, not modern.
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
  } finally {
    noteMcpEnd();
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
