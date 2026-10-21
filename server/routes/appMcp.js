import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';
import { isAdmin } from '../utils/roles.js';
import { lookupAccessToken } from '../services/oauthStore.js';
import { ACCESS_PREFIX, issuerOf, SCOPES_SUPPORTED } from '../services/oauthPolicy.js';
import { isMcpOauthOnly, oauthOnlyExemptIds } from '../services/apiKeyExpiry.js';
import { resolveAgentToken } from '../services/crewTokens.js';
import { decideAccess, effectiveRules, roleSatisfies, RULE_ROLES } from '../services/accessRules.js';
import { getAppMcp } from '../services/appMcp/manifest.js';
import {
  parseTarget, targetOf, appResourceOf, appResourceMetadataUrlOf, resourceIsApp,
} from '../services/appMcp/oauthResource.js';
import { translate, placeholderPath, ToolArgsError } from '../services/appMcp/translate.js';
import { identityHeadersFor } from '../services/appMcp/identityHeaders.js';
import { callApp, takeCall, LIMITS, UpstreamError } from '../services/appMcp/upstream.js';
import { recordToolCall } from '../services/appMcp/record.js';

// MCP front door for hosted apps: POST /api/mcp/apps/<slug> (production) and
// /api/mcp/apps/<slug>-sandbox is a Streamable HTTP MCP server whose tools are
// the app's own functionality, declared in its deployhub.json `mcp` block.
// Every call is made as the authenticated caller: AppCrane checks the caller's
// access to the app, the tool's roles and the app's path rules, then calls the
// app on its internal port with identity headers it signs itself.

const router = Router();
export const appMcpWellKnownRouter = Router();

const PROTOCOL_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const PROTOCOL_META_KEY = 'io.modelcontextprotocol/protocolVersion';
const SESSION_ID_RE = /^[\x21-\x7e]{1,200}$/;

function negotiateProtocol(req, params) {
  const asked = params?.protocolVersion || params?._meta?.[PROTOCOL_META_KEY] || req.get('MCP-Protocol-Version');
  if (asked && PROTOCOL_VERSIONS.includes(asked)) return asked;
  if (asked && asked > PROTOCOL_VERSIONS[0]) return PROTOCOL_VERSIONS[0];
  return '2024-11-05';
}

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

// The caller's per-app role, with /api/identity/verify's precedence: an
// explicit row wins, then platform admin, then a public app's viewer fallback.
// A view-as preview of this app uses the previewed role.
function callerAppRole(db, app, user) {
  const va = user.view_as;
  if (va && va.app_id === app.id) return va.role === 'none' ? 'none' : va.role;
  const row = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, user.id);
  if (row?.app_role) return row.app_role;
  if (isAdmin(user)) return 'admin';
  if (app.visibility === 'public') return 'viewer';
  return 'none';
}

/** Why this caller may not use this app's tools at all, or null. */
function appRefusal(app, user, appRole) {
  const scope = mcpScope(user);
  if (scope && scope.length === 0) return 'this credential has an empty MCP scope (locked out)';
  if (scope && !scope.includes(app.slug)) return `this credential's MCP scope does not include '${app.slug}'`;
  if (appRole === 'none') return `you do not have access to '${app.slug}'`;
  return null;
}

function minRole(roles) {
  return RULE_ROLES[Math.min(...roles.map((r) => RULE_ROLES.indexOf(r)))];
}

function isReadOnlyCaller(req) {
  return !!(req.user_mcp_key?.read_only || req.user?.mcp_read_only || req.view_as);
}

function authChallenge(req, res, t, error) {
  const parts = [`resource_metadata="${appResourceMetadataUrlOf(req, t.slug, t.env)}"`, `scope="${SCOPES_SUPPORTED[0]}"`];
  if (error) parts.unshift(`error="invalid_token"`, `error_description="${error}"`);
  res.set('WWW-Authenticate', `Bearer ${parts.join(', ')}`);
}

function apiKeyRefusedByOauthOnly(req) {
  if (!req.headers['x-api-key']) return false;
  const db = getDb();
  if (!isMcpOauthOnly(db)) return false;
  const uid = (req.real_user || req.user)?.id;
  return !oauthOnlyExemptIds(db).includes(uid);
}

// Authentication for one app endpoint. An OAuth access token is accepted only
// when it was issued for THIS endpoint (RFC 8707 audience); a Crew agent token
// acts as its owner; every other credential goes through requireAuth exactly
// as on POST /api/mcp, including the "MCP: OAuth only" setting.
function requireAppMcpAuth(req, res, next) {
  const t = parseTarget(req.params.slug);
  if (!t) return next(new AppError('Not found', 404, 'NOT_FOUND'));
  req.app_mcp_target = t;
  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (bearer.startsWith(ACCESS_PREFIX)) {
    const row = lookupAccessToken(bearer);
    if (!row) {
      authChallenge(req, res, t, 'The access token is invalid or expired');
      return next(new AppError('Invalid or expired access token', 401, 'UNAUTHORIZED'));
    }
    if (!row.active) return next(new AppError('Account is deactivated', 403, 'DEACTIVATED'));
    if (!resourceIsApp(req, row.resource, t.slug, t.env)) {
      authChallenge(req, res, t, 'This access token was issued for a different resource');
      return next(new AppError('This access token was issued for a different resource', 401, 'UNAUTHORIZED'));
    }
    req.user = {
      id: row.uid, name: row.name, email: row.email, role: row.role, active: row.active,
      kind: row.kind, username: row.username, mcp_app_scope: row.mcp_app_scope, mcp_read_only: !!row.read_only,
    };
    req.user_mcp_key = { id: `oauth-${row.grant_id}`, label: row.client_name, read_only: !!row.read_only };
    req.app_mcp_via = 'oauth';
    req.app_mcp_client = row.client_name;
    return next();
  }
  if (bearer.startsWith('dhk_crew_')) {
    const found = resolveAgentToken(bearer);
    if (!found) {
      authChallenge(req, res, t);
      return next(new AppError('Invalid agent token', 401, 'UNAUTHORIZED'));
    }
    req.user = found.owner;
    req.app_mcp_via = 'crew';
    req.app_mcp_agent = found.agent.name;
    return next();
  }
  requireAuth(req, res, (err) => {
    if (err) {
      if (err.status === 401) authChallenge(req, res, t);
      return next(err);
    }
    if (apiKeyRefusedByOauthOnly(req)) {
      authChallenge(req, res, t, 'API keys are turned off for MCP; sign in with OAuth');
      return next(new AppError('This AppCrane accepts only OAuth sign-in for MCP. API keys are turned off for MCP; connect your client again and sign in when it asks.', 401, 'MCP_OAUTH_ONLY'));
    }
    req.app_mcp_via = req.headers['x-api-key'] ? 'key' : 'session';
    next();
  });
}

function toolVisible(tool, { appRole, readOnly, rules }) {
  if (!roleSatisfies(appRole, minRole(tool.roles))) return false;
  if (readOnly && !tool.readOnly) return false;
  return decideAccess(rules, { method: tool.method, uri: placeholderPath(tool), mountPrefix: null, appRole }).ok;
}

function toolListing(tool) {
  return {
    name: tool.name,
    description: tool.description,
    inputSchema: tool.input_schema,
    annotations: { readOnlyHint: tool.readOnly, destructiveHint: tool.method === 'DELETE' },
  };
}

function resultFromResponse(r) {
  let text = r.text;
  if (r.truncated) text += `\n\n[response truncated by AppCrane at ${LIMITS.maxResponseBytes} bytes]`;
  const isError = r.status >= 400;
  return { content: [{ type: 'text', text: isError ? `HTTP ${r.status}: ${text}` : text }], isError };
}

const rpcError = (id, code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });

router.post('/:slug', requireAppMcpAuth, async (req, res) => {
  const db = getDb();
  const t = req.app_mcp_target;
  const body = req.body;
  const id = body && typeof body === 'object' ? body.id : null;
  if (JSON.stringify(body ?? null).length > LIMITS.maxRequestBytes) {
    return res.status(413).json(rpcError(id, -32600, `Request is larger than ${LIMITS.maxRequestBytes} bytes`));
  }
  if (!body || typeof body !== 'object' || Array.isArray(body) || body.jsonrpc !== '2.0' || typeof body.method !== 'string') {
    return res.status(400).json(rpcError(id, -32600, 'Invalid request: expected one JSON-RPC 2.0 message'));
  }
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(t.slug);
  if (!app) return res.status(404).json(rpcError(id, -32001, `App '${t.slug}' not found`));
  const appRole = callerAppRole(db, app, req.user);
  const refusal = appRefusal(app, req.user, appRole);
  if (refusal) return res.status(403).json(rpcError(id, -32000, `Forbidden: ${refusal}`));
  const decl = getAppMcp(db, app.id, t.env);
  if (!decl) {
    return res.status(404).json(rpcError(id, -32001, `'${app.slug}' offers no MCP tools on ${t.env}. The app declares them in deployhub.json "mcp" and they take effect on its next deploy.`));
  }
  const ctx = {
    db, app, env: t.env, decl, user: req.user,
    appRole,
    readOnly: isReadOnlyCaller(req),
    rules: effectiveRules(db, app.id, t.env),
    via: req.app_mcp_via, client: req.app_mcp_client || null, agent: req.app_mcp_agent || null,
  };
  if (decl.mode === 'proxy') return proxyToApp(req, res, ctx);

  const { method, params } = body;
  const protocolVersion = negotiateProtocol(req, params);
  res.set('MCP-Protocol-Version', protocolVersion);
  if (id === undefined) return res.status(202).end();
  const info = {
    protocolVersion,
    capabilities: { tools: { listChanged: false } },
    serverInfo: { name: `appcrane-app-${targetOf(app.slug, t.env)}`, version: '1.0.0' },
    instructions: `Tools of the ${app.name || app.slug} app (${t.env}), hosted on AppCrane. Every call acts as you: the app sees your identity and your role on it, and refuses what your role does not allow.`,
  };
  try {
    switch (method) {
      case 'initialize':
      case 'server/discover':
        return res.json({ jsonrpc: '2.0', id, result: info });
      case 'ping':
        return res.json({ jsonrpc: '2.0', id, result: {} });
      case 'tools/list':
        return res.json({ jsonrpc: '2.0', id, result: { tools: decl.tools.filter((tl) => toolVisible(tl, ctx)).map(toolListing) } });
      case 'tools/call':
        return res.json(await callTool(id, params, ctx));
      default:
        return res.json(rpcError(id, -32601, `Method not found: ${method}`));
    }
  } catch (err) {
    log.warn(`[app-mcp] ${method} on ${app.slug}: ${err.message}`);
    return res.json(rpcError(id, -32603, 'Internal error'));
  }
});

async function callTool(id, params, ctx) {
  const { app, env, user } = ctx;
  const name = params?.name;
  const tool = typeof name === 'string' ? ctx.decl.tools.find((tl) => tl.name === name) : null;
  if (!tool) return rpcError(id, -32602, `Unknown tool: ${typeof name === 'string' ? name.slice(0, 64) : '(none)'}`);
  const rec = (outcome, extra = {}) => recordToolCall({
    user, app, env, tool: tool.name, method: tool.method, pathTemplate: tool.path, outcome,
    via: ctx.via, client: ctx.client, agent: ctx.agent, ...extra,
  });
  const need = minRole(tool.roles);
  if (!roleSatisfies(ctx.appRole, need)) {
    rec('refused_role');
    return rpcError(id, -32000, `Forbidden: ${tool.name} needs the ${need} role on '${app.slug}' (you have ${ctx.appRole})`);
  }
  if (ctx.readOnly && !tool.readOnly) {
    rec('refused_read_only');
    return rpcError(id, -32000, `Forbidden: ${tool.name} changes state and this MCP credential is read-only`);
  }
  let reqSpec;
  try {
    reqSpec = translate(tool, params.arguments);
  } catch (e) {
    if (e instanceof ToolArgsError) return rpcError(id, -32602, `Invalid arguments for ${tool.name}: ${e.message}`);
    throw e;
  }
  const verdict = decideAccess(ctx.rules, { method: tool.method, uri: reqSpec.pathOnly, mountPrefix: null, appRole: ctx.appRole });
  if (!verdict.ok) {
    rec('refused_rule');
    return rpcError(id, -32000, verdict.reason === 'role'
      ? `Forbidden: '${app.slug}' requires the ${verdict.role} role for this path`
      : 'Forbidden: the request path could not be read unambiguously');
  }
  const wait = takeCall(`u${user.id}`, app.id, env);
  if (wait !== null) {
    rec('rate_limited');
    return rpcError(id, -32000, `Rate limited: at most ${LIMITS.callsPerMinute} tool calls a minute per app; retry in ${wait} s`);
  }
  const started = Date.now();
  try {
    const r = await callApp(app, env, {
      method: reqSpec.method, path: reqSpec.path, body: reqSpec.body,
      headers: { ...identityHeadersFor(ctx.db, { app, env, user, appRole: ctx.appRole }), 'X-AppCrane-Mcp-Tool': tool.name },
    });
    rec(r.status >= 400 ? 'app_error' : 'ok', { status: r.status, ms: Date.now() - started });
    return { jsonrpc: '2.0', id, result: resultFromResponse(r) };
  } catch (e) {
    if (!(e instanceof UpstreamError)) throw e;
    rec(e.code === 'timeout' ? 'timeout' : 'unreachable', { ms: Date.now() - started });
    return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: `AppCrane could not complete the call: ${e.message}` }], isError: true } };
  }
}

function lastSseMessage(text, id) {
  let found = null;
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trimStart()).join('\n');
    if (!data) continue;
    try {
      const msg = JSON.parse(data);
      if (msg && (msg.id === id || found === null)) found = msg;
    } catch (_) { /* not JSON */ }
  }
  return found;
}

// deployhub.json { "mcp": { "path": "/mcp" } }: the app speaks MCP itself.
// AppCrane still decides who may reach it (app access, the path rules for
// POST <path>), signs the caller's identity, limits tools/call, and refuses
// tools/call to read-only credentials, since it cannot know which of the
// app's own tools change state.
async function proxyToApp(req, res, ctx) {
  const { app, env, user, decl } = ctx;
  const body = req.body;
  const isCall = body.method === 'tools/call';
  const toolName = isCall && typeof body.params?.name === 'string' ? body.params.name.slice(0, 64) : null;
  const rec = (outcome, extra = {}) => isCall && recordToolCall({
    user, app, env, tool: toolName || '(none)', method: 'POST', pathTemplate: decl.path, outcome,
    via: ctx.via, client: ctx.client, agent: ctx.agent, ...extra,
  });
  if (isCall && ctx.readOnly) {
    rec('refused_read_only');
    return res.json(rpcError(body.id, -32000, `Forbidden: '${app.slug}' serves its own MCP tools, so AppCrane cannot tell which are read-only; this credential is read-only`));
  }
  const verdict = decideAccess(ctx.rules, { method: 'POST', uri: decl.path, mountPrefix: null, appRole: ctx.appRole });
  if (!verdict.ok) {
    rec('refused_rule');
    return res.status(403).json(rpcError(body.id, -32000, `Forbidden: '${app.slug}' requires the ${verdict.role || 'a higher'} role for its MCP endpoint`));
  }
  if (isCall) {
    const wait = takeCall(`u${user.id}`, app.id, env);
    if (wait !== null) {
      rec('rate_limited');
      return res.json(rpcError(body.id, -32000, `Rate limited: at most ${LIMITS.callsPerMinute} tool calls a minute per app; retry in ${wait} s`));
    }
  }
  const headers = { ...identityHeadersFor(ctx.db, { app, env, user, appRole: ctx.appRole }), Accept: 'application/json, text/event-stream' };
  const pv = req.get('MCP-Protocol-Version');
  if (pv && /^\d{4}-\d{2}-\d{2}$/.test(pv)) headers['MCP-Protocol-Version'] = pv;
  const sid = req.get('Mcp-Session-Id');
  if (sid && SESSION_ID_RE.test(sid)) headers['Mcp-Session-Id'] = sid;
  const started = Date.now();
  let r;
  try {
    r = await callApp(app, env, { method: 'POST', path: decl.path, headers, body: JSON.stringify(body) });
  } catch (e) {
    if (!(e instanceof UpstreamError)) throw e;
    rec(e.code === 'timeout' ? 'timeout' : 'unreachable', { ms: Date.now() - started });
    return res.status(502).json(rpcError(body.id, -32000, `AppCrane could not reach '${app.slug}': ${e.message}`));
  }
  const back = r.headers['mcp-session-id'];
  if (typeof back === 'string' && SESSION_ID_RE.test(back)) res.set('Mcp-Session-Id', back);
  if (r.status === 202) { rec('ok', { status: 202, ms: Date.now() - started }); return res.status(202).end(); }
  let msg = null;
  if (r.contentType.includes('text/event-stream')) msg = lastSseMessage(r.text, body.id);
  else { try { msg = JSON.parse(r.text); } catch (_) { msg = null; } }
  if (!msg || r.truncated) {
    rec('app_error', { status: r.status, ms: Date.now() - started });
    return res.status(502).json(rpcError(body.id, -32000, r.truncated
      ? `'${app.slug}' answered with more than ${LIMITS.maxResponseBytes} bytes`
      : `'${app.slug}' answered HTTP ${r.status} without a JSON-RPC message`));
  }
  rec(msg.error || msg.result?.isError ? 'app_error' : 'ok', { status: r.status, ms: Date.now() - started });
  return res.json(msg);
}

router.get('/:slug', requireAppMcpAuth, (req, res) => {
  const db = getDb();
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(req.app_mcp_target.slug);
  if (!app) return res.status(404).json(rpcError(null, -32001, `App '${req.app_mcp_target.slug}' not found`));
  const refusal = appRefusal(app, req.user, callerAppRole(db, app, req.user));
  if (refusal) return res.status(403).json(rpcError(null, -32000, `Forbidden: ${refusal}`));
  res.set('Allow', 'POST').status(405).json(rpcError(null, -32600, 'This MCP endpoint answers POST only (no server-sent event stream)'));
});

function appEntry(req, app, env, decl, role, readOnly, rules) {
  const url = appResourceOf(req, app.slug, env);
  const name = `${targetOf(app.slug, env)}`.replace(/[^a-z0-9-]/g, '-');
  return {
    slug: app.slug,
    name: app.name,
    env,
    url,
    mode: decl.mode,
    role,
    tools: decl.mode === 'proxy' ? null : decl.tools.filter((tl) => toolVisible(tl, { appRole: role, readOnly, rules })).length,
    claude_command: `claude mcp add --transport http ${name} ${url}`,
  };
}

// The catalogue: every app endpoint this caller can use as tools.
router.get('/', requireAuth, (req, res) => {
  const db = getDb();
  const rows = db.prepare(`
    SELECT a.*, m.env AS mcp_env FROM app_mcp_tools m JOIN apps a ON a.id = m.app_id ORDER BY a.slug, m.env
  `).all();
  const readOnly = isReadOnlyCaller(req);
  const apps = [];
  for (const row of rows) {
    const role = callerAppRole(db, row, req.user);
    if (appRefusal(row, req.user, role)) continue;
    const decl = getAppMcp(db, row.id, row.mcp_env);
    apps.push(appEntry(req, row, row.mcp_env, decl, role, readOnly, effectiveRules(db, row.id, row.mcp_env)));
  }
  res.json({ apps });
});

// One app's endpoints and tools, for its Manage page.
router.get('/:slug/tools', requireAuth, (req, res) => {
  const db = getDb();
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(req.params.slug);
  if (!app) throw new AppError(`App '${req.params.slug}' not found`, 404, 'NOT_FOUND');
  const role = callerAppRole(db, app, req.user);
  const refusal = appRefusal(app, req.user, role);
  if (refusal) throw new AppError(`Forbidden: ${refusal}`, 403, 'FORBIDDEN');
  const readOnly = isReadOnlyCaller(req);
  const envs = {};
  for (const env of ['production', 'sandbox']) {
    const decl = getAppMcp(db, app.id, env);
    if (!decl) { envs[env] = null; continue; }
    const rules = effectiveRules(db, app.id, env);
    envs[env] = {
      ...appEntry(req, app, env, decl, role, readOnly, rules),
      mcp_path: decl.path,
      updated_at: decl.updated_at,
      tool_list: decl.tools.map((tl) => ({
        name: tl.name, description: tl.description, method: tl.method, path: tl.path,
        roles: tl.roles, readOnly: tl.readOnly, allowed: toolVisible(tl, { appRole: role, readOnly, rules }),
      })),
    };
  }
  res.json({ slug: app.slug, role, envs });
});

// RFC 9728 metadata for one app endpoint: names it as its own resource, so an
// OAuth client asks for (and gets) a token bound to this app only.
appMcpWellKnownRouter.get('/oauth-protected-resource/api/mcp/apps/:slug', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  const t = parseTarget(req.params.slug);
  const app = t && getDb().prepare('SELECT slug, name FROM apps WHERE slug = ?').get(t.slug);
  if (!app) return res.status(404).json({ error: 'not_found' });
  res.json({
    resource: appResourceOf(req, t.slug, t.env),
    authorization_servers: [issuerOf(req)],
    scopes_supported: SCOPES_SUPPORTED,
    bearer_methods_supported: ['header'],
    resource_name: `${app.name || app.slug} on AppCrane (${t.env})`,
  });
});

export default router;
