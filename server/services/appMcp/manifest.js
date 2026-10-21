// deployhub.json `mcp`: how a hosted app offers its own functionality as MCP
// tools through AppCrane (routes/appMcp.js). Two shapes, one per release:
//
//   { "mcp": { "tools": [ { "name", "description", "method", "path",
//                           "input_schema", "roles", "readOnly" } ] } }
//       AppCrane translates each tools/call into an HTTP request to the app.
//       No MCP code in the app: this is what makes a vibe-coded app usable.
//
//   { "mcp": { "path": "/mcp" } }
//       The app implements MCP (Streamable HTTP) itself; AppCrane forwards.
//
// Validated at deploy before the build, like `access`: a bad block fails the
// deploy with the field named.

import { getDb } from '../../db.js';
import { RULE_ROLES } from '../accessRules.js';

export const TOOL_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
export const MAX_TOOLS = 100;
const MAX_SCHEMA_BYTES = 16 * 1024;
const MAX_DESCRIPTION = 1024;
const MAX_PATH_LEN = 256;
const NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SEG_RE = /^[A-Za-z0-9._~!$&'()+,=:@-]+$/;
const PARAM_RE = /^\{([A-Za-z_][A-Za-z0-9_]{0,63})\}$/;
const MCP_KEYS = ['tools', 'path'];
const TOOL_KEYS = ['name', 'description', 'method', 'path', 'input_schema', 'roles', 'readOnly'];
const SCHEMA_TYPES = ['string', 'number', 'integer', 'boolean', 'object', 'array', 'null'];

export class AppMcpError extends Error {}

function fail(field, why) {
  throw new AppMcpError(`deployhub.json ${field}: ${why}`);
}

function isObj(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Path template segments: literals, or whole-segment {param}. Returns the param names. */
function checkToolPath(field, path) {
  if (typeof path !== 'string' || !path.startsWith('/')) fail(field, `must be a string starting with "/" (got ${JSON.stringify(path)})`);
  if (path.length > MAX_PATH_LEN) fail(field, `must be at most ${MAX_PATH_LEN} characters`);
  if (path === '/') return [];
  const params = [];
  for (const seg of path.slice(1).split('/')) {
    if (seg === '') fail(field, `"${path}" has an empty segment`);
    if (seg === '.' || seg === '..') fail(field, `"${path}" has a "${seg}" segment`);
    const m = PARAM_RE.exec(seg);
    if (m) {
      if (params.includes(m[1])) fail(field, `"${path}" uses {${m[1]}} twice`);
      params.push(m[1]);
      continue;
    }
    if (!SEG_RE.test(seg)) fail(field, `"${path}" has a character that is not allowed (no %, ;, ?, #, * or spaces; a parameter is a whole segment like {id})`);
  }
  return params;
}

function checkSchema(field, schema, params) {
  if (schema === undefined) {
    if (params.length) fail(field, `is required when the path has parameters (${params.map(p => `{${p}}`).join(', ')})`);
    return { type: 'object', properties: {} };
  }
  if (!isObj(schema)) fail(field, 'must be a JSON Schema object');
  if (JSON.stringify(schema).length > MAX_SCHEMA_BYTES) fail(field, `must be at most ${MAX_SCHEMA_BYTES} bytes`);
  if (schema.type !== 'object') fail(`${field}.type`, 'must be "object"');
  const props = schema.properties === undefined ? {} : schema.properties;
  if (!isObj(props)) fail(`${field}.properties`, 'must be an object');
  for (const [k, p] of Object.entries(props)) {
    if (!isObj(p)) fail(`${field}.properties.${k}`, 'must be an object');
    if (p.type !== undefined && !SCHEMA_TYPES.includes(p.type)) fail(`${field}.properties.${k}.type`, `must be one of ${SCHEMA_TYPES.join(', ')}`);
  }
  const required = schema.required === undefined ? [] : schema.required;
  if (!Array.isArray(required) || required.some(r => typeof r !== 'string')) fail(`${field}.required`, 'must be an array of property names');
  for (const p of params) {
    if (!props[p]) fail(`${field}.properties`, `must declare the path parameter "${p}"`);
    if (!required.includes(p)) fail(`${field}.required`, `must list the path parameter "${p}"`);
    if (props[p].type !== undefined && !['string', 'integer', 'number'].includes(props[p].type)) {
      fail(`${field}.properties.${p}.type`, 'a path parameter must be a string, integer or number');
    }
  }
  return { ...schema, properties: props, required };
}

function parseTool(t, i, seen) {
  const f = `mcp.tools[${i}]`;
  if (!isObj(t)) fail(f, 'must be an object like { "name": "list_orders", "description": "...", "method": "GET", "path": "/api/orders" }');
  for (const k of Object.keys(t)) {
    if (!TOOL_KEYS.includes(k)) fail(`${f}.${k}`, `unknown key (allowed: ${TOOL_KEYS.join(', ')})`);
  }
  if (typeof t.name !== 'string' || !NAME_RE.test(t.name)) fail(`${f}.name`, 'must be 1-64 letters, digits, "_" or "-"');
  if (seen.has(t.name)) fail(`${f}.name`, `"${t.name}" is declared twice`);
  seen.add(t.name);
  if (typeof t.description !== 'string' || !t.description.trim()) fail(`${f}.description`, 'is required: it is how an agent decides to call the tool');
  if (t.description.length > MAX_DESCRIPTION) fail(`${f}.description`, `must be at most ${MAX_DESCRIPTION} characters`);
  const method = typeof t.method === 'string' ? t.method.toUpperCase() : t.method;
  if (!TOOL_METHODS.includes(method)) fail(`${f}.method`, `must be one of ${TOOL_METHODS.join(', ')}`);
  const params = checkToolPath(`${f}.path`, t.path);
  const inputSchema = checkSchema(`${f}.input_schema`, t.input_schema, params);
  let roles = ['viewer'];
  if (t.roles !== undefined) {
    if (!Array.isArray(t.roles) || t.roles.length === 0) fail(`${f}.roles`, `must be a non-empty array of: ${RULE_ROLES.join(', ')} (omit it to allow anyone with access to the app)`);
    for (const r of t.roles) {
      if (!RULE_ROLES.includes(r)) fail(`${f}.roles`, `unknown role ${JSON.stringify(r)} (allowed: ${RULE_ROLES.join(', ')})`);
    }
    roles = [...new Set(t.roles)];
  }
  if (t.readOnly !== undefined && typeof t.readOnly !== 'boolean') fail(`${f}.readOnly`, 'must be true or false');
  if (t.readOnly === true && method !== 'GET') fail(`${f}.readOnly`, 'only a GET tool can be read-only');
  return {
    name: t.name,
    description: t.description.trim(),
    method,
    path: t.path,
    params,
    input_schema: inputSchema,
    roles,
    readOnly: t.readOnly === undefined ? method === 'GET' : t.readOnly,
  };
}

/**
 * Validate an `mcp` block and return { mode, tools, path }, or null when there
 * is none. Throws AppMcpError naming the offending field.
 */
export function parseAppMcp(block) {
  if (block === undefined || block === null) return null;
  if (!isObj(block)) fail('mcp', 'must be an object like { "tools": [ ... ] } or { "path": "/mcp" }');
  for (const k of Object.keys(block)) {
    if (!MCP_KEYS.includes(k)) fail(`mcp.${k}`, `unknown key (allowed: ${MCP_KEYS.join(', ')})`);
  }
  if (block.tools !== undefined && block.path !== undefined) fail('mcp', 'declare either "tools" (AppCrane translates calls) or "path" (the app speaks MCP itself), not both');
  if (block.path !== undefined) {
    const params = checkToolPath('mcp.path', block.path);
    if (params.length) fail('mcp.path', 'must not contain parameters');
    return { mode: 'proxy', tools: [], path: block.path };
  }
  const tools = block.tools === undefined ? [] : block.tools;
  if (!Array.isArray(tools)) fail('mcp.tools', 'must be an array');
  if (tools.length > MAX_TOOLS) fail('mcp.tools', `at most ${MAX_TOOLS} tools`);
  const seen = new Set();
  return { mode: 'tools', tools: tools.map((t, i) => parseTool(t, i, seen)), path: null };
}

export function setAppMcp(db, appId, env, decl) {
  if (!decl || (decl.mode === 'tools' && decl.tools.length === 0)) {
    db.prepare('DELETE FROM app_mcp_tools WHERE app_id = ? AND env = ?').run(appId, env);
    return;
  }
  db.prepare(`
    INSERT INTO app_mcp_tools (app_id, env, mode, tools_json, mcp_path, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(app_id, env) DO UPDATE SET
      mode = excluded.mode, tools_json = excluded.tools_json, mcp_path = excluded.mcp_path, updated_at = excluded.updated_at
  `).run(appId, env, decl.mode, JSON.stringify(decl.tools), decl.path);
}

export function getAppMcp(db, appId, env) {
  const row = db.prepare('SELECT mode, tools_json, mcp_path, updated_at FROM app_mcp_tools WHERE app_id = ? AND env = ?').get(appId, env);
  if (!row) return null;
  return { mode: row.mode, tools: JSON.parse(row.tools_json), path: row.mcp_path, updated_at: row.updated_at };
}

/**
 * Deploy hook: the release's deployhub.json `mcp` replaces the previous
 * release's for that environment. No block clears it.
 */
export function storeManifestMcp(appId, env, decl) {
  setAppMcp(getDb(), appId, env, decl);
}
