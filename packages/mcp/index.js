#!/usr/bin/env node
/**
 * @appcrane/mcp — a stdio ↔ HTTP bridge to a remote AppCrane MCP server.
 *
 * AppCrane's MCP is a remote HTTP endpoint (JSON-RPC 2.0 at POST /api/mcp), so
 * clients that speak remote HTTP can connect directly with
 * `claude mcp add --transport http …`. This tiny proxy exists for the other
 * case: MCP clients that only spawn a local stdio process, and for an
 * npx/Docker/registry install path. It reads newline-delimited JSON-RPC from
 * stdin, forwards each message to /api/mcp with your auth headers, and writes
 * the response back to stdout. It holds no logic of its own — the real tools
 * run on your AppCrane server.
 *
 * Config (env or positional args):
 *   APPCRANE_URL           base URL or full /api/mcp URL   (arg 1)
 *   APPCRANE_API_KEY       dhk_* key → X-API-Key           (arg 2)
 *   APPCRANE_GITHUB_TOKEN  optional ghp_* → X-Github-Token
 */
import { createInterface } from 'node:readline';

const rawUrl = process.env.APPCRANE_URL || process.env.APPCRANE_MCP_URL || process.argv[2];
const apiKey = process.env.APPCRANE_API_KEY || process.argv[3];
const ghToken = process.env.APPCRANE_GITHUB_TOKEN || process.argv[4] || '';

function die(msg) { process.stderr.write(`[appcrane-mcp] ${msg}\n`); process.exit(1); }
if (!rawUrl) die('Set APPCRANE_URL (e.g. https://crane.example.com) or pass it as the first arg.');
if (!apiKey) die('Set APPCRANE_API_KEY (your dhk_* key) or pass it as the second arg.');

// Accept either a base URL or a full …/api/mcp URL.
const url = /\/api\/mcp\/?$/.test(rawUrl)
  ? rawUrl.replace(/\/$/, '')
  : rawUrl.replace(/\/+$/, '') + '/api/mcp';

const headers = { 'Content-Type': 'application/json', 'X-API-Key': apiKey };
if (ghToken) headers['X-Github-Token'] = ghToken;

process.stderr.write(`[appcrane-mcp] bridging stdio → ${url}${ghToken ? ' (with GitHub token)' : ''}\n`);

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', async (line) => {
  const text = line.trim();
  if (!text) return;
  let msg;
  try { msg = JSON.parse(text); } catch { return; } // ignore non-JSON lines
  const isRequest = msg.id !== undefined && msg.id !== null;
  try {
    const res = await fetch(url, { method: 'POST', headers, body: text, signal: AbortSignal.timeout(120000) });
    const body = (await res.text()).trim();
    // Notifications (no id) don't get a response written back.
    if (!isRequest) return;
    if (body) process.stdout.write(body + '\n');
    else process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: `AppCrane returned ${res.status} with no body` } }) + '\n');
  } catch (e) {
    if (isRequest) {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32000, message: `AppCrane proxy error: ${e.message}` } }) + '\n');
    }
  }
});

rl.on('close', () => process.exit(0));
