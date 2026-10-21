import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'http';
import express from 'express';

// LLM gateway for hosted apps: apps call Anthropic / OpenAI through AppCrane
// with a gateway token, and the provider key never enters the container.
//   - the app's token reaches the upstream with AppCrane's REAL key, and the app never sees it;
//   - other tokens, no token, and proxied requests are refused;
//   - only allowlisted paths and models go through; budgets answer 429;
//   - usage rows carry token counts and no content;
//   - SSE streams pass through and a client disconnect aborts the upstream;
//   - llmGatewayEnv hands out base URL + token, never the key; the config API is platform-admin only and masked.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-llm-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const REAL_ANTHROPIC = 'sk-ant-REALKEY-anthropic-0123456789';
const REAL_OPENAI = 'sk-proj-REALKEY-openai-0123456789';
const PROMPT = 'PROMPT-CANARY-do-not-store';
const ANSWER = 'ANSWER-CANARY-do-not-store';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name, role = 'user') {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name.toLowerCase()}@example.com`, role, hashApiKey(key)).lastInsertRowid;
  return { id: Number(id), key };
}
let slot = 1;
function mkApp(slug) {
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')").run(slug, slug, slot++).lastInsertRowid);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

// ── fake providers ────────────────────────────────────────────────────────
const seen = [];
let upstreamClosed = 0;
let mode = 'ok';
const fake = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => { raw += c; });
  req.on('end', () => {
    const body = raw ? JSON.parse(raw) : {};
    seen.push({ path: req.url, headers: req.headers, body });
    res.on('close', () => { if (!res.writableFinished) upstreamClosed++; });
    if (mode === 'hang') return;
    if (mode === '401') {
      res.writeHead(401, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: { message: `Incorrect API key provided: ${req.headers['x-api-key'] || req.headers.authorization}` } }));
    }
    if (mode === '400echo') {
      res.writeHead(400, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: { message: `bad request for key ${REAL_OPENAI}` } }));
    }
    if (req.url === '/v1/messages' && body.stream) {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      const events = [
        ['message_start', { type: 'message_start', message: { id: 'm1', usage: { input_tokens: 21, output_tokens: 1 } } }],
        ['content_block_delta', { type: 'content_block_delta', delta: { type: 'text_delta', text: ANSWER } }],
        ['message_delta', { type: 'message_delta', usage: { output_tokens: 9 } }],
        ['message_stop', { type: 'message_stop' }],
      ];
      if (mode === 'slow') {
        res.write(`event: ${events[0][0]}\ndata: ${JSON.stringify(events[0][1])}\n\n`);
        const t = setInterval(() => res.write(`event: ping\ndata: {"type":"ping"}\n\n`), 50);
        res.on('close', () => clearInterval(t));
        return;
      }
      for (const [e, d] of events) res.write(`event: ${e}\ndata: ${JSON.stringify(d)}\n\n`);
      return res.end();
    }
    if (req.url === '/v1/messages') {
      res.writeHead(200, { 'content-type': 'application/json', 'request-id': 'req_1', 'set-cookie': 'x=1' });
      return res.end(JSON.stringify({ id: 'm1', content: [{ type: 'text', text: ANSWER }], usage: { input_tokens: 12, output_tokens: 7, cache_read_input_tokens: 3 } }));
    }
    if (req.url === '/v1/chat/completions' && body.stream) {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: ANSWER } }] })}\n\n`);
      if (body.stream_options?.include_usage) res.write(`data: ${JSON.stringify({ choices: [], usage: { prompt_tokens: 30, completion_tokens: 4 } })}\n\n`);
      res.write('data: [DONE]\n\n');
      return res.end();
    }
    if (req.url === '/v1/chat/completions') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ choices: [{ message: { content: ANSWER } }], usage: { prompt_tokens: 15, completion_tokens: 5 } }));
    }
    if (req.url === '/v1/responses') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ output_text: ANSWER, usage: { input_tokens: 8, output_tokens: 2 } }));
    }
    res.writeHead(404); res.end('{}');
  });
});
await new Promise((r) => fake.listen(0, '127.0.0.1', r));
const FAKE = `http://127.0.0.1:${fake.address().port}`;

// ── AppCrane under test ───────────────────────────────────────────────────
const routes = await import('../server/routes/llmGateway.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { updateConfig, setAppEnabled, setAppOverrides } = await import('../server/services/llmGateway/config.js');
const { llmGatewayEnv } = await import('../server/services/llmGateway/env.js');
const { _resetRateWindowsForTests } = await import('../server/services/llmGateway/usage.js');
const { issueServiceToken } = await import('../server/services/appServiceToken.js');

const api = express();
api.use('/api/service/llm', routes.default);
api.use(express.json());
api.use('/api/llm-gateway', routes.adminRouter);
api.use('/api/apps', routes.appRouter);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.close(); fake.closeAllConnections?.(); fake.close(); });

const admin = mkUser('Admin', 'platform_admin');
const owner = mkUser('Owner');
const member = mkUser('Member');

updateConfig({
  providers: {
    anthropic: { enabled: true, api_key: REAL_ANTHROPIC, base_url: FAKE },
    openai: { enabled: true, api_key: REAL_OPENAI, base_url: FAKE },
  },
  private_hosts: ['127.0.0.1'],
  prices: { 'claude-x': { input: 3, output: 15 } },
}, admin.id);

const crm = mkApp('crm');
const hr = mkApp('hr');
const off = mkApp('off');
const budget = mkApp('budget');
db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(crm.id, owner.id, 'owner');
db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(crm.id, member.id, 'user');
for (const a of [crm, hr, budget]) setAppEnabled(a.id, true, admin.id);

const crmEnv = llmGatewayEnv(crm, 'production');
const crmTok = crmEnv.ANTHROPIC_API_KEY;
const hrTok = llmGatewayEnv(hr, 'production').OPENAI_API_KEY;
const budgetTok = llmGatewayEnv(budget, 'production').ANTHROPIC_API_KEY;
setAppEnabled(off.id, true, admin.id);
const offTok = llmGatewayEnv(off, 'production').ANTHROPIC_API_KEY;
setAppEnabled(off.id, false, admin.id);

async function call(path, { headers = {}, body, signal, raw } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST', signal,
    headers: { 'content-type': 'application/json', ...headers },
    body: raw ?? JSON.stringify(body ?? {}),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* SSE */ }
  return { status: res.status, text, json, headers: res.headers };
}
const anthropic = (tok, body, extra = {}) => call('/api/service/llm/anthropic/v1/messages', { headers: { 'x-api-key': tok, 'anthropic-version': '2023-06-01', ...extra }, body });
const openai = (tok, path, body, extra = {}) => call(`/api/service/llm/openai/v1${path}`, { headers: { authorization: `Bearer ${tok}`, ...extra }, body });
const lastUsage = (appId) => db.prepare('SELECT * FROM llm_gateway_usage WHERE app_id = ? ORDER BY id DESC LIMIT 1').get(appId);
const msg = { model: 'claude-x', max_tokens: 100, messages: [{ role: 'user', content: PROMPT }] };

test('llmGatewayEnv: SDK base URLs and the gateway token, never the provider key', () => {
  assert.equal(crmEnv.ANTHROPIC_BASE_URL, 'http://host.docker.internal:5001/api/service/llm/anthropic');
  assert.equal(crmEnv.OPENAI_BASE_URL, 'http://host.docker.internal:5001/api/service/llm/openai/v1');
  assert.match(crmTok, /^aclg_/);
  assert.equal(crmEnv.OPENAI_API_KEY, crmTok);
  const all = JSON.stringify(crmEnv);
  assert.ok(!all.includes(REAL_ANTHROPIC) && !all.includes(REAL_OPENAI));
  assert.deepEqual(llmGatewayEnv(off, 'production'), {});
  assert.notEqual(llmGatewayEnv(crm, 'sandbox').ANTHROPIC_API_KEY, crmTok);
  assert.equal(llmGatewayEnv(crm, 'production').ANTHROPIC_API_KEY, crmTok, 'stable across deploys');
});

test('Anthropic: the app token reaches the upstream as the REAL key; the app never sees it', async () => {
  seen.length = 0;
  const r = await anthropic(crmTok, msg);
  assert.equal(r.status, 200, r.text);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].path, '/v1/messages');
  assert.equal(seen[0].headers['x-api-key'], REAL_ANTHROPIC);
  assert.equal(seen[0].headers.authorization, undefined);
  assert.equal(seen[0].headers['anthropic-version'], '2023-06-01');
  assert.ok(!r.text.includes(REAL_ANTHROPIC));
  assert.equal(r.headers.get('set-cookie'), null, 'only allowlisted response headers come back');
  assert.equal(r.json.content[0].text, ANSWER);
  const u = lastUsage(crm.id);
  assert.equal(u.input_tokens, 15);
  assert.equal(u.output_tokens, 7);
  assert.equal(u.outcome, 'ok');
  assert.equal(u.env, 'production');
  assert.ok(Math.abs(u.cost_usd - (15 * 3 + 7 * 15) / 1e6) < 1e-12);
  const rowText = JSON.stringify(db.prepare('SELECT * FROM llm_gateway_usage').all());
  assert.ok(!rowText.includes(PROMPT) && !rowText.includes(ANSWER), 'usage rows carry no content');
});

test('OpenAI chat + responses: Bearer token in, REAL key out, usage from the usage block', async () => {
  seen.length = 0;
  const r = await openai(hrTok, '/chat/completions', { model: 'gpt-x', messages: [{ role: 'user', content: PROMPT }] });
  assert.equal(r.status, 200, r.text);
  assert.equal(seen[0].headers.authorization, `Bearer ${REAL_OPENAI}`);
  assert.ok(!r.text.includes(REAL_OPENAI));
  let u = lastUsage(hr.id);
  assert.deepEqual([u.input_tokens, u.output_tokens, u.endpoint], [15, 5, '/v1/chat/completions']);
  const r2 = await openai(hrTok, '/responses', { model: 'gpt-x', input: PROMPT });
  assert.equal(r2.status, 200, r2.text);
  u = lastUsage(hr.id);
  assert.deepEqual([u.input_tokens, u.output_tokens, u.endpoint], [8, 2, '/v1/responses']);
});

test('refused: no token, the service token, a disabled app, a proxied request', async () => {
  seen.length = 0;
  const none = await anthropic('', msg);
  assert.equal(none.status, 401);
  assert.equal(none.json.type, 'error');
  const svc = issueServiceToken(crm.id);
  assert.equal((await anthropic(svc, msg)).status, 401, 'APPCRANE_SERVICE_TOKEN does not open the gateway');
  assert.equal((await openai(svc, '/chat/completions', { model: 'gpt-x' })).status, 401);
  assert.equal((await anthropic('aclg_forged', msg)).status, 401);
  const disabled = await anthropic(offTok, msg);
  assert.equal(disabled.status, 403);
  assert.equal(disabled.json.error.type, 'LLM_GATEWAY_DISABLED');
  for (const h of [{ 'x-forwarded-for': '1.2.3.4' }, { via: '1.1 caddy' }, { 'x-forwarded-host': 'example.com' }]) {
    const p = await anthropic(crmTok, msg, h);
    assert.equal(p.status, 403);
    assert.equal(p.json.error.type, 'NOT_INTERNAL');
  }
  assert.equal(seen.length, 0, 'nothing reached the provider');
});

test("another app's token is that app: usage lands on it, not on the caller it imitates", async () => {
  const before = db.prepare('SELECT COUNT(*) AS n FROM llm_gateway_usage WHERE app_id = ?').get(crm.id).n;
  const r = await anthropic(hrTok, msg);
  assert.equal(r.status, 200);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM llm_gateway_usage WHERE app_id = ?').get(crm.id).n, before);
  assert.equal(lastUsage(hr.id).endpoint, '/v1/messages');
});

test('the gateway token opens no other AppCrane route', async () => {
  for (const headers of [{ 'X-API-Key': crmTok }, { Authorization: `Bearer ${crmTok}` }]) {
    const r = await fetch(`${BASE}/api/llm-gateway/config`, { headers });
    assert.equal(r.status, 401);
  }
});

test('path allowlist: nothing outside the fixed paths is forwarded', async () => {
  seen.length = 0;
  for (const p of ['/anthropic/v1/files', '/openai/v1/files', '/openai/v1/models', '/openai/v1/audio/speech', '/anthropic/v1/complete', '/other/v1/messages']) {
    const r = await call(`/api/service/llm${p}`, { headers: { authorization: `Bearer ${crmTok}`, 'x-api-key': crmTok }, body: { model: 'claude-x' } });
    assert.equal(r.status, 404, p);
  }
  const g = await fetch(`${BASE}/api/service/llm/openai/v1/chat/completions`, { headers: { authorization: `Bearer ${crmTok}` } });
  assert.equal(g.status, 404, 'GET is not forwarded');
  assert.equal(seen.length, 0);
});

test('model allowlist (platform and per-app) and the model map', async () => {
  updateConfig({ allowed_models: { anthropic: ['claude-x', 'claude-haiku-*'] }, model_map: { anthropic: { 'claude-old': 'claude-x' } } }, admin.id);
  seen.length = 0;
  const denied = await anthropic(crmTok, { ...msg, model: 'claude-opus-big' });
  assert.equal(denied.status, 403);
  assert.equal(denied.json.error.type, 'LLM_MODEL_NOT_ALLOWED');
  assert.equal(seen.length, 0);
  assert.equal(lastUsage(crm.id).outcome, 'refused');
  assert.equal((await anthropic(crmTok, { ...msg, model: 'claude-haiku-9' })).status, 200);
  const mapped = await anthropic(crmTok, { ...msg, model: 'claude-old' });
  assert.equal(mapped.status, 200);
  assert.equal(seen.at(-1).body.model, 'claude-x');
  setAppOverrides(crm.id, { allowed_models: { anthropic: ['claude-haiku-*'] } }, admin.id);
  assert.equal((await anthropic(crmTok, msg)).status, 403, 'the app override narrows further');
  setAppOverrides(crm.id, {}, admin.id);
  updateConfig({ allowed_models: { anthropic: [] }, model_map: { anthropic: {} } }, admin.id);
});

test('max tokens per request: over the cap is refused, absent is filled in', async () => {
  updateConfig({ limits: { max_tokens_per_request: 50 } }, admin.id);
  const r = await anthropic(crmTok, msg);
  assert.equal(r.status, 400);
  assert.equal(r.json.error.type, 'LLM_MAX_TOKENS');
  seen.length = 0;
  assert.equal((await openai(crmTok, '/chat/completions', { model: 'gpt-x', messages: [] })).status, 200);
  assert.equal(seen[0].body.max_completion_tokens, 50);
  updateConfig({ limits: { max_tokens_per_request: null } }, admin.id);
});

test('budget exceeded answers 429 with a clear error and records an aggregated event', async () => {
  setAppOverrides(budget.id, { env_limits: { production: { requests_per_day: 2 } } }, admin.id);
  assert.equal((await anthropic(budgetTok, msg)).status, 200);
  assert.equal((await anthropic(budgetTok, msg)).status, 200);
  seen.length = 0;
  const r = await anthropic(budgetTok, msg);
  assert.equal(r.status, 429);
  assert.equal(r.json.error.type, 'LLM_BUDGET_REQUESTS');
  assert.match(r.json.error.message, /used its 2 LLM requests for today/);
  assert.equal((await anthropic(budgetTok, msg)).status, 429);
  assert.equal(seen.length, 0);
  const ev = db.prepare("SELECT * FROM events WHERE kind = 'llm.request' AND app_id = ?").all(budget.id);
  assert.equal(ev.length, 1, 'one event, not one per refused call');
  setAppOverrides(budget.id, { env_limits: { production: { tokens_per_day: 10 } } }, admin.id);
  const t = await anthropic(budgetTok, msg);
  assert.equal(t.status, 429);
  assert.equal(t.json.error.type, 'LLM_BUDGET_TOKENS');
  setAppOverrides(budget.id, { limits: { usd_per_month: 0.0001 } }, admin.id);
  assert.equal((await anthropic(budgetTok, msg)).json.error.type, 'LLM_BUDGET_COST');
});

test('rate limit per minute answers 429', async () => {
  _resetRateWindowsForTests();
  setAppOverrides(hr.id, { limits: { requests_per_minute: 1 } }, admin.id);
  assert.equal((await anthropic(hrTok, msg)).status, 200);
  const r = await anthropic(hrTok, msg);
  assert.equal(r.status, 429);
  assert.equal(r.json.error.type, 'LLM_RATE_LIMITED');
  setAppOverrides(hr.id, {}, admin.id);
});

test('streaming: SSE passes through and usage is read from the stream', async () => {
  const r = await anthropic(crmTok, { ...msg, stream: true });
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /text\/event-stream/);
  assert.ok(r.text.indexOf('message_start') < r.text.indexOf(ANSWER) && r.text.indexOf(ANSWER) < r.text.indexOf('message_stop'));
  let u = lastUsage(crm.id);
  assert.deepEqual([u.input_tokens, u.output_tokens, u.stream, u.outcome], [21, 9, 1, 'ok']);
  seen.length = 0;
  const o = await openai(crmTok, '/chat/completions', { model: 'gpt-x', stream: true, messages: [] });
  assert.equal(o.status, 200);
  assert.equal(seen[0].body.stream_options.include_usage, true, 'usage requested from the provider');
  assert.ok(o.text.includes('[DONE]'));
  u = lastUsage(crm.id);
  assert.deepEqual([u.input_tokens, u.output_tokens], [30, 4]);
});

test('a client disconnect mid-stream aborts the upstream request', async () => {
  mode = 'slow';
  upstreamClosed = 0;
  const ctl = new AbortController();
  const res = await fetch(`${BASE}/api/service/llm/anthropic/v1/messages`, {
    method: 'POST', signal: ctl.signal,
    headers: { 'content-type': 'application/json', 'x-api-key': crmTok },
    body: JSON.stringify({ ...msg, stream: true }),
  });
  const reader = res.body.getReader();
  await reader.read();
  ctl.abort();
  const t0 = Date.now();
  while (upstreamClosed === 0 && Date.now() - t0 < 3000) await new Promise((r) => setTimeout(r, 25));
  mode = 'ok';
  assert.equal(upstreamClosed, 1, 'the provider connection was closed');
  await new Promise((r) => setTimeout(r, 50));
  const u = lastUsage(crm.id);
  assert.equal(u.outcome, 'aborted');
  assert.equal(u.input_tokens, 21, 'tokens counted up to the disconnect');
});

test('a client disconnect before the provider answers aborts the upstream request', async () => {
  mode = 'hang';
  upstreamClosed = 0;
  seen.length = 0;
  const ctl = new AbortController();
  const p = fetch(`${BASE}/api/service/llm/openai/v1/chat/completions`, {
    method: 'POST', signal: ctl.signal,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${crmTok}` },
    body: JSON.stringify({ model: 'gpt-x', messages: [] }),
  }).catch(() => null);
  const t0 = Date.now();
  while (seen.length === 0 && Date.now() - t0 < 3000) await new Promise((r) => setTimeout(r, 25));
  ctl.abort();
  await p;
  const t1 = Date.now();
  while (upstreamClosed === 0 && Date.now() - t1 < 3000) await new Promise((r) => setTimeout(r, 25));
  mode = 'ok';
  assert.equal(upstreamClosed, 1, 'the provider connection was closed');
  assert.equal(lastUsage(crm.id).outcome, 'aborted');
});

test('upstream errors pass through without the provider key', async () => {
  mode = '401';
  const a = await anthropic(crmTok, msg);
  assert.equal(a.status, 502);
  assert.equal(a.json.error.type, 'LLM_PROVIDER_AUTH');
  assert.ok(!a.text.includes(REAL_ANTHROPIC) && !a.text.includes('REALKEY'));
  mode = '400echo';
  const o = await openai(crmTok, '/chat/completions', { model: 'gpt-x', messages: [] });
  mode = 'ok';
  assert.equal(o.status, 400);
  assert.ok(!o.text.includes(REAL_OPENAI) && !o.text.includes('REALKEY'), o.text);
  assert.match(o.text, /redacted/);
  assert.equal(lastUsage(crm.id).outcome, 'upstream_error');
});

test('request body size cap', async () => {
  updateConfig({ limits: { max_body_kb: 1 } }, admin.id);
  const r = await anthropic(crmTok, { ...msg, messages: [{ role: 'user', content: 'x'.repeat(4096) }] });
  assert.equal(r.status, 413);
  updateConfig({ limits: { max_body_kb: null } }, admin.id);
});

test('SSRF guard: a private base URL is refused unless the admin listed the host', async () => {
  updateConfig({ private_hosts: [] }, admin.id);
  seen.length = 0;
  const r = await anthropic(crmTok, msg);
  assert.equal(r.status, 502);
  assert.equal(r.json.error.type, 'LLM_UPSTREAM_BLOCKED');
  assert.equal(seen.length, 0);
  updateConfig({ private_hosts: ['127.0.0.1'] }, admin.id);
});

test('config API: platform admin only, keys masked', async () => {
  const asUser = (u, method = 'GET', body) => fetch(`${BASE}/api/llm-gateway/config`, {
    method, headers: { 'X-API-Key': u.key, 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}),
  });
  assert.equal((await asUser(owner)).status, 403);
  assert.equal((await asUser(owner, 'PUT', { providers: { openai: { api_key: 'sk-evil' } } })).status, 403);
  assert.equal((await fetch(`${BASE}/api/llm-gateway/usage`, { headers: { 'X-API-Key': member.key } })).status, 403);
  const r = await asUser(admin);
  assert.equal(r.status, 200);
  const text = await r.text();
  assert.ok(!text.includes(REAL_ANTHROPIC) && !text.includes(REAL_OPENAI) && !text.includes('key_encrypted'));
  const body = JSON.parse(text);
  assert.equal(body.config.providers.anthropic.key_configured, true);
  assert.ok(body.config.providers.anthropic.key_preview.endsWith('789'));
  const put = await asUser(admin, 'PUT', { limits: { requests_per_day: 1000 } });
  assert.equal(put.status, 200);
  assert.ok(!(await put.text()).includes(REAL_OPENAI));
  const audit = JSON.stringify(db.prepare("SELECT * FROM audit_log WHERE action = 'llm-gateway-config'").all());
  assert.ok(!audit.includes(REAL_OPENAI));
  updateConfig({ limits: { requests_per_day: null } }, admin.id);
  const usage = await (await fetch(`${BASE}/api/llm-gateway/usage`, { headers: { 'X-API-Key': admin.key } })).json();
  assert.ok(usage.rows.some((x) => x.app_slug === 'crm' && x.input_tokens > 0));
});

test('per-app opt-in: owners and platform admins; overrides: platform admins only', async () => {
  const put = (u, path, body) => fetch(`${BASE}/api/apps/crm/llm-gateway${path}`, {
    method: 'PUT', headers: { 'X-API-Key': u.key, 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  assert.equal((await put(member, '', { enabled: false })).status, 403);
  assert.equal((await fetch(`${BASE}/api/apps/crm/llm-gateway/usage`, { headers: { 'X-API-Key': member.key } })).status, 403);
  assert.equal((await put(owner, '/overrides', { overrides: { limits: { requests_per_day: 1 } } })).status, 403);
  const off1 = await put(owner, '', { enabled: false });
  assert.equal(off1.status, 200);
  assert.equal((await anthropic(crmTok, msg)).status, 403);
  assert.equal((await put(owner, '', { enabled: true })).status, 200);
  assert.equal((await put(admin, '/overrides', { overrides: { limits: { requests_per_day: 500 } } })).status, 200);
  const view = await (await fetch(`${BASE}/api/apps/crm/llm-gateway`, { headers: { 'X-API-Key': owner.key } })).json();
  assert.equal(view.envs.production.limits.requests_per_day, 500);
  const usage = await (await fetch(`${BASE}/api/apps/crm/llm-gateway/usage?days=7`, { headers: { 'X-API-Key': owner.key } })).json();
  assert.ok(usage.rows.length > 0 && usage.rows.every((x) => x.app_slug === 'crm'));
});
