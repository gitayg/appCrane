import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// No-store on API responses (v2.35.1).
//
// A WAS scan found /api/me — the caller's id, name, email and role — served
// with no Cache-Control at all. HTML had it via sendHtml() and SSE routes set
// their own, but plain JSON responses had none, leaving an identity payload
// cacheable by the browser and by any intermediary in front of it.
//
// Mounts the same middleware shape rather than booting index.js, which starts
// the email worker, health checker and credential checker.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-cache-'));

const app = express();
app.use('/api', (req, res, next) => {
  if (!req.path.endsWith('/icon')) res.setHeader('Cache-Control', 'no-store');
  next();
});
app.get('/api/me', (_q, r) => r.json({ user: { email: 'a@x.io' } }));
app.get('/api/apps/:slug/icon', (_q, r) => r.type('image/png').send('png'));
app.get('/api/events', (_q, r) => { r.setHeader('Cache-Control', 'no-cache'); r.json({ ok: true }); });
app.get('/notapi', (_q, r) => r.send('hi'));

const server = await new Promise((res) => { const s = app.listen(0, () => res(s)); });
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;
const cc = async (p) => (await fetch(`${BASE}${p}`)).headers.get('cache-control');

test('identity and data endpoints are no-store', async () => {
  assert.equal(await cc('/api/me'), 'no-store');
});

test('app icons stay cacheable — public, unchanging, fetched constantly', async () => {
  assert.equal(await cc('/api/apps/demo/icon'), null,
    'no-store on icons would be a pure regression for no privacy gain');
});

test('a route can still override (SSE sets its own)', async () => {
  assert.equal(await cc('/api/events'), 'no-cache');
});

test('non-API routes are untouched', async () => {
  assert.equal(await cc('/notapi'), null);
});
