import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// The browser half of client error reporting. Shape checks pin that the
// reporter is installed where it must be; the behavioural half imports the
// real studio-web/src/lib/clientErrors.ts (Node >= 22.18 strips the types) into
// a fake window and watches what it would put on the wire.

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

test('main.tsx installs the reporter before rendering and wraps the app in an error boundary', () => {
  const main = read('studio-web/src/main.tsx');
  assert.match(main, /installClientErrorReporter\(\{ source: 'admin', headers: authHeaders \}\)/);
  assert.ok(main.indexOf('installClientErrorReporter(') < main.indexOf('createRoot('));
  assert.match(main, /<ErrorBoundary>\s*<AdminApp \/>\s*<\/ErrorBoundary>/);
  assert.match(read('studio-web/src/components/ErrorBoundary.tsx'), /componentDidCatch[\s\S]*reportClientError\(error\)/);
});

test('the topbar bundle entry installs the reporter too', () => {
  assert.match(read('studio-web/src/topbar-element/entry.ts'), /installClientErrorReporter\(\{ source: 'topbar', headers: authHeaders \}\)/);
});

const listeners = {};
const sent = [];
globalThis.window = {
  location: { pathname: '/settings' },
  addEventListener: (type, fn) => { (listeners[type] ||= []).push(fn); },
};
globalThis.document = { querySelector: () => null };
globalThis.fetch = (url, opts) => { sent.push({ url, opts, body: JSON.parse(opts.body) }); return Promise.resolve(); };

const mod = await import('../studio-web/src/lib/clientErrors.ts');
mod.installClientErrorReporter({ source: 'admin', headers: () => ({ 'X-API-Key': 'header-only' }) });
mod.installClientErrorReporter({ source: 'topbar' });
const fire = (error, message) => listeners.error.forEach(fn => fn({ error, message }));

test('installing twice registers one set of listeners', () => {
  assert.equal(listeners.error.length, 1);
  assert.equal(listeners.unhandledrejection.length, 1);
});

test('reports are scrubbed and stripped of query strings before they are sent', () => {
  const KEY = 'dhk_admin_' + 'Q7'.repeat(20);
  const err = new Error(`load failed ${KEY} Bearer abc.def123456 /api/x?token=s3cr3t#frag`);
  err.stack = `Error: x\n    at f (https://h.example/assets/app.js?sig=TOPSECRET:1:2)`;
  fire(err, err.message);
  assert.equal(sent.length, 1);
  const { url, opts, body } = sent[0];
  assert.equal(url, '/api/client-errors');
  assert.equal(opts.method, 'POST');
  assert.equal(opts.keepalive, true);
  const wire = opts.body;
  for (const secret of [KEY, 'abc.def123456', 's3cr3t', '#frag', 'TOPSECRET', 'sig=']) assert.ok(!wire.includes(secret), `sent: ${secret}`);
  assert.match(body.message, /dhk_\[redacted\]/);
  assert.equal(body.page, '/settings');
  assert.equal(body.source, 'admin');
  assert.deepEqual(Object.keys(body).sort(), ['appSlug', 'message', 'page', 'source', 'stack', 'ts', 'userAgent', 'version']);
  assert.equal(mod.stripQuery('/launch/x?code=1#y'), '/launch/x');
});

test('identical errors are sent once per page load', () => {
  const before = sent.length;
  const e1 = new Error('same thing'); e1.stack = 'Error: same thing\n    at g (/a.js:1:1)';
  const e2 = new Error('same thing'); e2.stack = 'Error: same thing\n    at g (/a.js:1:1)';
  fire(e1, e1.message);
  fire(e2, e2.message);
  listeners.unhandledrejection.forEach(fn => fn({ reason: e1 }));
  assert.equal(sent.length, before + 1);
});

test('distinct errors are capped per minute', () => {
  for (let i = 0; i < 20; i++) fire(new Error(`distinct ${i}`), `distinct ${i}`);
  assert.equal(sent.length, mod.MAX_PER_MINUTE);
});
