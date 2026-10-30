import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'http';
import express from 'express';

// With app isolation the dashboard cannot see inside an app's frame, so the
// Request button's element-picker fell back to "this page" for every app. A
// hidden page on the app's own host (/__appcrane/picker) runs the picker in
// the app's frame and posts the pick to the dashboard. The cross-host message
// flow was proven in Chrome with two hosts; these tests pin the server side
// and the checks each end makes on the other's messages.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-app-picker-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.test';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO settings (key, value) VALUES ('app_isolation_domain', 'apps.example.test')").run();
db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('hub','hub',1,'managed')").run();

const { appPickerRouter } = await import('../server/routes/appPicker.js');
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
// The platform's own blanket header (server/index.js): the picker page must undo it.
api.use((req, res, next) => { res.setHeader('X-Frame-Options', 'SAMEORIGIN'); next(); });
api.use('/__appcrane', appPickerRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });

function get(path, host) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: server.address().port, path, headers: { Host: host } }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    }).on('error', reject);
  });
}

const script = readFileSync(new URL('../server/assets/app-picker.js', import.meta.url), 'utf8');
const hook = readFileSync(new URL('../studio-web/src/hooks/usePeek.tsx', import.meta.url), 'utf8');

test('the picker page on an app host: framable by the platform host only, names it, loads its script', async () => {
  for (const host of ['hub.apps.example.test', 'hub-sandbox.apps.example.test']) {
    const r = await get('/__appcrane/picker', host);
    assert.equal(r.status, 200, host);
    assert.equal(r.headers['x-frame-options'], undefined, 'SAMEORIGIN would stop the dashboard framing it');
    assert.equal(r.headers['content-security-policy'],
      "default-src 'none'; script-src 'self'; frame-ancestors https://crane.example.test");
    assert.match(r.body, /<meta name="appcrane-platform" content="https:\/\/crane\.example\.test">/);
    assert.match(r.body, /<script src="\/__appcrane\/picker\.js"><\/script>/);
  }
  const js = await get('/__appcrane/picker.js', 'hub.apps.example.test');
  assert.equal(js.status, 200);
  assert.match(js.headers['content-type'], /^application\/javascript/);
  assert.equal(js.body, script);
});

test('not served on the platform host or a host that is no app', async () => {
  for (const host of ['crane.example.test', 'nope.apps.example.test', 'elsewhere.test']) {
    assert.equal((await get('/__appcrane/picker', host)).status, 404, host);
    assert.equal((await get('/__appcrane/picker.js', host)).status, 404, host);
  }
});

test('the picker answers only the platform, as the parent, and posts only to it', () => {
  assert.match(script, /if \(e\.origin !== PLATFORM \|\| e\.source !== window\.parent\) return;/);
  assert.match(script, /window\.parent\.postMessage\(msg, PLATFORM\)/);
  assert.doesNotMatch(script, /postMessage\([^)]*'\*'/, 'a wildcard target hands the pick to whoever frames it');
  assert.match(script, /adoptedStyleSheets/, 'a <style> element is refused by an app whose CSP bars inline styles');
  for (const t of ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'touchstart', 'touchend']) {
    assert.ok(script.includes(`'${t}'`), `${t} reaches the app during a pick`);
  }
});

test('the dashboard takes messages only from its own helper on the app host, and bounds them', () => {
  assert.match(hook, /helper\.src = origin \+ '\/__appcrane\/picker'/);
  assert.match(hook, /if \(e\.origin !== origin \|\| e\.source !== helper\.contentWindow\) return/);
  assert.match(hook, /contentWindow\?\.postMessage\(msg, origin\)/);
  assert.match(hook, /setTimeout\(fallback, 5000\)/, 'a helper that never answers must still end in the whole page');
  assert.match(hook, /setCtx\(fromAppHost\(m\.ctx, iframe\)\)/);
  assert.match(hook, /text:\s+str\(raw\?\.text, 200\)/);
  assert.match(hook, /helper\.remove\(\)/);
});
