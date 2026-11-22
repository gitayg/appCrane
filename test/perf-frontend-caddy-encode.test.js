import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupFixture } from './caddy-app-isolation-fixtures.js';

// AppCrane's own UI and API (the platform catch-all) are compressed at the
// edge; event streams and every app route are not.

await setupFixture();
const { generateCaddyfile, setAccessLogDirCheck } = await import('../server/services/caddy.js');
setAccessLogDirCheck(() => true);
const file = generateCaddyfile();

function block(text, opener) {
  const at = text.indexOf(opener);
  assert.ok(at >= 0, `no "${opener.trim()}" in the Caddyfile`);
  let depth = 0;
  for (let i = text.indexOf('{', at); i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}' && --depth === 0) return text.slice(at, i + 1);
  }
  throw new Error('unbalanced');
}

test('the platform catch-all encodes zstd/gzip ahead of its proxy', () => {
  const site = block(file, 'crane.example.test {');
  const catchAll = block(site, '\n    handle {\n');
  assert.match(catchAll, /encode zstd gzip \{[\s\S]*\}\s*\n\s*reverse_proxy 127\.0\.0\.1:5001/);
  for (const t of ['text/html', 'text/css', 'application/javascript', 'application/json']) {
    assert.ok(catchAll.includes(`header Content-Type ${t}*`), t);
  }
});

test('event streams are never matched for encoding', () => {
  const catchAll = block(block(file, 'crane.example.test {'), '\n    handle {\n');
  assert.doesNotMatch(catchAll, /Content-Type text\/\*/);
  assert.doesNotMatch(catchAll, /event-stream/);
});

test('app routes and custom-domain sites carry no encode', () => {
  const lines = file.split('\n').filter(l => l.includes('encode '));
  assert.equal(lines.length, 1, lines.join('\n'));
  assert.doesNotMatch(block(file, '    handle /hub* {'), /encode/);
  assert.doesNotMatch(block(file, 'shop.example.com {'), /encode/);
});
