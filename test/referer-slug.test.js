import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { refererSlug } from '../server/utils/refererSlug.js';

// The slug fallback 307s a root-path request into the app whose page sent it.
// Measured through Caddy: a Referer from ANOTHER site whose path began with an
// app slug (https://blog.example.org/crewdemo/post-1 → /crew) was 307'd to
// /crewdemo/crew, because the old regex read the first path segment of any
// host's URL.

test('a same-host app page yields its slug', () => {
  assert.equal(refererSlug('https://crane.example.com/crewdemo/page?x=1', 'crane.example.com'), 'crewdemo');
  assert.equal(refererSlug('http://localhost:8391/a2b-sandbox/x', 'localhost:8391'), 'a2b-sandbox');
  assert.equal(refererSlug('https://Crane.Example.com/crewdemo', 'crane.example.com'), 'crewdemo');
});

test('a Referer from another host is never an app page', () => {
  assert.equal(refererSlug('https://blog.example.org/crewdemo/post-1', 'crane.example.com'), null);
  assert.equal(refererSlug('http://localhost:9999/crewdemo/', 'localhost:8391'), null);
});

test('no Referer, a bare origin, or garbage yields nothing', () => {
  assert.equal(refererSlug('', 'crane.example.com'), null);
  assert.equal(refererSlug(undefined, 'crane.example.com'), null);
  assert.equal(refererSlug('https://crane.example.com/', 'crane.example.com'), null);
  assert.equal(refererSlug('not a url', 'crane.example.com'), null);
  assert.equal(refererSlug('javascript:alert(1)//crewdemo', 'crane.example.com'), null);
  assert.equal(refererSlug('https://crane.example.com/crewdemo', undefined), null);
});

test('the slug fallback in server/index.js uses it', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server/index.js'), 'utf8');
  assert.match(src, /refererSlug\(req\.headers\.referer \|\| req\.headers\.referrer, req\.headers\.host\)/);
});
