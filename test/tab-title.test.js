import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

test('the dashboard tab is titled "<host> - AppCrane"', () => {
  assert.match(read('studio-web/src/main.tsx'), /document\.title = `\$\{window\.location\.hostname\} - AppCrane`/);
});

test('the sign-in portal tab is titled "<host> - AppCrane" too', () => {
  assert.match(read('docs/login.html'), /document\.title = location\.hostname \+ ' - AppCrane';/);
});
