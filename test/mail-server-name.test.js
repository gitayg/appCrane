import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// Every admin e-mail names the AppCrane that sent it: an admin of several got
// "[AppCrane] Server critical: Memory available" with no way to tell which
// server was short of memory (1 Nov 2026). sendEmail() stamps it on the way out.

process.env.CRANE_DOMAIN = 'crane.example.test';
const { withServerName, serverName } = await import('../server/services/mailServerName.js');

test('an [AppCrane] subject carries the server name', () => {
  const m = withServerName({ subject: '[AppCrane] Server critical: Memory available' });
  assert.equal(m.subject, '[AppCrane: crane.example.test] Server critical: Memory available');
});

test('a subject that already names it, or is not an AppCrane notice, is left alone', () => {
  assert.equal(withServerName({ subject: '[AppCrane: x] y' }).subject, '[AppCrane: x] y');
  assert.equal(withServerName({ subject: 'Your sign-in code' }).subject, 'Your sign-in code');
});

test('the platform-admin footer says which AppCrane, in text and HTML', () => {
  const m = withServerName({
    subject: '[AppCrane] x',
    text: 'You get this because you are a platform admin of this AppCrane.',
    html: '<p>You get this because you are a platform admin of this AppCrane.</p>',
  });
  assert.equal(m.text, 'You get this because you are a platform admin of the AppCrane at crane.example.test.');
  assert.equal(m.html, '<p>You get this because you are a platform admin of the AppCrane at crane.example.test.</p>');
});

test('the name is HTML-escaped in the HTML body', () => {
  process.env.CRANE_DOMAIN = 'a<b>';
  const m = withServerName({ subject: 's', html: 'platform admin of this AppCrane' });
  assert.equal(m.html, 'platform admin of the AppCrane at a&lt;b&gt;');
  process.env.CRANE_DOMAIN = 'crane.example.test';
});

test('without CRANE_DOMAIN the host name still tells servers apart', () => {
  const saved = process.env.CRANE_DOMAIN;
  delete process.env.CRANE_DOMAIN;
  assert.ok(serverName().length > 0);
  process.env.CRANE_DOMAIN = saved;
});

test('sendEmail stamps every message before any transport sees it', () => {
  const src = readFileSync(new URL('../server/services/emailService.js', import.meta.url), 'utf8');
  const body = src.slice(src.indexOf('export async function sendEmail'));
  assert.ok(body.indexOf('withServerName(') > 0 && body.indexOf('withServerName(') < body.indexOf('sendViaGraph('));
});
