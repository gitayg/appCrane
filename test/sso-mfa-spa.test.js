import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { redeemSsoCode } from '../studio-web/src/utils/ssoHandoff.ts';
import { capturingMfaStep, mfaStepFrom, tellOpenerFrame, SSO_POPUP_PARAM } from '../studio-web/src/components/sso/ssoMfaHandoff.ts';

// The sign-in page after an SSO handoff that answers with AppCrane's MFA step
// instead of a token (server/routes/oidc.js, services/ssoMfa.js). The page is
// not loadable under node:test, so its wiring is checked in the source and the
// helpers it uses are run directly.

const LOGIN = readFileSync(new URL('../studio-web/src/components/Login.tsx', import.meta.url), 'utf8');
const STEP = { mfa_required: true, mfa_token: 'challenge-token', remember_device_days: 0, error: { code: 'MFA_REQUIRED', message: 'x' } };

test('mfaStepFrom takes only a real second step', () => {
  assert.deepEqual(mfaStepFrom(STEP), { token: 'challenge-token', rememberDays: 0 });
  for (const b of [null, {}, { token: 't' }, { mfa_required: 'true', mfa_token: 'x' }, { mfa_required: true }, { mfa_required: true, mfa_token: 7 }]) {
    assert.equal(mfaStepFrom(b), null, JSON.stringify(b));
  }
});

test('redeemSsoCode with the capturing fetch stores no token and hands over the MFA step', async () => {
  const stored = new Map();
  let step = null;
  const fetchImpl = async () => ({ ok: true, json: async () => STEP });
  const ok = await redeemSsoCode('code', { fetch: capturingMfaStep(fetchImpl, (s) => { step = s; }), store: { setItem: (k, v) => stored.set(k, v) } });
  assert.equal(ok, false);
  assert.equal(stored.size, 0, 'a token was stored from an MFA answer');
  assert.deepEqual(step, { token: 'challenge-token', rememberDays: 0 });

  step = null;
  const tok = await redeemSsoCode('code', { fetch: capturingMfaStep(async () => ({ ok: true, json: async () => ({ token: 'sess' }) }), (s) => { step = s; }), store: { setItem: (k, v) => stored.set(k, v) } });
  assert.equal(tok, true);
  assert.equal(stored.get('cc_identity_token'), 'sess');
  assert.equal(step, null);

  await redeemSsoCode('code', { fetch: capturingMfaStep(async () => ({ ok: false, json: async () => STEP }), (s) => { step = s; }), store: { setItem() {} } });
  assert.equal(step, null, 'a refused handoff produced an MFA step');
});

test('the popup tells the frame and closes only on success', () => {
  const sent = [];
  let closed = 0;
  const win = {
    BroadcastChannel: class { constructor(n) { this.n = n; } postMessage(m) { sent.push([this.n, m]); } close() {} },
    setTimeout: (fn) => fn(),
    close: () => { closed++; },
  };
  tellOpenerFrame(win, 'appcrane-sso', 'signed-in');
  assert.deepEqual(sent, [['appcrane-sso', { type: 'signed-in' }]]);
  assert.equal(closed, 1);
  tellOpenerFrame(win, 'appcrane-sso', 'sign-in-failed');
  assert.deepEqual(sent[1], ['appcrane-sso', { type: 'sign-in-failed' }]);
  assert.equal(closed, 1, 'a failed popup closed before the user could read why');
});

test('Login.tsx shows the code prompt after an SSO handoff, and the popup reports instead of navigating', () => {
  assert.equal(SSO_POPUP_PARAM, 'sso_popup');
  assert.match(LOGIN, /redeemSsoCode\(ssoCode, \{ fetch: capture, store: localStorage \}\)/);
  assert.match(LOGIN, /if \(!ok && got\.step\) \{\s+setMfa\(\{ kind: 'verify', token: got\.step\.token, rememberDays: got\.step\.rememberDays, popup \}\)/);
  const submit = LOGIN.slice(LOGIN.indexOf('async function submitMfaCode'), LOGIN.indexOf('async function confirmEnroll'));
  assert.match(submit, /if \(mfa\.popup\) \{[\s\S]*tellOpenerFrame\(window, SSO_CHANNEL, 'signed-in'\)[\s\S]*return\s+\}\s+postLoginRedirect\(\)/);
});
