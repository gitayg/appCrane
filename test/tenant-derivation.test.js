import { test } from 'node:test';
import assert from 'node:assert/strict';
import { orgFromEmail as serverOrg } from '../server/services/tenants.js';
import { orgFromEmail as pkgOrg } from '../packages/tenant/index.js';

// The (org, user) derivation used to be DUPLICATED: one copy in the AppCrane
// server (server/services/tenants.js, used by purge-on-revoke) and a
// byte-identical one in the appcrane-tenant helper (packages/tenant, used
// app-side). If the two ever disagreed, purge and the app would target
// different files.
//
// There is one function now: tenants.js re-exports the helper's. The identity
// assertion below is what keeps it that way — a re-introduced copy would still
// satisfy the input sweep while being a separate function, so the sweep alone
// cannot tell dedup from luck. Run: `npm test`.
test('the server re-exports the helper\'s orgFromEmail, it does not copy it', () => {
  assert.equal(serverOrg, pkgOrg, 'tenants.js defines its own orgFromEmail again — one derivation, re-exported');
});

test('server and appcrane-tenant orgFromEmail agree', () => {
  const emails = [
    'alice@acme.com', 'Alice@ACME.COM', 'a+tag@sub.acme.co.uk', 'a@b@corp.com',
    'no-at-sign', '', 'x@..', 'y@.', 'z@/etc', 'user@GMAIL.com',
    'weird@a_b!c.com', 'q@..evil', 'w@under_score.io', 'r@dash-domain.dev',
  ];
  for (const e of emails) {
    assert.equal(pkgOrg(e), serverOrg(e), `derivation drift for "${e}"`);
  }
});
