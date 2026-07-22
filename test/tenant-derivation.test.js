import { test } from 'node:test';
import assert from 'node:assert/strict';
import { orgFromEmail as serverOrg } from '../server/services/tenants.js';
import { orgFromEmail as pkgOrg } from '../packages/tenant/index.js';

// The (org, user) derivation is DUPLICATED: once in the AppCrane server
// (server/services/tenants.js, used by purge-on-revoke) and once in the
// appcrane-tenant helper (packages/tenant, used app-side). If the two ever
// disagree, purge and the app would target different files. This guard fails
// the moment they drift. Run: `npm test`.
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
