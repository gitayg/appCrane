import { test } from 'node:test';
import assert from 'node:assert/strict';

// Which advisories the RCE auto-patch policy may approve without a person.
// Records are trimmed copies of what /v1/vulns/<id> returned on 2026-10-22
// (id, summary, details, database_specific.cwe_ids, withdrawn); the synthetic
// rows are marked as such.

const { classifyAdvisory, RCE_CWES } = await import('../server/services/autoPatch/classify.js');

const rec = (id, cwe, summary, details = '', extra = {}) => ({ id, summary, details, database_specific: { cwe_ids: cwe }, ...extra });

const TABLE = [
  // measured
  [rec('GHSA-35jh-r3h4-6jhm', ['CWE-77', 'CWE-94'], 'Command Injection in lodash', '`lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the template function.'), true, 'CWE hit'],
  [rec('GHSA-jf85-cpcp-j695', ['CWE-1321', 'CWE-20'], 'Prototype Pollution in lodash', 'The function `defaultsDeep` allows a malicious user to modify the prototype of `Object`.'), false, 'prototype pollution without an execution claim'],
  [rec('GHSA-xvch-5gv4-984h', ['CWE-1321'], 'Prototype Pollution in minimist'), false, 'prototype pollution without an execution claim'],
  [rec('GHSA-jjmj-jmhj-qwj2', ['CWE-601', 'CWE-79'], 'React Router: Open redirect leading to XSS'), false, 'XSS'],
  [rec('GHSA-c2qf-rxjj-qqgw', ['CWE-1333'], 'semver vulnerable to Regular Expression Denial of Service'), false, 'ReDoS'],
  [rec('GHSA-4w2v-q235-vp99', ['CWE-918'], 'Axios vulnerable to Server-Side Request Forgery'), false, 'SSRF'],
  [rec('GHSA-ffrw-9mx8-89p8', ['CWE-1321'], 'Withdrawn Advisory: fast-redact vulnerable to prototype pollution', '', { withdrawn: '2025-09-25T00:00:00Z' }), false, 'withdrawn'],
  // synthetic
  [rec('SYN-1', [], 'Remote code execution via crafted payload'), true, 'text: remote code execution'],
  [rec('SYN-2', null, 'Parser bug', 'An attacker can achieve arbitrary code execution on the server.'), true, 'text: arbitrary code execution'],
  [rec('SYN-3', [], 'RCE in the template loader'), true, 'text: RCE'],
  [rec('SYN-4', ['CWE-1321'], 'Prototype pollution leads to remote code execution'), true, 'prototype pollution WITH an execution claim'],
  [rec('SYN-5', ['CWE-434'], 'Unrestricted file upload'), false, 'CWE-434 without an execution claim'],
  [rec('SYN-6', ['CWE-502'], 'Unsafe deserialization'), true, 'CWE-502'],
  [rec('SYN-7', ['CWE-94'], 'Code injection', '', { withdrawn: '2026-01-01T00:00:00Z' }), false, 'withdrawn beats a CWE hit'],
  [rec('SYN-8', ['CWE-79'], 'Stored XSS lets an attacker run script in the victim browser'), false, 'XSS wording is not code execution'],
  [rec('SYN-9', [], 'Sourcer prices'), false, 'the word "sources" is not RCE'],
];

for (const [record, rce, why] of TABLE) {
  test(`classify ${record.id}: ${rce ? 'RCE' : 'not RCE'} (${why})`, () => {
    const c = classifyAdvisory(record);
    assert.equal(c.rce, rce, JSON.stringify(c));
  });
}

test('the CWE allow-list is the documented one, and excludes prototype pollution and upload', () => {
  assert.deepEqual([...RCE_CWES].sort(), ['CWE-1336', 'CWE-502', 'CWE-77', 'CWE-78', 'CWE-917', 'CWE-94', 'CWE-95'].sort());
  assert.ok(!RCE_CWES.includes('CWE-1321'));
  assert.ok(!RCE_CWES.includes('CWE-434'));
});

test('a missing record is not RCE', () => {
  assert.equal(classifyAdvisory(null).rce, false);
});
