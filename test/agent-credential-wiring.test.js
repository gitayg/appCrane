import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// Phase 3b shipped the precedence (user token -> app credentials -> platform key)
// inside runAgent, and the route gates that accept a request when a user has a
// token. It did NOT wire the acting user through to dispatch, so the resolver was
// reachable only by tests: every real turn resolved with actingUserId undefined,
// fell through to the platform key, and a stored token was gated on but never
// spent. Nothing failed — the container just quietly billed the wrong account,
// which is the exact failure mode runAgent's own comment warns about.
//
// This is a call-site guard, in the shape of test/github-app-call-sites.test.js:
// the behaviour it protects needs a container, so what is pinned here is that the
// argument is passed at all.
const CALL_SITES = [
  ['server/services/builder/builderSession.js', 'runAgentExec'],
];

for (const [file, fn] of CALL_SITES) {
  test(`${file} passes actingUserId into ${fn}`, () => {
    const src = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
    const at = src.indexOf(`${fn}({`);
    assert.ok(at > -1, `${fn}({ ... }) is not called in ${file} any more`);
    let depth = 0, i = src.indexOf('{', at);
    const start = i;
    for (; i < src.length; i++) {
      if (src[i] === '{') depth++;
      else if (src[i] === '}' && --depth === 0) break;
    }
    const call = src.slice(start, i);
    assert.match(call, /actingUserId\s*:/,
      `${fn} is called without actingUserId — the caller's Claude subscription can never be used`);
    assert.doesNotMatch(call, /actingUserId\s*:\s*(null|undefined)\s*[,}]/,
      `${fn} is passed a hardcoded empty actingUserId, which resolves to the platform key every time`);
  });
}
