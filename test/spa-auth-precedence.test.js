import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

// The admin SPA ships two fetch helpers, and they resolved credentials in
// OPPOSITE order: adminApi.ts read cc_api_key first, api.ts read
// cc_identity_token first. A browser holding both — an operator who signed in
// through the portal and also pasted an API key — authenticated as a different
// principal depending on which helper the component happened to import, with
// nothing on screen to say which one answered.
//
// The identity session wins everywhere now: it is the credential the person
// actually signed in with, it carries their roles, and it expires. Both the
// header helper and the SSE query-parameter helper follow the same order,
// because SSE can't send headers and would otherwise be the one path that
// still preferred the key.
const SRC = join(fileURLToPath(new URL('../studio-web/src', import.meta.url)));
const TOKEN = 'cc_identity_token';
const KEY = 'cc_api_key';

/** Every function in the file that reads both credentials, by name. */
function credentialFunctions(src) {
  const out = [];
  const re = /(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\([^)]*\)[^{]*\{/g;
  let m;
  while ((m = re.exec(src))) {
    let depth = 0, i = re.lastIndex - 1;
    for (; i < src.length; i++) {
      if (src[i] === '{') depth++;
      else if (src[i] === '}' && --depth === 0) break;
    }
    const body = src.slice(re.lastIndex, i);
    if (body.includes(TOKEN) && body.includes(KEY)) out.push([m[1], body]);
  }
  return out;
}

for (const file of ['adminApi.ts', 'api.ts']) {
  test(`${file} reads the identity session before the API key`, () => {
    const src = readFileSync(join(SRC, file), 'utf8');
    const fns = credentialFunctions(src);
    assert.ok(fns.length > 0, `${file} has no function reading both credentials — did they get renamed?`);
    for (const [name, body] of fns) {
      assert.ok(
        body.indexOf(TOKEN) < body.indexOf(KEY),
        `${file}: ${name}() reads ${KEY} before ${TOKEN} — the two helpers disagree on who the caller is`,
      );
    }
  });
}
