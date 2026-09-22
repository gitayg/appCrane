import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'fs';

/**
 * The studio image must contain bash.
 *
 * node:*-alpine ships busybox `ash` as /bin/sh and no bash, and Claude Code's
 * Bash tool spawns bash specifically (its binary references /bin/bash). Without
 * it every shell call the agent makes dies at spawn. Measured in the image as
 * it shipped:
 *
 *     $ command -v bash        -> MISSING
 *     $ bash -lc "echo hello"  -> sh: bash: not found
 *
 * The user-visible symptom was not an error. The agent could still read and
 * edit files, so a session looked healthy while the model reported it had
 * "no shell in this environment" and handed the user commands to run by hand.
 *
 * Two copies of the recipe exist and BOTH matter: the checked-in Dockerfile,
 * and the inline fallback generator.js writes when that file is missing. A host
 * building from the fallback would otherwise silently get the broken image.
 */
const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const dockerfile = read('infra/studio.Dockerfile');
const generator  = read('server/services/appstudio/generator.js');

test('the checked-in studio image installs bash', () => {
  assert.match(
    dockerfile, /apk add --no-cache [^\n]*\bbash\b/,
    'no bash in infra/studio.Dockerfile — the agent has no working shell',
  );
});

test("generator's inline fallback recipe installs bash too", () => {
  const inline = generator.slice(generator.indexOf('inline recipe'));
  assert.match(
    inline.slice(0, 1200), /apk add --no-cache [^']*\bbash\b/,
    'the fallback recipe builds an image with no bash — a host without the Dockerfile gets the broken image',
  );
});

test('the image version is bumped past the shell-less build, in both places', () => {
  // ensureStudioImage compares this constant against the image label and only
  // rebuilds on mismatch, so a recipe change with no bump leaves every existing
  // host on the old image forever.
  const constant = /STUDIO_IMAGE_VERSION = '(\d+)'/.exec(generator)?.[1];
  const argDefault = /ARG STUDIO_IMAGE_VERSION=(\d+)/.exec(dockerfile)?.[1];
  assert.ok(constant, 'STUDIO_IMAGE_VERSION constant not found');
  assert.ok(argDefault, 'ARG STUDIO_IMAGE_VERSION default not found');
  assert.ok(
    Number(constant) >= 4,
    `STUDIO_IMAGE_VERSION is ${constant}; the shell-less image was 3, so existing hosts will never rebuild`,
  );
  assert.equal(
    argDefault, constant,
    'the Dockerfile default and the constant disagree — the rebuild check compares against a label the build never sets',
  );
});

test('no test shim reports a studio image label that disagrees with the constant', () => {
  // The docker shims in these suites answer `docker image inspect` with a
  // literal version. ensureStudioImage rebuilds whenever that label and
  // STUDIO_IMAGE_VERSION disagree, so a stale literal turns a version bump into
  // a REAL docker build inside a test — which is how the v4 bump (bash) broke
  // test/coder-release-sandbox.test.js with `docker build failed (exit 1)`,
  // in a file about releasing to sandbox. The failure names neither the image
  // nor the version, so this guard points at the cause instead.
  const constant = /STUDIO_IMAGE_VERSION = '(\d+)'/.exec(generator)?.[1];
  const dir = new URL('./', import.meta.url);
  const offenders = [];
  for (const name of readdirSync(dir).filter((n) => n.endsWith('.test.js'))) {
    const src = readFileSync(new URL(name, dir), 'utf8');
    // A shim that also stubs `build` survives the rebuild it triggers, so a
    // stale label there is harmless — appstudio-local-analysis.test.js does
    // exactly that on purpose. Only a mismatch with NO build stub is a trap.
    const stubsBuild = /build\)\s*exit 0/.test(src);
    for (const m of src.matchAll(/image\)\s+echo (\d+)\s*;/g)) {
      if (m[1] !== constant && !stubsBuild) {
        offenders.push(`${name}: shim reports ${m[1]}, constant is ${constant}, and it does not stub \`build\``);
      }
    }
  }
  assert.deepEqual(
    offenders, [],
    `a docker shim will trigger a real image build:\n  ${offenders.join('\n  ')}`,
  );
});
