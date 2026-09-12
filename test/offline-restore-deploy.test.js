import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// A restore must be able to START the app, not just hold its bytes.
//
// The image archive can save and load an app's exact image onto a bare host.
// That is worth nothing if the deploy path then refuses to run it, and it did:
// deployApp() called `await pullImage(requestedRef)` unconditionally before
// resolving the digest. On the machine the archive exists for — registry
// unreachable, or the publisher's image deleted — that throw happened BEFORE
// anything looked on disk. The restore would put the data back and then decline
// to start the app.
//
// Not hypothetical. Measured this year: bitnami/* 404 after their registry
// change, and medusajs/medusa, vendureio/vendure and crater/crater all 404
// today. Those are the exact apps a restore cannot re-pull.
//
// The rule is PULL FIRST, FALL BACK ON FAILURE, and the order matters in both
// directions:
//
//   - Preferring a local copy whenever one exists would pin every app to
//     whatever it first ran. A tag is a moving pointer on purpose; redeploying
//     'odoo:19' has to keep picking up patch releases. The registry stays the
//     source of truth whenever it can be reached.
//   - Treating a pull failure as fatal is what made the archive useless.
//
// Asserted against the source. Driving deployApp() end to end would need a real
// registry that can be taken away mid-test; the archive suite already proves the
// byte-level property (save -> rmi -> load -> docker run offline), and what is
// unproven there is precisely this ordering, which is what these assert.

const src = readFileSync(new URL('../server/services/deployer.js', import.meta.url), 'utf8');

/** The image branch of deployApp, where the pull happens. */
function imageBranch() {
  const start = src.indexOf('const { parseImageRef, pullImage, resolveDigest }');
  assert.ok(start > 0, 'the image deploy branch moved — update this test deliberately');
  const end = src.indexOf('} else if (opts.preExtractedDir)', start);
  assert.ok(end > start, 'could not delimit the image branch');
  return src.slice(start, end);
}

test('the pull still happens first, so a moving tag keeps picking up patches', () => {
  const b = imageBranch();
  const pullAt = b.indexOf('await pullImage(requestedRef)');
  const inspectAt = b.indexOf('inspectImages(');
  assert.ok(pullAt > 0, 'pullImage is gone from the image branch');
  assert.ok(inspectAt > pullAt,
    'the local-image lookup must come AFTER the pull attempt. Checking local first would pin ' +
    "every app to whatever it first ran, and redeploying 'odoo:19' would stop picking up patches");
});

test('a failed pull falls back to bytes already on the host instead of dying', () => {
  const b = imageBranch();
  assert.match(b, /catch \(e\) \{[\s\S]{0,600}?inspectImages\(/,
    'the pull must be wrapped so a registry failure can fall back to a local copy');
  assert.match(b, /if \(!localRef\) throw e;/,
    'when nothing is on disk the original pull error must still surface — a restore that cannot ' +
    'find the bytes must fail loudly, not start something else');
});

test('the fallback looks for the ARCHIVE TAG, not only the digest ref', () => {
  // The measured platform split this exists for: `docker load` does not restore
  // RepoDigests on a classic overlay2 store, so the digest ref resolves on
  // Docker Desktop and fails on a real Linux server. Looking only for the
  // digest would work on a Mac and fail on every production host — the same
  // class of bug that turned CI red on v2.71.0.
  const b = imageBranch();
  assert.match(b, /restoreTagFor\(/,
    'the fallback must try <repo>:appcrane-restore-<digest>, or an offline restore works on ' +
    'macOS and fails on Linux');
});

test('resolveDigest is not called when the registry is unreachable', () => {
  // resolveDigest is a REGISTRY lookup. Calling it after a failed pull would
  // throw for the same reason the pull did, turning the fallback into a
  // different error rather than a working deploy.
  const b = imageBranch();
  assert.doesNotMatch(b, /^\s*const digest = await resolveDigest/m,
    'resolveDigest must be conditional on the pull having succeeded');
  assert.match(b, /if \(!pullError\) \{[\s\S]{0,200}?resolveDigest\(requestedRef\)/,
    'the digest resolution must be guarded by the pull having succeeded');
});

test('the deployment still records a real image reference on the offline path', () => {
  // deployments.image_ref is the identity of what ran, and the archive's own
  // pairing is derived from it. Leaving it null on a restore would make the
  // restored deployment unarchivable next time.
  const b = imageBranch();
  assert.match(b, /pinnedImageRef = prior\?\.image_ref \|\| localRef;/,
    'the offline path must still pin a concrete ref for deployments.image_ref');
  const update = /UPDATE deployments SET image_ref = \? WHERE id = \?/;
  assert.match(b, update, 'the image_ref write must still happen on both paths');
});

test('the operator is told the registry was bypassed', () => {
  // Silently running different-but-local bytes is the failure mode this must
  // not have. It has to be in the deploy log, which is what an operator reads.
  const b = imageBranch();
  assert.match(b, /appendLog\(`Pull failed/,
    'the deploy log must say the pull failed and a local copy was used');
  assert.match(b, /log\.warn\(/, 'and it must reach the platform log, not only the deploy log');
});
