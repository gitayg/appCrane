import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// The Node floor is stated in three places and they must agree (v2.50.0).
//
// Two dependency upgrades — chalk 6 and better-sqlite3 13 — both declare
// engines.node >=22 while install.sh provisioned Node 20. Nothing caught it:
// CI runs on Node 22 so it could never fail, and package.json declared no
// `engines` at all, so npm did not even warn. The mismatch would have surfaced
// at runtime on a production host, in whatever code path first touched a
// Node-22-only feature.
//
// Three files now carry the number. A drift between them puts the platform back
// where it was — believing one floor while enforcing another — so this asserts
// they are the same, and that CI is not testing above what is supported.

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

const pkg = JSON.parse(read('package.json'));
const installSh = read('install.sh');
const indexJs = read('server/index.js');

function declaredFloor() {
  const m = String(pkg.engines?.node || '').match(/(\d+)/);
  return m ? Number(m[1]) : null;
}

test('package.json declares a Node floor at all', () => {
  assert.ok(pkg.engines?.node,
    'no engines.node — npm cannot warn when a dependency needs a newer runtime, which is ' +
    'exactly how chalk 6 and better-sqlite3 13 slipped past review');
  assert.ok(declaredFloor() >= 22, `floor is ${declaredFloor()}, expected at least 22`);
});

test('install.sh provisions the SAME major the package declares', () => {
  const m = installSh.match(/^NODE_MAJOR=(\d+)/m);
  assert.ok(m, 'install.sh no longer sets NODE_MAJOR');
  assert.equal(Number(m[1]), declaredFloor(),
    'install.sh provisions a different Node major than package.json requires — a fresh host ' +
    'would be built below the floor its own dependencies demand');
});

test('the boot-time guard checks the same number', () => {
  const m = indexJs.match(/const NODE_FLOOR = (\d+);/);
  assert.ok(m, 'the NODE_FLOOR constant is gone — nothing tells an operator their host is below the line');
  assert.equal(Number(m[1]), declaredFloor(),
    'the boot guard warns against a different floor than package.json declares');
});

test('the guard warns rather than exits', () => {
  // Refusing to boot would take a running platform down during an upgrade —
  // a worse failure than the mismatch being reported.
  const guard = indexJs.slice(indexJs.indexOf('nodeMajor < NODE_FLOOR'), indexJs.indexOf('nodeMajor < NODE_FLOOR') + 900);
  assert.doesNotMatch(guard, /process\.exit|throw /,
    'the Node floor guard exits or throws; an upgrade onto an older host would then fail to start ' +
    'entirely instead of reporting the problem and running');
  assert.match(guard, /log\.warn/, 'the guard no longer warns, so nothing is reported at all');
});

test('CI does not test above the supported floor', () => {
  // CI on 22 while the floor said 20 is why this was invisible: every check was
  // green on a runtime no production host was guaranteed to have.
  const workflows = ['role-check.yml', 'release-supply-chain.yml']
    .map(f => read(`.github/workflows/${f}`));
  for (const wf of workflows) {
    for (const m of wf.matchAll(/node-version:\s*'?(\d+)'?/g)) {
      assert.ok(Number(m[1]) >= declaredFloor(),
        `CI runs Node ${m[1]} but the floor is ${declaredFloor()} — CI must not be OLDER than supported`);
    }
  }
});

test('README states the same requirement operators will read', () => {
  const readme = read('README.md');
  const floor = declaredFloor();
  assert.match(readme, new RegExp(`Node\\.js ${floor}`),
    `README does not mention Node.js ${floor}; an operator following it would provision the wrong runtime`);
  assert.doesNotMatch(readme, /Node\.js 20/,
    'README still tells operators to install Node 20, which is below the floor and out of support');
});
