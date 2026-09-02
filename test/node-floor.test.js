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

// ---------------------------------------------------------------------------
// The runtime is reportable (v2.50.1)
// ---------------------------------------------------------------------------
//
// v2.50.0 raised the floor and warned at boot, and the very next question was
// "what is the production host actually running?" — which nothing could answer.
// getSystemInfo() reported CPU, memory and disk but not the runtime, so the one
// fact needed to decide whether a dependency upgrade was safe was reachable
// only over ssh. A floor you cannot check against is a floor on paper.

const { getSystemInfo } = await import('../server/services/platform.js');

test('getSystemInfo reports the Node version it is running on', () => {
  const info = getSystemInfo();
  assert.equal(info.node_version, process.versions.node,
    'the health payload does not report the runtime, so "is this host above the floor?" ' +
    'cannot be answered without shell access to the box');
  assert.equal(info.node_major, Number(process.versions.node.split('.')[0]));
});

test('the reported major is a number, so a caller can compare it to the floor', () => {
  const info = getSystemInfo();
  assert.equal(typeof info.node_major, 'number',
    'a string major would make `info.node_major < NODE_FLOOR` compare lexically and quietly ' +
    'report a modern host as out of date');
  assert.ok(info.node_major >= 18 && info.node_major < 100, `implausible major: ${info.node_major}`);
});

// ---------------------------------------------------------------------------
// The floor must survive a version JUMP (v2.51.1)
// ---------------------------------------------------------------------------
//
// v2.51.0 put the runtime check in self-update, and that only protects hosts
// already running v2.51.0 — the updater that executes is always the code you
// are upgrading FROM. A host that jumps from an older release straight to one
// needing Node 22 runs its own updater, which knows nothing, and installs
// anyway. .npmrc is read from the working tree that `git reset --hard` just
// produced, so it binds every updater, including ones written before the floor.

test('.npmrc does NOT set engine-strict — the guard moved (v2.57.0)', () => {
  // Reversed deliberately. engine-strict reached every updater, including ones
  // written before the floor existed, but it could only REFUSE. It turned
  // "installs dependencies the runtime cannot run" into "cannot update at all
  // until someone ssh's in", and a host in that state re-runs the update and
  // fails identically. That happened in production across three releases.
  //
  // scripts/safe-boot.sh now raises the runtime on every boot, which repairs
  // instead of refusing — and lets the old updater complete and restart itself,
  // at which point the reconciliation runs. Measured on node:20.20.2 against
  // the real tree: npm install --omit=dev exits 0 with 123 packages.
  const active = read('.npmrc').split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
  assert.deepEqual(active, [],
    'engine-strict (or any other setting) is back in .npmrc. If it is engine-strict, it will ' +
    'strand every host below the floor: the install fails, the old updater never reaches its ' +
    'process.exit(0), and safe-boot.sh — the thing that would fix the runtime — never runs.');
});

test('engines.node is still declared — safe-boot.sh reads it to learn the floor', () => {
  assert.ok(pkg.engines?.node,
    'safe-boot.sh derives the Node floor from engines.node; without it the boot wrapper has ' +
    'nothing to compare against and skips the runtime check entirely');
  assert.match(pkg.engines.node, /\d+/);
});
