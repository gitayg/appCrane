import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// Self-update brings the runtime up, or refuses (v2.51.0).
//
// install.sh installs Node when a host is below the floor. The updater never
// did — it ran git reset, npm install, rebuild, restart — so a box provisioned
// under an older floor stayed there through every update, forever, and the only
// signal was a line in the boot log.
//
// That was cosmetic until dependencies began declaring engines.node >= 22.
// `npm install --omit=dev` installs them regardless of the running runtime, and
// the failure lands later, in whatever code path first touches a newer feature,
// on a host running dozens of apps.
//
// The policy is what needs testing, not apt: WHEN is it safe to touch system
// packages on a live host, and what happens when it is not safe. planNodeUpgrade
// decides and returns commands; the caller runs them.

const { planNodeUpgrade, verifyUpgrade, SKIP } =
  await import('../server/services/nodeUpgrade.js');

const base = {
  currentMajor: 20, floor: 22, platform: 'linux',
  isRoot: true, hasApt: true, nodePath: '/usr/bin/node', skipEnv: undefined,
};
const plan = (over = {}) => planNodeUpgrade({ ...base, ...over });

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

test('a root Linux host below the floor gets upgraded', () => {
  const p = plan();
  assert.equal(p.upgrade, true);
  assert.equal(p.blocking, false);
  assert.equal(p.commands.length, 2, 'expected the nodesource setup script and the apt install');
  assert.match(p.commands[0][1].join(' '), /setup_22\.x/, 'the wrong Node major is being installed');
  assert.deepEqual(p.commands[1], ['apt-get', ['install', '-y', 'nodejs']]);
});

test('the installed major tracks the floor, not a hardcoded 22', () => {
  const p = plan({ floor: 24, currentMajor: 22 });
  assert.match(p.commands[0][1].join(' '), /setup_24\.x/,
    'the command hardcodes a version instead of following NODE_FLOOR — the next bump would ' +
    'silently install the old one');
});

test('a host already at or above the floor is left completely alone', () => {
  for (const major of [22, 24, 30]) {
    const p = plan({ currentMajor: major });
    assert.equal(p.upgrade, false, `Node ${major} was upgraded despite meeting the floor`);
    assert.equal(p.blocking, false, `Node ${major} blocked the update despite meeting the floor`);
    assert.equal(p.reason, SKIP.AT_FLOOR);
    assert.equal(p.commands, undefined, 'a compliant host was handed commands to run');
  }
});

// ---------------------------------------------------------------------------
// Refusing — every path that cannot upgrade must BLOCK, not warn
// ---------------------------------------------------------------------------

test('every un-upgradable case blocks the update rather than proceeding', () => {
  const cases = [
    ['not linux',       { platform: 'darwin' },              SKIP.NOT_LINUX],
    ['not root',        { isRoot: false },                   SKIP.NOT_ROOT],
    ['no apt',          { hasApt: false },                   SKIP.NO_APT],
    ['opted out',       { skipEnv: '1' },                    SKIP.DISABLED],
    ['nvm-managed',     { nodePath: '/root/.nvm/versions/node/v20.11.0/bin/node' }, SKIP.NOT_SYSTEM],
  ];
  for (const [label, over, reason] of cases) {
    const p = plan(over);
    assert.equal(p.upgrade, false, `${label}: attempted an upgrade it cannot perform`);
    assert.equal(p.blocking, true,
      `${label}: allowed the update to continue on a runtime below the floor — npm would install ` +
      'dependencies this Node cannot run, and the rollback sentinel cannot undo that');
    assert.equal(p.reason, reason);
    assert.match(p.message, /22/, `${label}: the message does not say what floor is required`);
  }
});

test('opting out is not the same as being supported', () => {
  // APPCRANE_SKIP_NODE_UPGRADE means "do not touch my runtime", not "my runtime
  // is fine". The host is still below the floor.
  const p = plan({ skipEnv: '1' });
  assert.equal(p.blocking, true,
    'the opt-out let an unsupported runtime through — an operator who manages Node themselves ' +
    'still has to actually upgrade it');
});

test('an nvm or asdf node is refused rather than shadowed by a second install', () => {
  // apt-get would add /usr/bin/node beside the nvm one, and PATH may keep
  // preferring the old one — the upgrade would report success and change
  // nothing that this process ever runs.
  for (const path of ['/root/.nvm/versions/node/v20.11.0/bin/node', '/opt/node/bin/node', '/home/x/.asdf/shims/node']) {
    const p = plan({ nodePath: path });
    assert.equal(p.reason, SKIP.NOT_SYSTEM, `${path} was treated as a system package`);
    assert.match(p.message, /second Node/i);
  }
});

test('system package paths ARE upgraded', () => {
  for (const path of ['/usr/bin/node', '/usr/local/bin/node']) {
    assert.equal(plan({ nodePath: path }).upgrade, true, `${path} should be upgradable`);
  }
});

test('an unknown node path does not block when the path could not be read', () => {
  // `command -v node` returning empty is not evidence of a non-system install.
  assert.equal(plan({ nodePath: '' }).upgrade, true,
    'an unreadable node path was treated as nvm and blocked the update');
});

// ---------------------------------------------------------------------------
// Verification after the fact
// ---------------------------------------------------------------------------

test('the upgrade is verified against PATH, and a no-op is caught', () => {
  assert.equal(verifyUpgrade(22, 22).ok, true);
  assert.equal(verifyUpgrade(24, 22).ok, true);

  const failed = verifyUpgrade(20, 22);
  assert.equal(failed.ok, false,
    'apt reported success while the runtime on PATH stayed below the floor, and that was accepted');
  assert.match(failed.message, /still 20/);

  assert.equal(verifyUpgrade(NaN, 22).ok, false, 'an unreadable version was treated as success');
});

// ---------------------------------------------------------------------------
// Wiring — the guard must be on the update path and NOT on rollback
// ---------------------------------------------------------------------------

test('the guard runs before npm install on the UPDATE path only', () => {
  const src = readFileSync(new URL('../server/index.js', import.meta.url), 'utf8');
  const guardAt = src.indexOf('planNodeUpgrade');
  const updateInstall = src.indexOf("execFileSync('npm', ['install', '--omit=dev', '--prefer-offline']", guardAt);
  assert.ok(guardAt > 0, 'the updater no longer consults planNodeUpgrade at all');
  assert.ok(updateInstall > guardAt,
    'npm install runs before the runtime check, so dependencies land on an unsupported Node first');

  // The auto-rollback reinstall appears EARLIER in the file and must stay
  // unguarded: it restores the previous release, which ran on this runtime.
  const rollbackInstall = src.indexOf("execFileSync('npm', ['install', '--omit=dev', '--prefer-offline']");
  assert.ok(rollbackInstall < guardAt,
    'the rollback reinstall is now behind the runtime guard — a host that failed an upgrade could ' +
    'be refused its way back to the working release');
});

// ---------------------------------------------------------------------------
// The pipeline must fail when the download fails (v2.51.0)
// ---------------------------------------------------------------------------
//
// Measured in a Debian container: `curl -fsSL <404> | bash -` exits **0**. A
// pipeline reports the LAST command's status, and bash exits 0 on empty stdin.
// So an unreachable nodesource looked like a successful setup, and the apt-get
// that follows would install whatever the base repos carry instead. verifyUpgrade
// catches the outcome either way, but a step should fail where it breaks rather
// than two steps later.

test('the nodesource step sets pipefail, so a failed download is not reported as success', () => {
  const p = plan();
  const script = p.commands[0][1][1];
  assert.match(script, /set -o pipefail/,
    'without pipefail a 404 from nodesource exits 0 (verified in a container: exit 0 with -f, ' +
    'exit 22 with pipefail) and the update proceeds to apt-get with nothing installed');
  assert.ok(script.indexOf('set -o pipefail') < script.indexOf('curl'),
    'pipefail must be set BEFORE the pipeline it protects');
});

// ---------------------------------------------------------------------------
// install.sh's protection must stay (v2.51.0)
// ---------------------------------------------------------------------------
//
// nodeUpgrade.js needs an explicit `set -o pipefail` because its command runs
// via execFileSync with no surrounding shell options. install.sh does NOT need
// one on the curl line — it sets `set -euo pipefail` at the top, which covers
// every pipeline in the file. Verified in a container: an install.sh-shaped
// script with a failing download exits 22 and never reaches the next line.
//
// That was almost "fixed" on the assumption the bug was shared. It is not — but
// the protection is one deletable line, and losing it would resurrect exactly
// the failure mode nodeUpgrade.js had to guard against explicitly.

test('install.sh keeps the shell options that protect its piped installs', () => {
  const sh = readFileSync(new URL('../install.sh', import.meta.url), 'utf8');
  const opts = sh.match(/^set -[a-z]*o?\s*[a-z]*/m);
  assert.ok(sh.includes('pipefail'),
    'install.sh no longer sets pipefail. Its `curl ... | bash -` would then report SUCCESS on a ' +
    'failed download (a pipeline returns the LAST status and bash exits 0 on empty stdin), and ' +
    'the apt-get after it would install whatever the base repos carry instead of the pinned major');
  assert.match(sh, /^set -euo pipefail$/m,
    `install.sh's shell options changed (${opts ? opts[0] : 'none found'}) — -e and pipefail together ` +
    'are what make a failed piped install abort the script');

  // And the protection must come BEFORE the download it protects.
  assert.ok(sh.indexOf('set -euo pipefail') < sh.indexOf('deb.nodesource.com'),
    'the shell options are set after the nodesource pipeline they are supposed to guard');
});
