import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';

// The boot wrapper repairs a native addon whose ABI no longer matches the
// runtime (v2.58.0).
//
// better-sqlite3 is a V8-ABI addon, not N-API: built for Node 20 it declares
// MODULE_VERSION 115, and Node 22 demands 127. Any Node major change breaks it,
// and unattended-upgrades doing that on its own is enough. It happened in
// production: the addon stopped loading, the process died on every boot, and
// with Restart=always / RestartSec=3 and no start limit systemd restarted it
// 10,394 times before anyone noticed.
//
// Two facts here were established by measurement against the real dependency
// tree, and both contradict what was assumed when v2.57.0 shipped:
//
//   1. `require("better-sqlite3")` SUCCEEDS on a mismatched ABI. The addon is
//      loaded lazily, on the first `new Database()`. A probe that only requires
//      the module reports healthy on a host that is about to crash — and that
//      is exactly the mistake behind v2.57.0's claim that nothing needed
//      rebuilding across a Node upgrade.
//   2. `npm install --omit=dev --prefer-offline` does NOT repair it — npm sees
//      node_modules as satisfied and skips the addon. `npm rebuild` does.
//
// The end-to-end behaviour was verified in containers (node:20 build, node:22
// runtime, real safe-boot.sh): it logs the mismatch, rebuilds, and the addon
// loads. These assertions pin the decisions that verification depended on, in
// a form that runs anywhere.

const SCRIPT = fileURLToPath(new URL('../scripts/safe-boot.sh', import.meta.url));
const SRC = readFileSync(SCRIPT, 'utf8');
const NATIVE_FN = SRC.slice(SRC.indexOf('reconcile_native()'), SRC.indexOf('# --check-runtime'));

test('the probe CONSTRUCTS a database — a bare require proves nothing', () => {
  const probe = SRC.match(/NATIVE_PROBE='([^']+)'/)?.[1];
  assert.ok(probe, 'NATIVE_PROBE is gone');
  assert.match(probe, /new D\(|new Database\(/,
    'the probe only requires the module. require() succeeds on a mismatched ABI because the addon '
    + 'loads lazily — the probe has to perform the operation that actually loads it, or it will '
    + 'report a host healthy seconds before it crash-loops');
  assert.match(probe, /prepare\(/,
    'and run a statement, which is what the app does on its first query');
});

test('repair uses npm rebuild, not npm install', () => {
  assert.match(NATIVE_FN, /npm rebuild better-sqlite3/,
    'measured on the real tree: npm install --omit=dev --prefer-offline leaves the addon broken, '
    + 'npm rebuild fixes it');
  assert.doesNotMatch(NATIVE_FN, /npm install/,
    'npm install skips an addon it considers already installed, so it cannot repair an ABI mismatch');
});

test('the native check runs after the runtime check', () => {
  const runtime = SRC.indexOf('\nreconcile_runtime\n');
  const native = SRC.indexOf('\nreconcile_native\n');
  assert.ok(runtime > -1 && native > -1, 'both reconcilers must be invoked at boot');
  assert.ok(runtime < native,
    'raising Node is itself an ABI change, so the addon must be checked after the runtime settles');
});

test('a failed rebuild still boots, and names the likely cause', () => {
  assert.match(NATIVE_FN, /python3 make g\+\+/,
    'the usual reason a rebuild fails on a minimal host is missing build tools; the log has to say so');
  assert.doesNotMatch(NATIVE_FN, /\bexit 1\b/,
    'a boot wrapper must not refuse to boot because a repair failed');
});

test('the probe result is observable without booting the app', () => {
  const out = execFileSync('bash', [SCRIPT, '--check-runtime'], {
    encoding: 'utf8',
    cwd: fileURLToPath(new URL('..', import.meta.url)),
  });
  assert.match(out, /native=(ok|broken)/,
    'operators need to see this from the shell, not by starting the service and watching it die');
});

test('systemd stops a hopeless crash loop instead of running it forever', () => {
  const unit = readFileSync(new URL('../install.sh', import.meta.url), 'utf8');
  assert.match(unit, /StartLimitBurst=/,
    'Restart=always with no start limit produced 10,394 restarts over eight hours. The service was '
    + 'down that whole time, so the looping bought nothing and buried the failure in the journal');
  assert.match(unit, /StartLimitIntervalSec=/);
});
