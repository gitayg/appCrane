import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

// The boot wrapper reconciles the Node runtime before starting AppCrane
// (v2.55.1).
//
// The self-update endpoint lives inside server/index.js, so the updater that
// runs is always the version being upgraded FROM. A host below the current Node
// floor runs an updater with no Node step: `git reset --hard origin/main`
// succeeds, and before v2.57.0 the `npm install` after it was refused by
// .npmrc's engine-strict, leaving the tree ahead of node_modules. That guard is
// gone now precisely because it could only refuse — but the wrapper's job is
// unchanged and matters more: it is what raises the runtime after the old
// updater completes and restarts itself.
//
// systemd's ExecStart is scripts/safe-boot.sh — a file inside that tree — so
// the reset that failed to finish still delivered a new wrapper. On the next
// restart it runs, even though the node process was old. That is the only
// channel into a host that is already stuck, which is why this logic lives
// here and not in the updater.
//
// Driven through the script's own --check-runtime mode: the decision is what
// matters, and invoking apt in a test would be both impossible on this machine
// and wrong on any other.

// fileURLToPath, not .pathname — the repo path contains a space, which .pathname
// percent-encodes into a filename bash cannot find.
const SCRIPT = fileURLToPath(new URL('../scripts/safe-boot.sh', import.meta.url));

function decide(engines) {
  const dir = mkdtempSync(join(tmpdir(), 'sb-'));
  mkdirSync(join(dir, 'data'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify(
    { name: 'appcrane', version: '9.9.9', ...(engines ? { engines } : {}) },
  ));
  const out = execFileSync('bash', [SCRIPT, '--check-runtime'], {
    env: { ...process.env, APPCRANE_DIR: dir, DATA_DIR: join(dir, 'data') },
    encoding: 'utf8',
  });
  // The script prints `have=.. want=..` on one line and `decision=..` on the
  // next, so split on all whitespace rather than newlines.
  return Object.fromEntries(out.trim().split(/\s+/).map((kv) => kv.split('=')));
}

const CURRENT = Number(process.versions.node.split('.')[0]);

test('a host at or above the floor boots without touching anything', () => {
  const r = decide({ node: `>=${CURRENT}` });
  assert.equal(r.want, String(CURRENT));
  assert.equal(r.decision, 'ok');
});

test('a host BELOW the floor is identified for upgrade — the app.example.com case', () => {
  const r = decide({ node: `>=${CURRENT + 2}` });
  assert.equal(r.have, String(CURRENT));
  assert.equal(r.want, String(CURRENT + 2));
  assert.equal(r.decision, 'upgrade',
    'nothing in the old node process knows to raise the runtime; this wrapper is the only thing ' +
    'that runs from the updated tree before the app starts');
});

test('the floor is read from the engines range, not guessed', () => {
  assert.equal(decide({ node: '>=22' }).want, '22');
  assert.equal(decide({ node: '>=22.11.0' }).want, '22');
  assert.equal(decide({ node: '^24.0.0' }).want, '24');
});

test('a package.json with no engines field does not block boot', () => {
  const r = decide(null);
  assert.equal(r.want, '?');
  assert.equal(r.decision, 'ok',
    'an unreadable or absent floor must never stop a host from booting — a boot wrapper that ' +
    'refuses to boot is worse than the problem it solves');
});

test('the real package.json declares a floor this can act on', () => {
  // Guards against the engines field being removed or reshaped into something
  // the wrapper silently reads as "no floor".
  const pkg = JSON.parse(execFileSync('cat', [fileURLToPath(new URL('../package.json', import.meta.url))], { encoding: 'utf8' }));
  assert.match(pkg.engines?.node || '', /\d+/, 'package.json must declare engines.node');
  const r = decide(pkg.engines);
  assert.notEqual(r.want, '?', 'the wrapper must be able to parse the real floor');
});

// v2.92.0: the Node AppCrane downloads for itself (<appcrane>/.runtime/current)
// is what boots when the system Node is below the floor, and only then.
// Fake `node` binaries report a chosen major and hand everything else to the
// real node, so the wrapper's own checks run unchanged.
import { chmodSync } from 'fs';
const REAL_NODE = process.execPath;
function fakeNode(dir, major) {
  mkdirSync(dir, { recursive: true });
  const p = join(dir, 'node');
  writeFileSync(p, `#!/bin/sh\ncase "$*" in *process.versions.node*) echo ${major}; exit 0 ;; esac\nexec "${REAL_NODE}" "$@"\n`);
  chmodSync(p, 0o755);
  return p;
}
function decideWith({ system, bundled, floor = 22 }) {
  const dir = mkdtempSync(join(tmpdir(), 'sb-bundled-'));
  mkdirSync(join(dir, 'data'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'appcrane', version: '9.9.9', engines: { node: `>=${floor}` } }));
  const sysBin = join(dir, 'sysbin');
  fakeNode(sysBin, system);
  let bundledNode = null;
  if (bundled) bundledNode = fakeNode(join(dir, '.runtime', 'current', 'bin'), bundled);
  const out = execFileSync('bash', [SCRIPT, '--check-runtime'], {
    env: { ...process.env, PATH: `${sysBin}:${process.env.PATH}`, APPCRANE_DIR: dir, DATA_DIR: join(dir, 'data') },
    encoding: 'utf8',
  });
  return { ...Object.fromEntries(out.trim().split(/\s+/).map((kv) => kv.split('='))), bundledNode, sysNode: join(sysBin, 'node') };
}

test("the system Node is below the floor and AppCrane's own meets it: boot on AppCrane's own", () => {
  const r = decideWith({ system: 20, bundled: 22 });
  assert.equal(r.have, '22');
  assert.equal(r.decision, 'ok');
  assert.equal(r.node_path, r.bundledNode, 'the wrapper still boots the system Node 20');
});

test('a system Node that meets the floor wins over the bundled one', () => {
  const r = decideWith({ system: 22, bundled: 22 });
  assert.equal(r.node_path, r.sysNode, 'an administrator who upgraded the system Node is overridden by an old download');
});

test('no bundled Node and a system Node below the floor is still flagged for upgrade', () => {
  const r = decideWith({ system: 20 });
  assert.equal(r.decision, 'upgrade');
});

test('the wrapper tells the server it was started by safe-boot.sh', () => {
  const src = readFileSync(SCRIPT, 'utf8');
  assert.ok(src.indexOf('export APPCRANE_SAFE_BOOT=1') < src.indexOf('node server/index.js &'),
    'the flag is set after node starts, so self-update would never offer a bundled Node');
  assert.match(src, /upgrade_node "\$want" \|\| install_bundled_node "\$want"/,
    'a stuck host without root never tries the download');
});
