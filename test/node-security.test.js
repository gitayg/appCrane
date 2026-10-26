import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync, spawn } from 'child_process';
import { fileURLToPath } from 'url';
import net from 'net';

// AppCrane's own runtime against known Node RCE advisories (CVE-2026-111497,
// "Node2Shell", fixed in 22.23.4 / 24.22.1 / 26.12.1; 23 and 25 are end of life).

const { nodeSecurityStatus, securityMinimum, NODE_SECURITY_ADVISORIES } = await import('../server/services/nodeSecurity.js');
const { planNodeUpgrade, verifySecurityUpgrade, SKIP } = await import('../server/services/nodeUpgrade.js');

test('security minimum table', () => {
  const cases = {
    '22.22.0': 'vulnerable', '22.23.4': 'ok', 'v22.23.5': 'ok', '24.22.0': 'vulnerable', '24.22.1': 'ok',
    '25.3.0': 'unsupported', '23.11.1': 'unsupported', '26.12.0': 'vulnerable', '26.12.1': 'ok', '20.19.5': 'unsupported', '27.0.0': 'ok',
  };
  for (const [v, want] of Object.entries(cases)) assert.equal(nodeSecurityStatus(v).status, want, v);
  assert.equal(securityMinimum(22), '22.23.4');
  assert.equal(securityMinimum(24), '24.22.1');
  assert.equal(securityMinimum(26), '26.12.1');
  assert.equal(securityMinimum(25), null);
  assert.equal(NODE_SECURITY_ADVISORIES[0].id, 'CVE-2026-111497');
  assert.match(nodeSecurityStatus('22.22.0').message, /CVE-2026-111497.*Upgrade to 22\.23\.4/);
  assert.match(nodeSecurityStatus('25.3.0').message, /unsupported\. Upgrade to 22\.23\.4\+, 24\.22\.1\+, 26\.12\.1\+/);
});

const HOST = { floor: 22, platform: 'linux', isRoot: true, hasApt: true, nodePath: '/usr/bin/node', arch: 'x64' };

test('self-update plan: a vulnerable runtime at the floor is upgraded within its major, never blocking', () => {
  const p = planNodeUpgrade({ ...HOST, currentMajor: 22, currentVersion: '22.22.0' });
  assert.equal(p.upgrade, true);
  assert.equal(p.blocking, false);
  assert.equal(p.security, true);
  assert.equal(p.targetMajor, 22);
  assert.match(p.commands[0][1][1], /setup_22\.x/);
  const p24 = planNodeUpgrade({ ...HOST, currentMajor: 24, currentVersion: '24.22.0' });
  assert.match(p24.commands[0][1][1], /setup_24\.x/, 'a security upgrade must not change the major');

  const bundled = planNodeUpgrade({ ...HOST, isRoot: false, underSafeBoot: true, currentMajor: 22, currentVersion: '22.22.0' });
  assert.deepEqual([bundled.upgrade, bundled.method, bundled.targetMajor, bundled.blocking], [true, 'bundled', 22, false]);
  const cannot = planNodeUpgrade({ ...HOST, isRoot: false, currentMajor: 22, currentVersion: '22.22.0' });
  assert.deepEqual([cannot.upgrade, cannot.blocking, cannot.reason], [false, false, SKIP.NOT_ROOT]);
  const skip = planNodeUpgrade({ ...HOST, skipEnv: '1', currentMajor: 22, currentVersion: '22.22.0' });
  assert.deepEqual([skip.upgrade, skip.blocking, skip.reason], [false, false, SKIP.DISABLED]);
  const mac = planNodeUpgrade({ ...HOST, platform: 'darwin', currentMajor: 22, currentVersion: '22.22.0' });
  assert.deepEqual([mac.upgrade, mac.blocking], [false, false]);
});

test('self-update plan: patched, unsupported, and the unchanged floor semantics', () => {
  assert.equal(planNodeUpgrade({ ...HOST, currentMajor: 22, currentVersion: '22.23.4' }).reason, SKIP.AT_FLOOR);
  const eol = planNodeUpgrade({ ...HOST, currentMajor: 25, currentVersion: '25.3.0' });
  assert.deepEqual([eol.upgrade, eol.blocking, eol.reason], [false, false, SKIP.UNSUPPORTED_LINE]);
  assert.match(eol.message, /24\.22\.1\+/);
  assert.equal(planNodeUpgrade({ ...HOST, currentMajor: 22 }).reason, SKIP.AT_FLOOR, 'without a version the old major-only answer stands');
  const low = planNodeUpgrade({ ...HOST, currentMajor: 20, currentVersion: '20.19.5' });
  assert.deepEqual([low.upgrade, low.blocking, low.security], [true, false, undefined], 'below the floor is still the floor upgrade');
  assert.match(low.commands[0][1][1], /setup_22\.x/);
  const lowSkip = planNodeUpgrade({ ...HOST, skipEnv: '1', currentMajor: 20, currentVersion: '20.19.5' });
  assert.equal(lowSkip.blocking, true, 'the floor refusal must stay blocking');
});

test('verifySecurityUpgrade asks the full version, not the major', () => {
  assert.equal(verifySecurityUpgrade('22.23.4').ok, true);
  assert.equal(verifySecurityUpgrade('22.22.1').ok, false);
  assert.equal(verifySecurityUpgrade('').ok, false);
});

test('Job Health: a vulnerable runtime is a warning row, a patched one is ok', async () => {
  process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-node-sec-'));
  process.env.ENCRYPTION_KEY = 'e'.repeat(64);
  const { initDb } = await import('../server/db.js');
  initDb();
  const jh = await import('../server/services/jobHealth.js');
  const { runNodeSecurityCheck, JOB_ID } = await import('../server/services/nodeSecurityCheck.js');
  jh._resetJobHealthForTests();
  jh.jobStarted(JOB_ID);
  const row = () => jh.getJobHealth().find((j) => j.id === JOB_ID);
  await jh.trackJob(JOB_ID, () => runNodeSecurityCheck('22.22.0'));
  assert.equal(row().status, 'warning');
  assert.match(row().detail.message, /CVE-2026-111497.*22\.23\.4/);
  await jh.trackJob(JOB_ID, () => runNodeSecurityCheck('22.23.4'));
  assert.equal(row().status, 'ok');
  await jh.trackJob(JOB_ID, () => runNodeSecurityCheck('25.3.0'));
  assert.equal(row().status, 'warning');
  jh._resetJobHealthForTests();
});

// ---- scripts/safe-boot.sh ------------------------------------------------------

const SCRIPT = fileURLToPath(new URL('../scripts/safe-boot.sh', import.meta.url));
const REAL_NODE = process.execPath;
function fakeNode(dir, major, verdict) {
  mkdirSync(dir, { recursive: true });
  const p = join(dir, 'node');
  writeFileSync(p, `#!/bin/sh\ncase "$*" in *nodeSecurity.js*) echo ${verdict}; exit 0 ;; *process.versions.node*) echo ${major}; exit 0 ;; esac\nexec "${REAL_NODE}" "$@"\n`);
  chmodSync(p, 0o755);
  return p;
}
function check({ system, bundled }) {
  const dir = mkdtempSync(join(tmpdir(), 'sb-sec-'));
  mkdirSync(join(dir, 'data'), { recursive: true });
  mkdirSync(join(dir, 'server', 'services'), { recursive: true });
  writeFileSync(join(dir, 'server', 'services', 'nodeSecurity.js'), '');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'appcrane', version: '9.9.9', engines: { node: '>=22' } }));
  const sys = fakeNode(join(dir, 'sysbin'), 22, system);
  const b = bundled ? fakeNode(join(dir, '.runtime', 'current', 'bin'), 22, bundled) : null;
  const out = execFileSync('bash', [SCRIPT, '--check-runtime'], {
    env: { ...process.env, PATH: `${join(dir, 'sysbin')}:${process.env.PATH}`, APPCRANE_DIR: dir, DATA_DIR: join(dir, 'data') }, encoding: 'utf8',
  });
  rmSync(dir, { recursive: true, force: true });
  return { ...Object.fromEntries(out.trim().split(/\s+/).map((kv) => kv.split('='))), sys, b };
}

test('safe-boot: a patched bundled Node wins over a vulnerable system Node of the same major', () => {
  const r = check({ system: 'vulnerable', bundled: 'ok' });
  assert.equal(r.node_path, r.b);
  assert.equal(r.security, 'ok');
});

test('safe-boot: a patched system Node, or a bundled one that is no better, keeps the system Node', () => {
  const a = check({ system: 'ok', bundled: 'ok' });
  assert.equal(a.node_path, a.sys);
  const b = check({ system: 'vulnerable', bundled: 'vulnerable' });
  assert.equal(b.node_path, b.sys);
  assert.equal(b.security, 'vulnerable');
});

test('safe-boot: the script-mode verdict of nodeSecurity.js matches the module', () => {
  const out = execFileSync(REAL_NODE, [fileURLToPath(new URL('../server/services/nodeSecurity.js', import.meta.url))], { encoding: 'utf8' }).trim();
  assert.equal(out, nodeSecurityStatus(process.versions.node).status);
});

// ---- boot log --------------------------------------------------------------------

test('boot log lines: 22.22.0 warns with the CVE and the fixed release; 22.23.4 says nothing', async () => {
  const { bootSecurityWarnings } = await import('../server/services/nodeSecurityCheck.js');
  const bad = bootSecurityWarnings('22.22.0');
  assert.match(bad[0], /SECURITY: Node 22\.22\.0 is affected by CVE-2026-111497.*Upgrade to 22\.23\.4 or later/);
  assert.deepEqual(bootSecurityWarnings('22.23.4'), []);
  assert.match(bootSecurityWarnings('25.3.0')[0], /unsupported/);
  const src = (await import('fs')).readFileSync(new URL('../server/index.js', import.meta.url), 'utf8');
  const listen = src.indexOf('app.listen(PORT, HOST');
  const call = src.indexOf('bootSecurityWarnings()) log.warn(line)', listen);
  assert.ok(listen > 0 && call > listen, 'server/index.js does not log bootSecurityWarnings() at boot');
});

test('one source: the host table is the Node entries of runtime-advisories.json', async () => {
  const bundled = JSON.parse((await import('fs')).readFileSync(new URL('../server/services/autoPatch/runtime-advisories.json', import.meta.url), 'utf8'));
  const node = bundled.advisories.filter((a) => a.runtime === 'node');
  assert.deepEqual(NODE_SECURITY_ADVISORIES.map((a) => a.id), node.map((a) => a.id));
  assert.deepEqual({ ...NODE_SECURITY_ADVISORIES[0].fixed }, { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' });
  const { runtimeAdvisories } = await import('../server/services/autoPatch/runtimeAdvisories.js');
  for (const v of ['22.22.0', '22.23.4', '24.22.0', '24.22.1', '25.3.0', '26.12.1']) {
    const hosted = await runtimeAdvisories('node', v, { osvRecords: [] });
    const host = nodeSecurityStatus(v).status;
    assert.equal(host === 'ok', !hosted.affected, `${v}: host says ${host}, hosted-app check says affected=${hosted.affected}`);
    assert.equal(host === 'unsupported', hosted.affected && hosted.unsupportedBranch, `${v}: unsupported disagrees`);
  }
});

async function freePort() {
  return new Promise((resolve) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
}

test('boot log: the running Node is reported when it is missing a security fix', async () => {
  const sec = nodeSecurityStatus(process.versions.node);
  const dir = mkdtempSync(join(tmpdir(), 'crane-node-sec-boot-'));
  const child = spawn(process.execPath, ['server/index.js'], {
    env: { ...process.env, DATA_DIR: dir, PORT: String(await freePort()), HOST: '127.0.0.1', ENCRYPTION_KEY: 'e'.repeat(64),
      CRANE_DOMAIN: 'crane.example.com', LOG_LEVEL: 'warn', APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  try {
    for (let i = 0; i < 120 && !/SECURITY: |boot sentinel|AppCrane .* running|listening/i.test(out); i++) await new Promise((r) => setTimeout(r, 250));
    await new Promise((r) => setTimeout(r, 1000));
    if (sec.status === 'ok') assert.doesNotMatch(out, /SECURITY: Node/);
    else assert.ok(out.includes(`SECURITY: ${sec.message}`), `boot log lacks the security warning for Node ${process.versions.node}`);
  } finally {
    child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});
