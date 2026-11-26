import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

// Docker reload-bug versions and package-source parsing (dockerVersionCheck.js,
// scripts/lib/docker-ce.sh). The dpkg/apt texts below are real output captured
// in mirror.gcr.io/library/ubuntu:24.04 and :25.10 on 2026-11-25 after adding
// Docker's repository, installing then removing containerd.io (state rc), and
// installing docker.io (trimmed to the rows that matter).

const ROOT = mkdtempSync(join(tmpdir(), 'crane-dockerver-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
after(() => rmSync(ROOT, { recursive: true, force: true }));

const { initDb } = await import('../server/db.js');
initDb();
const dv = await import('../server/services/dockerVersionCheck.js');
const { getJobHealth } = await import('../server/services/jobHealth.js');
const LIB = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'lib', 'docker-ce.sh');

const DPKG_L_NOBLE = `Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                          Version                           Architecture Description
+++-=============================-=================================-============-========================================================================
ii  adduser                       3.137ubuntu1                      all          add and remove users and groups
ii  containerd                    2.2.1-0ubuntu1~24.04.4            arm64        daemon to control runC
rc  containerd.io                 2.4.2-4~ubuntu.24.04~noble        arm64        An open and reliable container runtime
ii  docker.io                     29.1.3-0ubuntu3~24.04.2           arm64        Linux container runtime
ii  runc                          1.3.4-0ubuntu1~24.04.1            arm64        Open Container Project - runtime
`;

const POLICY_NOBLE = `docker.io:
  Installed: 29.1.3-0ubuntu3~24.04.2
  Candidate: 29.1.3-0ubuntu3~24.04.2
  Version table:
 *** 29.1.3-0ubuntu3~24.04.2 500
        500 http://ports.ubuntu.com/ubuntu-ports noble-updates/universe arm64 Packages
        500 http://ports.ubuntu.com/ubuntu-ports noble-security/universe arm64 Packages
        100 /var/lib/dpkg/status
     24.0.7-0ubuntu4 500
        500 http://ports.ubuntu.com/ubuntu-ports noble/universe arm64 Packages
docker-ce:
  Installed: (none)
  Candidate: 5:29.10.1-1~ubuntu.24.04~noble
  Version table:
     5:29.10.1-1~ubuntu.24.04~noble 500
        500 https://download.docker.com/linux/ubuntu noble/stable arm64 Packages
`;

const POLICY_QUESTING = `docker.io:
  Installed: 29.1.3-0ubuntu3~25.10.1
  Candidate: 29.1.3-0ubuntu3~25.10.1
  Version table:
 *** 29.1.3-0ubuntu3~25.10.1 500
        500 http://ports.ubuntu.com/ubuntu-ports questing-updates/universe arm64 Packages
        100 /var/lib/dpkg/status
     28.2.2-0ubuntu1 500
        500 http://ports.ubuntu.com/ubuntu-ports questing/universe arm64 Packages
docker-ce:
  Installed: (none)
  Candidate: 5:29.7.2-1~ubuntu.25.10~questing
`;

const MADISON_NOBLE = ` docker-ce | 5:29.10.1-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages
 docker-ce | 5:29.10.0-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages
 docker-ce | 5:29.9.3-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages
 docker-ce | 5:29.4.2-2~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages
 docker-ce | 5:29.4.2-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages
 docker-ce | 5:29.3.0-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages
 docker-ce | 5:29.2.1-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages
 docker-ce | 5:28.5.2-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable arm64 Packages
`;

// version -> reload bug? (measured, or unmeasured and counted as broken)
const TABLE = [
  ['26.1.4', false], ['27.5.1', false], ['28.0.0', true], ['28.0.3', true], ['28.0.4', true],
  ['28.5.2', true], ['29.0.0', true], ['29.1.3', true], ['29.2.0', true], ['29.2.1', true],
  ['29.3.0', false], ['29.4.0', false], ['29.5.0', false], ['29.10.1', false], ['30.0.0', false],
  ['29.1.3-0ubuntu3~24.04.2', true], ['5:29.10.1-1~ubuntu.24.04~noble', false], ['5:28.5.2-1~ubuntu.24.04~noble', true],
];

function lib(script) {
  return execFileSync('bash', ['-c', `set -euo pipefail; . "$1"; ${script}`, 'lib', LIB], { encoding: 'utf8' });
}

test('reload-bug table: JS and the shell library agree on every version', () => {
  for (const [v, bad] of TABLE) assert.equal(dv.hasReloadBug(v), bad, `JS ${v}`);
  const shell = lib(`for v in ${TABLE.map(([v]) => `'${v}'`).join(' ')}; do if dce_reload_bug "$v"; then echo "$v 1"; else echo "$v 0"; fi; done`);
  const got = Object.fromEntries(shell.trim().split('\n').map((l) => l.split(' ')).map(([v, b]) => [v, b === '1']));
  for (const [v, bad] of TABLE) assert.equal(got[v], bad, `shell ${v}`);
});

test('upstream version strips epoch and Debian revision; junk is not a version', () => {
  assert.equal(dv.upstreamVersion('5:29.10.1-1~ubuntu.24.04~noble'), '29.10.1');
  assert.equal(dv.upstreamVersion('29.1.3-0ubuntu3~25.10.1'), '29.1.3');
  assert.equal(dv.upstreamVersion('(none)'), null);
  assert.equal(dv.hasReloadBug(''), false);
  assert.equal(lib(`dce_upstream '5:29.10.1-1~ubuntu.24.04~noble'; dce_upstream '29.1.3-0ubuntu3~24.04.2'`), '29.10.1\n29.1.3\n');
});

test('install.sh fit test: bad set or below 27 or no candidate means Docker CE', () => {
  const out = lib(`for v in 26.1.4 27.5.1 29.1.3-0ubuntu3~24.04.2 29.3.0 none '(none)'; do if dce_distro_unfit "$v"; then echo "$v ce"; else echo "$v distro"; fi; done`);
  assert.deepEqual(out.trim().split('\n'), ['26.1.4 ce', '27.5.1 distro', '29.1.3-0ubuntu3~24.04.2 ce', '29.3.0 distro', 'none ce', '(none) ce']);
});

test('madison: newest >= 29.3 by default, an exact version on request, nothing below 29.3', () => {
  const pick = (want) => execFileSync('bash', ['-c', `. "$1"; dce_pick_version "$2"`, 'lib', LIB, want], { input: MADISON_NOBLE, encoding: 'utf8' }).trim();
  assert.equal(pick(''), '5:29.10.1-1~ubuntu.24.04~noble');
  assert.equal(pick('29.9.3'), '5:29.9.3-1~ubuntu.24.04~noble');
  assert.equal(pick('29.4.2'), '5:29.4.2-2~ubuntu.24.04~noble');
  assert.equal(pick('29.2.1'), '');
  assert.equal(pick('28.5.2'), '');
  assert.equal(pick('29.99.0'), '');
});

test('install arguments replace docker.io, containerd and runc in the same transaction', () => {
  const have = 'containerd=2.2.1-0ubuntu1~24.04.4\ndocker.io=29.1.3-0ubuntu3~24.04.2\nrunc=1.3.4-0ubuntu1~24.04.1\ndocker-buildx=0.30.1-0ubuntu1~24.04.1';
  const out = execFileSync('bash', ['-c', '. "$1"; dce_install_args "$2" "$3"', 'lib', LIB, '5:29.10.1-1~ubuntu.24.04~noble', have], { encoding: 'utf8' });
  assert.deepEqual(out.trim().split('\n'), [
    'docker-ce=5:29.10.1-1~ubuntu.24.04~noble', 'docker-ce-cli=5:29.10.1-1~ubuntu.24.04~noble', 'containerd.io',
    'docker-buildx-plugin', 'docker-buildx-', 'docker.io-', 'containerd-', 'runc-',
  ]);
});

test('dpkg -l parsing: ii and rc rows, header lines skipped', () => {
  const rows = dv.parseDpkgList(DPKG_L_NOBLE);
  assert.deepEqual(rows.map((r) => `${r.state} ${r.name} ${r.version}`), [
    'ii adduser 3.137ubuntu1',
    'ii containerd 2.2.1-0ubuntu1~24.04.4',
    'rc containerd.io 2.4.2-4~ubuntu.24.04~noble',
    'ii docker.io 29.1.3-0ubuntu3~24.04.2',
    'ii runc 1.3.4-0ubuntu1~24.04.1',
  ]);
});

test('dpkg -S and apt-cache policy parsing', () => {
  assert.equal(dv.parseDpkgSearch('docker.io: /usr/bin/dockerd\n'), 'docker.io');
  assert.equal(dv.parseDpkgSearch('docker-ce: /usr/bin/dockerd\n'), 'docker-ce');
  assert.equal(dv.parseDpkgSearch('dpkg-query: no path found matching pattern /usr/sbin/dockerd\n'), null);
  assert.deepEqual(dv.parseAptPolicy(POLICY_NOBLE), {
    'docker.io': { installed: '29.1.3-0ubuntu3~24.04.2', candidate: '29.1.3-0ubuntu3~24.04.2' },
    'docker-ce': { installed: null, candidate: '5:29.10.1-1~ubuntu.24.04~noble' },
  });
  assert.equal(dv.parseAptPolicy(POLICY_QUESTING)['docker.io'].candidate, '29.1.3-0ubuntu3~25.10.1');
});

test('the 24.04 host: docker.io 29.1.3 is a warning naming the upgrade script, rc leftovers listed', () => {
  const d = dv.evaluateDockerHost({ serverVersion: '29.1.3', owner: 'docker.io', dpkgList: dv.parseDpkgList(DPKG_L_NOBLE), policy: dv.parseAptPolicy(POLICY_NOBLE), script: '/srv/appcrane/scripts/docker-upgrade.sh' });
  assert.equal(d.severity, 'warning');
  assert.equal(d.reload_bug, true);
  assert.equal(d.mixed_source, false);
  assert.deepEqual(d.leftovers, ['containerd.io']);
  assert.match(d.message, /Docker 29\.1\.3 \(docker\.io \(Ubuntu\)\) has the reload bug/);
  assert.match(d.message, /Ubuntu's newest docker\.io here is 29\.1\.3, also affected/);
  assert.match(d.message, /sudo bash \/srv\/appcrane\/scripts\/docker-upgrade\.sh/);
  assert.match(d.message, /every container restarts/);
  assert.match(d.message, /dpkg state rc\): containerd\.io/);
});

test('mixed source is a warning even on a fixed version; rc leftovers alone are info', () => {
  const mixed = dv.parseDpkgList('ii  docker.io  29.4.0-0ubuntu1  arm64  x\nii  docker-ce-cli  5:29.10.1-1~ubuntu.24.04~noble  arm64  x\n');
  const m = dv.evaluateDockerHost({ serverVersion: '29.4.0', owner: 'docker.io', dpkgList: mixed });
  assert.equal(m.severity, 'warning');
  assert.equal(m.mixed_source, true);
  assert.match(m.message, /mixed-source/);
  assert.match(m.message, /docker-upgrade\.sh/);
  const rc = dv.evaluateDockerHost({ serverVersion: '29.10.1', owner: 'docker-ce', dpkgList: dv.parseDpkgList('ii  docker-ce  5:29.10.1-1~ubuntu.24.04~noble  arm64  x\nrc  docker.io  29.1.3-0ubuntu3~24.04.2  arm64  x\n') });
  assert.equal(rc.severity, 'info');
  assert.equal(rc.reload_bug, false);
  const clean = dv.evaluateDockerHost({ serverVersion: '29.10.1', owner: 'docker-ce', dpkgList: dv.parseDpkgList('ii  docker-ce  5:29.10.1-1~ubuntu.24.04~noble  arm64  x\n') });
  assert.equal(clean.severity, undefined);
  assert.match(clean.message, /reloads without breaking/);
});

test('runDockerVersionCheck reads docker, dpkg and apt and marks the Job Health row as a warning', async () => {
  const calls = [];
  dv._setDockerVersionExecForTests(async (cmd, args) => {
    calls.push(`${cmd} ${args.join(' ')}`);
    if (cmd === 'docker') return '29.1.3\n';
    if (cmd === 'dpkg' && args[0] === '-S') return `docker.io: ${args[1]}\n`;
    if (cmd === 'dpkg' && args[0] === '-l') return DPKG_L_NOBLE;
    if (cmd === 'apt-cache') return POLICY_NOBLE;
    throw new Error('unexpected');
  }, (p) => p === '/usr/bin/dockerd');
  try {
    const d = await dv.runDockerVersionCheck();
    assert.equal(d.owner, 'docker.io');
    assert.ok(calls.includes('dpkg -S /usr/bin/dockerd'));
    assert.ok(calls.includes('apt-cache policy docker.io docker-ce'));
    const row = getJobHealth().find((j) => j.id === 'docker-version');
    assert.equal(row.detail.severity, 'warning');
    assert.match(row.detail.message, /reload bug/);
  } finally {
    dv._setDockerVersionExecForTests(null);
  }
});
