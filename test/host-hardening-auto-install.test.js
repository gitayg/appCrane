import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// install-host-hardening.sh, run as root in an Ubuntu container, writes the
// version stamp the automatic apply reads; the server accepts exactly what it
// writes and refuses it once the checkout's script differs.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPTS = join(ROOT, 'scripts');
const src = readFileSync(join(SCRIPTS, 'host-hardening.sh'), 'utf8');
const version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;
const { images, buildTimeLeft, note, section } = await import('./host-hardening-harness.js');
const H = await import('../server/services/hostHardening.js');
const A = await import('../server/services/hostHardeningAuto.js');

const SUDO_TAG = 'appcrane-test-host-hardening-sudo:24.04';
let sudoImage = null;
if (images['24.04'] && buildTimeLeft() >= 1000) {
  const t0 = Date.now();
  try {
    execFileSync('docker', ['build', '-q', '-t', SUDO_TAG, '-'], {
      input: `FROM ${images['24.04']}\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo >/dev/null && rm -rf /var/lib/apt/lists/*\nRUN useradd -m app\n`,
      stdio: ['pipe', 'pipe', 'pipe'], timeout: Math.max(1000, buildTimeLeft()),
    });
    sudoImage = SUDO_TAG;
  } catch (_) { /* skipped below */ }
  note('sudo image', t0, !!sudoImage);
}

test('install-host-hardening writes a root-owned stamp the automatic apply accepts, and refuses once the checkout changes', { skip: sudoImage ? false : 'docker (or the package mirror) unavailable' }, () => {
  const body = [
    'mkdir -p /opt/appcrane/scripts',
    'cp /src/scripts/host-hardening.sh /src/scripts/install-host-hardening.sh /src/scripts/appcrane-publish-chain.sh /src/scripts/appcrane-db-chain.sh /opt/appcrane/scripts/',
    'cp /src/package.json /opt/appcrane/package.json',
    'chown -R app:app /opt/appcrane',
    'echo "@@INSTALL"; bash /opt/appcrane/scripts/install-host-hardening.sh app 2>&1; echo "@@EXIT $?"',
    `echo "@@STAMP"; cat ${A.STAMP_FILE}`,
    `echo "@@MODE"; stat -c '%U:%G %a' ${A.STAMP_FILE}`,
    `echo "@@COPY"; base64 -w0 ${H.INSTALLED_SCRIPT}; echo`,
    'echo "@@LEFT"; ls -A /usr/local/lib/appcrane',
    `echo "@@FORGE"; su app -c "echo x >> ${A.STAMP_FILE}" 2>&1; echo "rc=$?"`,
    'echo "@@END"',
    'rm -rf /usr/local/lib/appcrane; mkdir -p /tmp/shim; printf "#!/bin/sh\\nexit 1\\n" > /tmp/shim/chown; chmod +x /tmp/shim/chown',
    'echo "@@ABORT"; PATH=/tmp/shim:$PATH bash /opt/appcrane/scripts/install-host-hardening.sh app >/dev/null 2>&1; echo "rc=$?"; ls -A /usr/local/lib/appcrane',
    'echo "@@END2"',
  ].join('\n');
  const out = execFileSync('docker', ['run', '--rm',
    '-v', `${SCRIPTS}:/src/scripts:ro`, '-v', `${join(ROOT, 'package.json')}:/src/package.json:ro`,
    sudoImage, 'bash', '-c', body], { encoding: 'utf8', timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.match(out, /^@@EXIT 0$/m, out);
  const stamp = A.parseStamp(section(out, 'STAMP'));
  const installed = Buffer.from(section(out, 'COPY').trim(), 'base64').toString('utf8');
  const sha = (s) => createHash('sha256').update(s).digest('hex');
  assert.equal(stamp.version, version);
  assert.equal(stamp.source_sha256, sha(src));
  assert.equal(stamp.installed_sha256, sha(installed));
  assert.equal(stamp.publish_chain_sha256, sha(readFileSync(join(SCRIPTS, 'appcrane-publish-chain.sh'), 'utf8')), 'the stamp names the publish helper it installed');
  assert.equal(stamp.db_chain_sha256, sha(readFileSync(join(SCRIPTS, 'appcrane-db-chain.sh'), 'utf8')), 'the stamp names the database helper it installed');
  assert.equal(section(out, 'MODE').trim(), 'root:root 644');
  assert.deepEqual(section(out, 'LEFT').trim().split('\n').sort(), ['appcrane-db-chain.sh', 'appcrane-publish-chain.sh', 'host-hardening.sh', 'host-hardening.version'], 'no temporary files left');
  assert.match(section(out, 'FORGE'), /Permission denied\n.*rc=[1-9]$/ms, 'the run user cannot write the stamp');
  const abort = section(out, 'ABORT').trim().split('\n');
  assert.match(abort[0], /^rc=[1-9]/, `the install must stop when chown fails: ${abort}`);
  assert.deepEqual(abort.slice(1), [], 'an install aborted by set -e leaves no temporary file behind');

  const dbHelper = readFileSync(join(SCRIPTS, 'appcrane-db-chain.sh'), 'utf8');
  const files = {
    '/opt/appcrane/scripts/host-hardening.sh': src, [H.INSTALLED_SCRIPT]: installed, [A.STAMP_FILE]: section(out, 'STAMP'),
    '/opt/appcrane/scripts/appcrane-publish-chain.sh': readFileSync(join(SCRIPTS, 'appcrane-publish-chain.sh'), 'utf8'),
    '/opt/appcrane/scripts/appcrane-db-chain.sh': dbHelper,
  };
  const d = (f) => ({ repoDir: '/opt/appcrane', readFile: (p) => { if (f[p] == null) throw new Error('ENOENT'); return f[p]; } });
  assert.deepEqual(A.installedCopyMatches(d(files)).ok, true);
  const upgraded = { ...files, '/opt/appcrane/scripts/host-hardening.sh': `${src}# a later release\n` };
  assert.equal(A.installedCopyMatches(d(upgraded)).ok, false);
  const helperOnly = { ...files, '/opt/appcrane/scripts/appcrane-db-chain.sh': `${dbHelper}# a later release\n` };
  assert.equal(A.installedCopyMatches(d(helperOnly)).ok, false, 'a release that changes only the database helper is stale');
});
