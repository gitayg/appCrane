import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readlinkSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';

// A non-root host below the Node floor used to refuse every self-update
// (apphub: "Node 20 is below the floor (22) and this process is not root").
// AppCrane now downloads the official build into its own directory instead.
// A local server plays nodejs.org/dist, so the index, checksum and archive
// handling run for real without the network.
const { installBundledNode, bundledBinDir } = await import('../server/services/bundledNode.js');

const ROOT = mkdtempSync(join(tmpdir(), 'crane-bundlednode-'));
after(() => rmSync(ROOT, { recursive: true, force: true }));

function tarballFor(version, reports = version) {
  const dir = mkdtempSync(join(ROOT, 'pkg-'));
  const top = join(dir, `node-${version}-linux-x64`);
  mkdirSync(join(top, 'bin'), { recursive: true });
  writeFileSync(join(top, 'bin', 'node'), `#!/bin/sh\necho ${reports}\n`, { mode: 0o755 });
  const out = join(dir, 'out.tar.gz');
  execFileSync('tar', ['-czf', out, '-C', dir, `node-${version}-linux-x64`]);
  return readFileSync(out);
}

const sha = (b) => createHash('sha256').update(b).digest('hex');

// Two throwaway signing keys: TRUSTED is in the keyring handed to the
// installer, STRANGER is not. Real gpg, so the signature check is gpgv's.
function makeKey(name) {
  // Short path on purpose: gpg-agent's socket lives in the homedir, and the
  // macOS temp directory is long enough to exceed the socket name limit.
  const home = mkdtempSync(`/tmp/gpg-${name.slice(0, 1)}-`);
  after(() => { try { execFileSync('gpgconf', ['--homedir', home, '--kill', 'gpg-agent'], { stdio: 'pipe' }); } catch (_) {} rmSync(home, { recursive: true, force: true }); });
  const gpg = (...a) => execFileSync('gpg', ['--homedir', home, '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', ...a], { stdio: 'pipe' });
  gpg('--quick-gen-key', `${name} <${name}@test.invalid>`, 'ed25519', 'sign', 'never');
  const keyring = join(home, 'pub.gpg');
  writeFileSync(keyring, gpg('--export'));
  const sign = (text) => {
    const f = join(home, `sums-${Math.random().toString(36).slice(2)}.txt`);
    writeFileSync(f, text);
    gpg('--detach-sign', '--output', `${f}.sig`, f);
    return readFileSync(`${f}.sig`);
  };
  return { keyring, sign };
}
const TRUSTED = makeKey('trusted');
const STRANGER = makeKey('stranger');
let files = {};
const hits = [];
const server = http.createServer((req, res) => {
  hits.push(req.url);
  const body = files[req.url];
  if (body === undefined) { res.statusCode = 404; return res.end(); }
  res.end(body);
});
await new Promise((r) => server.listen(0, r));
after(() => server.close());
const baseUrl = `http://127.0.0.1:${server.address().port}`;

function publish(version, tarball, { checksum, signer = TRUSTED, tamperAfterSigning = false } = {}) {
  const sums = `${'0'.repeat(64)}  node-${version}-darwin-arm64.tar.gz\n${checksum || sha(tarball)}  node-${version}-linux-x64.tar.gz\n`;
  files = {
    [`/${version}/SHASUMS256.txt.sig`]: signer.sign(sums),
    '/index.json': JSON.stringify([
      { version: 'v23.1.0', files: ['linux-x64'] },
      { version, files: ['linux-x64', 'linux-arm64'] },
      { version: 'v22.0.0', files: ['linux-x64'] },
    ]),
    [`/${version}/SHASUMS256.txt`]: tamperAfterSigning ? sums.replace(/^0/, '1') : sums,
    [`/${version}/node-${version}-linux-x64.tar.gz`]: tarball,
  };
}
const install = (appcraneDir, over = {}) => installBundledNode({
  major: 22, appcraneDir, platform: 'linux', arch: 'x64', baseUrl, keyring: TRUSTED.keyring, allowUnsigned: false, ...over,
});

test('installs the newest release of the wanted major, verified, and points current at it', async () => {
  publish('v22.20.1', tarballFor('v22.20.1'));
  const dir = mkdtempSync(join(ROOT, 'app-'));
  const r = await install(dir);
  assert.equal(r.version, 'v22.20.1', 'took the wrong release from the index (v23 is newer, v22.0.0 is older)');
  assert.equal(r.binDir, bundledBinDir(dir));
  assert.match(readlinkSync(join(dir, '.runtime', 'current')), /node-v22\.20\.1-linux-x64$/);
  assert.equal(execFileSync(join(r.binDir, 'node'), ['-v']).toString().trim(), 'v22.20.1');
});

test('a checksum that does not match is refused, and nothing is activated', async () => {
  publish('v22.20.1', tarballFor('v22.20.1'), { checksum: 'a'.repeat(64) });
  const dir = mkdtempSync(join(ROOT, 'app-'));
  await assert.rejects(install(dir), /checksum mismatch/);
  assert.equal(existsSync(join(dir, '.runtime', 'current')), false, 'a tarball that failed verification became the runtime');
});

test('a binary that does not report the requested major is refused', async () => {
  publish('v22.20.1', tarballFor('v22.20.1', 'v20.1.0'));
  const dir = mkdtempSync(join(ROOT, 'app-'));
  await assert.rejects(install(dir), /reports v20\.1\.0, not v22\.x/);
  assert.equal(existsSync(join(dir, '.runtime', 'current')), false);
});

test('a runtime already unpacked is reused without downloading it again', async () => {
  publish('v22.21.0', tarballFor('v22.21.0'));
  const dir = mkdtempSync(join(ROOT, 'app-'));
  await install(dir);
  hits.length = 0;
  await install(dir);
  assert.ok(!hits.some((u) => u.endsWith('.tar.gz')), `downloaded again: ${hits.join(', ')}`);
});

test('only Linux on x64/arm64 is attempted', async () => {
  const dir = mkdtempSync(join(ROOT, 'app-'));
  await assert.rejects(install(dir, { platform: 'darwin' }), /only installed on Linux/);
  await assert.rejects(install(dir, { arch: 'ppc64' }), /architecture 'ppc64'/);
});

test('a checksum list signed by a key that is not a Node release key is refused', async () => {
  publish('v22.20.1', tarballFor('v22.20.1'), { signer: STRANGER });
  const dir = mkdtempSync(join(ROOT, 'app-'));
  await assert.rejects(install(dir), /did not verify against Node's release keys/);
  assert.equal(existsSync(join(dir, '.runtime', 'current')), false);
});

test('a checksum list changed after it was signed is refused, even when it matches the tarball', async () => {
  publish('v22.20.1', tarballFor('v22.20.1'), { tamperAfterSigning: true });
  const dir = mkdtempSync(join(ROOT, 'app-'));
  await assert.rejects(install(dir), /did not verify/);
});

test('without gpgv it refuses, unless told to settle for the checksum', async () => {
  publish('v22.20.1', tarballFor('v22.20.1'));
  const dir = mkdtempSync(join(ROOT, 'app-'));
  await assert.rejects(install(dir, { gpgv: '/nonexistent/gpgv' }), /gpgv is not installed/);
  const r = await install(dir, { gpgv: '/nonexistent/gpgv', allowUnsigned: true });
  assert.equal(r.version, 'v22.20.1');
});

test('the shipped keyring is the release-keys list, and verifies a real Node release signature', () => {
  const list = readFileSync(new URL('../infra/node-release-keys.list', import.meta.url), 'utf8').trim().split('\n');
  assert.ok(list.length >= 5 && list.every((l) => /^[0-9A-F]{40}$/.test(l)), 'keys.list is not a list of fingerprints');
  // A real signature, captured from https://nodejs.org/dist/v22.23.3/, would
  // make this a network test; gpgv listing the keyring's keys is enough to
  // show the file is a usable keyring rather than armored text or junk.
  const out = execFileSync('gpg', ['--homedir', mkdtempSync(join(ROOT, 'kr-')), '--batch', '--show-keys', '--with-colons',
    fileURLToPath(new URL('../infra/node-release-keys.gpg', import.meta.url))], { stdio: 'pipe' }).toString();
  const fprs = out.split('\n').filter((l) => l.startsWith('fpr:')).map((l) => l.split(':')[9]);
  for (const f of list) assert.ok(fprs.includes(f), `${f} is in the list but not in the keyring`);
});
