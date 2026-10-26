import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// The npm bump must change exactly the vulnerable package. The fixtures are
// real npm 10 output (2026-10-22): base = lodash 4.17.15 direct, minimist
// 1.2.5 transitive via mkdirp; direct = `npm install --package-lock-only
// lodash@4.17.21`; transitive = the same for minimist@1.2.6 followed by the
// original package.json and a second `npm install --package-lock-only`.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-auto-patch-bump-'));
const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'auto-patch');
const read = (f) => readFileSync(join(FIX, f), 'utf8');
const { verifyNpmBump, npmHelperArgs, dependencyMode, runNpmBump, NPM_HELPER_IMAGE } = await import('../server/services/autoPatch/npmBump.js');
const egress = await import('../server/services/autoPatch/egress.js');
const NET = { network: egress.INTERNAL_NETWORK, proxyUrl: 'http://appcrane-auto-patch-proxy-abc123:3128' };

const base = { packageJson: read('base.package.json'), packageLock: read('base.package-lock.json') };
const direct = { packageJson: read('direct.package.json'), packageLock: read('direct.package-lock.json') };
const transitive = { packageJson: base.packageJson, packageLock: read('transitive.package-lock.json') };
const edit = (text, fn) => { const o = JSON.parse(text); fn(o); return JSON.stringify(o, null, 2) + '\n'; };

test('dependencyMode: direct, transitive, and refused shapes', () => {
  const pkg = JSON.parse(base.packageJson);
  assert.equal(dependencyMode(pkg, 'lodash'), 'direct');
  assert.equal(dependencyMode(pkg, 'ms'), 'direct');
  assert.equal(dependencyMode(pkg, 'minimist'), 'transitive');
  assert.equal(dependencyMode({ dependencies: { a: '1' }, devDependencies: { a: '1' } }, 'a'), null);
  assert.equal(dependencyMode({ peerDependencies: { a: '1' } }, 'a'), null);
});

test('direct bump: only lodash moves (package.json range + lock root + its entry) and is accepted', () => {
  const v = verifyNpmBump({ before: base, after: direct, name: 'lodash', fromVersion: '4.17.15', toVersion: '4.17.21', mode: 'direct' });
  assert.deepEqual(v.problems, []);
  assert.equal(v.ok, true);
  assert.deepEqual(v.changed, ['node_modules/lodash']);
});

test('transitive bump: only node_modules/minimist moves, package.json untouched, accepted', () => {
  const v = verifyNpmBump({ before: base, after: transitive, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.deepEqual(v.problems, []);
  assert.equal(v.ok, true);
  assert.deepEqual(v.changed, ['node_modules/minimist']);
});

test('refused: an unrelated locked dependency moved', () => {
  const after = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.packages['node_modules/ms'].version = '2.1.2'; }) };
  const v = verifyNpmBump({ before: base, after, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('node_modules/ms changed')), v.problems.join('\n'));
});

test('refused: an unrelated dependency was added to the lock', () => {
  const after = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.packages['node_modules/left-pad'] = { version: '1.3.0' }; }) };
  const v = verifyNpmBump({ before: base, after, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('node_modules/left-pad was added')));
});

test('refused: an unrelated top-level dependency changed in package.json (direct bump)', () => {
  const after = { ...direct, packageJson: edit(direct.packageJson, (p) => { p.dependencies.mkdirp = '0.5.6'; }) };
  const v = verifyNpmBump({ before: base, after, name: 'lodash', fromVersion: '4.17.15', toVersion: '4.17.21', mode: 'direct' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('package.json changed beyond')));
});

test('refused: package.json changed at all for a transitive bump', () => {
  const after = { ...transitive, packageJson: edit(base.packageJson, (p) => { p.dependencies.minimist = '^1.2.6'; }) };
  const v = verifyNpmBump({ before: base, after, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('package.json changed for a transitive')));
});

test('refused: the vulnerable version is still locked somewhere', () => {
  const after = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.packages['node_modules/mkdirp/node_modules/minimist'] = { version: '1.2.5' }; }) };
  const before = { ...base, packageLock: edit(base.packageLock, (l) => { l.packages['node_modules/mkdirp/node_modules/minimist'] = { version: '1.2.5' }; }) };
  const v = verifyNpmBump({ before, after, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('minimist@1.2.5 is still in the lockfile')));
});

test('refused: the lockfile format was rewritten', () => {
  const after = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.lockfileVersion = 2; }) };
  const v = verifyNpmBump({ before: base, after, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('top-level fields changed')));
});

test('refused: the target moved to a version other than the fixed one, or off the public registry', () => {
  const higher = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.packages['node_modules/minimist'].version = '1.2.8'; }) };
  assert.equal(verifyNpmBump({ before: base, after: higher, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' }).ok, false);
  const elsewhere = { ...transitive, packageLock: edit(transitive.packageLock, (l) => { l.packages['node_modules/minimist'].resolved = 'https://registry.example.invalid/minimist-1.2.6.tgz'; }) };
  const v = verifyNpmBump({ before: base, after: elsewhere, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
  assert.ok(v.problems.some((p) => p.includes('outside the public registry')));
});

test('refused: nothing changed', () => {
  const v = verifyNpmBump({ before: base, after: base, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.equal(v.ok, false);
});

test('the helper container is confined: non-root, no caps, read-only, limits, lowest CPU weight, OOM flag, no secrets', () => {
  const args = npmHelperArgs({ workDir: '/data/tmp/auto-patch/bump-x', name: '@scope/pkg', version: '1.2.3', mode: 'transitive', containerName: 'appcrane-auto-patch-test', ...NET });
  const s = args.join(' ');
  for (const flag of ['--cap-drop ALL', '--security-opt no-new-privileges', '--read-only', '--user 1000:1000', '--pids-limit 256', '--memory 1024m', '--cpus 1', '--oom-score-adj=500', '--cpu-shares=2', '--rm', 'npm_config_ignore_scripts=true', 'npm_config_userconfig=/tmp/no-user-npmrc']) {
    assert.ok(s.includes(flag), `missing ${flag}`);
  }
  assert.ok(!/token|password|_auth/i.test(s));
  assert.deepEqual(args.slice(-4), ['@scope/pkg', '1.2.3', 'transitive', 'prefix']);
  assert.throws(() => npmHelperArgs({ workDir: '/x', name: 'a;rm -rf /', version: '1.0.0', mode: 'direct', containerName: 'c', ...NET }));
  assert.throws(() => npmHelperArgs({ workDir: '/x', name: 'a', version: '1.0.0 && x', mode: 'direct', containerName: 'c', ...NET }));
});

test('live: npm in the helper container bumps only the target (AUTO_PATCH_LIVE_DOCKER=1)', { skip: process.env.AUTO_PATCH_LIVE_DOCKER !== '1' }, async () => {
  const t = await runNpmBump({ ...base, name: 'minimist', version: '1.2.6', mode: 'transitive' });
  const vt = verifyNpmBump({ before: base, after: t, name: 'minimist', fromVersion: '1.2.5', toVersion: '1.2.6', mode: 'transitive' });
  assert.deepEqual(vt.problems, []);
  const dd = await runNpmBump({ ...base, name: 'lodash', version: '4.17.21', mode: 'direct' });
  const vd = verifyNpmBump({ before: base, after: dd, name: 'lodash', fromVersion: '4.17.15', toVersion: '4.17.21', mode: 'direct' });
  assert.deepEqual(vd.problems, []);
});

test('npmVersionInfo reads the publish time and the maintainer\'s deprecation message from the packument', async () => {
  const { npmVersionInfo } = await import('../server/services/autoPatch/registry.js');
  const real = global.fetch;
  const doc = {
    versions: { '4.18.0': { deprecated: 'Bad release. Please use lodash@4.17.21 instead.' }, '4.18.1': {} },
    time: { '4.18.0': '2026-03-31T18:18:42.717Z', '4.18.1': '2026-04-01T21:01:20.458Z' },
  };
  const seen = [];
  global.fetch = async (url) => { seen.push(String(url)); return { ok: true, status: 200, json: async () => doc }; };
  try {
    const bad = await npmVersionInfo('lodash', '4.18.0');
    assert.equal(bad.published.toISOString(), '2026-03-31T18:18:42.717Z');
    assert.equal(bad.deprecated, 'Bad release. Please use lodash@4.17.21 instead.');
    assert.equal((await npmVersionInfo('lodash', '4.18.1')).deprecated, null);
    await assert.rejects(npmVersionInfo('lodash', '9.9.9'), /not on the npm registry/);
    assert.equal(seen[0], 'https://registry.npmjs.org/lodash');
  } finally {
    global.fetch = real;
  }
});

test('npmVersionList lists every version with its publish time and deprecation from one packument read', async () => {
  const { npmVersionList } = await import('../server/services/autoPatch/registry.js');
  const real = global.fetch;
  const doc = {
    versions: { '4.17.21': {}, '4.18.0': { deprecated: 'Bad release. Please use lodash@4.17.21 instead.' }, '4.18.1': {} },
    time: { '4.17.21': '2021-02-20T15:42:16.891Z', '4.18.0': '2026-03-31T18:18:42.717Z', '4.18.1': '2026-04-01T21:01:20.458Z' },
  };
  let n = 0;
  global.fetch = async () => { n++; return { ok: true, status: 200, json: async () => doc }; };
  try {
    const list = await npmVersionList('lodash');
    assert.equal(n, 1);
    assert.deepEqual(list.map((v) => [v.version, v.published.toISOString(), v.deprecated]), [
      ['4.17.21', '2021-02-20T15:42:16.891Z', null],
      ['4.18.0', '2026-03-31T18:18:42.717Z', 'Bad release. Please use lodash@4.17.21 instead.'],
      ['4.18.1', '2026-04-01T21:01:20.458Z', null],
    ]);
  } finally {
    global.fetch = real;
  }
});

test('a failed helper is described without the docker command line or host paths', async () => {
  const { helperFailure } = await import('../server/services/autoPatch/npmBump.js');
  const cmd = 'Command failed: docker run --rm -v /srv/appcrane/data/tmp/auto-patch/bump-x:/work node:22-slim';
  assert.equal(helperFailure(Object.assign(new Error(cmd), { killed: true, signal: 'SIGTERM' }), ''), 'the npm helper timed out after 180s');
  assert.equal(helperFailure(Object.assign(new Error(cmd), { code: 1 }), 'npm error code ETARGET\nnpm error notarget No matching version'), 'npm error code ETARGET\nnpm error notarget No matching version');
  const quiet = helperFailure(Object.assign(new Error(cmd), { code: 1 }), '');
  assert.equal(quiet, 'the npm helper exited with code 1 and no output');
  assert.doesNotMatch(quiet, /docker run|\/work|data\/tmp/);
});

// ---- registry-only egress (egress.js, egressProxyServer.cjs) ----

test('the helper joins only the internal network and reaches npm through the proxy; refuses to build argv without them', () => {
  const args = npmHelperArgs({ workDir: '/data/tmp/auto-patch/bump-x', name: 'lodash', version: '4.17.21', mode: 'direct', containerName: 'c', ...NET });
  const i = args.indexOf('--network');
  assert.equal(args[i + 1], 'appcrane-auto-patch-internal');
  assert.equal(args.filter((a) => a === '--network').length, 1, 'exactly one network');
  assert.ok(args.includes('npm_config_https_proxy=http://appcrane-auto-patch-proxy-abc123:3128'));
  assert.ok(args.includes('npm_config_proxy=http://appcrane-auto-patch-proxy-abc123:3128'));
  assert.throws(() => npmHelperArgs({ workDir: '/x', name: 'a', version: '1.0.0', mode: 'direct', containerName: 'c' }), /internal network/);
  assert.throws(() => npmHelperArgs({ workDir: '/x', name: 'a', version: '1.0.0', mode: 'direct', containerName: 'c', network: 'n' }), /egress proxy/);
});

test('the helper image is pinned by digest, and the proxy runs the same image', () => {
  assert.match(NPM_HELPER_IMAGE, /^node:22-slim@sha256:[0-9a-f]{64}$/);
  const args = npmHelperArgs({ workDir: '/w', name: 'a', version: '1.0.0', mode: 'direct', containerName: 'c', ...NET });
  assert.ok(args.includes(NPM_HELPER_IMAGE));
  const p = egress.proxyRunArgs({ name: 'px', image: NPM_HELPER_IMAGE, sourceDir: '/s' });
  assert.ok(p.includes(NPM_HELPER_IMAGE));
  for (const f of ['--read-only', '--cap-drop', 'no-new-privileges', '--cpu-shares=2', '--user', '/s:/proxy:ro']) assert.ok(p.includes(f), f);
});

test('proxy policy: only CONNECT registry.npmjs.org:443; other hosts, ports, IP literals and junk are refused', () => {
  const { decide } = egress._proxyModule;
  assert.deepEqual(decide('registry.npmjs.org:443'), { host: 'registry.npmjs.org', port: 443 });
  assert.deepEqual(decide('REGISTRY.NPMJS.ORG:443'), { host: 'registry.npmjs.org', port: 443 });
  for (const t of ['example.com:443', 'registry.npmjs.org:80', 'registry.npmjs.org:8443', 'registry.npmjs.org.:443', 'evil.registry.npmjs.org:443',
    'registry.npmjs.org.evil.com:443', '104.16.0.35:443', '[2606:4700::6810:1b23]:443', 'registry.npmjs.org', 'http://registry.npmjs.org/', '', null]) {
    assert.equal(decide(t), null, String(t));
  }
});

test('proxy: tunnels to the registry, answers 403 to another host and to plain HTTP (real sockets)', async () => {
  const net = await import('net');
  const { createProxy } = egress._proxyModule;
  const dialed = [];
  // The upstream is a local echo server standing in for the registry, so the test needs no internet.
  const echo = net.createServer((s) => s.pipe(s));
  await new Promise((r) => echo.listen(0, '127.0.0.1', r));
  const proxy = createProxy({ connect: (port, host, cb) => { dialed.push(`${host}:${port}`); return net.connect(echo.address().port, '127.0.0.1', cb); } });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const port = proxy.address().port;
  const raw = (text) => new Promise((res) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(text));
    let out = '';
    s.on('data', (d) => { out += d; if (out.includes('ping')) s.end(); });
    s.on('close', () => res(out));
    setTimeout(() => s.destroy(), 3000);
  });
  try {
    const ok = await raw('CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\nping');
    assert.match(ok, /^HTTP\/1\.1 200 Connection Established/);
    assert.match(ok, /ping/, 'bytes flow through the tunnel');
    assert.match(await raw('CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n'), /^HTTP\/1\.1 403/);
    assert.match(await raw('GET http://registry.npmjs.org/lodash HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n'), /^HTTP\/1\.1 403/);
    assert.deepEqual(dialed, ['registry.npmjs.org:443'], 'only the registry was ever dialed');
  } finally {
    proxy.close(); echo.close();
  }
});

test('no confinement, no helper: an internal network that cannot be created, or exists without --internal, stops the bump', async () => {
  const calls = [];
  egress._setDockerForTests(async (args) => { calls.push(args.join(' ')); if (args[1] === 'inspect') throw new Error('no such network'); if (args[1] === 'create') throw new Error('could not find an available, non-overlapping IPv4 address pool'); return ''; });
  try {
    await assert.rejects(runNpmBump({ ...base, name: 'minimist', version: '1.2.6', mode: 'transitive' }), (e) => e.code === 'EGRESS_UNCONFINED' && /nothing ran/.test(e.message));
    assert.ok(!calls.some((c) => c.startsWith('run ')), 'neither the proxy nor the helper was started');
    calls.length = 0;
    egress._setDockerForTests(async (args) => { calls.push(args.join(' ')); if (args[1] === 'inspect') return 'false'; return ''; });
    await assert.rejects(egress.ensureInternalNetwork(), /exists but is not internal/);
    await assert.rejects(runNpmBump({ ...base, name: 'minimist', version: '1.2.6', mode: 'transitive' }), (e) => e.code === 'EGRESS_UNCONFINED');
    assert.ok(!calls.some((c) => c.startsWith('run ')));
  } finally {
    egress._setDockerForTests(null);
  }
});

test('live: inside the helper, https://example.com is unreachable and npm still reaches the registry (AUTO_PATCH_LIVE_DOCKER=1)', { skip: process.env.AUTO_PATCH_LIVE_DOCKER !== '1', timeout: 900_000 }, async () => {
  const { execFileSync } = await import('child_process');
  const { mkdtempSync } = await import('fs');
  const { tmpdir } = await import('os');
  const { join } = await import('path');
  const proxy = await egress.startEgressProxy({ image: NPM_HELPER_IMAGE, scratch: mkdtempSync(join(tmpdir(), 'ap-egress-')) });
  const inHelper = (script) => {
    const args = npmHelperArgs({ workDir: mkdtempSync(join(tmpdir(), 'ap-egress-w-')), name: 'lodash', version: '4.17.21', mode: 'direct', containerName: `appcrane-auto-patch-live-${Date.now()}`, network: proxy.network, proxyUrl: proxy.url });
    const at = args.indexOf('-c');
    args.splice(at + 1, args.length - at - 1, script);
    try { return { rc: 0, out: execFileSync('docker', args, { timeout: 300_000 }).toString() }; } catch (e) { return { rc: e.status, out: String(e.stdout || '') + String(e.stderr || '') }; }
  };
  try {
    const direct = inHelper('node -e "fetch(\'https://example.com\',{signal:AbortSignal.timeout(15000)}).then(r=>{console.log(\'REACHED\',r.status);process.exit(0)}).catch(e=>{console.log(\'BLOCKED\',e.cause&&e.cause.code||e.name);process.exit(3)})"');
    assert.equal(direct.rc, 3, direct.out);
    assert.match(direct.out, /BLOCKED/);
    const viaProxyElsewhere = inHelper('node -e "const s=require(\'net\').connect(3128,process.env.npm_config_proxy.split(\'//\')[1].split(\':\')[0],()=>s.write(\'CONNECT example.com:443 HTTP/1.1\\r\\n\\r\\n\'));s.on(\'data\',d=>{console.log(String(d).split(\'\\r\\n\')[0]);process.exit(0)})"');
    assert.match(viaProxyElsewhere.out, /403/, viaProxyElsewhere.out);
    const npm = inHelper('npm view lodash version');
    assert.equal(npm.rc, 0, npm.out);
    assert.match(npm.out, /^\d+\.\d+\.\d+/m);
  } finally {
    await proxy.stop();
  }
});

test('an exact pin stays exact: the helper is told to save exact, and a pin loosened to a range is refused', async () => {
  const { pinnedExactly } = await import('../server/services/autoPatch/npmBump.js');
  assert.equal(pinnedExactly({ dependencies: { handlebars: '4.7.6' } }, 'handlebars'), true);
  assert.equal(pinnedExactly({ dependencies: { handlebars: '^4.7.6' } }, 'handlebars'), false);
  assert.equal(pinnedExactly({ dependencies: {} }, 'handlebars'), false);
  const exactArgs = npmHelperArgs({ workDir: '/w', name: 'handlebars', version: '4.7.10', mode: 'direct', containerName: 'c', ...NET, save: 'exact' });
  assert.deepEqual(exactArgs.slice(-4), ['handlebars', '4.7.10', 'direct', 'exact']);
  assert.match(exactArgs[exactArgs.indexOf('-c') + 1], /--save-exact/);
  assert.throws(() => npmHelperArgs({ workDir: '/w', name: 'a', version: '1.0.0', mode: 'direct', containerName: 'c', ...NET, save: '--x' }), /save style/);
  const pkg = (spec) => JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { lodash: spec } });
  const lock = (v, spec) => JSON.stringify({ name: 'x', version: '1.0.0', lockfileVersion: 3, requires: true, packages: {
    '': { name: 'x', version: '1.0.0', dependencies: { lodash: spec } },
    'node_modules/lodash': { version: v, resolved: `https://registry.npmjs.org/lodash/-/lodash-${v}.tgz`, integrity: `sha512-${v}` } } });
  const before = { packageJson: pkg('4.17.15'), packageLock: lock('4.17.15', '4.17.15') };
  const loosened = verifyNpmBump({ before, after: { packageJson: pkg('^4.17.21'), packageLock: lock('4.17.21', '^4.17.21') }, name: 'lodash', fromVersion: '4.17.15', toVersion: '4.17.21', mode: 'direct' });
  assert.equal(loosened.ok, false);
  assert.ok(loosened.problems.some((p) => /pinned to an exact version/.test(p)), loosened.problems.join('; '));
  const kept = verifyNpmBump({ before, after: { packageJson: pkg('4.17.21'), packageLock: lock('4.17.21', '4.17.21') }, name: 'lodash', fromVersion: '4.17.15', toVersion: '4.17.21', mode: 'direct' });
  assert.deepEqual(kept.problems, []);
});
