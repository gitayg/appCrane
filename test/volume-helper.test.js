import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// The confined helper and the volume-subpath mount (volumeHelper.js), as argv.
// The race they close is reproduced against a real daemon in
// test/volume-race.test.js; this file pins the shape that makes them safe.

const h = await import('../server/services/volumeHelper.js');
const { resolveVolumeMounts } = await import('../server/services/containerRuntimeSpec.js');

const ROOT = '/srv/crane/data/apps/demo/production/shared/volumes';
const args = h.volumeHelperArgs({ root: ROOT, mode: 'chown', paths: ['/config', '/var/lib/odoo'], owner: '1000:1000' });
const valuesOf = (flag) => args.flatMap((a, i) => (args[i - 1] === flag ? [a] : []));

test('the helper mounts ONLY the app\'s volumes root, at a fixed path', () => {
  assert.deepEqual(valuesOf('-v'), [`${ROOT}:${h.HELPER_MOUNT}`]);
  assert.ok(!args.includes('--mount') && !args.includes('--volumes-from'), 'no other way in to the host filesystem');
});

test('the helper has no network, no new privileges and only the caps chown and cp -a need', () => {
  assert.deepEqual(valuesOf('--network'), ['none']);
  assert.deepEqual(valuesOf('--security-opt'), ['no-new-privileges']);
  assert.deepEqual(valuesOf('--cap-drop'), ['ALL']);
  assert.deepEqual(valuesOf('--cap-add').sort(), ['CHOWN', 'DAC_OVERRIDE', 'FOWNER']);
  assert.deepEqual(valuesOf('--pull'), ['never']);
  assert.ok(args.includes('--rm'));
  for (const a of args) {
    assert.ok(!/^--(privileged|pid|ipc|userns|device|volumes-from)$/.test(a) && !/unconfined/.test(a), `unexpected ${a}`);
  }
});

test('the helper runs a fixed, digest-pinned utility image — never the app\'s', () => {
  assert.match(h.HELPER_IMAGE, /^busybox@sha256:[0-9a-f]{64}$/);
  assert.ok(args.includes(h.HELPER_IMAGE));
  assert.ok(!args.includes('-i'), 'only extract reads stdin');
  assert.ok(h.volumeHelperArgs({ root: ROOT, mode: 'extract', paths: ['/config'], stdin: true }).includes('-i'));
});

test('mode, owner and paths are positional parameters, never script text', () => {
  const img = args.indexOf(h.HELPER_IMAGE);
  assert.deepEqual(args.slice(img, img + 3), [h.HELPER_IMAGE, '-c', h.HELPER_SCRIPT]);
  assert.deepEqual(args.slice(img + 3), ['appcrane-volume-helper', 'chown', '1000:1000', '/config', '/var/lib/odoo']);
  assert.ok(!h.HELPER_SCRIPT.includes('/config') && !h.HELPER_SCRIPT.includes('odoo'));
  assert.ok(args.indexOf('--entrypoint') < img, 'every docker flag comes before the image');
});

test('the helper refuses what would widen it', () => {
  const ok = { root: ROOT, mode: 'prep', paths: ['/config'] };
  assert.throws(() => h.volumeHelperArgs({ ...ok, root: '/a:b' }), /without ':'/);
  assert.throws(() => h.volumeHelperArgs({ ...ok, root: 'relative' }), /absolute/);
  assert.throws(() => h.volumeHelperArgs({ ...ok, mode: 'chown', owner: '1000:1000 /etc' }), /uid:gid/);
  assert.throws(() => h.volumeHelperArgs({ ...ok, mode: 'sh' }), /unknown/);
  assert.throws(() => h.volumeHelperArgs({ ...ok, mode: 'extract', paths: ['/a', '/b'] }), /exactly one/);
  assert.throws(() => h.volumeHelperArgs({ ...ok, paths: [h.HELPER_MOUNT] }), /overlaps/);
  assert.throws(() => h.volumeHelperArgs({ ...ok, paths: ['/../etc'] }), /\.\./);
});

test('helper output maps back onto paths; a missing line is "unreported", not a guess', () => {
  const out = 'seeded /config\nnoise\nchown-failed /var/lib/odoo\nseeded /not-asked\n';
  assert.deepEqual(h.parseVolumeHelperOutput(out, ['/config', '/var/lib/odoo', '/srv']), [
    { path: '/config', state: 'seeded' },
    { path: '/var/lib/odoo', state: 'chown-failed' },
    { path: '/srv', state: 'unreported' },
  ]);
});

// ---------------------------------------------------------------------------
// The tar guard, against crafted archives
// ---------------------------------------------------------------------------

/** A minimal ustar writer: [{ name, type?, data?, link?, prefix? }]. */
function tarOf(entries) {
  const blocks = [];
  for (const e of entries) {
    const data = Buffer.from(e.data || '');
    const hd = Buffer.alloc(512);
    hd.write(e.name, 0, 100, 'utf8');
    hd.write('0000644\0', 100); hd.write('0000000\0', 108); hd.write('0000000\0', 116);
    hd.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124);
    hd.write('00000000000\0', 136);
    hd.write(e.type || '0', 156);
    if (e.link) hd.write(e.link, 157, 100, 'utf8');
    hd.write('ustar\0', 257); hd.write('00', 263);
    if (e.prefix) hd.write(e.prefix, 345, 155, 'utf8');
    hd.fill(' ', 148, 156);
    let sum = 0; for (const b of hd) sum += b;
    hd.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
    blocks.push(hd, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}
const pax = (records) => Object.entries(records).map(([k, v]) => {
  const body = ` ${k}=${v}\n`;
  let len = body.length + 1;
  while (String(len).length + body.length !== len) len = String(len).length + body.length;
  return `${len}${body}`;
}).join('');

async function throughGuard(buf, chunk = 97) {
  const g = h.createTarGuard();
  const out = [];
  g.on('data', (d) => out.push(d));
  const done = new Promise((res, rej) => { g.on('end', res); g.on('error', rej); });
  for (let i = 0; i < buf.length; i += chunk) g.write(buf.subarray(i, i + chunk));
  g.end();
  await done;
  return Buffer.concat(out);
}

test('a well-formed archive passes byte for byte, including links that are only links', async () => {
  const good = tarOf([
    { name: './', type: '5' },
    { name: './conf/', type: '5' },
    { name: './conf/app.ini', data: 'x=1' },
    { name: './abs-link', type: '2', link: '/usr/share/zoneinfo/UTC' },
    { name: './hard', type: '1', link: 'conf/app.ini' },
    { name: 'deep.txt', prefix: 'a/b', data: 'y' },
  ]);
  assert.ok((await throughGuard(good)).equals(good));
});

for (const [why, entries] of [
  ['a .. name', [{ name: '../escape', data: 'EVIL' }]],
  ['a .. in the middle', [{ name: 'a/../../escape', data: 'EVIL' }]],
  ['an absolute name', [{ name: '/etc/cron.d/x', data: 'EVIL' }]],
  ['a .. in the ustar prefix', [{ name: 'x', prefix: '..', data: 'EVIL' }]],
  ['a hard link out', [{ name: 'h', type: '1', link: '../../etc/shadow' }]],
  ['an absolute hard link', [{ name: 'h', type: '1', link: '/etc/shadow' }]],
  ['a write through a symlink the archive made', [{ name: 'l', type: '2', link: '/etc' }, { name: 'l/passwd', data: 'EVIL' }]],
  ['a write through a nested symlink', [{ name: 'a/l', type: '2', link: '../..' }, { name: 'a/l/b/x', data: 'EVIL' }]],
  ['a pax path override', [{ name: 'PaxHeader', type: 'x', data: pax({ path: '../evil' }) }, { name: 'innocent', data: 'EVIL' }]],
  ['a GNU long name', [{ name: '././@LongLink', type: 'L', data: '../../evil\0' }, { name: 'innocent', data: 'EVIL' }]],
  ['a global pax path', [{ name: 'g', type: 'g', data: pax({ path: 'x' }) }]],
  ['a device node', [{ name: 'dev', type: '3' }]],
]) {
  test(`the tar guard refuses ${why}, before the entry reaches tar`, async () => {
    const evil = tarOf(entries);
    const g = h.createTarGuard();
    const passed = [];
    g.on('data', (d) => passed.push(d));
    const err = await new Promise((res) => { g.on('error', res); g.on('end', () => res(null)); g.end(evil); });
    assert.ok(err, `${why} was let through`);
    const out = Buffer.concat(passed);
    assert.ok(!out.includes(Buffer.from('EVIL')), 'the bad entry\'s data was forwarded');
  });
}

test('a truncated archive is a failure, not a short seed', async () => {
  const good = tarOf([{ name: 'a', data: 'x'.repeat(2000) }]);
  await assert.rejects(throughGuard(good.subarray(0, 900)), /truncated/);
});

test('a declared mount maps to a subpath of one volumes root; /data is not a declared mount', () => {
  const { mounts } = resolveVolumeMounts({ sharedDir: '/srv/s', paths: ['/config', '/var/lib/odoo'] });
  assert.equal(mounts[0].base, undefined, '/data stays AppCrane\'s own host-path bind');
  assert.equal(h.sharedVolumesRoot(mounts.slice(1)), '/srv/s/volumes');
  assert.deepEqual(mounts.slice(1).map(h.subpathOf), ['config', 'var/lib/odoo']);
  assert.throws(() => h.subpathOf({ ...mounts[1], host: '/etc' }), /outside/);
  assert.throws(() => h.volumesRootOf(mounts[0]), /no shared-tree base/);
});

test('the --mount record lets the daemon resolve the subpath, with no copy-up', () => {
  assert.equal(h.volumeSubpathMountArg({ volume: 'appcrane-vols-a-production', subpath: 'var/lib/odoo', container: '/var/lib/odoo' }),
    'type=volume,src=appcrane-vols-a-production,dst=/var/lib/odoo,volume-subpath=var/lib/odoo,volume-nocopy=true');
  for (const bad of ['', '../etc', 'a/../../etc', 'a//b', '.']) {
    assert.throws(() => h.volumeSubpathMountArg({ volume: 'v', subpath: bad, container: '/x' }), /refusing/);
  }
  assert.equal(h.volumesVolumeName('my-app', 'sandbox'), 'appcrane-vols-my-app-sandbox');
});

test('volume-subpath needs API 1.45', () => {
  assert.equal(h.apiSupportsVolumeSubpath('1.44'), false);
  assert.equal(h.apiSupportsVolumeSubpath('1.45'), true);
  assert.equal(h.apiSupportsVolumeSubpath('1.55'), true);
  assert.equal(h.apiSupportsVolumeSubpath('2.0'), true);
  assert.equal(h.apiSupportsVolumeSubpath('0123456789abcdef'), false);
});

test('GUARD: no host mkdir/chown of a declared volume path in the deploy or restart code', () => {
  // The runtime guard (no host fs call below <shared>/volumes during a real
  // deployApp) is in test/container-volumes.test.js. This pins the two loops
  // that used to walk every mount on the host.
  const deployer = readFileSync(new URL('../server/services/deployer.js', import.meta.url), 'utf8');
  const route = readFileSync(new URL('../server/routes/deploy.js', import.meta.url), 'utf8');
  assert.doesNotMatch(deployer, /for \(const vol of containerVolumes\)\s*(mkdirSync|\{\s*\n\s*try \{\s*\n\s*execFileSync\('chown')/);
  assert.match(deployer, /const hostOwnedVolumes = containerVolumes\.filter\(\(vol\) => !vol\.base\)/);
  assert.doesNotMatch(route, /for \(const vol of containerVolumes\) mkdirSync/);
  assert.match(route, /for \(const vol of containerVolumes\) if \(!vol\.base\) mkdirSync/);
});
