import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, readFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { chownTreeAsRoot } from '../server/services/docker.js';
import { HELPER_IMAGE } from '../server/services/volumeHelper.js';

// A host where AppCrane is not root: the host chown is refused the way
// a non-root install refused it on a root-owned folder an old appcrane_cp left in /data.
function nonRootHost() {
  const dir = mkdtempSync(join(tmpdir(), 'chown-fallback-'));
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  const calls = join(dir, 'docker-calls');
  writeFileSync(join(bin, 'chown'),
    "#!/bin/sh\necho \"chown: changing ownership of '$3/order-status': Operation not permitted\" >&2\nexit 1\n");
  writeFileSync(join(bin, 'docker'), `#!/bin/sh\necho "$*" >> '${calls}'\nexit 0\n`);
  chmodSync(join(bin, 'chown'), 0o755);
  chmodSync(join(bin, 'docker'), 0o755);
  const data = join(dir, 'data');
  mkdirSync(data);
  return { bin, calls, data };
}

async function withPath(bin, fn) {
  const saved = process.env.PATH;
  process.env.PATH = `${bin}:${saved}`;
  try { return await fn(); } finally { process.env.PATH = saved; }
}

test('a refused host chown is retried as root in the helper image, which is made present first', async () => {
  const { bin, calls, data } = nonRootHost();
  const order = [];
  const how = await withPath(bin, () => chownTreeAsRoot({
    hostDir: data, owner: '1000:1000', image: HELPER_IMAGE,
    ensureImage: async () => { order.push('ensure'); },
  }));
  assert.equal(how, 'container');
  const run = readFileSync(calls, 'utf8').trim();
  order.push('run');
  assert.deepEqual(order, ['ensure', 'run']);
  assert.match(run, /^run --rm /);
  assert.match(run, /--pull never/);
  assert.match(run, /--user 0:0/);
  assert.match(run, /--network none/);
  assert.ok(run.includes(`-v ${data}:/target ${HELPER_IMAGE} -R 1000:1000 /target`), run);
  assert.match(run, /--entrypoint chown/);
});

test('the per-deploy /data chown retries a refused mount as root, after the gates and before the app starts', () => {
  const src = readFileSync(new URL('../server/services/deployer.js', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /execFileSync\('chown'/);
  const refused = src.indexOf('refusedChowns.push(vol)');
  const retry = src.indexOf("chownTreeAsRoot({ hostDir: vol.host, owner: '1000:1000', image: HELPER_IMAGE, ensureImage: ensureHelperImage })");
  const seed = src.indexOf('await seedNewVolumeMounts(');
  const start = src.indexOf('await dockerStart({', seed);
  assert.ok(refused > 0 && retry > 0, 'a refused host chown is recorded and retried in the helper');
  assert.ok(seed < retry && retry < start, 'the retry runs once the image is resolved, just before the container starts');
});
