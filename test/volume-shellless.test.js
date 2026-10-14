import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync } from 'fs';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import { join } from 'path';
import { Readable } from 'stream';

// Declared volumes for an image with NO shell, against a real daemon.
//
// The volume helper used to run in the app's own image, so an image without
// sh/mkdir/cp/chown (distroless, FROM scratch) could not deploy once it
// declared a volume. The helper now runs a pinned busybox, and the seed
// content is read out of the app's image without running it (docker create +
// docker cp to a tar stream). The fixture here is FROM scratch: one static
// binary, seed content under a VOLUME, and a non-root USER.
//
// Also here: crafted archives pushed through the real extract path, so the
// tar guard is proven where it matters, not only on a byte buffer.

const execFileAsync = promisify(execFile);
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-shellless-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

let REAL_DOCKER = null;
try {
  REAL_DOCKER = execFileSync('/usr/bin/env', ['sh', '-c', 'command -v docker'], { encoding: 'utf8' }).trim() || null;
  if (REAL_DOCKER) execFileSync(REAL_DOCKER, ['version', '--format', '{{.Server.Version}}'], { timeout: 15000, stdio: 'pipe' });
} catch (_) {
  REAL_DOCKER = null;
}
const liveSkip = REAL_DOCKER ? false : 'no reachable Docker daemon on this host';

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug', 'error']) logger[lvl] = () => {};
(await import('../server/db.js')).initDb();
const spec = await import('../server/services/containerRuntimeSpec.js');
const { seedNewVolumeMounts } = await import('../server/services/volumeSeeder.js');
const { startApp, stopApp, extractTarIntoVolume, removeAppVolumes } = await import('../server/services/docker.js');
const { HELPER_IMAGE } = await import('../server/services/volumeHelper.js');

/** Minimal ustar: [{ name, type?, data?, link? }]. */
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
    hd.fill(' ', 148, 156);
    let sum = 0; for (const b of hd) sum += b;
    hd.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
    blocks.push(hd, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

describe('LIVE: declared volumes without a shell in the app image', { skip: liveSkip }, () => {
  const ID = `${process.pid}${Date.now().toString(36)}`;
  const IMAGE = `crane-shellless-${ID}:v1`;
  const SLUG = `shellless-${ID}`;
  const NAME = `appcrane-${SLUG}-production`;
  const shared = join(process.env.DATA_DIR, 'apps', SLUG, 'production', 'shared');
  const dk = (args, timeout = 120000) => execFileAsync(REAL_DOCKER, args, { timeout }).then((r) => r.stdout.trim());
  let problem = null;

  before(async () => {
    try { await dk(['image', 'inspect', HELPER_IMAGE], 30000); } catch (_) {
      problem = 'the pinned helper image is not on this host; not pulling in a test (Docker Hub rate limit)';
      return;
    }
    const ctx = join(process.env.DATA_DIR, 'ctx');
    mkdirSync(join(ctx, 'seed', 'sub'), { recursive: true });
    writeFileSync(join(ctx, 'seed', 'app.conf'), 'FROM-THE-IMAGE');
    writeFileSync(join(ctx, 'seed', 'sub', 'nested.txt'), 'NESTED');
    // FROM scratch: no /bin/sh, no mkdir, no tar, no chown. busybox is static,
    // and named /sleep it runs only the sleep applet — the image's ONLY program.
    writeFileSync(join(ctx, 'Dockerfile'),
      `FROM ${HELPER_IMAGE} AS bb\n` +
      'FROM scratch\n' +
      'COPY --from=bb /bin/busybox /sleep\n' +
      'COPY seed/ /config/\n' +
      'USER 1234:1234\n' +
      'VOLUME /config\n' +
      'CMD ["/sleep", "600"]\n');
    try { await dk(['build', '-q', '-t', IMAGE, ctx], 300000); } catch (e) {
      problem = `could not build the fixture: ${String(e.message).split('\n')[0].slice(0, 160)}`;
    }
  });

  after(async () => {
    await dk(['rm', '-f', NAME], 30000).catch(() => {});
    await removeAppVolumes(SLUG).catch(() => {});
    await dk(['image', 'rm', '-f', IMAGE], 60000).catch(() => {});
  });

  test('CONTROL: the fixture really has no shell', async (t) => {
    if (problem) return t.skip(problem);
    await assert.rejects(dk(['run', '--rm', '--entrypoint', 'sh', IMAGE, '-c', 'true']), /executable file not found|no such file/i);
  });

  test('it seeds, chowns to the image USER, starts, and reads its seeded config', async (t) => {
    if (problem) return t.skip(problem);
    const { mounts } = spec.resolveVolumeMounts({ sharedDir: shared, paths: ['/config'] });
    mkdirSync(mounts[0].host, { recursive: true });
    const res = await seedNewVolumeMounts({ image: IMAGE, volumes: mounts });
    assert.deepEqual(res.seeded, ['/config'], res.log.join('\n'));
    assert.match(res.log.join('\n'), /populated from the image, chown 1234:1234 → ok/);
    assert.equal(readFileSync(join(shared, 'volumes', 'config', 'app.conf'), 'utf8'), 'FROM-THE-IMAGE');
    assert.equal(readFileSync(join(shared, 'volumes', 'config', 'sub', 'nested.txt'), 'utf8'), 'NESTED');

    await startApp({ slug: SLUG, env: 'production', image: IMAGE, hostPort: 47290, memoryMb: 64, cpus: 0.2, volumes: mounts });
    assert.equal(await dk(['inspect', NAME, '--format', '{{.State.Running}}']), 'true');
    // Read through the CONTAINER's mount, with the daemon (the image cannot cat).
    const tar = await execFileAsync(REAL_DOCKER, ['cp', `${NAME}:/config/app.conf`, '-'], { encoding: 'buffer' });
    assert.ok(tar.stdout.includes(Buffer.from('FROM-THE-IMAGE')));
    // Ownership as the daemon's side sees it: the uid the image runs as.
    const owner = await dk(['run', '--rm', '--network', 'none',
      '--mount', `type=volume,src=appcrane-vols-${SLUG}-production,dst=/x,volume-subpath=config`,
      HELPER_IMAGE, 'stat', '-c', '%u:%g', '/x/app.conf']);
    assert.equal(owner, '1234:1234');
    await stopApp(SLUG, 'production');
  });

  test('a crafted archive cannot write outside the path it seeds, and leaves it empty', async (t) => {
    if (problem) return t.skip(problem);
    const root = join(shared, 'volumes');
    mkdirSync(join(root, 'victim'), { recursive: true });
    writeFileSync(join(root, 'victim', 'keep.txt'), 'SIBLING');
    mkdirSync(join(root, 'target'), { recursive: true });
    for (const [why, entries] of [
      ['..', [{ name: 'ok.txt', data: 'fine' }, { name: '../victim/keep.txt', data: 'EVIL' }]],
      ['absolute', [{ name: 'ok.txt', data: 'fine' }, { name: '/victim/keep.txt', data: 'EVIL' }]],
      ['symlink write-through', [{ name: 'l', type: '2', link: '../victim' }, { name: 'l/keep.txt', data: 'EVIL' }]],
      ['hard link out', [{ name: 'h', type: '1', link: '../victim/keep.txt' }]],
    ]) {
      await assert.rejects(
        extractTarIntoVolume({ root, path: '/target', tar: Readable.from([tarOf(entries)]) }),
        /seeding \/target failed/, `${why} was accepted`,
      );
      assert.equal(readFileSync(join(root, 'victim', 'keep.txt'), 'utf8'), 'SIBLING', `${why} reached a sibling volume`);
      assert.deepEqual(existsSync(join(root, 'target')) ? readdirSync(join(root, 'target')) : [], [],
        `${why}: the partial extract must be cleared`);
    }
    // And a good archive through the same path lands, so the refusals above
    // are the guard and not a broken pipe.
    assert.equal(await extractTarIntoVolume({ root, path: '/target', tar: Readable.from([tarOf([{ name: './ok.txt', data: 'fine' }])]) }), 'seeded');
    assert.equal(readFileSync(join(root, 'target', 'ok.txt'), 'utf8'), 'fine');
  });
});
