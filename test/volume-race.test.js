import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync, readdirSync, statSync, lstatSync } from 'fs';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import { join } from 'path';

// The race the v2.107.3 symlink checks left open, against a real daemon.
//
// A container that shares the app's volumes tree (the old container while a
// deploy prepares the new one, or any other process of the app) keeps swapping
// <shared>/volumes/var/lib between a real directory and a link to a directory
// OUTSIDE the app's tree. AppCrane then prepares and starts the app over and
// over. Nothing AppCrane does may create anything in, or mount, that outside
// directory.
//
// The CONTROLS run first and are what make a zero meaningful: the same
// attacker, against a plain host mkdir and a plain `-v` bind of the same path,
// must escape at least once — otherwise this machine is not exhibiting the
// race and the loop below proves nothing. Measured before the fix with the
// same sequence (resolve, host mkdir, seed, startApp): an app container's
// /var/lib/odoo landed in the outside directory.

const execFileAsync = promisify(execFile);
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-vrace-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
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
// This file exercises a real daemon, not memory admission (test/memory-admission.test.js); a busy
// Docker host must not refuse its containers.
(await import('../server/db.js')).getDb().prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
const spec = await import('../server/services/containerRuntimeSpec.js');
const { seedNewVolumeMounts } = await import('../server/services/volumeSeeder.js');
const { startApp, stopApp, volumeSubpathSupported } = await import('../server/services/docker.js');

describe('LIVE: a link swapped in mid-deploy never reaches the host', { skip: liveSkip }, () => {
  const IMAGE = 'alpine:3.20';
  const ID = `${process.pid}${Date.now().toString(36)}`;
  const SLUG = `vrace-${ID}`;
  const NAME = `appcrane-${SLUG}-production`;
  const ATTACKER = `crane-vrace-attacker-${ID}`;
  const CONTROL = `crane-vrace-control-${ID}`;
  const VOLUME = `appcrane-vols-${SLUG}-production`;
  const shared = join(process.env.DATA_DIR, 'apps', SLUG, 'production', 'shared');
  const lib = join(shared, 'volumes', 'var', 'lib');
  // Host-only: not below the app's shared tree, never mounted by AppCrane.
  const outside = join(process.env.DATA_DIR, 'host-only');
  const PATHS = ['/var/lib/odoo', '/var/lib/fresh'];

  const dk = (args, timeout = 120000) => execFileAsync(REAL_DOCKER, args, { timeout }).then((r) => r.stdout.trim());
  let problem = null;

  before(async () => {
    try { await dk(['image', 'inspect', IMAGE], 30000); } catch (_) {
      problem = `${IMAGE} is not present locally; not pulling (Docker Hub rate limit)`;
      return;
    }
    if (!(await volumeSubpathSupported())) { problem = 'daemon has no volume-subpath (API < 1.45)'; return; }
    mkdirSync(join(outside, 'odoo'), { recursive: true });
    writeFileSync(join(outside, 'MARK.txt'), 'host only');
    mkdirSync(join(lib, 'odoo'), { recursive: true });
    mkdirSync(join(shared, 'data'), { recursive: true });
    // /data already holds state, so it is never seeded here: its seed runs a
    // labelled `docker create` that volume-seed.test.js's leak check, running
    // in parallel, would count as leaked.
    writeFileSync(join(shared, 'data', 'state'), 'x');
    // dir (300ms) -> gone (20ms) -> link to `outside` (30ms), forever. Long
    // enough as a directory for a deploy to get through its checks, then a
    // link while the start that followed them is still in flight.
    await dk(['run', '-d', '--name', ATTACKER, '-v', `${join(shared, 'volumes', 'var')}:/v`, IMAGE, 'sh', '-c',
      `cd /v && while :; do rm -rf lib; usleep 20000; rm -rf lib; ln -s ${outside} lib; usleep 30000; rm -f lib; mkdir -p lib/odoo lib/fresh; usleep 300000; done`]);
  });

  after(async () => {
    for (const n of [ATTACKER, CONTROL, NAME]) await dk(['rm', '-f', n], 30000).catch(() => {});
    await dk(['volume', 'rm', '-f', VOLUME], 30000).catch(() => {});
  });

  test('CONTROL: the same attacker redirects a host mkdir and a host-path bind', { timeout: 300000 }, async (t) => {
    if (problem) return t.skip(problem);
    let mkdirTries = 0;
    const seen = {};
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline && !existsSync(join(outside, 'probe'))) {
      mkdirTries++;
      let k;
      try { const st = lstatSync(lib); k = st.isSymbolicLink() ? 'link' : 'dir'; } catch (_) { k = 'none'; }
      // Not recursive: a recursive mkdir that lands in the gap re-creates
      // `lib` as a real directory and stalls the attacker.
      try { mkdirSync(join(lib, 'probe')); k += ':ok'; } catch (e) { k += `:${e.code}`; }
      seen[k] = (seen[k] || 0) + 1;
      await new Promise((res) => setTimeout(res, 3));
    }
    t.diagnostic(`host view during control: ${JSON.stringify(seen)}; attacker: ${await dk(['logs', '--tail', '5', ATTACKER]).catch((e) => e.message)} ${await dk(['ps', '-a', '--filter', `name=${ATTACKER}`, '--format', '{{.Status}}'])}`);
    assert.ok(existsSync(join(outside, 'probe')),
      `a host mkdir never escaped in ${mkdirTries} tries — the race is not live here, so the zero below would prove nothing`);
    rmSync(join(outside, 'probe'), { recursive: true, force: true });

    // Time-bounded, not count-bounded: under a full parallel suite each run is
    // slower and the phase alignment shifts.
    let bindTries = 0;
    let bindEscaped = false;
    const bindDeadline = Date.now() + 180000;
    while (Date.now() < bindDeadline && !bindEscaped) {
      bindTries++;
      try {
        await dk(['run', '--rm', '--name', CONTROL, '-v', `${join(lib, 'odoo')}:/x`, IMAGE, 'touch', `/x/BIND-${bindTries}`]);
      } catch (_) {}
      bindEscaped = existsSync(join(outside, 'odoo', `BIND-${bindTries}`));
    }
    t.diagnostic(`control: host mkdir escaped after ${mkdirTries} tries; -v bind escaped=${bindEscaped} after ${bindTries} tries`);
    assert.ok(bindEscaped, `a -v bind of the same path never escaped in ${bindTries} tries`);
    for (const f of readdirSync(join(outside, 'odoo'))) rmSync(join(outside, 'odoo', f), { force: true });
  });

  test('prepare + seed + start, repeated under the attacker, never touches the outside directory', { timeout: 600000 }, async (t) => {
    if (problem) return t.skip(problem);
    const before = statSync(outside);
    const r = { attempts: 0, refused: 0, started: 0, escapes: [] };
    for (let i = 0; i < 60; i++) {
      r.attempts++;
      try {
        // The deploy sequence: resolve, host mkdir of AppCrane-owned mounts only
        // (deployer.js), seed/prepare (helper), start (volume-subpath).
        const { mounts } = spec.resolveVolumeMounts({ sharedDir: shared, paths: PATHS });
        for (const m of mounts) if (!m.base) mkdirSync(m.host, { recursive: true });
        await seedNewVolumeMounts({ image: IMAGE, volumes: mounts });
        await startApp({
          slug: SLUG, env: 'production', image: IMAGE, hostPort: 47100 + i, // Exits on SIGTERM, so stopApp's `docker stop` does not wait out
          // its 10s grace period sixty times (a bare `sleep` as PID 1 ignores it).
          command: ['sh', '-c', 'trap "exit 0" TERM; sleep 60 & wait'],
          memoryMb: 64, cpus: 0.2, volumes: mounts,
        });
        r.started++;
        await dk(['exec', NAME, 'touch', `/var/lib/odoo/APP-${i}`, `/var/lib/fresh/APP-${i}`]).catch(() => {});
      } catch (e) {
        r.refused++;
        r.reasons = r.reasons || {};
        const k = String(e.message).replace(/\/[^\s'"]+/g, '<path>').slice(0, 400);
        r.reasons[k] = (r.reasons[k] || 0) + 1;
      }
      for (const p of [join(outside, 'fresh'), join(outside, 'odoo', `APP-${i}`), join(outside, `APP-${i}`)]) {
        if (existsSync(p)) r.escapes.push(p.slice(outside.length));
      }
      await stopApp(SLUG, 'production');
    }
    const after = statSync(outside);
    t.diagnostic(`after: ${JSON.stringify({ ...r, outside: readdirSync(outside), outsideOdoo: readdirSync(join(outside, 'odoo')) })}`);
    assert.deepEqual(r.escapes, [], 'something AppCrane did landed in the host-only directory');
    assert.deepEqual(readdirSync(outside).sort(), ['MARK.txt', 'odoo']);
    assert.deepEqual(readdirSync(join(outside, 'odoo')), []);
    assert.equal(after.uid, before.uid, 'the host-only directory was chowned');
    assert.equal(after.mode, before.mode);
    assert.ok(r.started > 0, 'the app never started, so nothing was mounted and the zero proves nothing');
  });
});
