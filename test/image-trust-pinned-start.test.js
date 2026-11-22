import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Verify-before-run starts what it verified. startApp verifies the image by its
// exact id, then `docker run`s it. Started by TAG, a tag moved to other bytes
// between those two steps would run the other bytes. Real Docker throughout: a
// PATH wrapper forwards every call to the real CLI, answers only the pinned SBOM
// tool (not on every host), and moves the tag at the one moment that matters,
// right before the container's `docker run -d`.

function realDocker() {
  const r = spawnSync('sh', ['-c', 'command -v docker'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}
const DOCKER = realDocker();
const LIVE = !!DOCKER
  && spawnSync(DOCKER, ['version', '--format', '{{.Server.Version}}']).status === 0
  && spawnSync(DOCKER, ['image', 'inspect', 'alpine:3']).status === 0;

const ROOT = mkdtempSync(join(tmpdir(), 'crane-trust-pin-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test.local';

const SHIM = join(ROOT, 'bin');
const HOOK = join(ROOT, 'move-tag-before-run.json');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(ROOT, 'sbom.json'), readFileSync(new URL('./fixtures/image-trust-sbom.cdx.json', import.meta.url), 'utf8'));
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const { readFileSync, existsSync, unlinkSync } = require('fs');
const { spawnSync } = require('child_process');
const REAL = ${JSON.stringify(DOCKER)};
const argv = process.argv.slice(2);
if (argv.some((a) => String(a).startsWith('aquasec/trivy'))) {
  if (argv[0] === 'image') { process.stdout.write('sha256:' + 'a'.repeat(64)); process.exit(0); }
  const sbom = JSON.parse(readFileSync(${JSON.stringify(join(ROOT, 'sbom.json'))}, 'utf8'));
  sbom.metadata.component.properties = [{ name: 'aquasecurity:trivy:ImageID', value: argv[argv.length - 1] }];
  process.stdout.write(JSON.stringify(sbom));
  process.exit(0);
}
if (argv[0] === 'run' && argv[1] === '-d' && existsSync(${JSON.stringify(HOOK)})) {
  const { from, to } = JSON.parse(readFileSync(${JSON.stringify(HOOK)}, 'utf8'));
  unlinkSync(${JSON.stringify(HOOK)});
  const t = spawnSync(REAL, ['tag', from, to]);
  if (t.status !== 0) { process.stderr.write('shim: retag failed'); process.exit(97); }
}
const r = spawnSync(REAL, argv, { stdio: 'inherit' });
process.exit(r.status ?? 1);
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { setTrustPolicy } = await import('../server/services/imageTrust/policy.js');
const { attestDeployImage } = await import('../server/services/imageTrust/attest.js');
const docker = await import('../server/services/docker.js');

const SLUG = `itp-${randomBytes(4).toString('hex')}`;
const NAME = `appcrane-${SLUG}-sandbox`;
const TAG = `appcrane-${SLUG}-sandbox:c1`;
const OTHER = `appcrane-${SLUG}-sandbox:other`;
const created = { tags: [TAG, OTHER] };

after(() => {
  if (LIVE) {
    spawnSync(DOCKER, ['rm', '-f', NAME]);
    for (const t of created.tags) spawnSync(DOCKER, ['rmi', '-f', t]);
    spawnSync(DOCKER, ['image', 'prune', '-f', '--filter', `label=itp=${SLUG}`]);
  }
  rmSync(ROOT, { recursive: true, force: true });
});

function build(extra, ref) {
  const dir = mkdtempSync(join(ROOT, 'ctx-'));
  writeFileSync(join(dir, 'Dockerfile'), `FROM alpine:3\nLABEL itp=${SLUG}\nCOPY . /app\nCMD ["sleep","3600"]\n`);
  writeFileSync(join(dir, 'which.txt'), extra);
  execFileSync(DOCKER, ['build', '-q', '-t', ref, dir], { stdio: ['ignore', 'pipe', 'inherit'] });
  return execFileSync(DOCKER, ['image', 'inspect', ref, '--format', '{{.Id}}']).toString().trim();
}
const inspect = (fmt) => execFileSync(DOCKER, ['inspect', NAME, '--format', fmt]).toString().trim();

test('LIVE: a tag moved between verify and docker run does not change what starts; the container runs the verified id', { skip: !LIVE && 'docker or alpine:3 unavailable' }, async () => {
  const appId = db.prepare("INSERT INTO apps (name, slug, slot, source_type, branch) VALUES (?, ?, (SELECT COALESCE(MAX(slot), 0) + 1 FROM apps), 'managed', 'main')").run(SLUG, SLUG).lastInsertRowid;
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
  const verifiedId = build('verified', TAG);
  const otherId = build('other bytes', OTHER);
  assert.notEqual(verifiedId, otherId);

  const dep = Number(db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash) VALUES (?, 'sandbox', 'deploying', 'c1')").run(appId).lastInsertRowid);
  const att = await attestDeployImage({ db, app, env: 'sandbox', deploymentId: dep, image: TAG, fresh: true, allowPull: false });
  assert.equal(att.status, 'signed', att.error);
  assert.equal(att.sbomStatus, 'ok');

  setTrustPolicy(db, { mode: 'enforce' }, null);
  try {
    writeFileSync(HOOK, JSON.stringify({ from: OTHER, to: TAG }));
    const lines = [];
    await docker.startApp({ slug: SLUG, env: 'sandbox', image: TAG, hostPort: 0, admission: false, memoryMb: 64, cpus: 0.1, onLog: (l) => lines.push(l) });
    assert.ok(!existsSync(HOOK), 'the hook never ran, so nothing was raced');
    assert.match(lines.join('\n'), /Image trust: sha256:[0-9a-f]{12}… verified/);
    assert.equal(execFileSync(DOCKER, ['image', 'inspect', TAG, '--format', '{{.Id}}']).toString().trim(), otherId, 'the tag really did move before the run');

    assert.equal(inspect('{{.Image}}'), verifiedId, 'the container runs bytes that were not verified');
    assert.equal(inspect('{{index .Config.Labels "appcrane.image.ref"}}'), TAG);
    assert.equal(await docker.getContainerImage(SLUG, 'sandbox'), TAG, 'readers still see the tag');
    const ci = await (await import('../server/services/imageTrust/dockerImage.js')).containerImageId(NAME);
    assert.deepEqual(ci, { id: verifiedId, ref: TAG });

    // A docker restart / start reuses the container, which is bound to its
    // image id: the moved tag does not reach it either (measured, not assumed).
    execFileSync(DOCKER, ['stop', '-t', '0', NAME]);
    execFileSync(DOCKER, ['start', NAME]);
    assert.equal(inspect('{{.Image}}'), verifiedId);

    // restartApp verifies the id the container runs, so it still passes under
    // enforce although the tag now names other bytes.
    await docker.restartApp(SLUG, 'sandbox');
    assert.equal(inspect('{{.State.Status}}'), 'running');
    assert.equal(inspect('{{.Image}}'), verifiedId);
  } finally {
    setTrustPolicy(db, { mode: 'warn' }, null);
    rmSync(HOOK, { force: true });
  }
});

test('LIVE: with image trust off nothing is verified and the container is started by its tag, as before', { skip: !LIVE && 'docker or alpine:3 unavailable' }, async () => {
  setTrustPolicy(db, { mode: 'off' }, null);
  try {
    await docker.startApp({ slug: SLUG, env: 'sandbox', image: OTHER, hostPort: 0, admission: false, memoryMb: 64, cpus: 0.1 });
    assert.equal(inspect('{{.Config.Image}}'), OTHER);
    assert.equal(inspect('{{index .Config.Labels "appcrane.image.ref"}}'), '');
    assert.equal(await docker.getContainerImage(SLUG, 'sandbox'), OTHER);
  } finally {
    setTrustPolicy(db, { mode: 'warn' }, null);
  }
});

test('the metrics snapshot reports the tag of a container started by verified id', async () => {
  const { parseSnapshotInspect } = await import('../server/services/dockerSnapshot.js');
  const id = `sha256:${'e'.repeat(64)}`;
  const line = (labels, image) => ['/appcrane-x-sandbox', 'running', '1', 't', '0', '1', '1', '1', '0', '0', '0', JSON.stringify(labels), image].join('\t');
  const [pinned, byTag] = parseSnapshotInspect(`${line({ 'appcrane.image.ref': 'appcrane-x-sandbox:c1' }, id)}\n${line({}, 'appcrane-x-sandbox:c0')}`);
  assert.equal(pinned.image, 'appcrane-x-sandbox:c1');
  assert.equal(byTag.image, 'appcrane-x-sandbox:c0');
});
