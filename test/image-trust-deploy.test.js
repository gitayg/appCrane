import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Verify-before-run through deployApp, the way a deploy runs it: a real
// local-git managed repo, a real clone, the real pipeline, and a docker shim
// that records every call. The shim gives a built tag an image id (and a
// DIFFERENT id once told the tag was moved) and answers the pinned Trivy run
// with an SBOM. Under enforce a deploy whose image is signed reaches the
// container swap; one whose cached tag now names other bytes fails before any
// container is stopped or started.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-image-trust-deploy-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const SHIM = join(ROOT, 'bin');
const EVENTS = join(ROOT, 'docker-events.jsonl');
const BUILT = join(ROOT, 'built-tags');
const MOVED = join(ROOT, 'tag-moved');
mkdirSync(SHIM, { recursive: true });
writeFileSync(BUILT, '');
const FIXTURE = readFileSync(new URL('./fixtures/image-trust-sbom.cdx.json', import.meta.url), 'utf8');
writeFileSync(join(ROOT, 'sbom.json'), FIXTURE);
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const { appendFileSync, readFileSync, existsSync } = require('fs');
const argv = process.argv.slice(2);
let code = 0, out = '';
const idFor = () => 'sha256:' + (existsSync(${JSON.stringify(MOVED)}) ? 'c' : 'b').repeat(64);
if (argv[0] === 'build') {
  appendFileSync(${JSON.stringify(BUILT)}, argv[argv.indexOf('-t') + 1] + '\\n');
  out = 'Successfully built deadbeef\\n';
} else if (argv[0] === 'version') {
  out = '29.0.0\\n';
} else if (argv[0] === 'image' && argv[1] === 'inspect') {
  const ref = argv[2];
  const fmt = argv[argv.indexOf('--format') + 1] || '';
  const built = readFileSync(${JSON.stringify(BUILT)}, 'utf8').split('\\n').includes(ref) || ref === idFor();
  if (ref.startsWith('aquasec/trivy')) out = 'sha256:' + 'a'.repeat(64);
  else if (!built) code = 1;
  else if (fmt.includes('Labels')) out = 'null';
  else if (fmt.includes('RepoDigests')) out = idFor() + '|[]';
  else out = idFor();
} else if (argv[0] === 'inspect') {
  code = 1;
} else if (argv[0] === 'network' && argv[1] === 'inspect') {
  out = 'false|172.20.0.0/16\\n';
} else if (argv[0] === 'run' && argv.some((a) => a.startsWith('aquasec/trivy'))) {
  const sbom = JSON.parse(readFileSync(${JSON.stringify(join(ROOT, 'sbom.json'))}, 'utf8'));
  sbom.metadata.component.properties = [{ name: 'aquasecurity:trivy:ImageID', value: argv[argv.length - 1] }];
  out = JSON.stringify(sbom);
} else if (argv[0] === 'run' || argv[0] === 'create') {
  code = 1; out = 'shim: no containers here';
}
appendFileSync(${JSON.stringify(EVENTS)}, JSON.stringify({ verb: argv[0], sub: argv[1] || null, trivy: argv.some((a) => String(a).startsWith('aquasec/trivy')) }) + '\\n');
process.stdout.write(out);
process.exit(code);
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { setTrustPolicy } = await import('../server/services/imageTrust/policy.js');

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

global.fetch = async () => ({ ok: true, status: 200, headers: new Headers(), text: async () => '{}', json: async () => ({}) });

const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('itdadmin','itd@x.example','platform_admin','h',1,'human')",
).run().lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'itdadmin' };
async function tool(name, args) {
  const r = await callTool(admin, name, args);
  const text = r?.content?.[0]?.text ?? '';
  if (r?.isError) throw new Error(text);
  return JSON.parse(text);
}
const events = () => (existsSync(EVENTS) ? readFileSync(EVENTS, 'utf8') : '').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const CONTAINER_VERBS = new Set(['create', 'start', 'stop', 'rm', 'kill', 'restart']);
const containerTouched = (ev) => ev.filter((e) => CONTAINER_VERBS.has(e.verb) || (e.verb === 'run' && !e.trivy));

async function deploy(slug) {
  rmSync(EVENTS, { force: true });
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  const id = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)").run(app.id, adminId).lastInsertRowid;
  const err = await deployApp(id, app, 'sandbox', getPortsForSlot(app.slot), {}).then(() => null, (e) => e);
  const row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(id);
  return { id, err, row, log: row.log || '', ev: events() };
}

await tool('appcrane_create_managed_app', { name: 'Trust', slug: 'itd-app', description: 'trust' });
await tool('appcrane_push_to_managed_app', {
  slug: 'itd-app', message: 'app',
  files: [
    { path: 'package.json', content: '{"name":"itd","version":"1.0.0","main":"server.js","scripts":{"start":"node server.js"}}' },
    { path: 'package-lock.json', content: '{"name":"itd","lockfileVersion":3,"packages":{}}\n' },
    { path: 'server.js', content: 'require("http").createServer((q, s) => s.end("ok")).listen(3000);\n' },
  ],
});

test('enforce: a freshly built image is signed and verified, and the deploy reaches the container swap', async () => {
  setTrustPolicy(db, { mode: 'enforce' }, null);
  const d = await deploy('itd-app');
  assert.match(d.log, /Supply chain: signed image sha256:bbbbbbbbbbbb… with key [0-9a-f]{12}…/);
  assert.match(d.log, /Supply chain: CycloneDX 1\.6 SBOM, 4 component\(s\); hash 3\/4 \(SHA-1 3\), license 3\/4\./);
  assert.match(d.log, /License policy: warn — 2 component\(s\) under a flagged license/);
  assert.match(d.log, /Image trust: sha256:bbbbbbbbbbbb… verified/);
  assert.doesNotMatch(d.log, /IMAGE_UNTRUSTED/);
  assert.ok(containerTouched(d.ev).length > 0, 'a signed image should have reached the container swap');
  const att = db.prepare('SELECT * FROM deploy_attestations WHERE deployment_id = ?').get(d.id);
  assert.equal(att.status, 'signed');
  assert.equal(att.image_id, `sha256:${'b'.repeat(64)}`);
});

test('enforce: a cached tag that now names other bytes is not signed and the deploy stops before any container is touched', async () => {
  writeFileSync(MOVED, '1');
  try {
    const d = await deploy('itd-app');
    assert.equal(d.row.status, 'failed');
    assert.match(d.log, /Using cached image/);
    assert.match(d.log, /Supply chain: not signed — cached image appcrane-itd-app-sandbox:[0-9a-f]+ now points at sha256:c{64}, but this instance signed sha256:b{64} under that name/);
    assert.match(d.log, /IMAGE_UNTRUSTED: refusing to start itd-app\/sandbox deploy: TAMPERED/);
    assert.deepEqual(containerTouched(d.ev), [], 'a container was stopped or started for a tampered image');
  } finally {
    rmSync(MOVED, { force: true });
  }
});

test('warn: the same tampered tag is logged and the deploy goes on to the container swap', async () => {
  setTrustPolicy(db, { mode: 'warn' }, null);
  writeFileSync(MOVED, '1');
  try {
    const d = await deploy('itd-app');
    assert.match(d.log, /⚠ Image trust \(warn mode\): itd-app\/sandbox deploy: TAMPERED/);
    assert.ok(containerTouched(d.ev).length > 0, 'warn mode should not stop the deploy');
  } finally {
    rmSync(MOVED, { force: true });
  }
});

test('enforce: a cached tag that still names the signed bytes reuses the signature', async () => {
  setTrustPolicy(db, { mode: 'enforce' }, null);
  const d = await deploy('itd-app');
  assert.match(d.log, /Supply chain: cached image sha256:bbbbbbbbbbbb… reuses this instance's signature from attestation #\d+/);
  assert.match(d.log, /Image trust: sha256:bbbbbbbbbbbb… verified/);
  assert.ok(!d.ev.some((e) => e.trivy), 'a reused signature should not rerun the SBOM tool');
  setTrustPolicy(db, { mode: 'warn' }, null);
});
