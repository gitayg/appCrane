import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import express from 'express';

// License-policy warnings counted once. Measured in production: three apps
// built from one SBOM (220 components, license known for 217) logged
// "License policy: warn - 3 component(s) under a flagged license" on every
// deploy, and the operator saw 51 warnings for 9 distinct findings. Here the
// same shape runs through the real code path: attestImage signs each deploy
// and stores its license check, and the real router reads them back as unique
// (app, component, version, license) findings with the rule that matched. A
// docker shim on PATH answers image inspect and the pinned Trivy SBOM run.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-lic-dedupe-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.t.test';

const COMPONENTS = Array.from({ length: 220 }, (_, i) => (i < 3
  ? { type: 'library', name: `nolicense-${i}`, version: `1.0.${i}` }
  : { type: 'library', name: `lib-${i}`, version: '2.0.0', licenses: [{ license: { id: 'MIT' } }] }));
const SBOM = {
  bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
  metadata: { component: { type: 'container', name: 'img', properties: [] } },
  components: COMPONENTS,
};
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(ROOT, 'sbom.json'), JSON.stringify(SBOM));
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const { readFileSync } = require('fs');
const argv = process.argv.slice(2);
const trivy = argv.some((a) => String(a).startsWith('aquasec/trivy'));
const idOf = (ref) => 'sha256:' + require('crypto').createHash('sha256').update(String(ref)).digest('hex');
if (argv[0] === 'image' && argv[1] === 'inspect') {
  const ref = argv[2];
  const id = trivy ? 'sha256:' + 'a'.repeat(64) : (/^sha256:[a-f0-9]{64}$/.test(ref) ? ref : idOf(ref));
  const fmt = argv[argv.indexOf('--format') + 1] || '';
  process.stdout.write(fmt.includes('RepoDigests') ? id + '|[]' : id);
  process.exit(0);
}
if (argv[0] === 'run' && trivy) {
  const sbom = JSON.parse(readFileSync(${JSON.stringify(join(ROOT, 'sbom.json'))}, 'utf8'));
  sbom.metadata.component.properties = [{ name: 'aquasecurity:trivy:ImageID', value: argv[argv.length - 1] }];
  process.stdout.write(JSON.stringify(sbom));
  process.exit(0);
}
process.exit(1);
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { attestImage } = await import('../server/services/imageTrust/attest.js');
const { findingsOfCheck } = await import('../server/services/imageTrust/licenseFindings.js');

function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
}
const admin = mkUser('licadmin', 'platform_admin');
const member = mkUser('licmember', 'user');
const stranger = mkUser('licstranger', 'user');

let slot = 700;
function mkApp(slug) {
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')").run(slug, slug, slot++).lastInsertRowid);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const APPS = ['lic-voip', 'lic-site', 'lic-web'].map(mkApp);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(APPS[0].id, member.id);

const routes = (await import('../server/routes/licenseFindings.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api', routes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
async function get(as, path) {
  const res = await fetch(`${BASE}${path}`, { headers: as ? { 'X-API-Key': as.key } : {} });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, json, text };
}

after(() => {
  server.closeAllConnections?.();
  server.close();
  rmSync(ROOT, { recursive: true, force: true });
});

const DEPLOYS = 17;
const logs = [];

test('17 deploys of 3 apps from one SBOM: 51 per-deploy warnings, 9 unique findings', async () => {
  for (let n = 0; n < DEPLOYS; n++) {
    for (const app of APPS) {
      const env = n % 2 ? 'sandbox' : 'production';
      const dep = Number(db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash) VALUES (?, ?, 'live', ?)").run(app.id, env, `c${n}`).lastInsertRowid);
      const lines = [];
      const r = await attestImage({ db, app, env, deploymentId: dep, image: `appcrane-${app.slug}-${env}:c${n}`, appendLog: (l) => lines.push(l), allowPull: false });
      assert.equal(r.status, 'signed', r.error);
      assert.equal(r.sbomStatus, 'ok');
      logs.push(...lines.filter((l) => l.startsWith('License policy:')));
    }
  }
  assert.equal(logs.length, DEPLOYS * APPS.length, 'the per-deploy log line is kept');
  const perDeployWarns = db.prepare("SELECT COUNT(*) AS n FROM deploy_attestations WHERE license_check_json LIKE '%\"status\":\"warn\"%'").get().n;
  assert.equal(perDeployWarns, 51);

  const r = await get(admin, '/api/image-trust/license-findings');
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.count, 9, JSON.stringify(r.json));
  assert.equal(r.json.findings.length, r.json.count, 'the count shown is the number of unique findings');
  assert.deepEqual(r.json.by_rule, { flagged: 9 });
  const keys = new Set(r.json.findings.map((f) => `${f.app}|${f.component}|${f.version}|${f.license}`));
  assert.equal(keys.size, 9);
  const one = r.json.findings.find((f) => f.app === 'lic-voip' && f.component === 'nolicense-0');
  assert.equal(one.version, '1.0.0');
  assert.equal(one.license, 'unknown');
  assert.equal(one.rule, 'flagged');
  assert.match(one.rule_detail, /names no license.*"unknown" is on the flagged list/);
  assert.deepEqual(one.envs.sort(), ['production', 'sandbox']);
  assert.equal(one.deploys, DEPLOYS, 'each finding says how many deploys reported it');
  assert.deepEqual(r.json.incomplete, []);
});

test('the per-deploy log line names each component, its license and the rule, bounded', () => {
  const line = logs[0];
  assert.match(line, /^License policy: warn — 3 component\(s\) under a flagged license \(lic-voip\): /);
  for (const c of ['nolicense-0@1.0.0 unknown (flagged)', 'nolicense-1@1.0.1 unknown (flagged)', 'nolicense-2@1.0.2 unknown (flagged)']) {
    assert.ok(line.includes(c), `${c} missing from: ${line}`);
  }
  assert.ok(logs.every((l) => l.length <= 600), 'bounded');
});

test('one app: members see their app only; a stranger is refused', async () => {
  const mine = await get(member, '/api/apps/lic-voip/license-findings');
  assert.equal(mine.status, 200, mine.text);
  assert.equal(mine.json.count, 3);
  assert.ok(mine.json.findings.every((f) => f.app === 'lic-voip'));
  const other = await get(stranger, '/api/apps/lic-voip/license-findings');
  assert.ok([403, 404].includes(other.status), `stranger got ${other.status}`);
  const fleet = await get(member, '/api/image-trust/license-findings');
  assert.equal(fleet.status, 403);
  assert.equal((await get(null, '/api/apps/lic-voip/license-findings')).status, 401);
});

test('a row recorded before findings were stored is parsed from its reasons, and says when it listed fewer', () => {
  const legacy = {
    id: 'licenses', status: 'warn', flagged: 12, denied: 0, components: 300,
    reasons: ['12 component(s) under a flagged license (x)', '@scope/pkg@1.2.3: AGPL-3.0-only', 'plain@4: unknown, AGPL-3.0'],
  };
  const r = findingsOfCheck(legacy);
  assert.deepEqual(r.findings, [
    { component: '@scope/pkg', version: '1.2.3', license: 'AGPL-3.0-only', rule: 'flagged' },
    { component: 'plain', version: '4', license: 'unknown', rule: 'flagged' },
    { component: 'plain', version: '4', license: 'AGPL-3.0', rule: 'flagged' },
  ]);
  assert.equal(r.complete, false);
});
