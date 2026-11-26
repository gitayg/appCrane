import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { pathToFileURL } from 'url';
import express from 'express';

// Shared by test/container-recreate-parity.test.js and the one-off harness that
// recorded container-recreate-golden-argv.json from the v2.145.0 (d1d91883)
// restart handler: the same docker shim, the same two app shapes, the same
// normalisation. `root` is the server/ directory whose routes/deploy.js is run.
//
// Normalised: the temp DATA_DIR, and the per-database random values (service
// token, identity secret). Everything else in the argv is compared verbatim.

export const SHAPES = [
  { slug: 'golda', env: 'production', sql: "INSERT INTO apps (name, slug, slot, source_type, branch, container_command, resource_limits, container_port) VALUES ('A', 'golda', 3, 'managed', 'main', '[\"node\",\"server.js\"]', '{\"max_ram_mb\":256,\"max_cpu_percent\":25}', 8080)" },
  { slug: 'goldb', env: 'sandbox', sql: "INSERT INTO apps (name, slug, slot, source_type, branch, multitenant, volume_paths) VALUES ('B', 'goldb', 4, 'managed', 'main', 1, '[\"/config\",\"/var/lib/app\"]')" },
];

export async function prepare(root) {
  const DATA = mkdtempSync(join(tmpdir(), 'crane-recreate-golden-'));
  process.env.DATA_DIR = DATA;
  process.env.ENCRYPTION_KEY = 'f'.repeat(64);
  process.env.LOG_LEVEL = 'error';
  process.env.PORT = '5001';
  delete process.env.CRANE_DOMAIN;
  delete process.env.HOST_GATEWAY_IP;
  const SHIM = join(DATA, 'bin');
  const LOG = join(DATA, 'docker-argv.log');
  mkdirSync(SHIM, { recursive: true });
  writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(LOG)}, JSON.stringify(args) + '\\n');
const h = args.indexOf('appcrane-volume-helper');
if (h >= 0) {
  const [mode, ...rest] = args.slice(h + 1);
  const paths = mode === 'chown' ? rest.slice(1) : rest;
  const word = { prep: 'occupied', chown: 'chown-ok' }[mode] || 'occupied';
  process.stdout.write(paths.map((p) => word + ' ' + p).join('\\n') + '\\n');
  process.exit(0);
}
if (args[0] === 'info') { process.stdout.write('Ubuntu 22.04\\n'); process.exit(0); }
if (args[0] === 'network' && args[1] === 'inspect' && args.join(' ').includes('IPAM')) { process.stdout.write('172.17.0.1 \\n'); process.exit(0); }
if (args[0] === 'network' && args[1] === 'inspect') { process.stdout.write('false|172.20.0.0/16 '); process.exit(0); }
if (args[0] === 'inspect' && args.join(' ').includes('.Config.Env')) {
  process.stdout.write(JSON.stringify(['PATH=/usr/bin', 'APPCRANE_TENANT_QUOTA_BYTES=52428800', 'OTHER=1']) + '\\n');
  process.exit(0);
}
if (args[0] === 'inspect') { process.stdout.write('example/app:1|example/app:1\\n'); process.exit(0); }
process.stdout.write('0123456789abcdef\\n');
`, { mode: 0o755 });
  process.env.PATH = `${SHIM}:${process.env.PATH}`;

  const imp = (p) => import(pathToFileURL(join(root, p)).href);
  const { initDb, getDb } = await imp('db.js');
  const { generateApiKey, hashApiKey, encrypt } = await imp('services/encryption.js');
  initDb();
  const db = getDb();
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
  const KEY = generateApiKey('dhk_user');
  const uid = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('o','o@t.test','user',1,?)").run(hashApiKey(KEY)).lastInsertRowid;
  for (const s of SHAPES) {
    const appId = db.prepare(s.sql).run().lastInsertRowid;
    db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, uid);
    db.prepare('INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, ?, ?, ?)').run(appId, s.env, 'GREETING', encrypt(`hi-${s.slug}`));
  }
  const deployRoutes = (await imp('routes/deploy.js')).default;
  const { errorHandler } = await imp('utils/errors.js');
  const server = await new Promise((r) => {
    const app = express();
    app.use(express.json());
    app.use('/api/apps', deployRoutes);
    app.use(errorHandler);
    const s = app.listen(0, '127.0.0.1', () => r(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  const secrets = () => {
    const out = [];
    for (const r of db.prepare('SELECT * FROM apps').all()) {
      for (const [k, v] of Object.entries(r)) if (/token|secret/i.test(k) && typeof v === 'string' && v.length >= 16) out.push(v);
    }
    return out;
  };
  const normalise = (argv) => argv.map((a) => {
    let x = a.split(DATA).join('<DATA_DIR>');
    const m = /^(APPCRANE_SERVICE_TOKEN|APPCRANE_IDENTITY_SECRET)=/.exec(x);
    if (m) x = `${m[1]}=<random>`;
    for (const s of secrets()) x = x.split(s).join('<random>');
    return x;
  });

  /** The normalised docker argv (run/stop/rm, plus helper runs) one restart issues, and its status. */
  async function restart(slug, env) {
    writeFileSync(LOG, '');
    const r = await fetch(`${base}/api/apps/${slug}/restart/${env}`, { method: 'POST', headers: { 'x-api-key': KEY } });
    const body = await r.json();
    const argv = readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
      .filter((a) => ['run', 'stop', 'rm', 'create', 'start'].includes(a[0])).map(normalise);
    return { status: r.status, argv, injected_keys: body.injected_keys, image: body.image };
  }

  const close = () => { server.closeAllConnections?.(); server.close(); rmSync(DATA, { recursive: true, force: true }); };
  return { db, KEY, base, restart, close, LOG, normalise, imp };
}
