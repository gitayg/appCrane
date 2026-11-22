import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';

// Heroku / Render / Railway manifest import for the Adopt flow. The fixtures
// are the platforms' own documentation examples (test/fixtures/platforms/SOURCES.txt):
//   render-blueprint-spec.yaml  https://render.com/docs/blueprint-spec
//   railway.toml                https://docs.railway.com/config-as-code
//   railway.json                https://docs.railway.com/reference/config-as-code
//   app.json                    https://devcenter.heroku.com/articles/app-json-schema
//   heroku.yml                  https://devcenter.heroku.com/articles/build-docker-images-heroku-yml
//   Procfile                    https://devcenter.heroku.com/articles/procfile

process.env.LOG_LEVEL = 'error';
const { parseYamlLite, YamlLiteError } = await import('../server/services/adopt/platforms/yamlLite.js');
const { parseTomlLite, TomlLiteError } = await import('../server/services/adopt/platforms/tomlLite.js');
const { parseProcfile } = await import('../server/services/adopt/platforms/procfile.js');
const { detectPlatforms, literalPortIn } = await import('../server/services/adopt/platforms/index.js');
const { buildReport, scaffoldFor } = await import('../server/services/adopt/report.js');
const { parseManifestDatabase } = await import('../server/services/manifestDatabase.js');
const { parseCron } = await import('../server/services/cronScheduler.js');

const FIX = fileURLToPath(new URL('./fixtures/platforms/', import.meta.url));
const fixture = (name) => readFileSync(`${FIX}${name}`);
const tree = (entries) => new Map(Object.entries(entries).map(([k, v]) => [k, Buffer.isBuffer(v) ? v : Buffer.from(typeof v === 'string' ? v : JSON.stringify(v))]));
const nodeApp = (extra) => tree({
  'package.json': { name: 'shop', version: '1.2.3', scripts: { start: 'node server.js' }, dependencies: { express: '^5.0.0' } },
  'package-lock.json': '{}',
  'server.js': "const app = require('express')();\napp.listen(process.env.PORT || 3000);\n",
  ...extra,
});
const deployhubOf = (files) => JSON.parse(scaffoldFor(files, 'shop').find((f) => f.path === 'deployhub.json').content);
const fields = (plan) => plan.unmapped.map((u) => u.field);
const plain = (v) => JSON.parse(JSON.stringify(v));

test('yamlLite reads the Render documentation example the way a YAML 1.2 parser does', () => {
  const doc = plain(parseYamlLite(fixture('render-blueprint-spec.yaml').toString('utf8')));
  assert.equal(doc.services.length, 8);
  assert.deepEqual(doc.services[0].envVars[3], { key: 'DATABASE_URL', fromDatabase: { name: 'mydatabase', property: 'connectionString' } });
  assert.equal(doc.services[0].autoDeployTrigger, 'off', "quoted 'off' stays a string");
  assert.equal(doc.services[3].schedule, '0 * * * *');
  assert.equal(doc.services[3].buildCommand, 'true', "'true' quoted is a string");
  assert.deepEqual(doc.databases[1].ipAllowList, []);
  assert.deepEqual(doc.envVarGroups[0].envVars[0], { key: 'CONCURRENCY', value: 2 });
  assert.deepEqual(plain(parseYamlLite('a: |\n  one\n  two\nb: >-\n  x\n  y\n')), { a: 'one\ntwo\n', b: 'x y' });
  assert.deepEqual(plain(parseYamlLite('k:\n- a\n- b: 1\n  c: [x, "y z"]\n')), { k: ['a', { b: 1, c: ['x', 'y z'] }] });
  for (const bad of ['a: &x 1\nb: *x\n', 'a: 1\na: 2\n', 'a:\n  b\n  c\n', '---\na: 1\n---\nb: 2\n', 'a: "open\n']) {
    assert.throws(() => parseYamlLite(bad), YamlLiteError, bad);
  }
});

test('tomlLite reads the Railway TOML example', () => {
  assert.deepEqual(plain(parseTomlLite(fixture('railway.toml').toString('utf8'))), {
    build: { builder: 'railpack', buildCommand: 'echo building!' },
    deploy: { preDeployCommand: ['npm run db:migrate'], startCommand: 'echo starting!', healthcheckPath: '/', healthcheckTimeout: 100, restartPolicyType: 'never' },
  });
  assert.deepEqual(plain(parseTomlLite("a.b = 'x' # c\n[t]\nn = [1,\n 2,]\ni = { k = \"v\" }\n")), { a: { b: 'x' }, t: { n: [1, 2], i: { k: 'v' } } });
  for (const bad of ['a = 1\na = 2\n', '[t]\n[t]\n', 'a = \n', 'a = "x\n']) assert.throws(() => parseTomlLite(bad), TomlLiteError, bad);
});

test('Procfile: web is the start command, release is reported, other process types are not run', () => {
  assert.deepEqual(parseProcfile(fixture('Procfile').toString('utf8')).processes.map((p) => p.type), ['web', 'release', 'worker', 'urgentworker']);
  const plan = detectPlatforms(tree({ Procfile: fixture('Procfile') }));
  assert.equal(plan.web.start, 'bundle exec rails server -p $PORT');
  assert.equal(plan.web.start_source, 'Procfile web');
  assert.equal(plan.web.literal_port, null, '$PORT is not a literal port');
  assert.deepEqual(plan.release, [{ command: './release-tasks.sh', source: 'Procfile release', platform: 'Heroku' }]);
  assert.deepEqual(fields(plan), ['worker', 'urgentworker', '(Heroku Scheduler)']);
  assert.equal(literalPortIn('gunicorn --bind 0.0.0.0:8000 app:app'), 8000);
  assert.equal(literalPortIn('rails s -p 5000'), 5000);
  assert.equal(literalPortIn('node x --port=${PORT}'), null);
});

test('render.yaml (documentation example): web, pre-deploy, env names, database; everything else listed as not mapped', () => {
  const plan = detectPlatforms(tree({ 'render.yaml': fixture('render-blueprint-spec.yaml') }));
  assert.equal(plan.web.start, 'bundle exec ruby main.rb');
  assert.equal(plan.web.build, 'bundle install');
  assert.equal(plan.web.runtime, 'ruby');
  assert.deepEqual(plan.release.map((r) => r.command), ['bundle exec ruby migrate.rb']);
  assert.deepEqual(plan.database.block, { engine: 'postgres' });
  assert.equal(plan.database.origin, 'databases[0] elephant');
  const env = Object.fromEntries(plan.env.map((e) => [e.key, e.value]));
  assert.deepEqual(env, { ANTHROPIC_API_KEY: 'prompt', API_BASE_URL: 'literal', APP_SECRET: 'generate', DATABASE_URL: 'database', MINIO_PASSWORD: 'reference' });
  assert.equal(plan.crons.length, 0, 'the example cron job builds from another repo');
  const f = fields(plan);
  for (const want of ['services[1].rootDir', 'services[2]', 'services[3]', 'services[4]', 'services[5]', 'services[6]', 'services[0].envVars[5]', 'DATABASE_URL']) {
    assert.ok(f.includes(want), `${want} missing from unmapped: ${f.join(' ; ')}`);
  }
  assert.ok(plan.unmapped.some((u) => /services\[7\] lightning/.test(u.field) && u.kind === 'database'), 'second datastore reported');
  assert.ok(plan.unmapped.some((u) => /plan, region, numInstances, domains/.test(u.field)));
});

test('render.yaml cron service, healthCheckPath, fromDatabase fields and env groups', () => {
  const plan = detectPlatforms(tree({
    'render.yaml': [
      'services:',
      '  - type: web',
      '    name: api',
      '    runtime: node',
      '    buildCommand: npm install && npm run build',
      '    startCommand: npm start',
      '    healthCheckPath: /healthz',
      '    envVars:',
      '      - key: PG_HOST',
      '        fromDatabase: { name: main, property: host }',
      '      - key: PG_URL',
      '        fromDatabase:',
      '          name: main',
      '          property: connectionString',
      '      - key: PORT',
      '        value: 10000',
      '      - fromGroup: shared',
      '  - type: cron',
      '    name: nightly',
      '    runtime: node',
      "    schedule: '0 3 * * *'",
      '    buildCommand: npm install',
      '    startCommand: node jobs/nightly.js',
      '  - type: cron',
      '    name: broken',
      '    runtime: node',
      "    schedule: 'every day'",
      '    startCommand: node x.js',
      'databases:',
      '  - name: main',
      '    postgresMajorVersion: "16"',
      'envVarGroups:',
      '  - name: shared',
      '    envVars:',
      '      - key: FEATURE_FLAG',
      '        value: on',
      '',
    ].join('\n'),
  }));
  assert.deepEqual(plan.health, { path: '/healthz', source: 'render.yaml services[0].healthCheckPath' });
  assert.deepEqual(plan.crons.map(({ name, schedule, command }) => ({ name, schedule, command })), [{ name: 'render:nightly', schedule: '0 3 * * *', command: 'node jobs/nightly.js' }]);
  assert.ok(plan.unmapped.some((u) => /Cron render:broken/.test(u.title)));
  assert.deepEqual(plan.database.block, { engine: 'postgres', url_env: 'PG_URL', env: { host: 'PG_HOST' } });
  assert.deepEqual(parseManifestDatabase(plan.database.block), { engine: 'postgres', env: { host: 'PG_HOST' }, url_env: 'PG_URL' });
  assert.deepEqual(plan.database.injects, ['PG_URL', 'PG_HOST']);
  assert.ok(plan.env.find((e) => e.key === 'PG_URL').provided_by_database);
  assert.deepEqual(plan.env.find((e) => e.key === 'FEATURE_FLAG').value, 'literal');
  assert.ok(!plan.env.some((e) => e.key === 'PORT'), 'PORT is AppCrane\'s');
  assert.ok(plan.unmapped.some((u) => /PORT \(render\.yaml\)/.test(u.detail)));
});

test('railway.toml and railway.json (documentation examples)', () => {
  const toml = detectPlatforms(tree({ 'railway.toml': fixture('railway.toml') }));
  assert.equal(toml.web.start, 'echo starting!');
  assert.equal(toml.web.build, 'echo building!');
  assert.deepEqual(toml.health, { path: '/', source: 'railway.toml deploy.healthcheckPath' });
  assert.deepEqual(toml.release.map((r) => r.command), ['npm run db:migrate']);
  assert.ok(fields(toml).includes('deploy.healthcheckTimeout, deploy.restartPolicyType'));
  assert.ok(fields(toml).includes('(variables, databases)'));
  assert.equal(toml.database, null);

  const json = detectPlatforms(tree({ 'railway.json': fixture('railway.json') }));
  assert.deepEqual(json.crons.map(({ name, schedule, command }) => ({ name, schedule, command })), [{ name: 'railway:cron', schedule: '*/15 * * * *', command: 'node index.js' }]);
  assert.equal(json.web.start, null, 'a cronSchedule service has no web start command');
  assert.equal(json.web.build, 'yarn run build');
  assert.deepEqual(json.health.path, '/health');
  assert.ok(fields(json).includes('environments'));
  assert.ok(json.notes.some((n) => /cron job/.test(n)));
  assert.equal(detectPlatforms(tree({ 'railway.toml': '[deploy\n' })).unmapped[0].kind, 'unreadable');
});

test('app.json (documentation example): env names, add-ons to the managed database, the rest reported', () => {
  const plan = detectPlatforms(tree({ 'app.json': fixture('app.json') }));
  assert.equal(plan.web, null);
  assert.deepEqual(plan.database.block, { engine: 'postgres' });
  assert.deepEqual(plan.database.injects, ['DATABASE_URL']);
  assert.deepEqual(plan.env.map((e) => [e.key, e.value]), [['SECRET_TOKEN', 'generate'], ['WEB_CONCURRENCY', 'literal']]);
  const f = fields(plan);
  for (const want of ['scripts.postdeploy', 'buildpacks', 'environments', 'image', 'addons: openredis', 'addons: mongolab:shared-single-small', '(Heroku Scheduler)']) {
    assert.ok(f.includes(want), `${want} missing: ${f.join(' ; ')}`);
  }
  assert.equal(detectPlatforms(tree({ 'app.json': { expo: { name: 'x' } } })), null, 'an Expo app.json is not a Heroku manifest');
  const asMongo = detectPlatforms(tree({ 'app.json': { addons: [{ plan: 'heroku-redis', as: 'CACHE' }] } }));
  assert.deepEqual(asMongo.database.block, { engine: 'redis', url_env: 'CACHE_URL' }, '"as" renames the attachment variable');
});

test('heroku.yml (documentation example): run.web, release, setup add-ons and config names', () => {
  const plan = detectPlatforms(tree({ 'heroku.yml': fixture('heroku.yml') }));
  assert.equal(plan.web.start, 'bundle exec puma -C config/puma.rb');
  assert.equal(plan.web.docker_command, true);
  assert.deepEqual(plan.release.map((r) => r.command), ['./deployment-tasks.sh']);
  assert.deepEqual(plan.database.block, { engine: 'postgres' });
  assert.deepEqual(plan.env.map((e) => [e.key, e.value]), [['S3_BUCKET', 'literal']]);
  const f = fields(plan);
  for (const want of ['build.docker.worker', 'build.config', 'run.worker', 'run.asset-syncer']) assert.ok(f.includes(want), want);
  assert.ok(!JSON.stringify(plan).includes('development'), 'build.config values are not carried');
});

test('a Node app with Procfile + app.json: start applied, deployhub.json gets health, cron-free database block, values never carried', () => {
  const files = nodeApp({
    Procfile: 'web: node server.js\nrelease: npm run migrate\nworker: node worker.js\n',
    'app.json': { env: { SESSION_SECRET: { generator: 'secret' }, API_BASE: 'https://do-not-import.example', STRIPE_KEY: { description: 'Stripe secret key', value: 'sk_live_DO_NOT_IMPORT_0123456789' } }, addons: ['heroku-postgresql'] },
  });
  const r = buildReport(files, { name: 'shop' });
  assert.equal(r.project.start, 'node server.js');
  assert.equal(r.project.start_source, 'Procfile web');
  assert.equal(r.platform.start_applied, true);
  assert.deepEqual(r.platform.database, { engine: 'postgres', injects: ['DATABASE_URL'], origin: 'addons: heroku-postgresql' });
  const ids = r.changes.map((c) => c.id);
  for (const id of ['platform-database', 'platform-release:0', 'platform-env-values']) assert.ok(ids.includes(id), `${id} missing: ${ids}`);
  assert.equal(r.changes.find((c) => c.id === 'platform-release:0').request, true);
  assert.ok(r.platform.unmapped.some((u) => u.field === 'worker'));
  const env = Object.fromEntries(r.env.map((v) => [v.key, v]));
  assert.equal(env.STRIPE_KEY.manifest.value, 'literal');
  assert.equal(env.SESSION_SECRET.manifest.value, 'generate');
  assert.equal(env.API_BASE.scope, 'server');
  assert.ok(!('DATABASE_URL' in env), 'the managed database injects DATABASE_URL');
  const everything = JSON.stringify(r) + JSON.stringify(scaffoldFor(files, 'shop'));
  assert.ok(!everything.includes('sk_live_DO_NOT_IMPORT'), 'a manifest value reached the report or the scaffold');
  assert.ok(!everything.includes('do-not-import.example'), 'a manifest value reached the report or the scaffold');

  const m = deployhubOf(files);
  assert.deepEqual(m.database, { engine: 'postgres' });
  assert.equal(m.be.health, '/api/health');
  assert.match(scaffoldFor(files, 'shop').find((f) => f.path === 'Dockerfile').content, /CMD \["sh", "-c", "node server\.js"\]/);
});

test('render.yaml for a Node app: start/build applied, health path and cron written to deployhub.json', () => {
  const files = nodeApp({
    'render.yaml': [
      'services:',
      '  - type: web',
      '    name: shop',
      '    runtime: node',
      '    buildCommand: npm ci && npm run build',
      '    startCommand: node server.js --port $PORT',
      '    healthCheckPath: /healthz',
      '  - type: cron',
      '    name: digest',
      '    runtime: node',
      "    schedule: '*/30 * * * *'",
      '    startCommand: node digest.js',
      'databases:',
      '  - name: shopdb',
      '',
    ].join('\n'),
  });
  const r = buildReport(files, { name: 'shop' });
  assert.equal(r.project.build, 'npm ci && npm run build');
  assert.equal(r.project.start, 'node server.js --port $PORT');
  const health = r.changes.find((c) => c.id === 'health');
  assert.match(health.title, /\/healthz/);
  assert.equal(health.blocking, true, 'a declared path is held to the {status, version} body');
  const m = deployhubOf(files);
  assert.equal(m.be.health, '/healthz');
  assert.deepEqual(m.cron, [{ name: 'render:digest', schedule: '*/30 * * * *', command: 'node digest.js' }]);
  for (const c of m.cron) parseCron(c.schedule);
  assert.deepEqual(m.database, { engine: 'postgres' });
  assert.match(scaffoldFor(files, 'shop').find((f) => f.path === 'Dockerfile').content, /RUN npm ci && npm run build/);
});

test('a project with its own Dockerfile keeps its CMD; a literal port is a blocking change; an existing deployhub.json is not touched', () => {
  const docker = buildReport(nodeApp({ Dockerfile: 'FROM node:22\nEXPOSE 3000\nUSER node\nCMD ["node","server.js"]\n', 'heroku.yml': fixture('heroku.yml') }), { name: 'shop' });
  assert.equal(docker.project.start, 'npm run start', 'the detected start stays; the Dockerfile decides');
  const d = docker.changes.find((c) => c.id === 'platform-start-dockerfile');
  assert.ok(d && d.request, 'heroku.yml run.web overrides CMD on Heroku, so a request is opened');

  const port = buildReport(nodeApp({ Procfile: 'web: node server.js -p 8080\n' }), { name: 'shop' });
  const p = port.changes.find((c) => c.id === 'platform-port');
  assert.ok(p && p.blocking);

  const own = nodeApp({ 'deployhub.json': { name: 'shop', be: { health: '/api/health' } }, 'app.json': { addons: ['heroku-postgresql'] } });
  const ownR = buildReport(own, { name: 'shop' });
  assert.ok(ownR.changes.some((c) => c.id === 'platform-manifest-exists'));
  assert.ok(!scaffoldFor(own, 'shop').some((f) => f.path === 'deployhub.json'));
});

test('a manifest that cannot be read is reported, not guessed', () => {
  const r = buildReport(nodeApp({ 'render.yaml': 'services:\n  - type: web\n    startCommand: &a npm start\n' }), { name: 'shop' });
  assert.equal(r.platform.unmapped[0].kind, 'unreadable');
  assert.match(r.platform.unmapped[0].title, /render\.yaml could not be read/);
  assert.equal(r.project.start, 'npm run start');
  assert.equal(buildReport(nodeApp({}), { name: 'shop' }).platform, null);
});

// Adopted repositories are untrusted input parsed in the server process: a
// manifest key naming a prototype must never reach Object.prototype.
const POLLUTION = [
  ['railway.toml', '[__proto__]\npolluted_a = 1\n'],
  ['railway.toml', '__proto__.polluted_b = "y"\n'],
  ['railway.toml', '"__proto__".polluted_c = "y"\n'],
  ['railway.toml', 'a = { __proto__ = { polluted_d = 1 } }\n'],
  ['railway.toml', 'constructor.prototype.polluted_e = 1\n'],
  ['railway.toml', '[[deploy.__proto__]]\npolluted_f = 1\n'],
  ['render.yaml', '__proto__:\n  polluted_g: y\n'],
  ['render.yaml', 'services:\n  - type: web\n    __proto__: { polluted_h: 1 }\n'],
  ['render.yaml', 'x: {"__proto__": {polluted_i: 1}}\n'],
  ['render.yaml', "'constructor':\n  prototype:\n    polluted_j: 1\n"],
  ['heroku.yml', 'setup:\n  config:\n    __proto__:\n      polluted_k: y\n'],
  ['app.json', '{"env":{"__proto__":{"polluted_l":"y"}},"addons":[]}'],
  ['railway.json', '{"__proto__":{"polluted_m":1},"deploy":{"startCommand":"node x"}}'],
];

test('prototype-pollution payloads in every manifest format are refused as unreadable and never touch Object.prototype', () => {
  const before = Object.getOwnPropertyNames(Object.prototype).sort();
  for (const [file, text] of POLLUTION) {
    const files = nodeApp({ [file]: text });
    const plan = detectPlatforms(files);
    const r = buildReport(files, { name: 'shop' });
    scaffoldFor(files, 'shop');
    const u = plan.unmapped.find((x) => x.source === file);
    assert.equal(u?.kind, 'unreadable', `${file} ${JSON.stringify(text)} was not refused: ${JSON.stringify(plan.unmapped)}`);
    assert.match(u.detail, /is not allowed/);
    assert.equal(r.platform.unmapped.find((x) => x.source === file).kind, 'unreadable');
    assert.ok(!r.env.some((v) => v.key === '__proto__'));
  }
  assert.deepEqual(Object.getOwnPropertyNames(Object.prototype).sort(), before, 'Object.prototype gained a property');
  for (const k of 'abcdefghijklm') assert.equal(({})[`polluted_${k}`], undefined, `polluted_${k} reached Object.prototype`);
  assert.equal(Object.getPrototypeOf(parseYamlLite('a: 1\n')), null, 'yamlLite maps have no prototype');
  assert.equal(Object.getPrototypeOf(parseTomlLite('[t]\na = 1\n').t), null, 'tomlLite tables have no prototype');
});
