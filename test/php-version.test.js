import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

import {
  choosePhpVersion, describePhpBuild, pinnedPhpVersionFor, DEFAULT_PHP_VERSION, PHP_VERSIONS,
} from '../server/services/phpVersion.js';
import { ensureDockerfile } from '../server/services/dockerfileGen.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const dirs = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function app(files) {
  const dir = mkdtempSync(join(tmpdir(), 'crane-phpver-'));
  dirs.push(dir);
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, typeof body === 'string' ? body : JSON.stringify(body));
  }
  return dir;
}

function fromLine(composerJson, pinnedPhpVersion = null) {
  const dir = app({ 'composer.json': composerJson, 'composer.lock': {}, 'index.php': '<?php' });
  const res = ensureDockerfile({
    releaseDir: dir, manifest: {}, appBasePath: '/apps/demo/',
    craneUrl: 'https://crane.example', craneInternalUrl: 'http://127.0.0.1:5001', pinnedPhpVersion,
  });
  return { first: readFileSync(res.path, 'utf8').split('\n')[0], php: res.php };
}

const req = (php) => ({ require: { php } });

test('the supported set is 8.5, 8.4, 8.3 (newest first) and the default is 8.5', () => {
  assert.deepEqual(PHP_VERSIONS.map((v) => v.version), ['8.5', '8.4', '8.3']);
  assert.equal(DEFAULT_PHP_VERSION, '8.5');
});

// [constraint, chosen minor]
const TABLE = [
  ['^8.1', '8.5'],
  ['^8.3', '8.5'],
  ['~8.2', '8.5'],          // Composer: >=8.2 <9.0.0 (npm would stop at <8.3)
  ['~8.3', '8.5'],          // npm's reading (<8.4) would give 8.3
  ['~8.3.0', '8.3'],        // >=8.3.0 <8.4.0
  ['~8', '8.5'],            // same as ~8.0
  ['>=8.1', '8.5'],
  ['>=8.1 <8.4', '8.3'],
  ['>=8.1,<8.5', '8.4'],
  ['>= 8.2 < 8.5', '8.4'],  // space after the operator is not an AND
  ['>8.3 <8.5', '8.4'],
  ['<=8.4.99', '8.4'],
  ['8.3.*', '8.3'],
  ['8.4.*', '8.4'],
  ['8.x', '8.5'],
  ['8.3.12', '8.3'],
  ['8.4', '8.4'],
  ['*', '8.5'],
  ['^7.4 || ^8.0', '8.5'],
  ['7.4.*|8.3.*', '8.3'],
  ['^7.2 || >=8.0 <8.5', '8.4'],
  ['8.2 - 8.4', '8.4'],     // >=8.2.0 <8.5
  ['8.2.0 - 8.4.0', '8.4'], // >=8.2.0 <=8.4.0
  ['>=8.3 !=8.5.0', '8.5'], // 8.5.1+ still satisfies
  ['^8.2@dev', '8.5'],
  ['v8.3.*', '8.3'],
];

for (const [constraint, expected] of TABLE) {
  test(`require.php "${constraint}" -> PHP ${expected}`, () => {
    const php = choosePhpVersion({ composerJson: req(constraint) });
    assert.equal(php.version, expected);
    assert.equal(php.image, `php:${expected}-apache`);
    assert.match(php.reason, /composer\.json require\.php/);
  });
}

test('config.platform.php wins over require.php', () => {
  const php = choosePhpVersion({
    composerJson: { require: { php: '^8.1' }, config: { platform: { php: '8.3.0' } } },
  });
  assert.equal(php.version, '8.3');
  assert.match(php.reason, /config\.platform\.php "8\.3\.0"/);
});

for (const constraint of ['^7.4', '>=8.6', '<8.3', '8.2.*', '~7.4.0 || 9.*', 'banana']) {
  test(`require.php "${constraint}" fails the build naming the constraint and the supported set`, () => {
    assert.throws(
      () => choosePhpVersion({ composerJson: req(constraint), pinnedPhpVersion: '8.3' }),
      (err) => err.message.startsWith('PHP_VERSION_UNSUPPORTED: ')
        && err.message.includes(`"${constraint}"`)
        && err.message.includes('Supported PHP versions: 8.5, 8.4, 8.3'),
    );
  });
}

test('an unsatisfiable constraint fails ensureDockerfile rather than picking a version', () => {
  assert.throws(() => fromLine(req('^7.4')), /PHP_VERSION_UNSUPPORTED/);
});

test('a new app with no php requirement gets the default', () => {
  const php = choosePhpVersion({ composerJson: { require: { 'ext-gd': '*' } } });
  assert.equal(php.version, DEFAULT_PHP_VERSION);
  assert.equal(php.reason, 'default (no php requirement in composer.json)');
});

test('an app pinned to 8.3 by its previous deploy stays on 8.3', () => {
  const php = choosePhpVersion({ composerJson: { require: {} }, pinnedPhpVersion: '8.3' });
  assert.equal(php.version, '8.3');
  assert.match(php.reason, /pinned from the previous deploy/);
});

test('a constraint in composer.json overrides the pin', () => {
  const php = choosePhpVersion({ composerJson: req('^8.1'), pinnedPhpVersion: '8.3' });
  assert.equal(php.version, '8.5');
});

test('a pin AppCrane no longer builds falls back to the default and says so', () => {
  const php = choosePhpVersion({ composerJson: {}, pinnedPhpVersion: '8.1' });
  assert.equal(php.version, DEFAULT_PHP_VERSION);
  assert.match(php.reason, /previous deploy used PHP 8\.1/);
});

test('an unparseable composer.json falls back to the pin, then the default', () => {
  assert.equal(choosePhpVersion({ composerJson: null, pinnedPhpVersion: '8.3' }).version, '8.3');
  assert.equal(choosePhpVersion({ composerJson: null }).version, DEFAULT_PHP_VERSION);
});

// --- the generated Dockerfile ------------------------------------------------

test('FROM line: new app, no constraint -> default image', () => {
  assert.equal(fromLine({ require: {} }).first, `FROM php:${DEFAULT_PHP_VERSION}-apache`);
});

test('FROM line: pinned 8.3, no constraint -> php:8.3-apache', () => {
  assert.equal(fromLine({ require: {} }, '8.3').first, 'FROM php:8.3-apache');
});

test('FROM line: constraint beats the pin', () => {
  assert.equal(fromLine(req('>=8.1 <8.5'), '8.3').first, 'FROM php:8.4-apache');
  assert.equal(fromLine(req('8.3.*')).first, 'FROM php:8.3-apache');
});

test('FROM line: config.platform.php', () => {
  assert.equal(fromLine({ require: { php: '>=8.1' }, config: { platform: { php: '8.4.1' } } }).first,
    'FROM php:8.4-apache');
});

test('a pinned 8.3 build is byte-identical to the Dockerfile generated before version choice', () => {
  // test/fixtures/...: the generator's output for this exact app, captured from
  // the code as it was before PHP versions were chosen.
  const golden = readFileSync(join(here, 'fixtures', 'php-dockerfile-8.3.pre-version-choice.Dockerfile'), 'utf8');
  const dir = app({
    'composer.json': { require: { 'ext-gd': '*', 'ext-redis': '*', 'ext-zip': '*', 'ext-ldap': '*' } },
    'public/index.php': '<?php',
  });
  const res = ensureDockerfile({ releaseDir: dir, manifest: {}, pinnedPhpVersion: '8.3' });
  assert.equal(readFileSync(res.path, 'utf8'), golden);
});

// --- the deploy log line -------------------------------------------------------

test('the deploy log line names the image and the reason', () => {
  assert.equal(
    describePhpBuild(choosePhpVersion({ composerJson: req('^8.1') })),
    'Generated Dockerfile (php:8.5-apache, non-root) - PHP 8.5: newest supported version satisfying composer.json require.php "^8.1"',
  );
  assert.equal(
    describePhpBuild(choosePhpVersion({ composerJson: {}, pinnedPhpVersion: '8.3' })),
    'Generated Dockerfile (php:8.3-apache, non-root) - PHP 8.3: pinned from the previous deploy (no php requirement in composer.json)',
  );
  assert.equal(
    describePhpBuild(choosePhpVersion({ composerJson: {} })),
    `Generated Dockerfile (php:${DEFAULT_PHP_VERSION}-apache, non-root) - PHP ${DEFAULT_PHP_VERSION}: default (no php requirement in composer.json)`,
  );
});

test('deployer reads the pin, logs the choice and records php_version on the deployment', () => {
  const src = readFileSync(join(root, 'server/services/deployer.js'), 'utf8');
  assert.match(src, /const pinnedPhpVersion = pinnedPhpVersionFor\(db, app\.id, env\);/);
  assert.match(src, /ensureDockerfile\(\{[^}]*pinnedPhpVersion \}\)/);
  assert.match(src, /appendLog\(describePhpBuild\(php\)\);/);
  assert.match(src, /UPDATE deployments SET php_version = \? WHERE id = \?'\)\.run\(php\.version, deployId\)/);
  assert.doesNotMatch(src, /'Generated Dockerfile \(php:8\.3-apache, non-root\)'/);
});

// --- pins: migration 148 backfill and lookup ---------------------------------

function deploymentsDb() {
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, app_id INTEGER NOT NULL, env TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', log TEXT)`);
  return db;
}

const OLD_PHP_LOG = '[09:00:00] Building...\n[09:00:01] Generated Dockerfile (php:8.3-apache, non-root)\n';
const NODE_LOG = '[09:00:01] Generated Dockerfile (Node Alpine, non-root)\n';

test('migration 148 backfills 8.3 only onto generated-PHP deploys that went live', () => {
  const db = deploymentsDb();
  const ins = db.prepare('INSERT INTO deployments (app_id, env, status, log) VALUES (?, ?, ?, ?)');
  ins.run(1, 'production', 'live', OLD_PHP_LOG);
  ins.run(1, 'production', 'rolled_back', OLD_PHP_LOG);
  ins.run(1, 'sandbox', 'failed', OLD_PHP_LOG);
  ins.run(2, 'production', 'live', NODE_LOG);
  ins.run(3, 'production', 'live', null);
  db.exec(readFileSync(join(root, 'server/migrations/148-deployment-php-version.sql'), 'utf8'));
  assert.deepEqual(
    db.prepare('SELECT php_version FROM deployments ORDER BY id').all().map((r) => r.php_version),
    ['8.3', '8.3', null, null, null],
  );
  assert.equal(pinnedPhpVersionFor(db, 1, 'production'), '8.3');
  assert.equal(pinnedPhpVersionFor(db, 2, 'production'), null);
});

test('pin lookup: latest live row in the same env, else the other env, never a failed row', () => {
  const db = deploymentsDb();
  db.exec(readFileSync(join(root, 'server/migrations/148-deployment-php-version.sql'), 'utf8'));
  const ins = db.prepare('INSERT INTO deployments (app_id, env, status, php_version) VALUES (?, ?, ?, ?)');
  ins.run(7, 'sandbox', 'rolled_back', '8.3');
  ins.run(7, 'sandbox', 'live', '8.4');
  ins.run(7, 'sandbox', 'failed', '8.5');
  assert.equal(pinnedPhpVersionFor(db, 7, 'sandbox'), '8.4');
  assert.equal(pinnedPhpVersionFor(db, 7, 'production'), '8.4', 'first production deploy follows the sandbox');
  ins.run(7, 'production', 'live', '8.3');
  assert.equal(pinnedPhpVersionFor(db, 7, 'production'), '8.3');
  assert.equal(pinnedPhpVersionFor(db, 8, 'production'), null);
});
