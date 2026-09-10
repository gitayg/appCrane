import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { ensureDockerfile } from '../server/services/dockerfileGen.js';
import { detectPhpApp, extensionPlan } from '../server/services/dockerfileGenPhp.js';
import { validateDockerfile } from '../server/services/dockerfileValidator.js';

// PHP source builds (dockerfileGenPhp.js).
//
// Everything asserted about the RUNTIME here was first measured against a real
// `docker build` + `docker run` of this generator's own output, not reasoned
// about:
//
//   * stock php:8.3-apache, PORT=8123, container port 8123 published ->
//     curl rc=52, `grep -c "Listen 80" /etc/apache2/ports.conf` = 1, id = uid 0.
//     That is the control: the base image ignores $PORT and runs as root.
//   * the generated image, same PORT=8123 -> HTTP 200 and
//     {"port_env":"8123","gd":true,"zip":true,"pdo_mysql":true,"redis":false,
//      "uid":33,"user":"www-data","psr_log":true}
//   * the same image with no PORT in the environment -> HTTP 200 on 3000.
//   * root-docroot app: "/" 200 while /composer.json /composer.lock /.env
//     /Dockerfile /.git/HEAD /vendor/autoload.php all 403.
//
// The docker build is re-runnable from the suite: set APPCRANE_PHP_DOCKER_TEST=1
// (the last test in this file), which is skipped by default because it needs a
// daemon, the network and ~90s.

const dirs = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function scratch() {
  const d = mkdtempSync(join(tmpdir(), 'crane-php-'));
  dirs.push(d);
  return d;
}

function app(files) {
  const dir = scratch();
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, typeof body === 'string' ? body : JSON.stringify(body));
  }
  return dir;
}

function gen(dir, manifest = {}) {
  const res = ensureDockerfile({
    releaseDir: dir,
    manifest,
    appBasePath: '/apps/demo/',
    craneUrl: 'https://crane.example',
    craneInternalUrl: 'http://127.0.0.1:5001',
  });
  return { ...res, source: readFileSync(res.path, 'utf8') };
}

function withEnv(vars, fn) {
  const prev = {};
  for (const [k, v] of Object.entries(vars)) { prev[k] = process.env[k]; process.env[k] = v; }
  try { return fn(); } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
}

const COMPOSER = { name: 'acme/app', require: { php: '>=8.1' } };
const LOCK = { packages: [], 'packages-dev': [], 'content-hash': 'x' };

// --- detection and precedence -------------------------------------------

test('composer.json alone produces a PHP image, not a Node one', () => {
  const dir = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'index.php': '<?php echo 1;' });
  assert.equal(detectPhpApp(dir), true);

  const { source } = gen(dir);
  assert.match(source, /^FROM php:8\.3-apache$/m);
  assert.doesNotMatch(source, /FROM node:/);
  assert.match(source, /composer install --no-dev --prefer-dist --no-interaction/);
});

test('a package.json that CLAIMS the app keeps the Node path — precedence, stated', () => {
  // `scripts.start` and `main` are exactly what dockerfileGen's detectEntry()
  // reads, so "claims the app" means "the Node generator knows what to run".
  for (const pkg of [{ scripts: { start: 'node server.js' } }, { main: 'index.js' }]) {
    const dir = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'package.json': pkg });
    assert.equal(detectPhpApp(dir), false, JSON.stringify(pkg));
    assert.match(gen(dir).source, /^FROM node:20-alpine$/m, JSON.stringify(pkg));
  }
});

test('the Laravel/Symfony shape — composer.json plus an asset-only package.json — is PHP', () => {
  const dir = app({
    'composer.json': COMPOSER,
    'composer.lock': LOCK,
    'package.json': { private: true, scripts: { dev: 'vite', build: 'vite build' }, devDependencies: { vite: '^5' } },
    'public/index.php': '<?php echo 1;',
  });
  assert.equal(detectPhpApp(dir), true);
  assert.match(gen(dir).source, /^FROM php:8\.3-apache$/m);
});

test('the PHP path says out loud that it does not build Vite assets', () => {
  const dir = app({
    'composer.json': COMPOSER, 'composer.lock': LOCK, 'public/index.php': '<?php',
    'package.json': { scripts: { build: 'vite build' }, devDependencies: { vite: '^5' } },
  });
  const { warnings } = gen(dir);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /"build" script/);
  assert.match(warnings[0], /no npm install and no asset build/);

  // Control: an app with no build script must not be nagged.
  const plain = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'public/index.php': '<?php' });
  assert.deepEqual(gen(plain).warnings, []);
});

test('an unparseable package.json falls back to Node — the path that runs today', () => {
  const dir = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'package.json': '{ not json' });
  assert.equal(detectPhpApp(dir), false);
});

test('a Node app with no composer.json is untouched by any of this', () => {
  const dir = app({ 'package.json': { name: 'n', scripts: { start: 'node s.js' } }, 'package-lock.json': {} });
  assert.equal(detectPhpApp(dir), false);
  const { source } = gen(dir);
  assert.match(source, /^FROM node:20-alpine$/m);
  assert.doesNotMatch(source, /php|composer/i);
});

test('an app-provided Dockerfile still wins over PHP detection', () => {
  const dir = app({
    'composer.json': COMPOSER, 'composer.lock': LOCK, 'index.php': '<?php',
    Dockerfile: 'FROM php:8.3-apache\nUSER www-data\nEXPOSE 3000\n',
  });
  const res = gen(dir);
  assert.equal(res.userProvided, true);
  assert.equal(res.source, 'FROM php:8.3-apache\nUSER www-data\nEXPOSE 3000\n', 'the author\'s file must be left byte-identical');
});

// --- $PORT ---------------------------------------------------------------

test('the generated image listens on $PORT, and 80 appears nowhere', () => {
  const dir = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'index.php': '<?php' });
  const { source } = gen(dir);

  assert.match(source, /'Listen \$\{PORT\}'/, 'ports.conf must be rewritten to ${PORT}');
  assert.match(source, /'<VirtualHost \*:\$\{PORT\}>'/, 'the vhost must be rewritten to ${PORT}');
  assert.doesNotMatch(source, /Listen 80\b/);
  assert.doesNotMatch(source, /\*:80>/);

  // ${PORT} must survive INTO the image. An unquoted (or double-quoted) printf
  // argument is expanded by the BUILD shell — ENV PORT=3000 is in scope there —
  // which bakes 3000 into the config and reintroduces the fixed-port bug.
  // Segments at an odd index of a split on "'" are the single-quoted ones.
  for (const line of source.split('\n').filter(l => l.includes('${PORT}'))) {
    if (!line.includes('printf')) continue;
    line.split("'").forEach((seg, i) => {
      if (i % 2 === 0) assert.ok(!seg.includes('${PORT}'), `unquoted \${PORT} in: ${line}`);
    });
  }
  assert.match(source, /^ENV PORT=3000$/m, 'a default so Apache never parses a bare ${PORT}');
  assert.match(source, /^EXPOSE 3000$/m, 'AppCrane wires source builds to container port 3000');
});

// --- non-root ------------------------------------------------------------

test('the generated PHP Dockerfile passes AppCrane\'s own non-root validator', () => {
  const dir = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'public/index.php': '<?php' });
  const { source } = gen(dir);

  assert.match(source, /^USER\s+(?!root\b|0(:|$))\S+/mi);
  assert.match(source, /^RUN chown -R www-data:www-data \/var\/www\/html$/m, 'www-data must own the tree it was handed');

  const res = validateDockerfile(dir, { expectedPort: 3000 });
  assert.deepEqual(res.errors, []);
  assert.deepEqual(res.warnings.filter(w => /USER|root/i.test(w)), []);
  assert.equal(res.valid, true);
});

test('the generated PHP Dockerfile passes under APPCRANE_REQUIRE_NONROOT=1 too', () => {
  const dir = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'index.php': '<?php' });
  gen(dir);
  const res = withEnv({ APPCRANE_REQUIRE_NONROOT: '1' }, () => validateDockerfile(dir, { expectedPort: 3000 }));
  assert.equal(res.valid, true);
  assert.deepEqual(res.errors, []);
});

// --- lockfile policy: the same contract as the Node path ------------------

test('composer.lock present: no finding, and no warning baked into the build', () => {
  const dir = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'index.php': '<?php' });
  const { warnings, source } = gen(dir);
  assert.deepEqual(warnings, []);
  assert.doesNotMatch(source, /SUPPLY-CHAIN WARNING/);
});

test('composer.lock missing: a host-side finding AND a line in the deploy log', () => {
  const dir = app({ 'composer.json': COMPOSER, 'index.php': '<?php' });
  const { warnings, source } = gen(dir);

  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /composer\.lock/);
  assert.match(warnings[0], /re-resolves every dependency at build time/);
  assert.match(source, /RUN echo "APPCRANE SUPPLY-CHAIN WARNING: no composer\.lock/);
  assert.match(source, /APPCRANE_REQUIRE_LOCKFILE=1/, 'the message must name the switch that makes it fatal');
});

test('APPCRANE_REQUIRE_LOCKFILE=1 makes a missing composer.lock fatal — same as npm', () => {
  const missing = app({ 'composer.json': COMPOSER, 'index.php': '<?php' });
  assert.throws(
    () => withEnv({ APPCRANE_REQUIRE_LOCKFILE: '1' }, () => gen(missing)),
    /LOCKFILE_REQUIRED/,
  );

  // Control: with the lock committed the same flag must not block.
  const present = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'index.php': '<?php' });
  const { warnings } = withEnv({ APPCRANE_REQUIRE_LOCKFILE: '1' }, () => gen(present));
  assert.deepEqual(warnings, []);
});

test('composer audit runs, and APPCRANE_REQUIRE_CLEAN_AUDIT=1 turns it into a gate', () => {
  const files = { 'composer.json': COMPOSER, 'composer.lock': LOCK, 'index.php': '<?php' };

  const permissive = gen(app(files)).source;
  assert.match(permissive, /RUN composer audit --no-interaction/);
  assert.match(permissive, /APPCRANE AUDIT WARNING:/);
  assert.doesNotMatch(permissive, /exit 1;/, 'default mode must not block the build');

  const blocking = withEnv({ APPCRANE_REQUIRE_CLEAN_AUDIT: '1' }, () => gen(app(files)).source);
  assert.match(blocking, /APPCRANE AUDIT FAILED:/);
  assert.match(blocking, /tail -n 30 \/tmp\/appcrane-audit\.txt; exit 1;/);
});

test('the audit block sits after COPY . . so the cache cannot hide a new advisory', () => {
  const { source } = gen(app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'index.php': '<?php' }));
  assert.ok(source.indexOf('COPY . .') < source.indexOf('composer audit'));
});

// --- ext-* mapping -------------------------------------------------------

test('extensionPlan maps the common extensions to their OS deps and configure step', () => {
  const plan = extensionPlan({
    'ext-gd': '*', 'ext-zip': '*', 'ext-intl': '*', 'ext-pdo_pgsql': '*', 'ext-pdo_mysql': '*',
  });
  assert.deepEqual(plan.install, ['gd', 'intl', 'pdo_mysql', 'pdo_pgsql', 'zip']);
  for (const pkg of ['libpng-dev', 'libzip-dev', 'libicu-dev', 'libpq-dev']) {
    assert.ok(plan.apt.includes(pkg), `${pkg} missing from apt list`);
  }
  assert.deepEqual(plan.configure, ['docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp']);
  assert.deepEqual(plan.unknown, []);
});

test('extensions php:8.3-apache already ships are not reinstalled', () => {
  // Measured with `docker run --rm php:8.3-apache php -m`.
  const plan = extensionPlan({
    'ext-mbstring': '*', 'ext-json': '*', 'ext-pdo': '*', 'ext-pdo_sqlite': '*',
    'ext-curl': '*', 'ext-openssl': '*', 'ext-xml': '*', 'ext-opcache': '*',
  });
  assert.deepEqual(plan.install, []);
  assert.deepEqual(plan.apt, []);
  assert.deepEqual(plan.unknown, []);
});

test('non-extension requirements are ignored', () => {
  const plan = extensionPlan({ php: '>=8.1', 'laravel/framework': '^11', 'psr/log': '^3' });
  assert.deepEqual(plan, { apt: [], configure: [], install: [], unknown: [] });
});

test('an extension AppCrane cannot build is reported, never guessed at', () => {
  const dir = app({
    'composer.json': { require: { 'ext-redis': '*', 'ext-imagick': '*', 'ext-gd': '*' } },
    'composer.lock': LOCK, 'index.php': '<?php',
  });
  const { warnings, source } = gen(dir);

  assert.deepEqual(extensionPlan({ 'ext-redis': '*' }).unknown, ['redis']);
  assert.match(source, /docker-php-ext-install -j"\$\(nproc\)" gd$/m, 'only the mappable extension is installed');
  assert.doesNotMatch(source, /ext-install.*redis/);

  assert.equal(warnings.filter(w => /ext-redis|ext-imagick/.test(w)).length, 2);
  assert.match(source, /RUN echo "APPCRANE WARNING: composer\.json requires ext-redis/);

  // Measured: `composer install` HARD-FAILS on a missing platform extension
  // ("Root composer.json requires PHP extension ext-redis * but it is missing
  // from your system"), so without this the whole build dies at the install
  // step — the "fails at build time" outcome the extension warning exists to
  // avoid.
  assert.match(source, /composer install .*--ignore-platform-req=ext-imagick --ignore-platform-req=ext-redis/);
  assert.doesNotMatch(source, /--ignore-platform-req=ext-gd/, 'a mappable extension must still be enforced');
});

test('an app requiring no extensions gets no apt layer at all', () => {
  const { source } = gen(app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'index.php': '<?php' }));
  assert.doesNotMatch(source, /apt-get/);
  assert.doesNotMatch(source, /docker-php-ext-install/);
});

// --- document root -------------------------------------------------------

test('a front-controller sub-directory becomes the document root', () => {
  for (const dirName of ['public', 'web', 'html', 'public_html']) {
    const dir = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, [`${dirName}/index.php`]: '<?php' });
    assert.match(gen(dir).source, new RegExp(`DocumentRoot /var/www/html/${dirName}`), dirName);
  }
});

test('deployhub.json php.docroot overrides detection, and ".." is rejected', () => {
  const files = { 'composer.json': COMPOSER, 'composer.lock': LOCK, 'site/index.php': '<?php' };
  assert.match(gen(app(files), { php: { docroot: 'site' } }).source, /DocumentRoot \/var\/www\/html\/site/);
  // A fresh release dir: ensureDockerfile() would otherwise reuse the Dockerfile
  // the previous call just wrote and never reach the generator at all.
  assert.throws(() => gen(app(files), { php: { docroot: '../etc' } }), /contains ".."/);
});

test('a root-served app denies its own source files over HTTP', () => {
  const dir = app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'index.php': '<?php' });
  const { source } = gen(dir);
  assert.match(source, /DocumentRoot \/var\/www\/html'/);
  assert.match(source, /composer\\\.\(json\|lock\)/);
  assert.match(source, /Require all denied/);
  assert.match(source, /DirectoryMatch .*vendor/);
});

test('a sub-directory docroot does not carry the deny rules — it does not need them', () => {
  const { source } = gen(app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'public/index.php': '<?php' }));
  assert.doesNotMatch(source, /Require all denied/, 'composer.json is already outside the document root');
});

test('no index.php anywhere is a visible warning, not a silently broken deploy', () => {
  const { warnings } = gen(app({ 'composer.json': COMPOSER, 'composer.lock': LOCK, 'src/App.php': '<?php' }));
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /no index\.php in the repo root/);
  assert.match(warnings[0], /php\.docroot/);
});

test('an unparseable composer.json is reported rather than crashing generation', () => {
  const dir = app({ 'composer.json': '{ "require": ', 'composer.lock': LOCK, 'index.php': '<?php' });
  const { warnings, source } = gen(dir);
  assert.ok(warnings.some(w => /not valid JSON/.test(w)));
  assert.match(source, /^FROM php:8\.3-apache$/m);
});

// --- the real thing ------------------------------------------------------

test('the generated image really builds, serves on a non-80 port, and runs as www-data', {
  skip: process.env.APPCRANE_PHP_DOCKER_TEST === '1' ? false : 'set APPCRANE_PHP_DOCKER_TEST=1 (needs docker + network)',
}, () => {
  const dir = app({
    'composer.json': { name: 'acme/probe', require: { 'ext-gd': '*', 'ext-mbstring': '*', 'ext-redis': '*' } },
    'public/index.php':
      "<?php header('Content-Type: application/json'); echo json_encode([" +
      "'port_env' => getenv('PORT'), 'gd' => extension_loaded('gd'), 'redis' => extension_loaded('redis')," +
      "'uid' => posix_getuid()]);",
  });
  gen(dir);

  const tag = `appcrane-php-suite-${process.pid}`;
  const name = `${tag}-run`;
  const sh = (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    sh('docker', ['build', '-q', '-t', tag, dir]);
    sh('docker', ['run', '-d', '--name', name, '-e', 'PORT=8123', '-p', '127.0.0.1:19199:8123', tag]);

    let body = '';
    for (let i = 0; i < 40 && !body; i++) {
      try { body = sh('curl', ['-sf', '-m', '2', 'http://127.0.0.1:19199/']); } catch (_) { sh('sleep', ['0.5']); }
    }
    const seen = JSON.parse(body);
    assert.equal(seen.port_env, '8123', 'Apache must bind the port AppCrane assigned, not 80');
    assert.equal(seen.gd, true, 'ext-gd was required and must be loaded');
    assert.equal(seen.redis, false, 'ext-redis is unmappable: absent, but the build still succeeded');

    // NOT seen.user. Apache's master process forks its workers as
    // APACHE_RUN_USER, so PHP reports "www-data" even when the container runs
    // as root — measured: mutating the generator to `USER root` left this whole
    // test green until it asked the container itself.
    assert.equal(sh('docker', ['exec', name, 'id', '-u']).trim(), '33', 'the container must run as uid 33, not root');
  } finally {
    try { sh('docker', ['rm', '-f', name]); } catch (_) {}
    try { sh('docker', ['rmi', '-f', tag]); } catch (_) {}
  }
});
