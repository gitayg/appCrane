import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import log from '../utils/logger.js';

const PHP_IMAGE = 'php:8.3-apache';
const COMPOSER_IMAGE = 'composer:2';

/**
 * Same opt-in enforcement switches the Node generator honours
 * (dockerfileGen.js). Read here rather than imported so the two modules do not
 * import each other; the contract is the env var, not the function.
 */
function requireLockfile() { return process.env.APPCRANE_REQUIRE_LOCKFILE === '1'; }
function requireCleanAudit() { return process.env.APPCRANE_REQUIRE_CLEAN_AUDIT === '1'; }

/**
 * Extensions php:8.3-apache already ships enabled — measured with
 * `docker run --rm php:8.3-apache php -m`, not assumed. Requiring one of these
 * is a no-op: `docker-php-ext-install` would either rebuild it for nothing or
 * fail outright, so they are dropped from the install list.
 */
const BUILTIN_EXTS = new Set([
  'ctype', 'curl', 'date', 'dom', 'fileinfo', 'filter', 'hash', 'iconv', 'json',
  'libxml', 'mbstring', 'mysqlnd', 'openssl', 'pcre', 'pdo', 'pdo_sqlite', 'phar',
  'posix', 'random', 'readline', 'reflection', 'session', 'simplexml', 'sodium',
  'spl', 'sqlite3', 'standard', 'tokenizer', 'xml', 'xmlreader', 'xmlwriter',
  'zlib', 'opcache', 'zend opcache',
]);

/**
 * Extensions the generated build can actually produce, with the Debian -dev
 * packages and the `docker-php-ext-configure` invocation each one needs.
 *
 * Deliberately NOT a catch-all: anything absent from this table is reported
 * instead of guessed at. `docker-php-ext-install <name>` for an extension that
 * is not bundled with PHP (ext-redis, ext-imagick, ext-memcached — all PECL)
 * fails the build with "not found", which would turn every such app into a
 * failed deploy with a docker error instead of an AppCrane explanation.
 */
const EXT_TABLE = {
  bcmath: {},
  calendar: {},
  exif: {},
  ftp: {},
  gd: {
    apt: ['libfreetype6-dev', 'libjpeg62-turbo-dev', 'libpng-dev', 'libwebp-dev'],
    configure: 'docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp',
  },
  gettext: {},
  gmp: { apt: ['libgmp-dev'] },
  intl: { apt: ['libicu-dev'] },
  ldap: {
    apt: ['libldap2-dev'],
    configure: 'docker-php-ext-configure ldap --with-libdir="lib/$(dpkg-architecture --query DEB_BUILD_MULTIARCH)"',
  },
  mysqli: {},
  pcntl: {},
  pdo_mysql: {},
  pdo_pgsql: { apt: ['libpq-dev'] },
  pgsql: { apt: ['libpq-dev'] },
  soap: { apt: ['libxml2-dev'] },
  sockets: {},
  sysvmsg: {},
  sysvsem: {},
  sysvshm: {},
  xsl: { apt: ['libxslt1-dev'] },
  zip: { apt: ['libzip-dev'] },
};

function readJson(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch (_) { return null; }
}

/**
 * Does a package.json at the release root claim to BE the app?
 *
 * A `start` script or a `main` entry is what dockerfileGen's detectEntry()
 * looks for, i.e. it is exactly the evidence the Node generator uses to decide
 * what to run. A package.json with neither — Laravel's, Symfony's, any PHP app
 * with a Vite/webpack asset pipeline — declares an asset build, not a server.
 *
 * An unparseable package.json counts as claiming the app: that is the
 * pre-existing behaviour (the Node path is what runs today for any release with
 * a package.json), and falling back to it cannot break an app that deploys now.
 */
function packageJsonClaimsApp(releaseDir) {
  const path = join(releaseDir, 'package.json'); // nosemgrep: path-join-resolve-traversal — releaseDir is an internal computed path
  if (!existsSync(path)) return false;
  const pkg = readJson(path);
  if (!pkg) return true;
  return Boolean(pkg.scripts?.start || pkg.main);
}

/**
 * PRECEDENCE, stated explicitly because the brief asked for a decision:
 *
 *   composer.json present  AND  no package.json that claims the app  ->  PHP.
 *
 * Node wins any tie where package.json declares a `start` script or `main`,
 * so every app that builds today keeps building the same way. The common
 * both-files shape — Laravel/Symfony with a `build` script for assets and no
 * `start` — resolves to PHP, which is the only one of the two that can run it:
 * a node image has no php binary at all.
 */
export function detectPhpApp(releaseDir) {
  return existsSync(join(releaseDir, 'composer.json')) // nosemgrep: path-join-resolve-traversal — releaseDir is an internal computed path
    && !packageJsonClaimsApp(releaseDir);
}

function safeRel(p) {
  const cleaned = String(p || '').replace(/^[/\\]+/, '').replace(/\/+$/, '').trim();
  if (cleaned.includes('..')) throw new Error(`deployhub.json php.docroot contains "..": ${p}`);
  return cleaned;
}

/**
 * Where index.php lives. Laravel/Symfony/Slim serve from a front-controller
 * sub-directory; pointing Apache at the repo root for those exposes .env,
 * composer.json and vendor/ over HTTP.
 */
function detectDocroot(releaseDir, manifest) {
  if (manifest?.php?.docroot) return safeRel(manifest.php.docroot);
  for (const dir of ['public', 'web', 'html', 'public_html']) {
    if (existsSync(join(releaseDir, dir, 'index.php'))) return dir; // nosemgrep: path-join-resolve-traversal — releaseDir is an internal computed path
  }
  return '.';
}

/**
 * Turn composer.json `require` into an install plan.
 * Returns { apt, configure, install, unknown } — `unknown` is reported, never
 * guessed at.
 */
export function extensionPlan(require_) {
  const apt = new Set();
  const configure = [];
  const install = [];
  const unknown = [];

  for (const name of Object.keys(require_ || {})) {
    const m = /^ext-(.+)$/.exec(name);
    if (!m) continue;
    const ext = m[1].toLowerCase();
    if (BUILTIN_EXTS.has(ext)) continue;
    const spec = EXT_TABLE[ext];
    if (!spec) { unknown.push(ext); continue; }
    for (const pkg of spec.apt || []) apt.add(pkg);
    if (spec.configure) configure.push(spec.configure);
    install.push(ext);
  }

  return {
    apt: [...apt].sort(),
    configure,
    install: install.sort(),
    unknown: unknown.sort(),
  };
}

/**
 * The finding raised when a PHP release ships no composer.lock — the same
 * class of finding lockfileFinding() raises for a missing package-lock.json,
 * and it feeds the same APPCRANE_REQUIRE_LOCKFILE=1 switch.
 */
function composerLockFinding(releaseDir) {
  if (existsSync(join(releaseDir, 'composer.lock'))) return null; // nosemgrep: path-join-resolve-traversal — releaseDir is an internal computed path
  return 'the repo root has composer.json but no composer.lock. The generated build runs ' +
    '"composer install" with nothing to install FROM, so Composer re-resolves every dependency ' +
    'at build time: two builds of the same commit can ship different code, and a compromised ' +
    'transitive release lands with no version change to notice.';
}

/**
 * Build-time supply-chain block, the PHP twin of supplyChainLines(). Same
 * placement rule and same reason: emitted after `COPY . .` so Docker cannot
 * serve a stale advisory report out of the layer cache for months.
 */
function supplyChainLines(lockfileMissing) {
  const report = '/tmp/appcrane-audit.txt';
  const lines = ['# AppCrane supply-chain checks for the repo root (PHP)'];

  if (lockfileMissing) {
    lines.push(
      'RUN echo "APPCRANE SUPPLY-CHAIN WARNING: no composer.lock in the repo root - this image was ' +
      'built by re-resolving every dependency and is NOT reproducible. Commit composer.lock. Set ' +
      'APPCRANE_REQUIRE_LOCKFILE=1 on the AppCrane host to make this fatal instead of a warning."',
    );
  }

  const blocking = requireCleanAudit();
  const banner = blocking
    ? 'APPCRANE AUDIT FAILED: composer audit reported advisories in the repo root, or could not run at all. Blocking this build because APPCRANE_REQUIRE_CLEAN_AUDIT=1 is set on the AppCrane host:'
    : 'APPCRANE AUDIT WARNING: composer audit reported advisories in the repo root, or could not run at all. Deploy NOT blocked - set APPCRANE_REQUIRE_CLEAN_AUDIT=1 on the AppCrane host to block:';
  const onFail = `{ echo "${banner}"; tail -n 30 ${report};${blocking ? ' exit 1;' : ''} }`;

  lines.push(
    `RUN composer audit --no-interaction > ${report} 2>&1 ` +
    '&& echo "APPCRANE AUDIT: no known advisories in the repo root." ' +
    `|| ${onFail}`,
    '',
  );

  return lines;
}

/**
 * Apache in php:8.3-apache listens on 80 in two places — `Listen 80` in
 * ports.conf and `<VirtualHost *:80>` in 000-default.conf — and AppCrane hands
 * every container its own port in $PORT. Both files are rewritten to `${PORT}`,
 * which httpd expands from the process environment at config-parse time (the
 * stock config already relies on that: `ErrorLog ${APACHE_LOG_DIR}/error.log`).
 *
 * The single quotes matter: they stop the BUILD shell expanding ${PORT} into
 * the literal build-time value, which would bake the port into the image and
 * reintroduce exactly the bug this replaces.
 */
function apacheConfLines(docroot) {
  const root = docroot === '.' ? '/var/www/html' : `/var/www/html/${docroot}`;
  const vhost = [
    '<VirtualHost *:${PORT}>',
    '  ServerName localhost',
    `  DocumentRoot ${root}`,
    `  <Directory ${root}>`,
    '    Options -Indexes +FollowSymLinks',
    '    AllowOverride All',
    '    Require all granted',
    '  </Directory>',
  ];

  // An app with no front-controller sub-directory is served straight out of
  // the release root, which is also where composer.json, composer.lock, .env
  // and vendor/ live. Apache hands those out as plain text on request unless
  // told not to.
  if (docroot === '.') {
    vhost.push(
      '  <FilesMatch "^(composer\\.(json|lock)|deployhub\\.json|package(-lock)?\\.json|Dockerfile|\\.env.*|\\.git.*|.*\\.(ya?ml|ini|log|sqlite3?|db))$">',
      '    Require all denied',
      '  </FilesMatch>',
      `  <DirectoryMatch "^${root}/(vendor|\\.git)">`,
      '    Require all denied',
      '  </DirectoryMatch>',
    );
  }

  vhost.push(
    '  ErrorLog /proc/self/fd/2',
    '  CustomLog /proc/self/fd/1 combined',
    '</VirtualHost>',
  );

  return [
    '# AppCrane listens on $PORT, not 80. Apache expands ${PORT} from the environment.',
    'ENV PORT=3000',
    "RUN set -eux; \\\n" +
    "    printf '%s\\n' 'Listen ${PORT}' 'ServerName localhost' > /etc/apache2/ports.conf; \\\n" +
    `    printf '%s\\n' ${vhost.map((l) => `'${l}'`).join(' ')} > /etc/apache2/sites-available/000-default.conf; \\\n` +
    "    a2enmod rewrite",
    '',
  ];
}

/**
 * Generate the Dockerfile body for a PHP app. Returns { lines, warnings };
 * `warnings` are host-side findings (raised at generation time), as opposed to
 * the ones the generated build prints while it runs.
 */
export function generatePhpDockerfile({ releaseDir, manifest }) {
  const warnings = [];
  const composerJson = readJson(join(releaseDir, 'composer.json')); // nosemgrep: path-join-resolve-traversal — releaseDir is an internal computed path
  if (!composerJson) {
    warnings.push(
      'composer.json is not valid JSON, so no ext-* requirement could be read. The build will ' +
      'still run "composer install", which will report the parse error itself.',
    );
  }

  // The precedence rule sends the Laravel/Symfony shape here, and this build
  // runs Composer only. An app whose CSS/JS comes out of Vite therefore ships
  // whatever it committed — which is the white-page deploy distValidator.js
  // exists to catch, so it must not be silent.
  const pkg = readJson(join(releaseDir, 'package.json')); // nosemgrep: path-join-resolve-traversal — releaseDir is an internal computed path
  if (pkg?.scripts?.build) {
    warnings.push(
      'package.json declares a "build" script, but the PHP build runs Composer only - no npm ' +
      'install and no asset build. Commit the built assets, or add your own Dockerfile if the ' +
      'frontend must be built at deploy time.',
    );
  }

  const plan = extensionPlan(composerJson?.require);
  const docroot = detectDocroot(releaseDir, manifest);
  const docrootAbs = docroot === '.' ? releaseDir : join(releaseDir, docroot); // nosemgrep: path-join-resolve-traversal — releaseDir is an internal computed path
  if (!existsSync(join(docrootAbs, 'index.php'))) { // nosemgrep: path-join-resolve-traversal — releaseDir is an internal computed path
    warnings.push(
      `no index.php in ${docroot === '.' ? 'the repo root' : docroot}, which is the document root ` +
      'this build serves. Apache will answer 403/404 for "/". Set php.docroot in deployhub.json ' +
      'if your front controller lives somewhere else.',
    );
  }

  const finding = composerLockFinding(releaseDir);
  if (finding) {
    if (requireLockfile()) {
      throw new Error(
        `LOCKFILE_REQUIRED: ${finding} Commit a lockfile, or unset APPCRANE_REQUIRE_LOCKFILE on the AppCrane host.`,
      );
    }
    log.warn(`dockerfileGenPhp: ${finding}`);
    warnings.push(finding);
  }

  const lines = [`FROM ${PHP_IMAGE}`, ''];

  if (plan.apt.length) {
    lines.push(
      'RUN apt-get update \\\n' +
      `    && apt-get install -y --no-install-recommends ${plan.apt.join(' ')} \\\n` +
      '    && rm -rf /var/lib/apt/lists/*',
      '',
    );
  }
  for (const cfg of plan.configure) lines.push(`RUN ${cfg}`);
  if (plan.install.length) {
    lines.push(`RUN docker-php-ext-install -j"$(nproc)" ${plan.install.join(' ')}`, '');
  } else if (plan.configure.length) {
    lines.push('');
  }

  // An extension AppCrane cannot build is announced in the deploy log rather
  // than handed to docker-php-ext-install, which would fail the build with
  // "error: undefined symbol"-grade output and no explanation.
  //
  // It also has to be excused from Composer's platform check, measured:
  //   "Root composer.json requires PHP extension ext-redis * but it is missing
  //    from your system."
  // is a hard resolver failure, so an app requiring one PECL extension would
  // not build at all. --ignore-platform-req is Composer's own suggested escape
  // and is scoped to the exact extension, so every OTHER platform requirement
  // is still enforced.
  for (const ext of plan.unknown) {
    const msg =
      `composer.json requires ext-${ext}, which AppCrane's generated PHP build cannot install ` +
      '(it is not bundled with PHP - most likely a PECL extension such as redis, imagick or ' +
      'memcached). The image is built WITHOUT it and the app may fail at runtime. Commit your own ' +
      'Dockerfile if you need it.';
    warnings.push(msg);
    lines.push(`RUN echo "APPCRANE WARNING: ${msg}"`);
  }
  if (plan.unknown.length) lines.push('');

  lines.push(...apacheConfLines(docroot));

  lines.push(
    `COPY --from=${COMPOSER_IMAGE} /usr/bin/composer /usr/bin/composer`,
    'ENV COMPOSER_HOME=/tmp/composer',
    'ENV COMPOSER_ALLOW_SUPERUSER=1',
    '',
    'WORKDIR /var/www/html',
    'COPY . .',
    '',
    `RUN composer install --no-dev --prefer-dist --no-interaction${
      plan.unknown.map((ext) => ` --ignore-platform-req=ext-${ext}`).join('')}`,
    '',
  );

  lines.push(...supplyChainLines(Boolean(finding)));

  lines.push(
    'RUN chown -R www-data:www-data /var/www/html',
    'USER www-data',
    '',
    'EXPOSE 3000',
    '',
    'CMD ["apache2-foreground"]',
    '',
  );

  return { lines, warnings };
}

export function ensurePhpDockerfile({ releaseDir, manifest, dockerfilePath }) {
  const { lines, warnings } = generatePhpDockerfile({ releaseDir, manifest });
  writeFileSync(dockerfilePath, lines.join('\n'));
  return { path: dockerfilePath, warnings };
}
