import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import log from '../utils/logger.js';

const SUPPORTED_NODE = new Set(['18', '20', '22']);
const DEFAULT_NODE = '20';

// Lockfiles `npm ci` can actually consume. Only these make the generated
// install reproducible, because the generated install runs npm.
const NPM_LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json'];
// Any lockfile at all. Used only for app-provided Dockerfiles, where we do not
// know which package manager runs inside and a yarn/pnpm/bun lock is evidence
// the author pinned their tree even though npm could not use it.
const ANY_LOCKFILES = [...NPM_LOCKFILES, 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb'];

function findLockfile(dir, names) {
  return names.find((n) => existsSync(join(dir, n))) || null;
}

/**
 * Opt-in enforcement switches, same shape as APPCRANE_REQUIRE_NONROOT /
 * APPCRANE_AUDIT_REQUIRED: ship permissive so an upgrade cannot fail the next
 * deploy of every app in the fleet at once, and let the operator turn each one
 * on after sweeping their own estate.
 */
function requireLockfile() { return process.env.APPCRANE_REQUIRE_LOCKFILE === '1'; }
function requireCleanAudit() { return process.env.APPCRANE_REQUIRE_CLEAN_AUDIT === '1'; }

function pickNodeVersion(manifest) {
  const v = String(manifest?.node_version || manifest?.engines?.node || '').replace(/[^\d]/g, '').slice(0, 2);
  return SUPPORTED_NODE.has(v) ? v : DEFAULT_NODE;
}

function safeRel(p) {
  // Strip leading slashes / drive letters; reject path traversal.
  const cleaned = String(p || '').replace(/^[/\\]+/, '').trim();
  if (cleaned.includes('..')) throw new Error(`deployhub.json workdir/dist contains "..": ${p}`);
  return cleaned;
}

/**
 * Auto-detect a monorepo frontend workdir when the manifest doesn't declare one.
 *
 * Common pattern: repo root holds the backend's package.json, and a sub-directory
 * (`client/`, `frontend/`, `web/`, `app/`) holds a Vite/webpack/CRA frontend with
 * its own package.json + build script. Without this detection, the generated
 * Dockerfile only installs root deps and the frontend never gets built —
 * deploy goes "live" with a missing or stale dist.
 *
 * Returns the workdir name (string) or null. Caller should treat as a
 * fallback: explicit manifest.fe.workdir always wins.
 */
function detectFrontendWorkdir(releaseDir) {
  const candidates = ['client', 'frontend', 'web', 'app', 'apps/web', 'apps/frontend'];
  for (const dir of candidates) {
    const pkgPath = join(releaseDir, dir, 'package.json');
    if (!existsSync(pkgPath)) continue;
    let pkg;
    try { pkg = JSON.parse(readFileSync(pkgPath, 'utf8')); } catch { continue; }
    const hasBuild = !!pkg?.scripts?.build;
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    const hasBundler = !!(
      deps.vite ||
      deps.webpack ||
      deps['react-scripts'] ||
      deps['@vitejs/plugin-react'] ||
      deps['@vitejs/plugin-vue'] ||
      deps.parcel ||
      deps.rollup ||
      deps.esbuild
    );
    if (hasBuild && hasBundler) return dir;
  }
  return null;
}

function detectEntry(manifest, releaseDir, beWorkdir) {
  if (manifest?.be?.entry) return manifest.be.entry;
  if (manifest?.start?.backend) return manifest.start.backend;
  const pkgPath = beWorkdir
    ? join(releaseDir, beWorkdir, 'package.json')
    : join(releaseDir, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
      if (pkg.scripts?.start) return 'npm start';
      if (pkg.main) return `node ${pkg.main}`;
    } catch (_) {}
  }
  return 'node server.js';
}

function detectBuild(manifest, releaseDir, feWorkdir) {
  const fromManifest = manifest?.fe?.build || manifest?.build?.frontend;
  if (fromManifest) return fromManifest;
  const pkgPath = feWorkdir
    ? join(releaseDir, feWorkdir, 'package.json')
    : join(releaseDir, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
      if (pkg.scripts?.build) return 'npm run build';
    } catch (_) {}
  }
  return null;
}

function entryToCmd(entry) {
  const trimmed = entry.trim();
  if (/[;&|<>]/.test(trimmed)) {
    return `["sh", "-c", ${JSON.stringify(trimmed)}]`;
  }
  return JSON.stringify(trimmed.split(/\s+/));
}

function defaultInstall() {
  // npm ci if a lockfile exists, else npm install. Stay --omit=dev.
  return `if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi`;
}

/**
 * A directory whose deps the generated Dockerfile installs with defaultInstall().
 * Only these get the supply-chain block: a manifest-supplied `be.install` /
 * `fe.install` may run pnpm, yarn or something bespoke, and `npm audit` there
 * would report a package-manager mismatch rather than a vulnerability.
 */
function lockfileFinding(releaseDir, relDir) {
  const abs = relDir === '.' ? releaseDir : join(releaseDir, relDir);
  if (!existsSync(join(abs, 'package.json'))) return null;
  if (findLockfile(abs, NPM_LOCKFILES)) return null;

  const where = relDir === '.' ? 'the repo root' : relDir;
  const foreign = findLockfile(abs, ANY_LOCKFILES);
  return foreign
    ? `${where} has ${foreign} but no package-lock.json. The generated build installs with npm, which ignores ${foreign} and re-resolves every dependency at build time, so the image is not reproducible.`
    : `${where} has no lockfile. The generated build falls back to "npm install", which re-resolves every dependency at build time: two builds of the same commit can ship different code, and a compromised transitive release lands with no version change to notice.`;
}

/**
 * Build-time supply-chain block for one install directory.
 *
 * Emitted AFTER `COPY . .` on purpose. Docker would otherwise serve these
 * layers from cache whenever package*.json is unchanged, so a freshly
 * disclosed advisory in an unchanged dependency — the most common way an app
 * becomes vulnerable without anyone touching it — would never be printed
 * again after the first build. Sitting after the COPY ties them to the source
 * layer, which every new commit invalidates anyway, so the report is at worst
 * one deploy old and costs nothing on builds that were going to rerun the
 * COPY regardless.
 *
 * Output reaches the deploy log for free: docker.js streams both build stdout
 * and stderr into deployer's appendLog.
 */
function supplyChainLines({ relDir, lockfileMissing, omitDev }) {
  const label = relDir === '.' ? 'the repo root' : relDir;
  const cd = relDir === '.' ? '' : `cd ${relDir} && `;
  const omit = omitDev ? ' --omit=dev' : '';
  const report = '/tmp/appcrane-audit.txt';

  const lines = [`# AppCrane supply-chain checks for ${label} (v2.44.0)`];

  if (lockfileMissing) {
    lines.push(
      `RUN echo "APPCRANE SUPPLY-CHAIN WARNING: no package-lock.json in ${label} - this image was built with 'npm install' and is NOT reproducible. Commit a lockfile. Set APPCRANE_REQUIRE_LOCKFILE=1 on the AppCrane host to make this fatal instead of a warning."`,
    );
  }

  // npm audit exits non-zero both when advisories are found and when it cannot
  // run at all (no registry reachable on the build host). Neither blocks by
  // default; the report is tailed rather than dumped because deployer caps the
  // deploy log at 500 lines and a full audit report can consume all of it.
  const blocking = requireCleanAudit();
  const banner = blocking
    ? `APPCRANE AUDIT FAILED: npm audit reported high or critical advisories in ${label}, or could not run at all. Blocking this build because APPCRANE_REQUIRE_CLEAN_AUDIT=1 is set on the AppCrane host:`
    : `APPCRANE AUDIT WARNING: npm audit reported high or critical advisories in ${label}, or could not run at all. Deploy NOT blocked - set APPCRANE_REQUIRE_CLEAN_AUDIT=1 on the AppCrane host to block:`;
  const onFail = `{ echo "${banner}"; tail -n 30 ${report};${blocking ? ' exit 1;' : ''} }`;

  lines.push(
    `RUN ${cd}npm audit${omit} --audit-level=high > ${report} 2>&1 ` +
    `&& echo "APPCRANE AUDIT: no high or critical advisories in ${label}." ` +
    `|| ${onFail}`,
    '',
  );

  return lines;
}

/**
 * Generate a Dockerfile into releaseDir, overwriting any user-provided one.
 * Uses Node {version} Alpine, runs as non-root `node` user (UID 1000),
 * runs build step at image build time if manifest declares one.
 *
 * Monorepo support (Option 2):
 *   manifest.be = { workdir, install, entry }
 *   manifest.fe = { workdir, install, build, dist }
 * If be.workdir is set, npm install runs there and the container CWD is /app/<workdir>.
 * If fe.workdir is set, npm install + build run there independently.
 * Apps without these fields use the existing flat-layout build (unchanged).
 *
 * Returns `warnings` — supply-chain findings raised on the AppCrane host at
 * generation time, as opposed to the ones the generated Dockerfile prints
 * during the build.
 */
export function ensureDockerfile({ releaseDir, manifest, appBasePath, craneUrl, craneInternalUrl }) {
  const existing = join(releaseDir, 'Dockerfile'); // nosemgrep: path-join-resolve-traversal — releaseDir is an internal computed path
  const warnings = [];

  // If the app ships its own Dockerfile, use it as-is.
  if (existsSync(existing)) {
    // Everything below this line is unreachable for these apps: their build
    // steps are the author's, so the generated install, the lockfile fallback
    // and the npm-audit block never run. The one rule that can still be
    // applied from out here is "pin your dependencies somehow" — and only
    // loosely, since we cannot see which package manager their Dockerfile
    // invokes, so ANY lockfile satisfies it.
    if (existsSync(join(releaseDir, 'package.json')) && !findLockfile(releaseDir, ANY_LOCKFILES)) {
      const msg =
        'app-provided Dockerfile with a package.json but no lockfile of any kind ' +
        '(package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lockb). ' +
        'Whatever install command that Dockerfile runs re-resolves dependencies at build time, ' +
        'so the image is not reproducible.';
      if (requireLockfile()) {
        throw new Error(
          `LOCKFILE_REQUIRED: ${msg} Commit a lockfile, or unset APPCRANE_REQUIRE_LOCKFILE on the AppCrane host.`,
        );
      }
      log.warn(`dockerfileGen: ${msg}`);
      warnings.push(msg);
    }
    return { path: existing, userProvided: true, warnings };
  }

  const node = pickNodeVersion(manifest);

  const beWorkdir = manifest?.be?.workdir ? safeRel(manifest.be.workdir) : null;
  // Auto-detect a frontend monorepo workdir when the manifest doesn't say.
  // Only kicks in if there's no `fe` block at all — if the user declared
  // `fe.workdir` we honor it, and if they declared `fe` without a workdir
  // they probably meant the flat layout (root has the frontend too).
  let feWorkdir = manifest?.fe?.workdir ? safeRel(manifest.fe.workdir) : null;
  if (!feWorkdir && !manifest?.fe) {
    feWorkdir = detectFrontendWorkdir(releaseDir);
  }
  const beInstall = manifest?.be?.install || defaultInstall();
  const feInstall = manifest?.fe?.install || defaultInstall();

  // Install directories AppCrane resolves dependencies for itself. A
  // manifest-supplied be.install / fe.install owns its own resolution (it may
  // not even be npm), so it is left alone rather than second-guessed.
  const scanTargets = [];
  const trackInstall = (relDir, omitDev) => {
    const finding = lockfileFinding(releaseDir, relDir);
    if (finding) {
      if (requireLockfile()) {
        throw new Error(
          `LOCKFILE_REQUIRED: ${finding} Commit a lockfile, or unset APPCRANE_REQUIRE_LOCKFILE on the AppCrane host.`,
        );
      }
      log.warn(`dockerfileGen: ${finding}`);
      warnings.push(finding);
    }
    scanTargets.push({ relDir, lockfileMissing: !!finding, omitDev });
  };

  const entry = detectEntry(manifest, releaseDir, beWorkdir);
  const buildCmd = detectBuild(manifest, releaseDir, feWorkdir);
  const cmd = entryToCmd(entry);

  const lines = [
    `FROM node:${node}-alpine`,
    '',
    'RUN apk add --no-cache tini',
    '',
    'WORKDIR /app',
    '',
  ];

  if (beWorkdir || feWorkdir) {
    // Monorepo path — install per workdir for cache efficiency, then COPY everything.
    if (beWorkdir) {
      if (!manifest?.be?.install) trackInstall(beWorkdir, true);
      lines.push(
        `# Backend deps (${beWorkdir})`,
        `COPY ${beWorkdir}/package*.json ./${beWorkdir}/`,
        `RUN cd ${beWorkdir} && ${beInstall}`,
        '',
      );
    } else {
      // Root has its own package.json (e.g. workspaces); install at root
      trackInstall('.', true);
      lines.push(
        'COPY package*.json ./',
        `RUN ${defaultInstall()}`,
        '',
      );
    }
    if (feWorkdir && feWorkdir !== beWorkdir) {
      if (!manifest?.fe?.install) trackInstall(feWorkdir, false);
      lines.push(
        `# Frontend deps (${feWorkdir}) — devDeps included for build`,
        `COPY ${feWorkdir}/package*.json ./${feWorkdir}/`,
        `RUN cd ${feWorkdir} && ${feInstall.replace(/--omit=dev/g, '').trim()}`,
        '',
      );
    }
    lines.push('COPY . .', '');
  } else {
    // Flat-layout (unchanged from previous releases)
    trackInstall('.', true);
    lines.push(
      'COPY package*.json ./',
      `RUN ${defaultInstall()}`,
      '',
      'COPY . .',
      '',
    );
  }

  for (const target of scanTargets) lines.push(...supplyChainLines(target));

  if (buildCmd) {
    const buildDir = feWorkdir || '.';
    // APP_BASE_PATH / PUBLIC_URL / VITE_BASE_PATH are scoped to the build RUN
    // only (not declared as ENV). They must NOT persist into the runtime image
    // because Caddy strips the slug prefix from incoming requests; backends
    // mount at '/'. See bugs/2026-04-26-appcrane-app-base-path-resolution.md
    const buildEnv = `APP_BASE_PATH="${appBasePath}" PUBLIC_URL="${appBasePath}" VITE_BASE_PATH="${appBasePath}"`;
    lines.push(
      `ENV CRANE_URL="${craneUrl}"`,
      `ENV CRANE_INTERNAL_URL="${craneInternalUrl}"`,
      'ENV NODE_ENV=production',
      'ENV CI=true',
      buildDir === '.'
        ? `RUN ${buildEnv} ${buildCmd}`
        : `RUN cd ${buildDir} && ${buildEnv} ${buildCmd}`,
      '',
    );
  }

  const runWorkdir = beWorkdir ? `/app/${beWorkdir}` : '/app';

  lines.push(
    'RUN chown -R node:node /app',
    'USER node',
    '',
    `WORKDIR ${runWorkdir}`,
    '',
    'EXPOSE 3000',
    '',
    'ENTRYPOINT ["/sbin/tini", "--"]',
    `CMD ${cmd}`,
    '',
  );

  writeFileSync(existing, lines.join('\n'));
  return { path: existing, warnings };
}

/**
 * Inject `ARG APP_BASE_PATH` + `ENV APP_BASE_PATH=$APP_BASE_PATH` into a
 * user-provided Dockerfile if those declarations are absent.
 *
 * Docker silently discards `--build-arg` values that the Dockerfile never
 * declares with ARG, so bundlers (Vite, CRA) see `undefined` and fall back to
 * `/` or `./`, breaking sub-path deployments.
 *
 * The injection is placed immediately after the first FROM line so it is
 * in scope for all subsequent RUN / ENV / CMD instructions.
 */
export function injectAppBasePathArg(dockerfilePath) {
  const content = readFileSync(dockerfilePath, 'utf8');
  if (/^ARG\s+APP_BASE_PATH\b/m.test(content)) return; // already declared

  const lines = content.split('\n');
  const fromIdx = lines.findIndex(l => /^\s*FROM\s+/i.test(l));
  if (fromIdx === -1) return; // malformed Dockerfile — skip silently

  lines.splice(fromIdx + 1, 0, 'ARG APP_BASE_PATH=/', 'ENV APP_BASE_PATH=$APP_BASE_PATH', '');
  writeFileSync(dockerfilePath, lines.join('\n'), 'utf8');
}
