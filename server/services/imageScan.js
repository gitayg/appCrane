// Container image CVE scanning for source_type='image' apps.
//
// v2.52.0 gave AppCrane a dependency scanner that reads lockfiles out of the
// live release directory. That covers every app the platform BUILDS and misses
// every app it PULLS: an image app has no release tree, so findLockfiles()
// returns nothing and scanApp records 'skipped — no recognised manifest'. The
// catalogue is 67 third-party images. The apps the org wrote itself were
// scanned; the apps somebody else wrote were not, which is exactly backwards.
//
// Same contract as appScan.js, deliberately, because this is the same feature
// wearing a different reader:
//
//   REPORT, NEVER BLOCK. Nothing in this file may throw into a deploy. These
//   are other teams' apps and a third-party base image with a transitive
//   advisory is not a reason to wedge a deploy nobody else asked for.
//
//   ONE ROW PER SCAN. This module produces a result; appScan.scanApp owns the
//   single INSERT, so image and lockfile scans cannot drift into two shapes.
//
//   A SCAN THAT COULD NOT RUN IS NOT A CLEAN SCAN. Every path out of here that
//   did not actually examine an image records 'skipped' or 'error' with a
//   reason. 'ok' means Trivy looked and found nothing.
//
// ---------------------------------------------------------------------------
// Why the scanner runs in a container
// ---------------------------------------------------------------------------
//
// The obvious implementation is `trivy image <ref>` against a host binary. That
// makes the scanner a new deployment dependency: an operator who installs
// AppCrane and does not also install Trivy gets a platform where this feature
// silently does not exist. AppCrane already requires Docker — it is how every
// app on the box runs — so the scanner is pulled and run like anything else,
// and the only thing an operator has to have is the thing they already have.
//
// The socket mount is what lets Trivy read the image out of the LOCAL daemon,
// which matters: the deploy already pulled those bytes, and re-fetching them
// from the registry would need the registry credentials all over again (Trivy's
// 'remote' fallback is what produced "UNAUTHORIZED: authentication required"
// when the image was not local). It also means the scanner container can drive
// the daemon, which is a real grant — it is made to a version-pinned image, by
// the same code path that already runs `docker pull` on operator-supplied
// references, so it does not widen the trust boundary that the deploy path
// already sits inside.
//
// ---------------------------------------------------------------------------
// The invocation, measured rather than assumed
// ---------------------------------------------------------------------------
//
//   docker run --rm
//     -v /var/run/docker.sock:/var/run/docker.sock
//     -v <DATA_DIR>/trivy-cache:/root/.cache/trivy
//     aquasec/trivy:<pin> image --quiet --scanners vuln --format json
//     --timeout <n>s <digest-ref>
//
// Every flag was checked against a real run of aquasec/trivy:0.74.0 on
// alpine@sha256:0f2d… and python@sha256:b9e0…:
//
//   --quiet      Trivy writes its report to STDOUT and its log to STDERR, so
//                the JSON is parseable either way. --quiet drops the INFO/WARN
//                lines and KEEPS FATAL, so a failure still explains itself.
//   --scanners vuln
//                the default for `image` also runs the secret scanner, which
//                costs time and emits a Results entry this module does not map.
//   --format json
//                schema 2. The shape is pinned by mapTrivyReport below.
//   cache volume a cold run downloads the vulnerability database from ghcr.io:
//                12.5s measured, against 2.1s once the cache is warm. Without
//                the mount every scan on the box pays that download again.
//   --timeout    Trivy's own deadline, set just inside the execFile deadline so
//                a slow scan ends as a Trivy error message rather than as a
//                killed process with no explanation.
//
// The scanner image is PINNED. `aquasec/trivy:latest` would change the report
// schema, the default scanner set and the findings under a running platform
// with no diff anywhere.

import { execFile } from 'child_process';
import { promisify } from 'util';
import { join, resolve } from 'path';
import { assertFinding } from './scanShapes.js';
import { compareVersions } from './appScan.js';

const execFileAsync = promisify(execFile);

export const SCANNER_IMAGE = 'aquasec/trivy:0.74.0';

// Pulling the scanner happens at most once per box; a first scan on a fresh
// install should not fail because a 150 MB pull ran long on a slow link.
const SCANNER_PULL_TIMEOUT_MS = 10 * 60 * 1000;

// The scan itself. Trivy's own default is 5 minutes and a scan of a multi-GB
// image can legitimately approach it. This is the one number that lands on a
// deploy's response latency (see the call site in deployer.js — the deploy is
// already complete and live by then, so the cost is latency, never outcome).
const SCAN_TIMEOUT_MS = 5 * 60 * 1000;
const SCAN_TIMEOUT_S = Math.floor(SCAN_TIMEOUT_MS / 1000) - 10;

// A full report for a distro image is large — 1.8 MB measured for
// python:3.9-slim-bullseye, 364 vulnerabilities across 107 packages. The
// default 1 MB maxBuffer would have truncated it into a JSON parse error, i.e.
// into a fleet-wide 'error' on exactly the images with the most to report.
const SCAN_MAX_BUFFER = 64 * 1024 * 1024;

const DOCKER_SOCKET = '/var/run/docker.sock';

/** Where the vulnerability database is cached between scans. */
function cacheDir() {
  return join(resolve(process.env.DATA_DIR || './data'), 'trivy-cache');
}

/**
 * The image reference to scan: the DIGEST recorded against the live
 * deployment, never the tag on the app row.
 *
 * A tag is a moving pointer on purpose — that is the entire reason
 * deployer.js resolves it once and records `deployments.image_ref` as
 * `name@sha256:…`. Scanning `odoo:19` would describe whatever the publisher
 * has behind that tag TODAY, which is not necessarily the bytes in the
 * container that is running. A scan that describes the wrong bytes is worse
 * than no scan, because it reads exactly like a correct one.
 *
 * This mirrors appScan.js reading the live `current` symlink rather than a
 * release path handed in by the caller, for the same reason.
 *
 * @returns {{ ref: string|null, reason: string|null }}
 */
export function scanTargetFor(db, app, env) {
  const row = db.prepare(`
    SELECT image_ref FROM deployments
    WHERE app_id = ? AND env = ? AND status = 'live' AND image_ref IS NOT NULL
    ORDER BY id DESC
    LIMIT 1
  `).get(app.id, env);

  if (row?.image_ref) return { ref: row.image_ref, reason: null };

  const live = db.prepare(
    "SELECT id FROM deployments WHERE app_id = ? AND env = ? AND status = 'live' ORDER BY id DESC LIMIT 1"
  ).get(app.id, env);

  if (!live) {
    return { ref: null, reason: `no live deployment for ${app.slug}/${env}, so there is no image to scan` };
  }
  // Falling back to apps.image_ref here was considered and rejected. Every
  // image deploy writes the resolved digest (deployer.js), and rollback and
  // promote both carry it forward, so a live deployment without one means the
  // record of what is running is incomplete — and the honest report for that
  // is "we do not know what is running", not a scan of a tag that may have
  // moved since.
  return {
    ref: null,
    reason:
      `deployment #${live.id} (${app.slug}/${env}) has no resolved image digest recorded, so the only `
      + `reference available is the tag on the app row — and a tag can point at different bytes than the `
      + `running container. Re-deploy to record a digest.`,
  };
}

/**
 * Turn one Trivy schema-2 report into the finding shape every other scanning
 * surface uses. Pure — no Docker, no database — because this is where the
 * report's shape is actually pinned and it is the half worth asserting on.
 *
 * Trivy emits ONE ENTRY PER (vulnerability, package): python:3.9-slim-bullseye
 * produced 364 entries covering 59 distinct package versions, 43 of which
 * carried more than one advisory. assertFinding's `ids` is a list precisely so
 * those collapse into one finding per package rather than 364 rows of noise
 * naming the same 59 packages over and over.
 *
 * @returns {{ findings: Array<object>, packageCount: number, ecosystem: string|null,
 *             eosl: boolean, osLabel: string|null }}
 */
export function mapTrivyReport(report) {
  const results = Array.isArray(report?.Results) ? report.Results : [];

  const os = report?.Metadata?.OS || null;
  const eosl = os?.EOSL === true;
  const osLabel = os?.Family ? `${os.Family} ${os.Name || ''}`.trim() : null;

  let packageCount = 0;
  const ecosystems = new Set();
  // Keyed by ecosystem + package + version, because a report can carry the
  // same package name under two ecosystems (an OS `python3` and a python-pkg
  // `python3` are different things with different advisories).
  const groups = new Map();

  for (const result of results) {
    // `Type` is Trivy's own ecosystem name ('debian', 'alpine', 'npm',
    // 'python-pkg', 'gobinary'). Used verbatim rather than translated to OSV's
    // spelling: the overlapping names already agree ('npm'), and inventing a
    // mapping for the distro ones would have to guess a distro RELEASE that
    // OSV wants ('Debian:11') and that Trivy does not put in this field.
    const type = (typeof result?.Type === 'string' && result.Type)
      || (typeof result?.Class === 'string' && result.Class)
      || 'unknown';

    if (Array.isArray(result?.Packages)) packageCount += result.Packages.length;

    const vulns = Array.isArray(result?.Vulnerabilities) ? result.Vulnerabilities : [];
    if (vulns.length > 0) ecosystems.add(type);

    for (const v of vulns) {
      const name = typeof v?.PkgName === 'string' ? v.PkgName : '';
      const version = typeof v?.InstalledVersion === 'string' ? v.InstalledVersion : '';
      const id = typeof v?.VulnerabilityID === 'string' ? v.VulnerabilityID : '';
      // A vulnerability with no id renders as a finding nobody can look up,
      // and one with no package name cannot be acted on at all. Neither is
      // recoverable here, so they are counted and reported by the caller
      // rather than dropped into a row that would then read as complete.
      if (!name || !version || !id) {
        groups.set('__malformed__', (groups.get('__malformed__') || 0) + 1);
        continue;
      }

      const key = `${type}:${name}@${version}`;
      let g = groups.get(key);
      if (!g) {
        g = { name, version, ecosystem: type, ids: new Set(), fixed: new Set() };
        groups.set(key, g);
      }
      g.ids.add(id);

      // FixedVersion is absent for an advisory with no published fix
      // ('affected', 'will_not_fix', 'fix_deferred' — all three appear in a
      // real Debian report) and is occasionally a comma-separated list when
      // several branches were patched.
      if (typeof v?.FixedVersion === 'string' && v.FixedVersion) {
        for (const part of v.FixedVersion.split(',')) {
          const t = part.trim();
          if (t) g.fixed.add(t);
        }
      }
    }
  }

  const malformed = typeof groups.get('__malformed__') === 'number' ? groups.get('__malformed__') : 0;
  groups.delete('__malformed__');

  const findings = [];
  for (const g of groups.values()) {
    // Across the advisories on one package, the HIGHEST published fix: a
    // version that resolves only some of the CVEs named in this finding is not
    // a fix for the finding. Same rule appScan.js applies to OSV, using the
    // same comparator so the two surfaces cannot disagree about which of
    // '20230311+deb12u1~deb11u1' and '20250419~deb12u1~deb11u1' is newer.
    const fixes = [...g.fixed];
    const fixed = fixes.length === 0
      ? null
      : fixes.reduce((hi, c) => (compareVersions(c, hi) > 0 ? c : hi));
    findings.push(assertFinding({
      name: g.name,
      version: g.version,
      ecosystem: g.ecosystem,
      ids: [...g.ids],
      fixed,
    }, `trivy finding for ${g.name}`));
  }

  findings.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  return {
    findings,
    packageCount,
    ecosystem: ecosystems.size ? [...ecosystems].sort().join(',') : null,
    eosl,
    osLabel,
    malformed,
  };
}

// An image id as `docker image inspect --format '{{.Id}}'` renders it. Measured
// on a real daemon: `sha256:` plus 64 hex, for both the scanner image and an
// unrelated one.
const IMAGE_ID_RE = /^sha256:[a-f0-9]{64}$/;

/** Is the scanner image present locally? Resolves to its id, or null. */
async function scannerImageId() {
  let stdout;
  try {
    ({ stdout } = await execFileAsync(
      'docker', ['image', 'inspect', SCANNER_IMAGE, '--format', '{{.Id}}'],
      { timeout: 60000 },
    ));
  } catch {
    // Absent locally, or no Docker at all. ensureScanner tells those apart
    // through the pull's own error text rather than by guessing here.
    return null;
  }
  const id = (stdout || '').trim();
  // The OUTPUT is checked, not just the exit status, following the precedent
  // services/imageSource.js sets for resolveDigest: some Docker versions render
  // a value they do not have as the literal '<no value>' and exit 0, and a
  // presence check that believes an exit code would then hand `docker run` a
  // scanner that is not there — producing an 'error' row about a broken scan
  // where the truth is that the scanner was never installed.
  return IMAGE_ID_RE.test(id) ? id : null;
}

/**
 * Make sure the scanner image is on the box.
 *
 * Done as an explicit step rather than leaning on `docker run`'s implicit pull,
 * so that "this box has no Docker, or cannot obtain the scanner" is
 * distinguishable from "the scan ran and failed". The first is 'skipped' — the
 * control is not installed here — and the second is 'error'. Collapsing them
 * would make an unreachable registry look like a broken image, and would put
 * the platform's own missing dependency into a column that reads as a finding
 * about somebody else's app.
 *
 * A DEPLOY NEVER PULLS THE SCANNER. `allowPull` is false on the deploy-time
 * path and true on the scheduled and manual ones. Obtaining the scanner is a
 * ~150 MB registry fetch of PLATFORM tooling, and doing it inside somebody
 * else's deploy is the same class of surprise as blocking on the result: the
 * app team did not choose this control and should not pay a first-run download
 * for it, on a deploy that is already complete and live. On a box that has
 * never scanned an image, the first deploy therefore records 'skipped' with
 * that reason, the nightly scan pulls the scanner, and every deploy after it
 * scans inline.
 *
 * @returns {Promise<{ ok: boolean, reason?: string }>} never throws
 */
export async function ensureScanner({ allowPull = true } = {}) {
  if (await scannerImageId()) return { ok: true };

  if (!allowPull) {
    return {
      ok: false,
      reason:
        `container image scanner unavailable: ${SCANNER_IMAGE} is not present on this host, and a deploy `
        + 'does not pull it — the next scheduled scan will, and this app/env is scanned from then on',
    };
  }

  let pullError = null;
  try {
    await execFileAsync('docker', ['pull', SCANNER_IMAGE], {
      timeout: SCANNER_PULL_TIMEOUT_MS,
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch (err) {
    pullError = (err.stderr || err.message || '').trim().split('\n').slice(-3).join(' ');
  }

  // Re-checked after the pull rather than trusting its exit status, for the
  // same reason the first check reads the output: the thing that has to be true
  // before `docker run` is that the image IS HERE, and the only statement about
  // that is the daemon's.
  if (await scannerImageId()) return { ok: true };

  return {
    ok: false,
    reason:
      `container image scanner unavailable: ${SCANNER_IMAGE} is not present on this host`
      + `${pullError ? ` and could not be pulled — ${pullError}` : ' after a pull that reported success'}`,
  };
}

/**
 * Run the scanner against one image reference.
 *
 * Never throws. A non-zero exit, a timeout, or output that is not JSON are all
 * "we did not get an answer", and none of them are "no vulnerabilities".
 *
 * @returns {Promise<{ ok: boolean, report?: object, error?: string }>}
 */
export async function runScanner(ref) {
  const args = [
    'run', '--rm',
    '-v', `${DOCKER_SOCKET}:${DOCKER_SOCKET}`,
    '-v', `${cacheDir()}:/root/.cache/trivy`,
    SCANNER_IMAGE,
    'image',
    '--quiet',
    '--scanners', 'vuln',
    '--format', 'json',
    '--timeout', `${SCAN_TIMEOUT_S}s`,
    ref,
  ];

  let stdout;
  try {
    ({ stdout } = await execFileAsync('docker', args, {
      timeout: SCAN_TIMEOUT_MS,
      maxBuffer: SCAN_MAX_BUFFER,
    }));
  } catch (err) {
    // Trivy's FATAL line survives --quiet and is the only place the real reason
    // is stated (image not found, registry unauthorized, database download
    // failed). The tail is kept rather than the whole thing: a multi-error
    // report runs to a dozen lines and the column has to stay readable.
    const detail = (err.stderr || err.message || '').trim().split('\n').slice(-3).join(' ');
    return { ok: false, error: `image scan failed for ${ref}: ${detail || 'no output'}` };
  }

  let report;
  try {
    report = JSON.parse(stdout);
  } catch (e) {
    return { ok: false, error: `image scan for ${ref} returned unparseable output: ${e.message}` };
  }

  // Schema 2 is what mapTrivyReport was written against. A future Trivy that
  // bumps it is a scan that has to be re-read before it can be trusted, not a
  // scan that quietly reports whatever the old field names happen to still
  // match — which, for a renamed Vulnerabilities key, would be zero findings.
  if (report?.SchemaVersion !== 2) {
    return {
      ok: false,
      error: `image scan for ${ref} returned report schema ${JSON.stringify(report?.SchemaVersion)}, expected 2`,
    };
  }

  return { ok: true, report };
}

/**
 * Scan the image running for one app/env. Never throws, never writes: returns
 * the fields appScan.scanApp records, so both scanners land in one INSERT.
 *
 * `allowPull` is threaded through to ensureScanner — false on the deploy path,
 * so a deploy never fetches platform tooling.
 *
 * @returns {Promise<{ status: string, ecosystem: string|null, packageCount: number,
 *                     findings: Array<object>, error: string|null }>}
 */
export async function scanImage(db, app, env, { allowPull = true } = {}) {
  const skipped = (reason) => ({
    status: 'skipped', ecosystem: null, packageCount: 0, findings: [], error: reason,
  });

  const target = scanTargetFor(db, app, env);
  if (!target.ref) return skipped(target.reason);

  const scanner = await ensureScanner({ allowPull });
  if (!scanner.ok) return skipped(scanner.reason);

  const run = await runScanner(target.ref);
  if (!run.ok) {
    return { status: 'error', ecosystem: null, packageCount: 0, findings: [], error: run.error };
  }

  let mapped;
  try {
    mapped = mapTrivyReport(run.report);
  } catch (e) {
    // assertFinding rejecting something is a real answer about the report, not
    // a clean image: a mapping that cannot produce a valid finding has not
    // established that there are none.
    return {
      status: 'error', ecosystem: null, packageCount: 0, findings: [],
      error: `image scan for ${target.ref} produced an unusable finding: ${e.message}`,
    };
  }

  if (mapped.malformed > 0) {
    return {
      status: 'error', ecosystem: mapped.ecosystem, packageCount: mapped.packageCount, findings: [],
      error:
        `image scan for ${target.ref} returned ${mapped.malformed} vulnerabilit${mapped.malformed === 1 ? 'y' : 'ies'} `
        + 'with no package name, version or advisory id — recording them would produce findings nobody can look up, '
        + 'and dropping them would report a vulnerable image as scanned',
    };
  }

  if (mapped.findings.length > 0) {
    return {
      status: 'findings',
      ecosystem: mapped.ecosystem,
      packageCount: mapped.packageCount,
      findings: mapped.findings,
      error: null,
    };
  }

  // ZERO FINDINGS IS NOT AUTOMATICALLY 'ok'.
  //
  // Trivy reports EOSL when the image's OS release is past end of support.
  // Measured, because the intuition here is wrong in both directions: debian
  // 11.11 is EOSL and still returned 364 vulnerabilities (Debian LTS keeps
  // publishing), while alpine 3.14.10 is EOSL and returned ZERO across 14
  // packages — not because it is clean, but because Alpine stops publishing
  // secdb for an EOL branch. So EOSL alone is not a skip, and a clean result
  // from an EOSL image is not evidence of anything.
  if (mapped.eosl) {
    return {
      status: 'skipped',
      ecosystem: mapped.ecosystem,
      packageCount: mapped.packageCount,
      findings: [],
      error:
        `the image's OS (${mapped.osLabel || 'unknown'}) is past end of life, and the scan found nothing — `
        + 'the distribution no longer publishes security data for it, so this is an absence of advisories '
        + 'rather than an absence of vulnerabilities. Rebuild on a supported base image.',
    };
  }

  // Nothing found AND nothing to find: an image with no packages Trivy
  // recognises (a scratch image holding one static binary) has not been
  // meaningfully examined either.
  if (mapped.packageCount === 0) {
    return skipped(`the scanner found no packages in ${target.ref} — nothing in the image was recognised as scannable`);
  }

  return { status: 'ok', ecosystem: mapped.ecosystem, packageCount: mapped.packageCount, findings: [], error: null };
}

export default { SCANNER_IMAGE, scanTargetFor, mapTrivyReport, ensureScanner, runScanner, scanImage };
