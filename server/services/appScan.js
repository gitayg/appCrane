// Dependency CVE scanning for the apps AppCrane HOSTS — not for AppCrane itself.
//
// v2.49.1 made AppCrane's own dependency scan blocking, which covers the
// platform. It says nothing about the ~57 apps the platform runs, whose
// lockfiles AppCrane already has on disk at deploy time and has never looked at.
// A competitor's enterprise tier reports CVEs across every hosted app with
// per-app drill-down; AppCrane scanned only its own tree.
//
// REPORT, NEVER BLOCK. These apps belong to other teams. A scan that can fail a
// deploy would wedge people who did not choose this control and cannot fix a
// transitive advisory on someone else's schedule. Findings are recorded and
// mailed; the deploy proceeds either way.
//
// Scanned at deploy AND daily. Deploy-time catches what a change introduced;
// daily catches the case that actually bites — an advisory published for code
// that was already deployed and has not changed since.

import { existsSync, readdirSync } from 'fs';
import { join, resolve } from 'path';
import { MANIFESTS, parseManifest } from './ecosystems.js';
import { assertFinding, assertPackage } from './scanShapes.js';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';

// Measured against the live endpoint, not inferred: 1000 queries returns 200,
// 1001 returns `400 {"code":3,"message":"too many queries"}`. Chunking at 500
// keeps a comfortable margin under a limit the API does not document in its
// response headers, and still turns the largest lockfile on the box into a
// single request. The number that matters is that this is NOT one request per
// package — a 500-package app made 500 round trips in the shape this replaces.
const OSV_MAX_QUERIES_PER_BATCH = 500;

// OSV is a report-only dependency of a report-only feature. A scan that hangs
// must not keep a deploy's promise pending, so the timeout is per-batch and
// deliberately short of the health-check budgets elsewhere in a deploy.
const OSV_TIMEOUT_MS = 20000;

// Which manifests exist and how to read them lives in ecosystems.js — this file
// owns finding them, asking OSV about them and recording the answer. Each row
// there carries the OSV ecosystem name, which is why nothing here has to know
// that go.sum means 'Go'.

// Bounds on the manifest walk, all three deliberate:
//   depth 3   — a repo root, plus e.g. services/api/go.sum. Deep enough for the
//               monorepo layouts on the box, shallow enough that a release
//               directory full of checked-in fixtures cannot turn a scan into a
//               filesystem crawl.
//   50 files  — a scan that found fifty manifests has found a vendored tree,
//               not an app. The cap keeps one pathological repo from spending
//               the OSV batch budget for the whole fleet.
//   2000 dirs — the same guard for wide trees rather than deep ones.
// Hitting a bound truncates the list, which under-reports; that is why the
// bounds are set well above any real app rather than tuned for the common case.
const MANIFEST_MAX_DEPTH = 3;
const MANIFEST_MAX_FILES = 50;
const MANIFEST_MAX_DIRS = 2000;

// Directories that hold other projects' manifests rather than this app's.
// node_modules is the important one: an installed dependency ships its own
// lockfiles, and those describe ITS development tree, not what this app runs.
// Dot-directories are skipped wholesale by the walk.
const SKIP_DIRS = new Set([
  'node_modules', 'vendor', 'dist', 'build', 'coverage', 'target',
  'venv', '__pycache__', 'site-packages',
]);

/**
 * Every manifest in the release, not the first one.
 *
 * The first-match-wins version of this function was a silent under-report of
 * the same class as the alias bug: a repo that is a Node frontend plus a Go
 * service had its go.mod invisible, and an app with an unscanned half reads
 * exactly like an app that scanned clean.
 *
 * @returns {Array<{ path: string, ecosystem: string, entry: object }>}
 */
export function findLockfiles(releaseDir) {
  if (!releaseDir || !existsSync(releaseDir)) return [];

  const wanted = new Map(MANIFESTS.map((entry) => [entry.file, entry]));

  const found = [];
  let dirsVisited = 0;

  const walk = (dir, depth) => {
    if (found.length >= MANIFEST_MAX_FILES || dirsVisited >= MANIFEST_MAX_DIRS) return;
    dirsVisited++;

    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      // An unreadable subdirectory is not a scan failure. The release root
      // being unreadable is, and that surfaces when the parse finds nothing.
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    for (const d of entries) {
      if (!d.isFile()) continue;
      const entry = wanted.get(d.name);
      if (!entry) continue;
      found.push({ path: join(dir, d.name), ecosystem: entry.ecosystem, entry });
      if (found.length >= MANIFEST_MAX_FILES) return;
    }

    if (depth >= MANIFEST_MAX_DEPTH) return;
    for (const d of entries) {
      // isDirectory() is false for a symlink to a directory, so the walk cannot
      // follow one into a cycle or out of the release. The release root itself
      // is reached through the `current` symlink, which readdirSync resolves.
      if (!d.isDirectory()) continue;
      if (d.name.startsWith('.') || SKIP_DIRS.has(d.name)) continue;
      walk(join(dir, d.name), depth + 1);
      if (found.length >= MANIFEST_MAX_FILES || dirsVisited >= MANIFEST_MAX_DIRS) return;
    }
  };

  walk(releaseDir, 0);
  return found;
}

/**
 * Parse one manifest into the packages to query. The parsers live in
 * ecosystems.js; this is the seam the scanner calls them through, and it is
 * exported because the false-clean hazards in a lockfile (aliases, nested
 * paths, workspace members) are worth asserting on from the scanner's own side
 * of that seam rather than only inside the parser.
 * @returns {Array<{name: string, version: string, ecosystem: string}>}
 */
export function parseLockfile(lockPath, ecosystem, entry = null) {
  // entry omitted lets ecosystems.js resolve the row from the filename, which
  // is what the ecosystem argument would otherwise have to be trusted for.
  const packages = parseManifest(lockPath, entry || undefined);
  if (!Array.isArray(packages)) {
    throw new Error(`parseManifest returned ${typeof packages} for ${lockPath}, expected an array`);
  }
  // Asserted on the way out as well as on the way in: a package that reaches
  // queryOsv without an ecosystem is asked about under the wrong one, and OSV
  // answers "no vulnerabilities" for a name it does not have in that namespace.
  packages.forEach((p, i) => assertPackage(p, `${ecosystem} package[${i}]`));
  return packages;
}


// Ordering for version strings across ecosystems, which is why this is not
// `semver`: OSV hands back Go's "v1.2.3", PyPI's "1.0.0rc1" and npm's semver
// through the same field. Numeric segments compare numerically, and a version
// that runs out of segments where the other continues with a NUMBER is the
// smaller one (1.2 < 1.2.1) while one that continues with a WORD is the larger
// (1.2.0 > 1.2.0-rc1). It is not a full semver implementation and does not need
// to be: it only ever orders fixed versions of one package against each other,
// and a wrong answer picks a different real fixed version rather than inventing
// one.
function compareVersions(a, b) {
  const segs = (v) => String(v).replace(/^v/i, '').split(/[.+_-]/).filter(Boolean);
  const A = segs(a);
  const B = segs(b);
  const num = (s) => /^\d+$/.test(s);
  for (let i = 0; i < Math.max(A.length, B.length); i++) {
    const x = A[i];
    const y = B[i];
    if (x === undefined) return num(y) ? -1 : 1;
    if (y === undefined) return num(x) ? 1 : -1;
    if (num(x) && num(y)) {
      if (Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1;
      continue;
    }
    if (num(x) !== num(y)) return num(x) ? 1 : -1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// OSV's `affected` list covers every package an advisory touches, across
// ecosystems — a Debian entry and a PyPI entry for the same CVE carry different
// fixed versions. Taking a fix from the wrong one names an upgrade that does
// not exist in the registry the app installs from. Distro ecosystems are
// qualified ("Debian:11", "Alpine:v3.15"), so the comparison is on the part
// before the colon.
function affectedMatchesPackage(affected, pkg) {
  const p = affected?.package;
  if (!p) return false;
  if (typeof p.name === 'string' && p.name !== pkg.name) return false;
  if (typeof p.ecosystem !== 'string') return true;
  return p.ecosystem.split(':')[0] === pkg.ecosystem;
}

/**
 * The version to upgrade to, or null when OSV published no fixed event for
 * this package.
 *
 * Null means "OSV did not say", never "we did not look" — discarding this field
 * is what left the digest able to name a problem but never the remedy, which
 * costs every reader a separate investigation.
 *
 * The choice, when there is one: within a single advisory take the LOWEST fixed
 * version above the installed one, because an advisory patched on several
 * branches lists them all (4.17.16 and 5.0.1) and the smaller upgrade is the
 * one an owner can actually take. Across advisories take the HIGHEST of those,
 * because the finding names them together and a version that fixes only some of
 * them is not a fix. GIT ranges are ignored outright — a commit hash is not
 * something anyone can put in a manifest.
 */
function fixedVersionFor(vulns, pkg) {
  let best = null;
  for (const vuln of vulns) {
    const candidates = [];
    for (const affected of vuln?.affected ?? []) {
      if (!affectedMatchesPackage(affected, pkg)) continue;
      for (const range of affected.ranges ?? []) {
        if (range?.type === 'GIT') continue;
        for (const event of range?.events ?? []) {
          if (typeof event?.fixed === 'string' && event.fixed) candidates.push(event.fixed);
        }
      }
    }
    if (candidates.length === 0) continue;

    // Falling back to the highest published fix when none compares as greater
    // than the installed version keeps a real answer in the mail: OSV said this
    // version is affected, so a comparison that disagrees is the comparator
    // being wrong about an unusual version string, not OSV publishing nothing.
    const above = candidates.filter((c) => compareVersions(c, pkg.version) > 0);
    const forThisVuln = above.length > 0
      ? above.reduce((lo, c) => (compareVersions(c, lo) < 0 ? c : lo))
      : candidates.reduce((hi, c) => (compareVersions(c, hi) > 0 ? c : hi));

    if (best === null || compareVersions(forThisVuln, best) > 0) best = forThisVuln;
  }
  return best;
}

/**
 * Ask OSV about these packages. Network call; must never throw for a network
 * problem — an unreachable OSV is 'error', not 'no vulnerabilities'.
 * @returns {Promise<{ ok: boolean, findings: Array<object>, error?: string }>}
 */
export async function queryOsv(packages) {
  if (!packages || packages.length === 0) return { ok: true, findings: [] };
  packages.forEach((p, i) => assertPackage(p, `queryOsv packages[${i}]`));

  const findings = [];
  for (let i = 0; i < packages.length; i += OSV_MAX_QUERIES_PER_BATCH) {
    const chunk = packages.slice(i, i + OSV_MAX_QUERIES_PER_BATCH);
    // The ecosystem travels on the package. querybatch takes a different
    // ecosystem per query in the same request, so a repo that is npm plus Go
    // costs the same number of round trips as one that is npm alone — there is
    // no reason left for this to be hardcoded, and hardcoding it meant every
    // non-npm package was asked about in npm's namespace and came back clean.
    const queries = chunk.map((p) => ({
      package: { name: p.name, ecosystem: p.ecosystem },
      version: p.version,
    }));

    let res, body;
    try {
      res = await fetch(OSV_BATCH_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries }),
        signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
      });
      if (!res.ok) {
        return { ok: false, findings: [], error: `OSV returned HTTP ${res.status}` };
      }
      body = await res.json();
    } catch (e) {
      // Every way of not getting an answer lands here — DNS, refused, TLS,
      // timeout, a 200 with a body that is not JSON. All of them are
      // "unknown", and the caller records 'error'. None of them are "clean".
      return { ok: false, findings: [], error: `OSV query failed: ${e.message}` };
    }

    // Results are POSITIONAL: results[n] answers queries[n], and a package with
    // nothing against it comes back as `{}` rather than being omitted. Verified
    // against the live endpoint. A length mismatch would silently shift every
    // finding onto the wrong package, so it is checked rather than assumed.
    const results = body?.results;
    if (!Array.isArray(results) || results.length !== chunk.length) {
      return {
        ok: false,
        findings: [],
        error: `OSV returned ${Array.isArray(results) ? results.length : 'no'} results for ${chunk.length} queries`,
      };
    }

    for (let n = 0; n < chunk.length; n++) {
      const vulns = results[n]?.vulns;
      if (!vulns || vulns.length === 0) continue;
      const ids = vulns.map((v) => v.id).filter(Boolean);
      if (ids.length === 0) {
        // OSV said this package is vulnerable but named nothing. Recording it
        // with an empty id list would render as a finding nobody can look up;
        // dropping it would record a vulnerable package as clean. Neither is
        // an answer, so the scan reports that it did not get one.
        return {
          ok: false,
          findings: [],
          error: `OSV returned ${vulns.length} vulnerabilities with no id for ${chunk[n].name}@${chunk[n].version}`,
        };
      }
      findings.push(assertFinding({
        name: chunk[n].name,
        version: chunk[n].version,
        ecosystem: chunk[n].ecosystem,
        ids,
        fixed: fixedVersionFor(vulns, chunk[n]),
      }, `queryOsv finding for ${chunk[n].name}`));
    }
  }

  return { ok: true, findings };
}

/**
 * Scan one app/env and record the result. Never throws: a failed scan is a
 * recorded 'error' row, because a scanner that can break a deploy is a blocking
 * control wearing a reporting label.
 * @returns {Promise<object>} the recorded scan row
 */
export async function scanApp(db, app, env, source = 'deploy') {
  // Scans read the LIVE release, via the same `current` symlink the running
  // container was built from, rather than a release path passed in by a
  // caller. A deploy-time scan that read the directory the deploy just built
  // would report on a release that a late failure could still have prevented
  // from going live.
  const dataDir = resolve(process.env.DATA_DIR || './data');
  const releaseDir = join(dataDir, 'apps', app.slug, env, 'current');

  let ecosystem = null;
  let packageCount = 0;
  let status, findingsJson = null, error = null;

  try {
    const manifests = findLockfiles(releaseDir);
    if (manifests.length === 0) {
      // Nothing AppCrane can read is not a failure — a static site has no
      // manifest and never will. It is recorded so the fleet view can
      // distinguish "clean" from "never looked at", which an absent row could
      // not.
      status = 'skipped';
      error = 'no recognised manifest in the live release';
    } else {
      // Every ecosystem present, comma-joined, so a mixed repo is not recorded
      // as whichever manifest happened to sort first. The column takes it
      // as-is: 078 left ecosystem free of a CHECK precisely because this list
      // was always going to grow.
      ecosystem = [...new Set(manifests.map((m) => m.ecosystem))].sort().join(',');

      // One package can appear in two manifests of the same ecosystem (a
      // monorepo's frontend and its admin app both pin lodash). The key
      // includes the ecosystem because npm's `crypto` and PyPI's `crypto` are
      // different packages with different advisories.
      const packages = [];
      const seen = new Set();
      for (const manifest of manifests) {
        // A manifest that cannot be parsed fails the WHOLE scan rather than
        // contributing nothing to a scan that otherwise reports 'ok'. Partial
        // results recorded as a completed scan are the false clean again: the
        // app looks scanned, and the file nothing could read is invisible.
        for (const pkg of parseLockfile(manifest.path, manifest.ecosystem, manifest.entry)) {
          const key = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
          if (seen.has(key)) continue;
          seen.add(key);
          packages.push(pkg);
        }
      }
      packageCount = packages.length;

      const osv = await queryOsv(packages);
      if (!osv.ok) {
        status = 'error';
        error = osv.error;
      } else if (osv.findings.length > 0) {
        status = 'findings';
        findingsJson = JSON.stringify(osv.findings);
      } else {
        status = 'ok';
      }
    }
  } catch (e) {
    status = 'error';
    error = e.message;
  }

  const info = db.prepare(`
    INSERT INTO app_vuln_scans (app_id, env, source, ecosystem, status, package_count, findings_json, error)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(app.id, env, source, ecosystem, status, packageCount, findingsJson, error);

  return db.prepare('SELECT * FROM app_vuln_scans WHERE id = ?').get(info.lastInsertRowid);
}

/** Most recent scan for an app/env, or null. */
export function latestScan(db, appId, env) {
  return db.prepare(`
    SELECT * FROM app_vuln_scans
    WHERE app_id = ? AND env = ?
    ORDER BY scanned_at DESC, id DESC
    LIMIT 1
  `).get(appId, env) || null;
}

/** Every app's current state, for the fleet view and the digest. */
export function fleetScanSummary(db) {
  // LEFT JOIN so an app that has never been scanned appears with a null scan
  // rather than vanishing. An app missing from this list reads as "fine" to
  // every caller, and "never scanned" is the one state most worth seeing.
  //
  // Ties on scanned_at are broken by id: a deploy-time and a scheduled scan
  // landing in the same second would otherwise order arbitrarily, and
  // "arbitrary" here means the dashboard flickers between two answers.
  const rows = db.prepare(`
    SELECT a.id AS app_id, a.slug, a.name, s.env, s.status, s.source,
           s.ecosystem, s.package_count, s.findings_json, s.error, s.scanned_at
    FROM apps a
    LEFT JOIN (
      SELECT * FROM (
        SELECT *, ROW_NUMBER() OVER (
          PARTITION BY app_id, env ORDER BY scanned_at DESC, id DESC
        ) AS rn
        FROM app_vuln_scans
      ) WHERE rn = 1
    ) s ON s.app_id = a.id
    ORDER BY a.slug, s.env
  `);
  return rows.all().map(r => ({
    ...r,
    findings: r.findings_json ? JSON.parse(r.findings_json) : [],
  }));
}
