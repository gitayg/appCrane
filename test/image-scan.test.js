import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Container image CVE scanning for source_type='image' apps.
//
// 67 of the catalogue's entries are third-party images. Before this, every one
// of them recorded 'skipped — no recognised manifest in the live release',
// because the lockfile scanner looks in a release directory an image app does
// not have. The apps the org wrote were scanned; the apps strangers wrote were
// not.
//
// What is worth asserting here is almost entirely about NOT LYING and NOT
// BLOCKING, which is the same contract test/app-scan.test.js pins for the
// lockfile scanner:
//
//   * the scanner runs against the DIGEST recorded for the live deployment,
//     never the tag on the app row. A tag is a moving pointer; a scan of
//     different bytes than the ones running reads exactly like a correct one.
//   * no Docker, no scanner image, a scanner that exits non-zero, output that
//     is not JSON, a report schema nobody has read — every one of them is a
//     'skipped' or 'error' row with a reason. None of them is 'ok'.
//   * a clean report from an END-OF-LIFE base image is not 'ok' either.
//     Measured against real Trivy 0.74.0: alpine 3.14.10 returns ZERO
//     vulnerabilities across 14 packages, not because it is clean but because
//     Alpine stops publishing secdb for an EOL branch.
//   * nothing here can throw into a deploy.
//   * a source app still goes down the lockfile path and never touches Docker.
//
// Docker is a recording shim on PATH — the pattern in
// test/docker-resource-flags.test.js, test/managed-db-status.test.js and
// test/image-deploy.test.js — so no real Trivy runs in CI. The report fixtures
// below are REAL output: field names, nesting and values were taken from
// `docker run aquasec/trivy:0.74.0 image --format json` against
// python@sha256:b9e0… and alpine@sha256:0f2d…, not invented from the docs.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-imgscan-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
const DATA_DIR = process.env.DATA_DIR;

// ---------------------------------------------------------------------------
// A `docker` that records its argv and answers from environment switches
// ---------------------------------------------------------------------------

const SHIM_DIR = join(DATA_DIR, 'bin');
const ARGV_DIR = join(DATA_DIR, 'docker-calls');
const REPORT_FILE = join(DATA_DIR, 'trivy-report.json');
mkdirSync(SHIM_DIR, { recursive: true });
mkdirSync(ARGV_DIR, { recursive: true });

// CommonJS on purpose: the file is named `docker` with no extension, so Node
// parses it as CJS and an `import` would be a syntax error at spawn time,
// surfacing as an unexplained docker failure rather than a test error.
// One file per call rather than a shared append-log, for the reason
// test/managed-db-status.test.js documents: concurrent shells interleave
// inside a single record.
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n'
  + 'const { writeFileSync, readFileSync, existsSync } = require("fs");\n'
  + 'const { join } = require("path");\n'
  + 'const argv = process.argv.slice(2);\n'
  + 'const f = join(process.env.CRANE_TEST_DOCKER_DIR, "call." + process.pid + "." + Date.now() + "." + Math.random().toString(36).slice(2));\n'
  + 'writeFileSync(f, JSON.stringify(argv));\n'
  + 'const fail = (msg) => { process.stderr.write(msg + "\\n"); process.exit(1); };\n'
  + 'if (process.env.CRANE_TEST_NO_DOCKER) fail("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?");\n'
  + 'const pulled = join(process.env.CRANE_TEST_DOCKER_DIR, "..", "scanner-pulled");\n'
  + 'if (argv[0] === "image" && argv[1] === "inspect") {\n'
  + '  if (process.env.CRANE_TEST_SCANNER_ABSENT && !existsSync(pulled)) fail("Error response from daemon: No such image: " + argv[2]);\n'
  // Exit 0 with a value the daemon does not actually have: some Docker
  // versions render a missing template value this way instead of failing.
  + '  if (process.env.CRANE_TEST_INSPECT_JUNK) { process.stdout.write(process.env.CRANE_TEST_INSPECT_JUNK + "\\n"); process.exit(0); }\n'
  // A real daemon answers --format {{.Id}} with a bare sha256 image id.
  + '  process.stdout.write("sha256:" + "0".repeat(64) + "\\n"); process.exit(0);\n'
  + '}\n'
  + 'if (argv[0] === "pull") {\n'
  + '  if (process.env.CRANE_TEST_PULL_FAIL) fail(process.env.CRANE_TEST_PULL_FAIL);\n'
  + '  writeFileSync(pulled, "1");\n'
  + '  process.stdout.write("Status: Downloaded\\n"); process.exit(0);\n'
  + '}\n'
  + 'if (argv[0] === "run") {\n'
  + '  if (process.env.CRANE_TEST_SCAN_FATAL) fail(process.env.CRANE_TEST_SCAN_FATAL);\n'
  + '  if (process.env.CRANE_TEST_SCAN_GARBAGE) { process.stdout.write("not json at all"); process.exit(0); }\n'
  + '  const rf = process.env.CRANE_TEST_REPORT_FILE;\n'
  + '  process.stdout.write(rf && existsSync(rf) ? readFileSync(rf, "utf8") : "{}");\n'
  + '  process.exit(0);\n'
  + '}\n'
  + 'process.stdout.write("\\n");\n',
  { mode: 0o755 },
);
process.env.CRANE_TEST_DOCKER_DIR = ARGV_DIR;
process.env.CRANE_TEST_REPORT_FILE = REPORT_FILE;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

function dockerCalls() {
  return readdirSync(ARGV_DIR).sort().map(f => JSON.parse(readFileSync(join(ARGV_DIR, f), 'utf8')));
}
const PULLED_MARKER = join(DATA_DIR, 'scanner-pulled');
function reset() {
  for (const f of readdirSync(ARGV_DIR)) rmSync(join(ARGV_DIR, f));
  rmSync(PULLED_MARKER, { force: true });
  delete process.env.CRANE_TEST_NO_DOCKER;
  delete process.env.CRANE_TEST_SCANNER_ABSENT;
  delete process.env.CRANE_TEST_PULL_FAIL;
  delete process.env.CRANE_TEST_SCAN_FATAL;
  delete process.env.CRANE_TEST_SCAN_GARBAGE;
  delete process.env.CRANE_TEST_INSPECT_JUNK;
}
function setReport(report) {
  writeFileSync(REPORT_FILE, JSON.stringify(report));
}
/** The single `docker run` argv, or a failure naming how many there were. */
function runArgs() {
  const runs = dockerCalls().filter(c => c[0] === 'run');
  assert.equal(runs.length, 1, `expected exactly one \`docker run\`, saw ${runs.length}`);
  return runs[0];
}

// ---------------------------------------------------------------------------
// Real Trivy 0.74.0 output, trimmed
// ---------------------------------------------------------------------------

const PY_DIGEST = 'python@sha256:b9e06687fbfc57f6fe563e94e4c8751e39513dde89afc120dc6f56afe5ffc761';

/** Schema-2 report shaped exactly like the measured one. */
function trivyReport({ os, results }) {
  return {
    SchemaVersion: 2,
    Trivy: { Version: '0.74.0' },
    ArtifactName: PY_DIGEST,
    ArtifactType: 'container_image',
    Metadata: { OS: os },
    Results: results,
  };
}

// debian 11.11 out of the real python:3.9-slim-bullseye report. ca-certificates
// carries TWO advisories with TWO DIFFERENT fixed versions; coreutils carries
// five with none at all ('will_not_fix' / 'affected' are real Status values).
const DEBIAN_RESULT = {
  Target: `${PY_DIGEST} (debian 11.11)`,
  Class: 'os-pkgs',
  Type: 'debian',
  Packages: Array.from({ length: 104 }, (_, i) => ({ Name: `pkg${i}`, Version: '1.0' })),
  Vulnerabilities: [
    { VulnerabilityID: 'DLA-4485-1', PkgName: 'ca-certificates', InstalledVersion: '20210119', FixedVersion: '20230311+deb12u1~deb11u1', Severity: 'UNKNOWN', Status: 'fixed' },
    { VulnerabilityID: 'DLA-4726-1', PkgName: 'ca-certificates', InstalledVersion: '20210119', FixedVersion: '20250419~deb12u1~deb11u1', Severity: 'UNKNOWN', Status: 'fixed' },
    { VulnerabilityID: 'CVE-2016-2781', PkgName: 'coreutils', InstalledVersion: '8.32-4', Severity: 'LOW', Status: 'will_not_fix' },
    { VulnerabilityID: 'CVE-2017-18018', PkgName: 'coreutils', InstalledVersion: '8.32-4', Severity: 'LOW', Status: 'affected' },
    { VulnerabilityID: 'CVE-2025-5278', PkgName: 'coreutils', InstalledVersion: '8.32-4', Severity: 'LOW', Status: 'affected' },
  ],
};

const PYTHON_RESULT = {
  Target: 'Python',
  Class: 'lang-pkgs',
  Type: 'python-pkg',
  Packages: [{ Name: 'pip', Version: '23.0.1' }, { Name: 'setuptools', Version: '58.1.0' }, { Name: 'wheel', Version: '0.45.1' }],
  Vulnerabilities: [
    { VulnerabilityID: 'CVE-2023-5752', PkgName: 'pip', InstalledVersion: '23.0.1', FixedVersion: '23.3', Severity: 'MEDIUM', Status: 'fixed' },
    { VulnerabilityID: 'CVE-2025-8869', PkgName: 'pip', InstalledVersion: '23.0.1', FixedVersion: '25.3', Severity: 'MEDIUM', Status: 'fixed' },
  ],
};

const VULNERABLE_REPORT = trivyReport({
  os: { Family: 'debian', Name: '11.11' },
  results: [DEBIAN_RESULT, PYTHON_RESULT],
});

// The measured alpine:3.14 report: EOSL, 14 packages, and NO Vulnerabilities
// key at all — the false clean this feature must not report as 'ok'.
const EOSL_CLEAN_REPORT = trivyReport({
  os: { Family: 'alpine', Name: '3.14.10', EOSL: true },
  results: [{
    Target: 'alpine@sha256:0f2d (alpine 3.14.10)',
    Class: 'os-pkgs',
    Type: 'alpine',
    Packages: Array.from({ length: 14 }, (_, i) => ({ Name: `apk${i}`, Version: '1.0' })),
  }],
});

const SUPPORTED_CLEAN_REPORT = trivyReport({
  os: { Family: 'debian', Name: '12.8' },
  results: [{
    Target: 'x (debian 12.8)',
    Class: 'os-pkgs',
    Type: 'debian',
    Packages: Array.from({ length: 92 }, (_, i) => ({ Name: `pkg${i}`, Version: '1.0' })),
  }],
});

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { assertFindings } = await import('../server/services/scanShapes.js');
const { scanApp, latestScan, compareVersions } = await import('../server/services/appScan.js');
const {
  SCANNER_IMAGE, scanTargetFor, mapTrivyReport, ensureScanner, runScanner, scanImage,
} = await import('../server/services/imageScan.js');

let slot = 900;
function makeImageApp(slug, { imageRef = 'odoo:19' } = {}) {
  const id = db.prepare(
    "INSERT INTO apps (name,slug,slot,source_type,image_ref) VALUES (?,?,?,'image',?)"
  ).run(slug, slug, slot++, imageRef).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
function makeSourceApp(slug) {
  const id = db.prepare(
    "INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'managed')"
  ).run(slug, slug, slot++).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
function liveDeployment(app, env, imageRef) {
  return db.prepare(
    "INSERT INTO deployments (app_id,env,version,status,image_ref) VALUES (?,?,'1','live',?)"
  ).run(app.id, env, imageRef).lastInsertRowid;
}

// ---------------------------------------------------------------------------
// mapTrivyReport — the report shape, pinned against real output
// ---------------------------------------------------------------------------

test('one finding per package, not one per advisory', () => {
  const m = mapTrivyReport(VULNERABLE_REPORT);
  // 7 vulnerability entries covering 3 distinct packages. Real Trivy emits one
  // entry per (vulnerability, package): the measured python report had 364
  // entries for 59 packages, so collapsing is the difference between a
  // readable finding list and 364 rows naming the same 59 things.
  assert.equal(m.findings.length, 3, JSON.stringify(m.findings, null, 2));
  const byName = Object.fromEntries(m.findings.map(f => [f.name, f]));
  assert.deepEqual(byName['coreutils'].ids.sort(), ['CVE-2016-2781', 'CVE-2017-18018', 'CVE-2025-5278']);
  assert.deepEqual(byName['ca-certificates'].ids.sort(), ['DLA-4485-1', 'DLA-4726-1']);
  assert.deepEqual(byName['pip'].ids.sort(), ['CVE-2023-5752', 'CVE-2025-8869']);
});

test('the fix offered is the HIGHEST across the advisories on that package', () => {
  const m = mapTrivyReport(VULNERABLE_REPORT);
  const byName = Object.fromEntries(m.findings.map(f => [f.name, f]));
  // Real Debian values. Naming 20230311 here would offer a version that does
  // not resolve DLA-4726-1 — a fix that is not a fix.
  assert.equal(byName['ca-certificates'].fixed, '20250419~deb12u1~deb11u1');
  assert.equal(byName['pip'].fixed, '25.3');
});

test("'~' orders Debian fixed versions — without it the OLDER fix wins", () => {
  // The direct assertion on the comparator change this feature needed. These
  // are the two real ca-certificates fixes; the split used to treat
  // '20250419~deb12u1~deb11u1' as one non-numeric segment and sort it below.
  assert.ok(compareVersions('20250419~deb12u1~deb11u1', '20230311+deb12u1~deb11u1') > 0);
  // And Debian's own meaning of '~' still falls out: a pre-release is lower.
  assert.ok(compareVersions('1.0~rc1', '1.0') < 0);
  // npm/PyPI ordering, which the lockfile scanner depends on, is untouched.
  assert.ok(compareVersions('4.17.21', '4.17.15') > 0);
  assert.ok(compareVersions('1.2.0', '1.2.0-rc1') > 0);
});

test('an advisory with no published fix records fixed: null, never a guess', () => {
  const m = mapTrivyReport(VULNERABLE_REPORT);
  const coreutils = m.findings.find(f => f.name === 'coreutils');
  // All five real coreutils entries are 'will_not_fix' / 'affected' and carry
  // no FixedVersion. null means "Trivy did not say", which is what the digest
  // renders; a fabricated version would send someone chasing a release that
  // does not exist.
  assert.equal(coreutils.fixed, null);
});

test('the ecosystem is per finding, so one image can report debian and python-pkg', () => {
  const m = mapTrivyReport(VULNERABLE_REPORT);
  assert.equal(m.ecosystem, 'debian,python-pkg');
  assert.equal(m.findings.find(f => f.name === 'pip').ecosystem, 'python-pkg');
  assert.equal(m.findings.find(f => f.name === 'coreutils').ecosystem, 'debian');
});

test('package_count counts every package in the image, not just the vulnerable ones', () => {
  assert.equal(mapTrivyReport(VULNERABLE_REPORT).packageCount, 107);
  assert.equal(mapTrivyReport(EOSL_CLEAN_REPORT).packageCount, 14);
});

test('every mapped finding satisfies assertFinding', () => {
  const m = mapTrivyReport(VULNERABLE_REPORT);
  assertFindings(m.findings, 'mapped trivy findings');
});

// ---------------------------------------------------------------------------
// scanTargetFor — the digest, never the tag
// ---------------------------------------------------------------------------

test('the scan target is the digest recorded against the live deployment', () => {
  const app = makeImageApp('tgt-digest');
  liveDeployment(app, 'production', `odoo@sha256:${'a'.repeat(64)}`);
  const t = scanTargetFor(db, app, 'production');
  assert.equal(t.ref, `odoo@sha256:${'a'.repeat(64)}`);
  assert.equal(t.reason, null);
});

test('the newest live deployment wins, so a re-deploy re-points the scan', () => {
  const app = makeImageApp('tgt-newest');
  liveDeployment(app, 'production', `odoo@sha256:${'b'.repeat(64)}`);
  liveDeployment(app, 'production', `odoo@sha256:${'c'.repeat(64)}`);
  assert.equal(scanTargetFor(db, app, 'production').ref, `odoo@sha256:${'c'.repeat(64)}`);
});

test('a live deployment with no digest is a skip, NOT a scan of the tag', async () => {
  reset();
  const app = makeImageApp('tgt-notag', { imageRef: 'odoo:19' });
  liveDeployment(app, 'production', null);

  const t = scanTargetFor(db, app, 'production');
  assert.equal(t.ref, null);
  assert.match(t.reason, /no resolved image digest/);

  // And the whole scan stops there: scanning 'odoo:19' would describe whatever
  // the publisher has behind that tag today, which is not necessarily the
  // bytes in the running container.
  const row = await scanApp(db, app, 'production', 'manual');
  assert.equal(row.status, 'skipped');
  assert.equal(dockerCalls().length, 0, 'no docker call may be made without a digest');
});

test('an app with no live deployment is skipped with that reason', () => {
  const app = makeImageApp('tgt-nodeploy');
  const t = scanTargetFor(db, app, 'production');
  assert.equal(t.ref, null);
  assert.match(t.reason, /no live deployment/);
});

// ---------------------------------------------------------------------------
// The invocation
// ---------------------------------------------------------------------------

test('the scanner is invoked against the digest, and the tag never appears', async () => {
  reset();
  setReport(VULNERABLE_REPORT);
  const digest = `odoo@sha256:${'d'.repeat(64)}`;
  const app = makeImageApp('inv-digest', { imageRef: 'odoo:19' });
  liveDeployment(app, 'production', digest);

  await scanApp(db, app, 'production', 'deploy');

  const args = runArgs();
  assert.equal(args[args.length - 1], digest, `scanned ${args[args.length - 1]}`);
  assert.ok(!args.includes('odoo:19'), `the moving tag reached docker: ${JSON.stringify(args)}`);
});

test('the scanner runs in a pinned container, not as a host binary', async () => {
  reset();
  setReport(VULNERABLE_REPORT);
  const app = makeImageApp('inv-shape');
  liveDeployment(app, 'production', `x@sha256:${'e'.repeat(64)}`);

  await scanApp(db, app, 'production', 'deploy');
  const args = runArgs();

  // Pinned by tag. ':latest' would change the report schema, the default
  // scanner set and the findings under a running platform with no diff.
  assert.ok(args.includes(SCANNER_IMAGE), JSON.stringify(args));
  assert.match(SCANNER_IMAGE, /^aquasec\/trivy:\d+\.\d+\.\d+$/);
  assert.ok(!SCANNER_IMAGE.endsWith(':latest'));

  // The socket mount is what lets Trivy read the image out of the LOCAL
  // daemon; without it Trivy falls back to 'remote' and needs the registry
  // credentials all over again.
  assert.ok(args.includes('/var/run/docker.sock:/var/run/docker.sock'), JSON.stringify(args));
  // The vulnerability database is cached between scans. Measured: 12.5s cold
  // against 2.1s warm.
  assert.ok(args.some(a => a.endsWith(':/root/.cache/trivy')), JSON.stringify(args));
  // --scanners vuln, because the default for `image` also runs the secret
  // scanner, which costs time and emits a Results entry nothing here maps.
  assert.ok(args.includes('--scanners') && args.includes('vuln'), JSON.stringify(args));
  assert.ok(args.includes('--format') && args.includes('json'), JSON.stringify(args));
  assert.ok(args.includes('--rm'), JSON.stringify(args));
});

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

test('an image app produces a real scan row, not a skip', async () => {
  reset();
  setReport(VULNERABLE_REPORT);
  const app = makeImageApp('happy');
  liveDeployment(app, 'production', PY_DIGEST);

  const row = await scanApp(db, app, 'production', 'deploy');

  assert.equal(row.status, 'findings');
  assert.notEqual(row.status, 'skipped');
  assert.equal(row.package_count, 107);
  assert.equal(row.ecosystem, 'debian,python-pkg');
  assert.equal(row.error, null);
  assert.equal(row.source, 'deploy');

  // Recorded findings satisfy the shape the digest and the fleet view read.
  const findings = JSON.parse(row.findings_json);
  assertFindings(findings, 'recorded image findings');
  assert.equal(findings.length, 3);

  // One row, and it is the one latestScan returns.
  assert.equal(latestScan(db, app.id, 'production').id, row.id);
  assert.equal(
    db.prepare('SELECT COUNT(*) c FROM app_vuln_scans WHERE app_id = ?').get(app.id).c, 1,
    'one row per scan, not one per finding',
  );
});

test('a clean supported image records ok', async () => {
  reset();
  setReport(SUPPORTED_CLEAN_REPORT);
  const app = makeImageApp('clean-ok');
  liveDeployment(app, 'production', `x@sha256:${'1'.repeat(64)}`);

  const row = await scanApp(db, app, 'production', 'scheduled');
  assert.equal(row.status, 'ok');
  assert.equal(row.findings_json, null);
  assert.equal(row.package_count, 92);
});

// ---------------------------------------------------------------------------
// Everything that must not read as clean
// ---------------------------------------------------------------------------

test('Docker unavailable is a skip with a reason, and no scan is attempted', async () => {
  reset();
  process.env.CRANE_TEST_NO_DOCKER = '1';
  setReport(VULNERABLE_REPORT);
  const app = makeImageApp('no-docker');
  liveDeployment(app, 'production', `x@sha256:${'2'.repeat(64)}`);

  // 'scheduled', so the pull IS attempted and its error is the one reported —
  // the deploy path deliberately never gets that far (see the next test).
  const row = await scanApp(db, app, 'production', 'scheduled');

  assert.equal(row.status, 'skipped');
  assert.notEqual(row.status, 'ok');
  assert.match(row.error, /scanner unavailable/);
  assert.match(row.error, /docker daemon/i, `the reason must name the cause: ${row.error}`);
  assert.equal(dockerCalls().filter(c => c[0] === 'run').length, 0, 'no scan may run without Docker');
});

test('a scanner image that cannot be pulled is a skip, not a clean scan', async () => {
  reset();
  process.env.CRANE_TEST_SCANNER_ABSENT = '1';
  process.env.CRANE_TEST_PULL_FAIL = 'Error response from daemon: manifest unknown';
  setReport(VULNERABLE_REPORT);
  const app = makeImageApp('no-scanner');
  liveDeployment(app, 'production', `x@sha256:${'3'.repeat(64)}`);

  const row = await scanApp(db, app, 'production', 'scheduled');
  assert.equal(row.status, 'skipped');
  assert.match(row.error, /manifest unknown/);
  assert.equal(dockerCalls().filter(c => c[0] === 'run').length, 0);
});

test('the scanner image is pulled once when absent, then the scan proceeds', async () => {
  reset();
  process.env.CRANE_TEST_SCANNER_ABSENT = '1';
  setReport(SUPPORTED_CLEAN_REPORT);
  const app = makeImageApp('pull-then-scan');
  liveDeployment(app, 'production', `x@sha256:${'4'.repeat(64)}`);

  const row = await scanApp(db, app, 'production', 'scheduled');
  assert.equal(row.status, 'ok');
  const pulls = dockerCalls().filter(c => c[0] === 'pull');
  assert.equal(pulls.length, 1);
  assert.deepEqual(pulls[0], ['pull', SCANNER_IMAGE]);
});

test('a DEPLOY never pulls the scanner image', async () => {
  reset();
  process.env.CRANE_TEST_SCANNER_ABSENT = '1';
  setReport(SUPPORTED_CLEAN_REPORT);
  const app = makeImageApp('deploy-no-pull');
  liveDeployment(app, 'production', `x@sha256:${'5'.repeat(63)}a`);

  const row = await scanApp(db, app, 'production', 'deploy');

  // Obtaining ~150 MB of PLATFORM tooling inside somebody else's deploy is the
  // same class of surprise as making the scan blocking: the app team did not
  // choose this control, and the deploy is already complete and live by the
  // time this runs. The nightly scan pulls it; every deploy after that scans.
  assert.equal(row.status, 'skipped');
  assert.match(row.error, /a deploy does not pull it/);
  assert.equal(dockerCalls().filter(c => c[0] === 'pull').length, 0);
  assert.equal(dockerCalls().filter(c => c[0] === 'run').length, 0);

  // …and the same app on the scheduled path does pull, and does scan.
  reset();
  process.env.CRANE_TEST_SCANNER_ABSENT = '1';
  setReport(SUPPORTED_CLEAN_REPORT);
  const after = await scanApp(db, app, 'production', 'scheduled');
  assert.equal(after.status, 'ok');
  assert.equal(dockerCalls().filter(c => c[0] === 'pull').length, 1);
});

test('an inspect that exits 0 without an image id does not count as present', async () => {
  reset();
  // The failure this guards: `docker image inspect --format {{.Id}}` can exit 0
  // and render '<no value>' rather than failing. Believing the exit status
  // would hand `docker run` a scanner that is not there and turn the
  // platform's own missing dependency into an 'error' row about someone
  // else's app. Measured shape of a real answer: 'sha256:' + 64 hex.
  process.env.CRANE_TEST_INSPECT_JUNK = '<no value>';
  const app = makeImageApp('inspect-junk');
  liveDeployment(app, 'production', `x@sha256:${'a1'.repeat(32)}`);

  const row = await scanApp(db, app, 'production', 'deploy');
  assert.equal(row.status, 'skipped');
  assert.match(row.error, /not present on this host/);
  assert.equal(dockerCalls().filter(c => c[0] === 'run').length, 0,
    'no scanner container may be started when the scanner image is not confirmed present');
});

test('a scanner that exits non-zero records error, never ok', async () => {
  reset();
  process.env.CRANE_TEST_SCAN_FATAL =
    'FATAL\tFatal error\trun error: image scan error: unable to find the specified image';
  const app = makeImageApp('scan-fatal');
  liveDeployment(app, 'production', `x@sha256:${'5'.repeat(64)}`);

  const row = await scanApp(db, app, 'production', 'deploy');
  assert.equal(row.status, 'error');
  assert.notEqual(row.status, 'ok');
  assert.match(row.error, /unable to find the specified image/);
});

test('output that is not JSON records error', async () => {
  reset();
  process.env.CRANE_TEST_SCAN_GARBAGE = '1';
  const app = makeImageApp('scan-garbage');
  liveDeployment(app, 'production', `x@sha256:${'6'.repeat(64)}`);

  const row = await scanApp(db, app, 'production', 'deploy');
  assert.equal(row.status, 'error');
  assert.match(row.error, /unparseable/);
});

test('a report schema nobody has read records error rather than zero findings', async () => {
  reset();
  // A future Trivy that renames Vulnerabilities would otherwise map to an
  // empty findings list, i.e. to a fleet that looks clean the moment the
  // scanner stopped being understood.
  setReport({ ...VULNERABLE_REPORT, SchemaVersion: 3 });
  const app = makeImageApp('scan-schema');
  liveDeployment(app, 'production', `x@sha256:${'7'.repeat(64)}`);

  const row = await scanApp(db, app, 'production', 'deploy');
  assert.equal(row.status, 'error');
  assert.match(row.error, /schema 3, expected 2/);
});

test('a clean report from an end-of-life base image is a skip, not ok', async () => {
  reset();
  setReport(EOSL_CLEAN_REPORT);
  const app = makeImageApp('eosl');
  liveDeployment(app, 'production', `alpine@sha256:${'8'.repeat(64)}`);

  const row = await scanApp(db, app, 'production', 'scheduled');

  // Measured against real Trivy 0.74.0: alpine 3.14.10 returns EOSL and ZERO
  // vulnerabilities across its 14 packages. Alpine stops publishing secdb for
  // an EOL branch, so that is an absence of ADVISORIES, not of vulnerabilities.
  assert.equal(row.status, 'skipped');
  assert.notEqual(row.status, 'ok');
  assert.match(row.error, /end of life/);
  assert.equal(row.package_count, 14, 'the packages it did see are still recorded');
});

test('EOSL WITH findings still reports the findings', async () => {
  reset();
  // The other half of the measurement, and the reason EOSL alone is not a
  // skip: debian 11.11 is EOSL and still returned 364 vulnerabilities, because
  // Debian LTS keeps publishing.
  setReport(trivyReport({
    os: { Family: 'debian', Name: '11.11', EOSL: true },
    results: [DEBIAN_RESULT],
  }));
  const app = makeImageApp('eosl-findings');
  liveDeployment(app, 'production', `x@sha256:${'9'.repeat(64)}`);

  const row = await scanApp(db, app, 'production', 'scheduled');
  assert.equal(row.status, 'findings');
  assert.equal(JSON.parse(row.findings_json).length, 2);
});

test('an image with no recognised packages is a skip, not a clean scan', async () => {
  reset();
  setReport(trivyReport({ os: null, results: [] }));
  const app = makeImageApp('scratch');
  liveDeployment(app, 'production', `x@sha256:${'0'.repeat(64)}`);

  const row = await scanApp(db, app, 'production', 'deploy');
  assert.equal(row.status, 'skipped');
  assert.match(row.error, /no packages/);
});

test('a vulnerability with no id records error rather than a finding nobody can look up', async () => {
  reset();
  setReport(trivyReport({
    os: { Family: 'debian', Name: '12.8' },
    results: [{
      Target: 'x', Class: 'os-pkgs', Type: 'debian',
      Packages: [{ Name: 'zlib1g', Version: '1:1.2.13' }],
      Vulnerabilities: [{ PkgName: 'zlib1g', InstalledVersion: '1:1.2.13', Severity: 'HIGH' }],
    }],
  }));
  const app = makeImageApp('no-id');
  liveDeployment(app, 'production', `x@sha256:${'f'.repeat(64)}`);

  const row = await scanApp(db, app, 'production', 'deploy');
  assert.equal(row.status, 'error');
  assert.equal(row.findings_json, null);
  assert.match(row.error, /no package name, version or advisory id/);
});

// ---------------------------------------------------------------------------
// The lockfile path is untouched
// ---------------------------------------------------------------------------

test('a source app still goes down the lockfile path and never invokes Docker', async () => {
  reset();
  const app = makeSourceApp('source-app');
  const dir = join(DATA_DIR, 'apps', app.slug, 'production', 'current');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: { '': { name: 'x' }, 'node_modules/lodash': { version: '4.17.15' } },
  }));

  const realFetch = globalThis.fetch;
  globalThis.fetch = async (_url, opts) => {
    const body = JSON.parse(opts.body);
    return {
      ok: true,
      status: 200,
      json: async () => ({ results: body.queries.map(() => ({ vulns: [{ id: 'GHSA-x' }] })) }),
    };
  };
  let row;
  try {
    row = await scanApp(db, app, 'production', 'deploy');
  } finally {
    globalThis.fetch = realFetch;
  }

  assert.equal(row.status, 'findings');
  assert.equal(row.ecosystem, 'npm');
  assert.equal(row.package_count, 1);
  assertFindings(JSON.parse(row.findings_json), 'lockfile findings');
  assert.equal(dockerCalls().length, 0, 'the lockfile scanner must not touch Docker');
});

test('a source app with no manifest keeps its original skip reason', async () => {
  reset();
  const app = makeSourceApp('source-empty');
  const row = await scanApp(db, app, 'production', 'deploy');
  assert.equal(row.status, 'skipped');
  assert.equal(row.error, 'no recognised manifest in the live release');
});

// ---------------------------------------------------------------------------
// Nothing here can fail a deploy
// ---------------------------------------------------------------------------

test('no image-scan path throws — every failure is a recorded row', async () => {
  const app = makeImageApp('never-throws');
  liveDeployment(app, 'production', `x@sha256:${'c'.repeat(64)}`);

  const breakages = [
    ['no docker', () => { process.env.CRANE_TEST_NO_DOCKER = '1'; }],
    ['no scanner image', () => { process.env.CRANE_TEST_SCANNER_ABSENT = '1'; process.env.CRANE_TEST_PULL_FAIL = 'no such host'; }],
    ['scanner fatal', () => { process.env.CRANE_TEST_SCAN_FATAL = 'FATAL boom'; }],
    ['garbage output', () => { process.env.CRANE_TEST_SCAN_GARBAGE = '1'; }],
    ['empty report', () => { setReport({}); }],
    ['null Results', () => { setReport({ SchemaVersion: 2, Results: null, Metadata: null }); }],
    ['Results not an array', () => { setReport({ SchemaVersion: 2, Results: 'nope' }); }],
  ];

  for (const [label, breakIt] of breakages) {
    reset();
    setReport(VULNERABLE_REPORT);
    breakIt();
    const row = await scanApp(db, app, 'production', 'deploy');
    assert.ok(row && row.id, `${label}: no row recorded`);
    assert.ok(['skipped', 'error'].includes(row.status), `${label}: recorded ${row.status}`);
    assert.ok(row.error, `${label}: recorded no reason`);
  }
});

test('scanImage and runScanner resolve rather than reject when Docker fails', async () => {
  reset();
  process.env.CRANE_TEST_NO_DOCKER = '1';
  const app = makeImageApp('contract');
  liveDeployment(app, 'production', `x@sha256:${'7'.repeat(64)}`);

  // Asserted directly on the two exported seams, because scanApp's own catch
  // would otherwise hide a broken contract and turn it into an 'error' row
  // that looks identical to a real scan failure.
  const scanner = await ensureScanner();
  assert.equal(scanner.ok, false);
  assert.ok(scanner.reason);

  const run = await runScanner('x@sha256:abc');
  assert.equal(run.ok, false);
  assert.ok(run.error);

  const result = await scanImage(db, app, 'production');
  assert.equal(result.status, 'skipped');
  assert.deepEqual(result.findings, []);
});
