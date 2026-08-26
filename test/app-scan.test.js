import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Dependency CVE scanning for HOSTED apps (v2.52.0).
//
// The contract under test is mostly about what the scanner must NOT do. It is
// report-only, so the interesting assertions are the ones that stop it turning
// into either a blocking gate or a liar:
//
//   * a scan that could not complete records 'error' — never 'ok'. A reporting
//     control that renders "could not check" as "nothing found" reports a clean
//     fleet loudest at the moment it has stopped working.
//   * a package name derived wrongly gets a real "no vulnerabilities" from OSV,
//     which is a false-clean that looks identical to a real one.
//   * the scanner cannot reach the deploy's outcome.
//
// Real sqlite (migrations included) and real lockfiles on disk. Only the
// network is stubbed — everything else here is the code that runs in
// production.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-scan-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
const DATA_DIR = process.env.DATA_DIR;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const {
  findLockfiles, parseLockfile, queryOsv, scanApp, latestScan, fleetScanSummary,
} = await import('../server/services/appScan.js');

let slot = 100;
function makeApp(slug) {
  const id = db.prepare(
    "INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'managed')"
  ).run(slug, slug, slot++).lastInsertRowid;
  return { id, slug };
}

// The live release the scanner reads: <DATA_DIR>/apps/<slug>/<env>/current
function releaseDirFor(slug, env = 'production') {
  const dir = join(DATA_DIR, 'apps', slug, env, 'current');
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLock(slug, packages, env = 'production', extra = {}) {
  const dir = releaseDirFor(slug, env);
  writeFileSync(join(dir, 'package-lock.json'),
    JSON.stringify({ lockfileVersion: 3, packages, ...extra }));
  return dir;
}

// --- network stub -----------------------------------------------------------
// Records every request so batching can be asserted on the wire rather than
// inferred from a return value.
const realFetch = globalThis.fetch;
let calls = [];
function stubOsv(handler) {
  calls = [];
  globalThis.fetch = async (url, opts) => {
    const body = JSON.parse(opts.body);
    calls.push({ url, queries: body.queries });
    return handler(body);
  };
}
function osvReplies(vulnsByNameVersion) {
  stubOsv((body) => ({
    ok: true,
    status: 200,
    json: async () => ({
      results: body.queries.map(q => {
        const ids = vulnsByNameVersion[`${q.package.name}@${q.version}`];
        return ids ? { vulns: ids.map(id => ({ id })) } : {};
      }),
    }),
  }));
}
const restoreFetch = () => { globalThis.fetch = realFetch; };

// ---------------------------------------------------------------------------
// parseLockfile — the false-clean hazards
// ---------------------------------------------------------------------------

test('the root "" entry is the app itself and is never queried', () => {
  const dir = writeLock('rootentry', {
    '': { name: 'my-app', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.21' },
  });
  const pkgs = parseLockfile(join(dir, 'package-lock.json'), 'npm');
  assert.deepEqual(pkgs, [{ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }],
    'the root "" entry leaked into the query set — it is the app, not a dependency, ' +
    'and it is not published to any registry');
});

test('a real npm workspace lockfile yields only registry packages', () => {
  // These three entries are exactly what `npm install --package-lock-only`
  // writes for a one-workspace repo; captured from real npm output rather than
  // hand-written, because the shape here is what the parser gets wrong.
  // "packages/ui" is the trap: it carries a real version and is NOT under
  // node_modules, so a parser that only strips a node_modules prefix reports a
  // dependency literally named "packages/ui".
  const dir = writeLock('workspace', {
    '': { name: 'root-app', version: '1.0.0', workspaces: ['packages/*'] },
    'node_modules/design-system': { resolved: 'packages/design-system', link: true },
    // Deliberately longer than the string 'node_modules/'. A parser that slices
    // a fixed 13 characters off every key instead of testing for the prefix
    // turns this into a dependency named 'esign-system' — which is short
    // enough to look plausible in a report and matches nothing in OSV.
    'packages/design-system': { version: '3.2.1' },
    'node_modules/lodash': { version: '4.17.21' },
  });
  const pkgs = parseLockfile(join(dir, 'package-lock.json'), 'npm');
  assert.deepEqual(pkgs, [{ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }],
    'a workspace member or its link entry was queried against OSV — neither is ' +
    'published to any registry, and such a name either matches nothing or matches ' +
    'something unrelated');
});

test('a nested dependency resolves to its own name, not a path', () => {
  const dir = writeLock('nested', {
    '': { name: 'app', version: '1.0.0' },
    'node_modules/body-parser': { version: '1.20.2' },
    'node_modules/body-parser/node_modules/content-type': { version: '1.0.4' },
  });
  const pkgs = parseLockfile(join(dir, 'package-lock.json'), 'npm');
  const names = pkgs.map(p => p.name).sort();
  assert.deepEqual(names, ['body-parser', 'content-type'],
    'a nested package was named after its path (e.g. "body-parser/content-type"). ' +
    'No registry has that name, so OSV answers "no vulnerabilities" and a real ' +
    'advisory is silently reported clean');
});

test('a scoped package keeps its scope', () => {
  const dir = writeLock('scoped', {
    '': { name: 'app', version: '1.0.0' },
    'node_modules/@babel/traverse': { version: '7.23.1' },
  });
  assert.deepEqual(parseLockfile(join(dir, 'package-lock.json'), 'npm'),
    [{ name: '@babel/traverse', version: '7.23.1', ecosystem: 'npm' }]);
});

test('a versionless entry is dropped rather than queried at "undefined"', () => {
  const dir = writeLock('links', {
    '': { name: 'app', version: '1.0.0' },
    'node_modules/my-workspace': { resolved: 'packages/thing', link: true },
    'node_modules/no-version': { resolved: 'https://example.invalid/x.tgz' },
    'node_modules/real': { version: '2.0.0' },
  });
  assert.deepEqual(parseLockfile(join(dir, 'package-lock.json'), 'npm'),
    [{ name: 'real', version: '2.0.0', ecosystem: 'npm' }],
    'an entry with no version reached the query set; OSV would be asked about ' +
    'name@undefined and answer "no vulnerabilities"');
});

test('the same name@version at two depths is queried once', () => {
  const dir = writeLock('dupes', {
    '': { name: 'app', version: '1.0.0' },
    'node_modules/a': { version: '1.0.0' },
    'node_modules/b/node_modules/a': { version: '1.0.0' },
    'node_modules/c/node_modules/a': { version: '2.0.0' },
  });
  const pkgs = parseLockfile(join(dir, 'package-lock.json'), 'npm');
  assert.equal(pkgs.length, 2, 'duplicate name@version pairs were sent to OSV as separate queries');
});

test('a lockfile with no "packages" is an error, not an empty clean scan', () => {
  const dir = releaseDirFor('v1lock');
  writeFileSync(join(dir, 'package-lock.json'),
    JSON.stringify({ lockfileVersion: 1, dependencies: { lodash: { version: '4.17.15' } } }));
  assert.throws(() => parseLockfile(join(dir, 'package-lock.json'), 'npm'), /lockfileVersion 1/,
    'a v1 lockfile parsed to zero packages instead of throwing — that records a clean ' +
    'bill of health for a file nothing ever read');
});

// ---------------------------------------------------------------------------
// findLockfiles
// ---------------------------------------------------------------------------
//
// CONTRACT CHANGE (this round): findLockfile returned ONE manifest and the
// first match won. A repo that is a Node frontend plus a Go service had
// everything after the first match silently unscanned, and an app with an
// unscanned half reads exactly like an app that scanned clean — the same
// false-clean class as the alias bug. It returns every manifest now, so these
// two tests assert on a list.

test('findLockfiles reports the ecosystem so a second one needs no caller change', () => {
  const dir = writeLock('eco', { '': { name: 'a', version: '1.0.0' } });
  const found = findLockfiles(dir);
  assert.equal(found.length, 1);
  assert.equal(found[0].path, join(dir, 'package-lock.json'));
  assert.equal(found[0].ecosystem, 'npm');
});

test('findLockfiles returns an empty list when there is nothing to scan', () => {
  assert.deepEqual(findLockfiles(releaseDirFor('nolock')), []);
});

// ---------------------------------------------------------------------------
// queryOsv — batching, and never throwing
// ---------------------------------------------------------------------------

test('900 packages go out in batches, not 900 requests', async () => {
  osvReplies({});
  const pkgs = Array.from({ length: 900 }, (_, i) => ({ name: `p${i}`, version: '1.0.0', ecosystem: 'npm' }));
  const r = await queryOsv(pkgs);
  restoreFetch();
  assert.equal(r.ok, true);
  assert.equal(calls.length, 2, `expected 2 batched requests for 900 packages, got ${calls.length}`);
  // The live endpoint returns 400 "too many queries" above 1000 (measured).
  for (const c of calls) {
    assert.ok(c.queries.length <= 1000,
      `a batch of ${c.queries.length} exceeds the measured OSV ceiling of 1000 and would 400`);
  }
  assert.equal(calls.reduce((n, c) => n + c.queries.length, 0), 900,
    'packages were lost or duplicated across batch boundaries');
});

test('a network failure is ok:false, never a clean result', async () => {
  stubOsv(() => { throw new Error('ECONNREFUSED'); });
  const r = await queryOsv([{ name: 'lodash', version: '4.17.15', ecosystem: 'npm' }]);
  restoreFetch();
  assert.equal(r.ok, false, 'an unreachable OSV reported success');
  assert.match(r.error, /ECONNREFUSED/);
  assert.deepEqual(r.findings, []);
});

test('a non-2xx from OSV is ok:false', async () => {
  stubOsv(() => ({ ok: false, status: 503, json: async () => ({}) }));
  const r = await queryOsv([{ name: 'lodash', version: '4.17.15', ecosystem: 'npm' }]);
  restoreFetch();
  assert.equal(r.ok, false, 'HTTP 503 from OSV was treated as a completed scan');
  assert.match(r.error, /503/);
});

test('a truncated result set is refused rather than misattributed', async () => {
  // Results are positional. A short array would shift every finding onto the
  // wrong package, which is worse than no answer.
  stubOsv(() => ({ ok: true, status: 200, json: async () => ({ results: [{}] }) }));
  const r = await queryOsv([
    { name: 'a', version: '1', ecosystem: 'npm' },
    { name: 'b', version: '2', ecosystem: 'npm' },
  ]);
  restoreFetch();
  assert.equal(r.ok, false, 'a result array shorter than the query array was accepted');
});

test('findings are attributed to the package at the same index', async () => {
  osvReplies({ 'b@2.0.0': ['GHSA-bbbb'] });
  const r = await queryOsv([
    { name: 'a', version: '1.0.0', ecosystem: 'npm' },
    { name: 'b', version: '2.0.0', ecosystem: 'npm' },
    { name: 'c', version: '3.0.0', ecosystem: 'npm' },
  ]);
  restoreFetch();
  assert.deepEqual(r.findings,
    [{ name: 'b', version: '2.0.0', ecosystem: 'npm', ids: ['GHSA-bbbb'], fixed: null }]);
});

// ---------------------------------------------------------------------------
// scanApp — the four recorded states
// ---------------------------------------------------------------------------

test('a clean app records ok', async () => {
  const app = makeApp('clean-app');
  writeLock('clean-app', {
    '': { name: 'clean-app', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.21' },
  });
  osvReplies({});
  const row = await scanApp(db, app, 'production', 'deploy');
  restoreFetch();
  assert.equal(row.status, 'ok');
  assert.equal(row.package_count, 1);
  assert.equal(row.ecosystem, 'npm');
  assert.equal(row.error, null);
  assert.equal(row.source, 'deploy');
});

test('a vulnerable app records findings, with the advisory ids', async () => {
  const app = makeApp('vuln-app');
  writeLock('vuln-app', {
    '': { name: 'vuln-app', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.15' },
    'node_modules/safe': { version: '1.0.0' },
  });
  osvReplies({ 'lodash@4.17.15': ['GHSA-p6mc-m468-83gw', 'GHSA-35jh-r3h4-6jhm'] });
  const row = await scanApp(db, app, 'production', 'scheduled');
  restoreFetch();
  assert.equal(row.status, 'findings');
  assert.equal(row.source, 'scheduled');
  const findings = JSON.parse(row.findings_json);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].name, 'lodash');
  assert.deepEqual(findings[0].ids, ['GHSA-p6mc-m468-83gw', 'GHSA-35jh-r3h4-6jhm']);
});

test('an app with no lockfile records skipped, not ok and not error', async () => {
  const app = makeApp('static-site');
  releaseDirFor('static-site');
  osvReplies({});
  const row = await scanApp(db, app, 'production');
  restoreFetch();
  assert.equal(row.status, 'skipped',
    'an app with nothing to scan must be distinguishable from one that scanned clean');
  assert.equal(calls.length, 0, 'OSV was queried for an app with no lockfile');
});

test('an unreachable OSV records error and NOT ok', async () => {
  const app = makeApp('unreachable');
  writeLock('unreachable', {
    '': { name: 'unreachable', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.15' },
  });
  stubOsv(() => { throw new Error('getaddrinfo ENOTFOUND api.osv.dev'); });
  const row = await scanApp(db, app, 'production');
  restoreFetch();
  assert.equal(row.status, 'error',
    'an unreachable OSV was recorded as a completed scan — this is the failure mode ' +
    'where the fleet looks cleanest exactly when the scanner is broken');
  assert.notEqual(row.status, 'ok');
  assert.match(row.error, /ENOTFOUND/);
  assert.equal(row.findings_json, null);
});

test('an unparseable lockfile records error', async () => {
  const app = makeApp('badlock');
  const dir = releaseDirFor('badlock');
  writeFileSync(join(dir, 'package-lock.json'), '{ this is not json');
  osvReplies({});
  const row = await scanApp(db, app, 'production');
  restoreFetch();
  assert.equal(row.status, 'error');
  assert.ok(row.error);
});

test('scanApp never throws, whatever the lockfile contains', async () => {
  const app = makeApp('hostile');
  const dir = releaseDirFor('hostile');
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ packages: null }));
  osvReplies({});
  const row = await scanApp(db, app, 'production');
  restoreFetch();
  assert.equal(row.status, 'error');
});

// ---------------------------------------------------------------------------
// The reads
// ---------------------------------------------------------------------------

test('latestScan returns the newest row for that app AND env', async () => {
  const app = makeApp('twoenv');
  writeLock('twoenv', { '': { name: 'a', version: '1.0.0' }, 'node_modules/x': { version: '1.0.0' } });
  writeLock('twoenv', { '': { name: 'a', version: '1.0.0' }, 'node_modules/x': { version: '1.0.0' } }, 'sandbox');

  osvReplies({});
  await scanApp(db, app, 'production');
  osvReplies({ 'x@1.0.0': ['GHSA-zzzz'] });
  await scanApp(db, app, 'production');
  osvReplies({});
  await scanApp(db, app, 'sandbox');
  restoreFetch();

  assert.equal(latestScan(db, app.id, 'production').status, 'findings',
    'latestScan returned an older row — same-second scans must break the tie on id');
  assert.equal(latestScan(db, app.id, 'sandbox').status, 'ok',
    'production and sandbox scans were mixed together');
  assert.equal(latestScan(db, app.id, 'nonexistent'), null);
});

test('fleetScanSummary keeps never-scanned apps visible', async () => {
  const scanned = makeApp('fleet-scanned');
  makeApp('fleet-never');
  writeLock('fleet-scanned', {
    '': { name: 'a', version: '1.0.0' }, 'node_modules/bad': { version: '1.0.0' },
  });
  osvReplies({ 'bad@1.0.0': ['GHSA-aaaa'] });
  await scanApp(db, scanned, 'production');
  restoreFetch();

  const summary = fleetScanSummary(db);
  const never = summary.find(r => r.slug === 'fleet-never');
  assert.ok(never, 'an app that has never been scanned vanished from the fleet view — ' +
    'absent reads as "fine" to every caller, and "never scanned" is the state most worth seeing');
  assert.equal(never.status, null);

  const hit = summary.find(r => r.slug === 'fleet-scanned' && r.env === 'production');
  assert.equal(hit.status, 'findings');
  assert.deepEqual(hit.findings,
    [{ name: 'bad', version: '1.0.0', ecosystem: 'npm', ids: ['GHSA-aaaa'], fixed: null }]);
});

test('fleetScanSummary reports one row per app+env, newest only', async () => {
  const app = makeApp('fleet-many');
  writeLock('fleet-many', { '': { name: 'a', version: '1.0.0' }, 'node_modules/x': { version: '1.0.0' } });
  osvReplies({});
  await scanApp(db, app, 'production');
  await scanApp(db, app, 'production');
  await scanApp(db, app, 'production');
  restoreFetch();
  const rows = fleetScanSummary(db).filter(r => r.slug === 'fleet-many');
  assert.equal(rows.length, 1, 'the fleet view returned scan history instead of current state');
});

// ---------------------------------------------------------------------------
// The scanner cannot reach the deploy's outcome
// ---------------------------------------------------------------------------

test('a scanner that throws is caught before it can reach the deploy result', () => {
  // scanApp is contractually non-throwing, but the DB insert is the one part
  // that can still throw (a locked or migrated-away table), so the deployer's
  // guard is load-bearing rather than decorative. Prove it can throw...
  const app = makeApp('throws');
  writeLock('throws', { '': { name: 'a', version: '1.0.0' }, 'node_modules/x': { version: '1.0.0' } });
  const brokenDb = { prepare() { throw new Error('database is locked'); } };
  osvReplies({});
  assert.rejects(() => scanApp(brokenDb, app, 'production'), /database is locked/);
  restoreFetch();

  // ...and that the deploy path wraps the call so it cannot propagate. The
  // hook sits after the deployment row is already 'live', so an exception
  // escaping here would report failure for a deploy that fully succeeded.
  const src = readFileSync(new URL('../server/services/deployer.js', import.meta.url), 'utf8');
  const hook = src.slice(src.indexOf('11. Dependency CVE scan'));
  const guarded = hook.slice(0, hook.indexOf('return { success: true'));
  assert.match(guarded, /try \{[\s\S]*scanApp\(db, app, env, 'deploy'\)[\s\S]*\} catch/,
    'the post-deploy scan is not inside a try/catch — a scanner exception would ' +
    'turn a fully-successful deploy into a reported failure');
  assert.doesNotMatch(guarded.slice(guarded.indexOf('} catch')), /throw/,
    'the post-deploy scan catch rethrows, which defeats the point of catching');
});

test('the scan hook runs only after the deployment row is marked live', () => {
  const src = readFileSync(new URL('../server/services/deployer.js', import.meta.url), 'utf8');
  const liveAt = src.indexOf("UPDATE deployments SET status = 'live'");
  const scanAt = src.indexOf('11. Dependency CVE scan');
  assert.ok(liveAt > 0 && scanAt > 0);
  assert.ok(scanAt > liveAt,
    'the scan was attached before the deploy is marked live — at that point it is still ' +
    'on the path that decides the outcome');
});

// ---------------------------------------------------------------------------
// npm aliases must resolve to the REAL package (found in review)
// ---------------------------------------------------------------------------
//
// The lockfile key is the INSTALL PATH. For an aliased dependency that path is
// the alias, not the package: `npm i mylodash@npm:lodash@4.17.15` writes
// "node_modules/mylodash": { name: "lodash", version: "4.17.15" }. Deriving the
// name from the key asks OSV about "mylodash", gets nothing back, and records a
// vulnerable lodash as status 'ok' — a silent false-clean, the exact failure
// this feature exists to prevent.
//
// Not hypothetical: npm ships aliases itself. string-width-cjs, strip-ansi-cjs
// and ansi-styles-cjs appear in ordinary lockfiles via cliui/wrap-ansi.

test('an aliased dependency is queried under its real registry name', () => {
  const dir = mkdtempSync(join(tmpdir(), 'crane-alias-'));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
    name: 'app', lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0' },
      'node_modules/mylodash': { name: 'lodash', version: '4.17.15' },
      'node_modules/string-width-cjs': { name: 'string-width', version: '4.2.3' },
    },
  }));
  const pkgs = parseLockfile(join(dir, 'package-lock.json'), 'npm');
  const names = pkgs.map((p) => p.name).sort();
  assert.deepEqual(names, ['lodash', 'string-width'],
    'the alias was sent to OSV instead of the real package — OSV knows nothing about "mylodash", ' +
    'answers empty, and a vulnerable lodash 4.17.15 records as clean');
});

test('a normal dependency still resolves from its path when name is absent', () => {
  const dir = mkdtempSync(join(tmpdir(), 'crane-alias2-'));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
    name: 'app', lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0' },
      'node_modules/plain': { version: '2.0.0' },
      'node_modules/a/node_modules/nested': { version: '3.0.0' },
    },
  }));
  const pkgs = parseLockfile(join(dir, 'package-lock.json'), 'npm');
  const byName = Object.fromEntries(pkgs.map((p) => [p.name, p.version]));
  assert.equal(byName.plain, '2.0.0', 'the path fallback broke for entries with no name field');
  assert.equal(byName.nested, '3.0.0', 'nested resolution regressed — a/nested is not a real package');
});

// ---------------------------------------------------------------------------
// findLockfiles — every manifest, not the first one
// ---------------------------------------------------------------------------
//
// A release is not always one project. The npm frontend at the root and the Go
// service under services/api are one deploy, one app row and one scan, and the
// version of this that stopped at the first hit reported on the frontend alone
// while recording status 'ok' for the whole thing.

const { assertFinding, assertFindings } = await import('../server/services/scanShapes.js');

function writeLockAt(dir, packages) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package-lock.json'),
    JSON.stringify({ lockfileVersion: 3, packages }));
}

test('findLockfiles returns every manifest in the release, not just the first', () => {
  const root = releaseDirFor('multi');
  writeLockAt(root, { '': { name: 'root', version: '1.0.0' }, 'node_modules/a': { version: '1.0.0' } });
  writeLockAt(join(root, 'frontend'), { '': { name: 'fe', version: '1.0.0' }, 'node_modules/b': { version: '2.0.0' } });
  writeLockAt(join(root, 'services', 'api'), { '': { name: 'api', version: '1.0.0' }, 'node_modules/c': { version: '3.0.0' } });

  const paths = findLockfiles(root).map((m) => m.path).sort();
  assert.deepEqual(paths, [
    join(root, 'frontend', 'package-lock.json'),
    join(root, 'package-lock.json'),
    join(root, 'services', 'api', 'package-lock.json'),
  ].sort(), 'a manifest below the release root was never discovered — everything it ' +
    'declares is unscanned, and the app still records a completed scan');
});

test('findLockfiles never descends into node_modules', () => {
  const root = releaseDirFor('nm');
  writeLockAt(root, { '': { name: 'root', version: '1.0.0' } });
  writeLockAt(join(root, 'node_modules', 'left-pad'), { '': { name: 'left-pad', version: '1.0.0' } });

  const paths = findLockfiles(root).map((m) => m.path);
  assert.deepEqual(paths, [join(root, 'package-lock.json')],
    'the walk read an installed package\'s own manifest — those describe copies of ' +
    'dependencies the root lockfile already pins, so every transitive package would ' +
    'be re-reported as a direct one');
});

test('findLockfiles stops at the documented depth bound', () => {
  // Bound is 3 levels below the release root. Four levels down is a checked-in
  // fixture or a vendored tree, and the bound is what keeps a scan from turning
  // into a filesystem crawl.
  const root = releaseDirFor('deep');
  writeLockAt(join(root, 'a', 'b', 'c'), { '': { name: 'ok', version: '1.0.0' } });
  writeLockAt(join(root, 'a', 'b', 'c', 'd'), { '': { name: 'too-deep', version: '1.0.0' } });

  const paths = findLockfiles(root).map((m) => m.path);
  assert.deepEqual(paths, [join(root, 'a', 'b', 'c', 'package-lock.json')],
    'the walk did not honour its depth bound');
});

test('scanApp scans every manifest it found, not the first', async () => {
  const app = makeApp('multi-app');
  const root = releaseDirFor('multi-app');
  writeLockAt(root, { '': { name: 'root', version: '1.0.0' }, 'node_modules/lodash': { version: '4.17.21' } });
  writeLockAt(join(root, 'frontend'), { '': { name: 'fe', version: '1.0.0' }, 'node_modules/minimist': { version: '1.2.0' } });

  osvReplies({ 'minimist@1.2.0': ['GHSA-vh95-rmgr-6w4m'] });
  const row = await scanApp(db, app, 'production');
  restoreFetch();

  assert.equal(row.package_count, 2,
    'a package declared by the second manifest never reached OSV');
  assert.equal(row.status, 'findings',
    'the only vulnerable package lived in the second manifest, and the scan reported clean');
  assert.equal(JSON.parse(row.findings_json)[0].name, 'minimist');
});

test('the same package in two manifests is queried once', async () => {
  const app = makeApp('multi-dupe');
  const root = releaseDirFor('multi-dupe');
  writeLockAt(root, { '': { name: 'root', version: '1.0.0' }, 'node_modules/lodash': { version: '4.17.21' } });
  writeLockAt(join(root, 'admin'), { '': { name: 'admin', version: '1.0.0' }, 'node_modules/lodash': { version: '4.17.21' } });

  osvReplies({});
  const row = await scanApp(db, app, 'production');
  restoreFetch();
  assert.equal(row.package_count, 1, 'the same name@version was sent to OSV twice');
});

test('a manifest that cannot be read fails the whole scan rather than half of it', async () => {
  const app = makeApp('multi-broken');
  const root = releaseDirFor('multi-broken');
  writeLockAt(root, { '': { name: 'root', version: '1.0.0' }, 'node_modules/lodash': { version: '4.17.21' } });
  mkdirSync(join(root, 'broken'), { recursive: true });
  writeFileSync(join(root, 'broken', 'package-lock.json'), '{ not json');

  osvReplies({});
  const row = await scanApp(db, app, 'production');
  restoreFetch();
  assert.equal(row.status, 'error',
    'one unreadable manifest was skipped and the rest recorded as a completed scan — ' +
    'the app then reads as scanned while a file nothing could read stays invisible');
});

// ---------------------------------------------------------------------------
// The ecosystem travels with the package
// ---------------------------------------------------------------------------

test('each query carries its own package ecosystem, mixed in one request', async () => {
  osvReplies({});
  const r = await queryOsv([
    { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
    { name: 'django', version: '3.2.0', ecosystem: 'PyPI' },
    { name: 'github.com/gin-gonic/gin', version: 'v1.6.0', ecosystem: 'Go' },
  ]);
  restoreFetch();
  assert.equal(r.ok, true);
  assert.equal(calls.length, 1,
    'a mixed-ecosystem package set was split across requests — querybatch takes a ' +
    'different ecosystem per query, so it costs no extra round trip');
  assert.deepEqual(calls[0].queries.map((q) => q.package.ecosystem), ['npm', 'PyPI', 'Go'],
    'the ecosystem was hardcoded at query time again — every non-npm package is then ' +
    'asked about in npm\'s namespace, where it does not exist, and comes back clean');
});

test('a package with no ecosystem is refused, not guessed at', async () => {
  osvReplies({});
  await assert.rejects(() => queryOsv([{ name: 'lodash', version: '4.17.15' }]),
    /ecosystem/,
    'a package with no ecosystem reached the wire; whatever it was queried as, the ' +
    'answer is not about that package');
  restoreFetch();
});

// ---------------------------------------------------------------------------
// fixed — the upgrade, which is the actionable half of a finding
// ---------------------------------------------------------------------------
//
// OSV puts it at affected[].ranges[].events[].fixed. It was discarded, so the
// digest could name a problem but never the remedy. null is a real answer here
// ("OSV published no fixed version") and must never mean "we did not look".

function osvVulns(byNameVersion) {
  stubOsv((body) => ({
    ok: true,
    status: 200,
    json: async () => ({
      results: body.queries.map((q) => {
        const vulns = byNameVersion[`${q.package.name}@${q.version}`];
        return vulns ? { vulns } : {};
      }),
    }),
  }));
}
const npmPkg = (name, version) => ({ name, version, ecosystem: 'npm' });
const range = (...events) => ({ type: 'SEMVER', events });

test('fixed is the lowest published fix above the installed version', async () => {
  // One advisory patched on two branches. 5.0.1 also fixes it, but 4.17.16 is
  // the upgrade an owner on 4.17.15 can actually take this afternoon.
  osvVulns({
    'lodash@4.17.15': [{
      id: 'GHSA-p6mc-m468-83gw',
      affected: [{
        package: { name: 'lodash', ecosystem: 'npm' },
        ranges: [range({ introduced: '0' }, { fixed: '4.17.16' }), range({ introduced: '5.0.0' }, { fixed: '5.0.1' })],
      }],
    }],
  });
  const r = await queryOsv([npmPkg('lodash', '4.17.15')]);
  restoreFetch();
  assert.equal(r.findings[0].fixed, '4.17.16',
    'the fix named was not the smallest upgrade that resolves the advisory');
});

test('fixed across several advisories is the version that resolves all of them', async () => {
  osvVulns({
    'lodash@4.17.15': [
      { id: 'GHSA-one', affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [range({ introduced: '0' }, { fixed: '4.17.16' })] }] },
      { id: 'GHSA-two', affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [range({ introduced: '0' }, { fixed: '4.17.21' })] }] },
    ],
  });
  const r = await queryOsv([npmPkg('lodash', '4.17.15')]);
  restoreFetch();
  assert.deepEqual(r.findings[0].ids, ['GHSA-one', 'GHSA-two']);
  assert.equal(r.findings[0].fixed, '4.17.21',
    'the finding names two advisories but the upgrade named fixes only one of them, ' +
    'which sends the reader to do the work again');
});

test('fixed is null when OSV published no fixed event', async () => {
  osvVulns({
    'abandoned@1.0.0': [{
      id: 'GHSA-nofix',
      affected: [{ package: { name: 'abandoned', ecosystem: 'npm' }, ranges: [range({ introduced: '0' })] }],
    }],
  });
  const r = await queryOsv([npmPkg('abandoned', '1.0.0')]);
  restoreFetch();
  assert.equal(r.findings[0].fixed, null,
    'a version was invented for an advisory OSV published no fix for');
});

test('a GIT range is not offered as an upgrade', async () => {
  // A commit hash is not something anyone can put in a package.json, and
  // rendering one in the fixed column reads as a version.
  osvVulns({
    'thing@1.0.0': [{
      id: 'GHSA-git',
      affected: [{
        package: { name: 'thing', ecosystem: 'npm' },
        ranges: [{ type: 'GIT', repo: 'https://example.invalid/x', events: [{ introduced: '0' }, { fixed: 'a3f9c1e2b4d5' }] }],
      }],
    }],
  });
  const r = await queryOsv([npmPkg('thing', '1.0.0')]);
  restoreFetch();
  assert.equal(r.findings[0].fixed, null,
    'a git commit hash was reported as the version to upgrade to');
});

test('a fix from another ecosystem is not attributed to this package', async () => {
  // The same CVE covers a Debian package and the npm one, with different fixed
  // versions. Naming Debian's fix to an npm user names a version the registry
  // does not have.
  osvVulns({
    'thing@1.0.0': [{
      id: 'CVE-multi',
      affected: [
        { package: { name: 'thing', ecosystem: 'Debian:11' }, ranges: [range({ introduced: '0' }, { fixed: '1.0.0-3+deb11u1' })] },
        { package: { name: 'thing', ecosystem: 'npm' }, ranges: [range({ introduced: '0' }, { fixed: '1.2.0' })] },
      ],
    }],
  });
  const r = await queryOsv([npmPkg('thing', '1.0.0')]);
  restoreFetch();
  assert.equal(r.findings[0].fixed, '1.2.0',
    'a fixed version from a different ecosystem\'s packaging of the same advisory was ' +
    'reported as the npm upgrade');
});

test('a Go module version keeps its v prefix and orders correctly', async () => {
  osvVulns({
    'github.com/x/y@v1.6.0': [{
      id: 'GO-1',
      affected: [{
        package: { name: 'github.com/x/y', ecosystem: 'Go' },
        ranges: [range({ introduced: '0' }, { fixed: 'v1.7.7' }), range({ introduced: 'v2.0.0' }, { fixed: 'v2.1.0' })],
      }],
    }],
  });
  const r = await queryOsv([{ name: 'github.com/x/y', version: 'v1.6.0', ecosystem: 'Go' }]);
  restoreFetch();
  assert.equal(r.findings[0].fixed, 'v1.7.7');
});

// ---------------------------------------------------------------------------
// The shape is enforced where it is produced, not only where it is read
// ---------------------------------------------------------------------------

test('every finding queryOsv emits satisfies the frozen shape', async () => {
  osvVulns({
    'lodash@4.17.15': [{
      id: 'GHSA-p6mc-m468-83gw',
      affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [range({ introduced: '0' }, { fixed: '4.17.16' })] }],
    }],
  });
  const r = await queryOsv([npmPkg('lodash', '4.17.15'), npmPkg('safe', '1.0.0')]);
  restoreFetch();
  assertFindings(r.findings);
  assert.equal(r.findings.length, 1);
});

test('what scanApp stores is what the digest asserts on', async () => {
  // The v2.52.0 mismatch — scanner wrote { name, version, ids }, the digest
  // brief described { package, id, fixed_version } — survived because the mail
  // template coded defensively. Reading the stored row back through the same
  // asserter is what stops that being possible again.
  const app = makeApp('shape-app');
  writeLock('shape-app', {
    '': { name: 'shape-app', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.15' },
  });
  osvVulns({
    'lodash@4.17.15': [{
      id: 'GHSA-p6mc-m468-83gw',
      affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [range({ introduced: '0' }, { fixed: '4.17.19' })] }],
    }],
  });
  const row = await scanApp(db, app, 'production');
  restoreFetch();
  assert.equal(row.status, 'findings');
  const stored = JSON.parse(row.findings_json);
  assertFindings(stored, 'app_vuln_scans.findings_json');
  assert.deepEqual(stored, [{
    name: 'lodash', version: '4.17.15', ecosystem: 'npm',
    ids: ['GHSA-p6mc-m468-83gw'], fixed: '4.17.19',
  }]);
  assert.equal(fleetScanSummary(db).find((r) => r.slug === 'shape-app').findings[0].fixed, '4.17.19',
    'the fleet view dropped the upgrade on the way out of the database');
});

test('a vulnerability OSV names no id for is an error, not a dropped finding', async () => {
  // Dropping it records a vulnerable package as clean; storing it with an empty
  // id list renders a finding nobody can look up. Neither is an answer.
  osvVulns({ 'weird@1.0.0': [{ affected: [] }] });
  const r = await queryOsv([npmPkg('weird', '1.0.0')]);
  restoreFetch();
  assert.equal(r.ok, false, 'a vulnerability with no id was silently dropped');
  assert.match(r.error, /no id/);
});

// ---------------------------------------------------------------------------
// A repo that is two projects — the case both changes exist for
// ---------------------------------------------------------------------------

test('a Node frontend and a Go service in one release are both scanned', async () => {
  // The shape that was silently half-scanned: findLockfile stopped at
  // package-lock.json, so every Go module was invisible, and the app recorded
  // a completed scan with an ecosystem column reading 'npm'.
  const app = makeApp('mixed-app');
  const root = releaseDirFor('mixed-app');
  writeLockAt(root, {
    '': { name: 'fe', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.15' },
  });
  mkdirSync(join(root, 'services', 'api'), { recursive: true });
  writeFileSync(join(root, 'services', 'api', 'go.sum'),
    'github.com/gin-gonic/gin v1.6.0 h1:aaa=\n' +
    'github.com/gin-gonic/gin v1.6.0/go.mod h1:bbb=\n');

  osvVulns({
    'github.com/gin-gonic/gin@v1.6.0': [{
      id: 'GO-2021-0052',
      affected: [{
        package: { name: 'github.com/gin-gonic/gin', ecosystem: 'Go' },
        ranges: [range({ introduced: '0' }, { fixed: 'v1.7.7' })],
      }],
    }],
  });
  const row = await scanApp(db, app, 'production');
  restoreFetch();

  assert.equal(row.package_count, 2, 'one of the two projects in this release was never read');
  assert.deepEqual(calls[0].queries.map((q) => q.package.ecosystem).sort(), ['Go', 'npm'],
    'the Go module was asked about in npm\'s namespace, where it does not exist — ' +
    'OSV answers clean and the finding disappears');
  assert.equal(calls.length, 1, 'a mixed repo cost more than one OSV round trip');
  assert.equal(row.ecosystem, 'Go,npm',
    'the recorded ecosystem names only one of the two the release actually contains');
  assert.deepEqual(JSON.parse(row.findings_json), [{
    name: 'github.com/gin-gonic/gin', version: 'v1.6.0', ecosystem: 'Go',
    ids: ['GO-2021-0052'], fixed: 'v1.7.7',
  }]);
});

test('an advisory id that is not a string fails the scan instead of being stored', async () => {
  // The producer asserts the shape it emits, so a malformed answer stops here
  // rather than reaching a mail template that renders whatever it was handed.
  // scanApp still records it as 'error', which is a state a reader can see.
  const app = makeApp('badshape');
  writeLock('badshape', {
    '': { name: 'badshape', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.15' },
  });
  osvVulns({ 'lodash@4.17.15': [{ id: 12345 }] });
  const row = await scanApp(db, app, 'production');
  restoreFetch();
  assert.equal(row.status, 'error',
    'a finding whose advisory id is not a string was stored as a finding — the shape is ' +
    'only enforced in tests, so a future change can reshape it quietly');
  assert.match(row.error, /id/);
  assert.equal(row.findings_json, null);
});

test('findLockfiles stops at the documented file cap', () => {
  // 50. A release with more manifests than that is a vendored tree, and the cap
  // is what stops one pathological repo spending the OSV batch budget for the
  // whole fleet. It truncates, which under-reports — which is why it sits well
  // above any real app rather than close to the common case.
  const root = releaseDirFor('wide');
  for (let i = 0; i < 60; i++) {
    writeLockAt(join(root, `p${String(i).padStart(2, '0')}`), { '': { name: `p${i}`, version: '1.0.0' } });
  }
  assert.equal(findLockfiles(root).length, 50, 'the walk did not honour its file cap');
});
