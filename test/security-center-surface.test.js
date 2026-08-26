import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The MCP surface over hosted-app CVE scanning and platform policy.
//
// The scanning and the policy live in their own services; what is tested here
// is the part an agent actually consumes — the gate, the flags and the words.
// Three properties carry the weight:
//
//   1. An unscanned app is never reported as a clean one. `skipped` (no
//      lockfile AppCrane can read), `error` (OSV unreachable) and "no scan row
//      at all" produce no findings, and neither does a clean scan. The tool has
//      to hold those apart in a field a program reads AND in the sentence a
//      model reads, or the first summary an agent relays turns "we never
//      looked" into "it is fine". The mirror-image mistake is as bad: `findings`
//      is a COMPLETED scan, and counting it as unscanned would hide the apps
//      that are actually vulnerable behind a coverage complaint.
//   2. The gates hold. Fleet CVE state is an admin question; the policy levers
//      override every app owner on the platform, so they are platform-admin
//      only — checked as the FIRST statement in the handler, because anything
//      above it runs for a caller who was about to be refused.
//   3. Policy is not retroactive, and the tool says so. Enabling a lever
//      reports the apps already in violation and changes none of them; an agent
//      that reports the lever as having fixed them is wrong about live URLs.
//
// The scan rows here are inserted directly rather than produced by a scan: what
// is under test is how a status is REPORTED, and going through the scanner
// would make the interesting statuses depend on OSV being reachable.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-seccenter-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { callTool, getToolCatalog } = await import('../server/services/mcpTools.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { assertFinding } = await import('../server/services/scanShapes.js');

function mkUser(role, email) {
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(role, email, role, hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}
const platformAdmin = mkUser('platform_admin', 'pa@x.io');
const plainAdmin    = mkUser('admin', 'admin@x.io');
const owner         = mkUser('user', 'user@x.io');

let slot = 0;
function mkApp(slug, visibility = 'private') {
  return db.prepare('INSERT INTO apps (name,slug,slot,source_type,visibility) VALUES (?,?,?,?,?)')
    .run(slug, slug, ++slot, 'managed', visibility).lastInsertRowid;
}
function scanRow(appId, env, status, extra = {}) {
  db.prepare(`INSERT INTO app_vuln_scans (app_id, env, source, ecosystem, status, package_count, findings_json, error, scanned_at)
              VALUES (?,?,?,?,?,?,?,?,datetime('now'))`)
    .run(appId, env, extra.source ?? 'scheduled', 'ecosystem' in extra ? extra.ecosystem : 'npm',
         status, extra.packages ?? 12,
         extra.findings ? JSON.stringify(extra.findings) : null, extra.error ?? null);
}

// The shape scanShapes.js freezes, written out once. Inline literals are how
// the previous round drifted: the scanner stored { name, version, ids } and
// nothing failed until a human read the mail it produced.
const finding = (over = {}) => ({
  name: 'lodash', version: '4.17.20', ecosystem: 'npm',
  ids: ['GHSA-29mw-wpgm-hmr9'], fixed: '4.17.21', ...over,
});
const clearScans = () => db.prepare('DELETE FROM app_vuln_scans').run();
const clearApps  = () => { clearScans(); db.prepare('DELETE FROM apps').run(); };

const call = (u, name, args = {}) => callTool(u, name, args);
const unwrap = (r) => (typeof r === 'string' ? JSON.parse(r) : (r?.content ? JSON.parse(r.content[0].text) : r));
const byName = new Map(getToolCatalog().map(t => [t.name, t]));

const TOOLS = ['appcrane_scan_report', 'appcrane_scan_app', 'appcrane_platform_policy'];
const argsFor = (name) => (name === 'appcrane_scan_app' ? { slug: 'gate-probe' } : {});

// ---------------------------------------------------------------------------
// A scan that did not happen is never reported as a clean one
// ---------------------------------------------------------------------------

test('a fleet of skipped and errored scans is not reported as clean', async () => {
  clearApps();
  const a = mkApp('static-site');
  const b = mkApp('offline-when-scanned');
  scanRow(a, 'production', 'skipped', { error: 'no recognised lockfile in the live release', packages: 0 });
  scanRow(b, 'production', 'error',   { error: 'OSV unreachable: fetch failed', packages: 40 });

  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report'));

  assert.equal(r.scanned, false, 'a fleet where nothing completed a scan reported itself scanned');
  assert.equal(r.assurance, 'none', 'assurance must be none when no app has a completed scan');
  assert.equal(r.unscanned_count, 2);
  assert.deepEqual(r.unscanned_by_status, { skipped: 1, error: 1 },
    'skipped and error are not counted as missing coverage, so they read as results');
  assert.equal(r.vulnerable_count, 0);
  // The flags are what a program reads; this is what the model relays, and it
  // is the half that turns into a sentence in a status report.
  assert.match(r.summary, /UNKNOWN, not clean/,
    'the summary does not say the unscanned apps are unknown rather than clean');
  assert.doesNotMatch(r.summary, /no vulnerabilities|are clean|is clean/i,
    'a fleet that was never successfully scanned was described in the language of a clean result');
});

test('an app whose newest scan errored reads as NOT SCANNED, even after an older clean one', async () => {
  clearApps();
  const id = mkApp('regressed');
  scanRow(id, 'production', 'ok');
  scanRow(id, 'production', 'error', { error: 'OSV unreachable: fetch failed' });
  scanRow(id, 'sandbox', 'ok');

  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'regressed' }));

  assert.deepEqual(r.unscanned, ['production'],
    'the newest production row errored, so production is unknown — an older clean scan is not current evidence');
  assert.equal(r.scanned, false);
  assert.equal(r.assurance, 'partial');
  assert.match(r.summary, /NOT SCANNED: production \(error\)/);
  assert.match(r.summary, /must not be reported as a clean result/i);
});

test('an app with no scan row at all is unknown in both stages', async () => {
  clearApps();
  mkApp('never-touched');
  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'never-touched' }));

  assert.equal(r.assurance, 'none');
  assert.deepEqual(r.unscanned, ['production', 'sandbox']);
  assert.equal(r.scans.production, null);
  assert.match(r.summary, /no scan on record/);
});

test('findings are a COMPLETED scan — counted as vulnerable, never as missing coverage', async () => {
  clearApps();
  const vuln = mkApp('has-cves');
  const good = mkApp('genuinely-clean');
  for (const env of ['production', 'sandbox']) {
    scanRow(vuln, env, 'findings', { findings: [finding()] });
    scanRow(good, env, 'ok');
  }

  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report'));
  assert.equal(r.unscanned_count, 0,
    'a scan that found something was counted as missing coverage, which buries the vulnerable apps under a coverage complaint');
  assert.equal(r.assurance, 'complete');
  assert.equal(r.vulnerable_count, 2);
  assert.match(r.summary, /2 scanned row\(s\) have known-vulnerable dependencies/);

  const one = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'has-cves' }));
  assert.deepEqual(one.vulnerable_stages, ['production', 'sandbox']);
  assert.deepEqual(one.unscanned, []);
  assert.equal(one.scanned, true);
});

test('a genuinely clean scan is allowed to say so — a report that never says yes is useless', async () => {
  clearApps();
  const id = mkApp('all-good');
  scanRow(id, 'production', 'ok');
  scanRow(id, 'sandbox', 'ok');

  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'all-good' }));
  assert.equal(r.scanned, true);
  assert.equal(r.assurance, 'complete');
  assert.match(r.summary, /scanned and nothing was found/);
});

test('every scan payload states report-only, so a finding is never relayed as a deploy failure', async () => {
  clearApps();
  mkApp('any-app');
  const fleet = unwrap(await call(plainAdmin, 'appcrane_scan_report'));
  const one   = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'any-app' }));
  assert.equal(fleet.enforcement, 'report-only');
  assert.equal(one.enforcement, 'report-only');
  assert.match(fleet.summary, /never blocked and cannot block a deploy/);
});

// ---------------------------------------------------------------------------
// What a finding actually says — ecosystem, and the fix there is to apply
// ---------------------------------------------------------------------------
//
// The previous round froze function signatures and the payload drifted anyway:
// the scanner stored { name, version, ids } while the digest's brief described
// { package, id, fixed_version }. Both halves shipped, neither matched, and the
// email rendered only because its author coded defensively. So the surface
// asserts what it hands out, against the same scanShapes.js the producer
// asserts against, and these tests assert the asserter actually runs.

test('a surfaced finding carries the ecosystem and the version that fixes it', async () => {
  clearApps();
  const id = mkApp('needs-upgrading');
  scanRow(id, 'production', 'findings', { findings: [finding({ fixed: '4.17.21' })] });
  scanRow(id, 'sandbox', 'ok');

  const one = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'needs-upgrading' }));
  const f = one.scans.production.findings[0];

  // Against the frozen contract, not against a hand-written field list: a
  // producer reshape has to fail here as loudly as it fails in the digest.
  assertFinding(f, 'surfaced finding');
  assert.equal(f.ecosystem, 'npm', 'the finding does not say which ecosystem the package belongs to');
  assert.equal(f.fixed, '4.17.21',
    'the report dropped the fixed version — an agent reporting a CVE without naming the upgrade ' +
    'costs its reader a separate investigation');
  assert.deepEqual(f.ids, ['GHSA-29mw-wpgm-hmr9'], 'the advisory list did not survive the surface');
});

test('fixed: null survives as null — OSV published no fix, which is not "no fix needed"', async () => {
  clearApps();
  const id = mkApp('no-fix-published');
  scanRow(id, 'production', 'findings', { findings: [finding({ name: 'abandonware', fixed: null })] });

  const one = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'no-fix-published' }));
  const f = one.scans.production.findings[0];
  assertFinding(f, 'unfixed finding');
  assert.equal(f.fixed, null,
    'a null fixed version was coerced or dropped, so an agent cannot tell "OSV published no fix" ' +
    'from "this field was never populated"');
  assert.ok('fixed' in f, 'the field vanished entirely rather than being reported as null');
});

test('the fleet view surfaces the same asserted findings, not raw stored JSON', async () => {
  clearApps();
  const id = mkApp('fleet-finding');
  scanRow(id, 'production', 'findings', { findings: [finding()] });

  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report'));
  const row = r.apps.find((a) => a.slug === 'fleet-finding' && a.status === 'findings');
  assertFinding(row.findings[0], 'fleet finding');
  assert.equal(row.findings[0].fixed, '4.17.21');
  // A raw copy beside the asserted list is a second, unchecked path to the same
  // data, and a consumer that reads it bypasses the contract entirely.
  assert.ok(!('findings_json' in row), 'the unasserted raw JSON is still shipped beside the asserted list');
});

test('a finding stored in the OLD shape fails the report loudly instead of surfacing half of it', async () => {
  clearApps();
  const id = mkApp('stale-producer');
  // Exactly what v2.52.0's scanner wrote: no ecosystem, no fixed. Under the
  // defensive read this replaces, the report rendered a finding with two
  // undefined fields and said nothing about it.
  scanRow(id, 'production', 'findings', { findings: [{ name: 'lodash', version: '4.17.20', ids: ['GHSA-x'] }] });

  await assert.rejects(
    () => call(plainAdmin, 'appcrane_scan_report', { slug: 'stale-producer' }),
    /ecosystem must be a non-empty string/,
    'a producer that reshaped its findings was surfaced silently rather than failing the report');
  await assert.rejects(
    () => call(plainAdmin, 'appcrane_scan_report'),
    /ecosystem must be a non-empty string/,
    'the fleet view read the same malformed row without asserting it');
});

// ---------------------------------------------------------------------------
// Which manifests were read — coverage is per manifest, not per app
// ---------------------------------------------------------------------------
//
// Every assertion above is about one finding being right. This is the level
// above: an app whose Go service was never looked at, reported beside its
// scanned npm frontend with an empty findings list, is a false clean at the app
// level even when every individual finding on the row is correct. One scan row
// reads ONE manifest, so the report has to name which.

test('the report names the manifests it read, per stage', async () => {
  clearApps();
  const id = mkApp('two-stages');
  scanRow(id, 'production', 'ok', { ecosystem: 'npm' });
  scanRow(id, 'sandbox', 'ok', { ecosystem: 'npm' });

  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'two-stages' }));
  assert.deepEqual(r.manifests_scanned, ['npm'],
    'the report does not say which manifest produced its clean result');
  assert.deepEqual(r.manifests_by_stage, { production: 'npm', sandbox: 'npm' });
  assert.equal(r.scans.production.manifest, 'npm');
  assert.match(r.summary, /Manifests read: production \(npm\), sandbox \(npm\)/);
  assert.match(r.summary, /Coverage is per manifest, not per app/,
    'nothing tells the reader that a language AppCrane cannot read is absent from these findings, ' +
    'not absent from the app');
});

test('a stage whose scan read nothing reports no manifest, and the app says so', async () => {
  clearApps();
  const id = mkApp('go-service');
  // What a Go or static app records today: findLockfile found nothing, so the
  // row carries no ecosystem at all.
  scanRow(id, 'production', 'skipped', { ecosystem: null, packages: 0, error: 'no recognised lockfile in the live release' });
  scanRow(id, 'sandbox', 'skipped', { ecosystem: null, packages: 0, error: 'no recognised lockfile in the live release' });

  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'go-service' }));
  assert.deepEqual(r.manifests_scanned, [],
    'an app where no manifest was read reported one anyway');
  assert.deepEqual(r.manifests_by_stage, { production: null, sandbox: null });
  assert.match(r.summary, /No manifest was read in either stage/);
});

test('a mixed app reports the manifest it read and the stage it did not', async () => {
  clearApps();
  const id = mkApp('npm-front-go-back');
  scanRow(id, 'production', 'ok', { ecosystem: 'npm' });
  scanRow(id, 'sandbox', 'skipped', { ecosystem: null, packages: 0 });

  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'npm-front-go-back' }));
  assert.deepEqual(r.manifests_scanned, ['npm']);
  assert.deepEqual(r.manifests_by_stage, { production: 'npm', sandbox: null },
    'a stage that read no manifest was folded in with the one that did');
  assert.equal(r.assurance, 'partial');
});

test('the manifest reported is the one the row recorded, not the one npm happens to be', async () => {
  clearApps();
  // appScan's LOCKFILES list is explicitly built so pip and go can be added
  // without touching a caller, and `ecosystem` travels on the row for exactly
  // that reason. A surface that assumes npm reports the wrong language the day
  // the second entry lands, and reports it confidently.
  const py = mkApp('python-service');
  scanRow(py, 'production', 'findings', {
    ecosystem: 'PyPI',
    findings: [finding({ name: 'urllib3', version: '1.26.4', ecosystem: 'PyPI', ids: ['GHSA-q2q7-5pp4-w6pg'], fixed: '1.26.5' })],
  });
  const js = mkApp('node-service');
  scanRow(js, 'production', 'ok', { ecosystem: 'npm' });

  const one = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'python-service' }));
  assert.deepEqual(one.manifests_scanned, ['PyPI'],
    'a PyPI scan was reported as an npm one, so the report names a language the app does not use');
  assert.equal(one.scans.production.manifest, 'PyPI');
  assert.equal(one.scans.production.findings[0].ecosystem, 'PyPI');

  const fleet = unwrap(await call(plainAdmin, 'appcrane_scan_report'));
  assert.deepEqual(fleet.manifests_scanned, { PyPI: 1, npm: 1 },
    'the fleet folded two ecosystems into one count, hiding which half of the platform is covered by which');
});

test('the fleet view counts rows per manifest and says nothing was read when nothing was', async () => {
  clearApps();
  const a = mkApp('has-npm');
  const b = mkApp('has-nothing');
  scanRow(a, 'production', 'ok', { ecosystem: 'npm' });
  scanRow(b, 'production', 'skipped', { ecosystem: null, packages: 0 });

  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report'));
  assert.deepEqual(r.manifests_scanned, { npm: 1 },
    'the fleet report does not say how much of itself is npm coverage and how much is nothing at all');
  assert.match(r.summary, /Manifests read: npm: 1 row\(s\)/);
  assert.match(r.summary, /one row reads ONE manifest/);

  clearScans();
  const none = unwrap(await call(plainAdmin, 'appcrane_scan_report'));
  assert.deepEqual(none.manifests_scanned, {});
  assert.match(none.summary, /NO MANIFEST WAS READ in any row/,
    'a fleet where no dependency file was ever opened did not say so');
});

// ---------------------------------------------------------------------------
// On-demand scan
// ---------------------------------------------------------------------------

test('an on-demand scan with nothing to read reports ok:false and records why', async () => {
  clearApps();
  mkApp('no-lockfile');
  // No release directory exists under DATA_DIR, so the scanner finds no
  // lockfile: a real end-to-end call that reaches no network.
  const r = unwrap(await call(plainAdmin, 'appcrane_scan_app', { slug: 'no-lockfile' }));

  assert.equal(r.ok, false, 'a scan that read nothing reported success');
  assert.equal(r.env, 'production', 'the on-demand scan did not default to the deployed stage');
  assert.equal(r.scan.status, 'skipped');
  assert.equal(r.scan.source, 'manual', 'an on-demand scan is attributed to a deploy or the scheduler');
  assert.match(r.note, /was NOT scanned/);
  assert.doesNotMatch(JSON.stringify(r), /no vulnerabilities/i);

  // Recorded, not just returned — the next report has to see it too.
  const report = unwrap(await call(plainAdmin, 'appcrane_scan_report', { slug: 'no-lockfile' }));
  assert.deepEqual(report.unscanned, ['production', 'sandbox']);
});

test('on a box whose migrations have not reached the scanner, nothing reads as clean', async () => {
  clearApps();
  mkApp('pre-migration');
  // The table arrives with the scanner's own migration and an admin can call
  // these on a host that has not applied it yet. Renamed rather than dropped so
  // the rest of the file still has its history.
  db.exec('ALTER TABLE app_vuln_scans RENAME TO app_vuln_scans_hidden');
  try {
    const fleet = unwrap(await call(plainAdmin, 'appcrane_scan_report'));
    assert.equal(fleet.scanned, false);
    assert.equal(fleet.assurance, 'none');
    assert.match(fleet.summary, /NEVER SCANNED/,
      'a host with no scan history at all produced a report that does not say so');
    assert.doesNotMatch(fleet.summary, /no vulnerabilities|is clean|are clean/i);

    const one = unwrap(await call(plainAdmin, 'appcrane_scan_app', { slug: 'pre-migration' }));
    assert.equal(one.ok, false, 'a scan with nowhere to record its result reported success');
    assert.equal(one.status, 'unavailable');
    assert.match(one.note, /NOT scanned/);
  } finally {
    db.exec('ALTER TABLE app_vuln_scans_hidden RENAME TO app_vuln_scans');
  }
});

test('the scan tools refuse an app the caller cannot see', async () => {
  await assert.rejects(() => call(plainAdmin, 'appcrane_scan_report', { slug: 'no-such-app' }), /not found/i);
  await assert.rejects(() => call(plainAdmin, 'appcrane_scan_app', { slug: 'no-such-app' }), /not found/i);
});

// ---------------------------------------------------------------------------
// Policy: enforced forward, reported backward
// ---------------------------------------------------------------------------

test('enabling ban_public_apps reports the existing public apps and changes none of them', async () => {
  clearApps();
  mkApp('legacy-public', 'public');
  mkApp('a-private-one', 'private');

  const r = unwrap(await call(platformAdmin, 'appcrane_platform_policy', { ban_public_apps: true }));
  // Reset in a finally: a failure here would otherwise leave the lever on and
  // fail the next two tests for a reason that has nothing to do with them.
  try {
    assert.equal(r.policy.ban_public_apps, true);
    assert.deepEqual(r.changed_fields, ['ban_public_apps']);
    assert.equal(r.retroactive, false, 'the payload does not state that the change is not retroactive');
    assert.equal(r.violation_count, 1);
    assert.equal(r.violations[0].slug, 'legacy-public');

    // The point of the whole design: the row is untouched and the URL still works.
    assert.equal(db.prepare("SELECT visibility FROM apps WHERE slug = 'legacy-public'").get().visibility, 'public',
      'turning the lever on rewrote an existing app behind its owner, breaking a live URL with no record');
    assert.match(r.summary, /NOT changed/,
      'the summary lets an agent report the violations as having been fixed');
  } finally {
    await call(platformAdmin, 'appcrane_platform_policy', { ban_public_apps: false });
  }
});

test('reading policy with no arguments changes nothing', async () => {
  const r = unwrap(await call(platformAdmin, 'appcrane_platform_policy'));
  assert.deepEqual(r.changed_fields, []);
  assert.equal(r.policy.ban_public_apps, false);
  assert.equal(r.policy.mandate_security_scans, false);
  assert.match(r.summary, /Read only/);
});

test('both levers default OFF, so an upgrade enforces nothing', async () => {
  const r = unwrap(await call(platformAdmin, 'appcrane_platform_policy'));
  assert.deepEqual(r.policy, { ban_public_apps: false, mandate_security_scans: false });
  assert.equal(r.violation_count, 0, 'a platform with no lever on reported violations of nothing');
});

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

test('an ordinary user is refused all three tools by the dispatcher', async () => {
  clearApps();
  mkApp('gate-probe');
  for (const name of TOOLS) {
    await assert.rejects(() => call(owner, name, argsFor(name)), /Forbidden/i,
      `${name} was callable by a user with no admin role`);
  }
});

test('a plain admin may read and run scans — fleet CVE state is an admin question', async () => {
  // The positive half of the gate: a control nobody can call is not a control.
  assert.equal(byName.get('appcrane_scan_report').requiredRole, 'admin');
  assert.equal(byName.get('appcrane_scan_app').requiredRole, 'admin');
  const r = unwrap(await call(plainAdmin, 'appcrane_scan_report'));
  assert.equal(typeof r.assurance, 'string');
});

test('a plain admin cannot read or change platform policy', async () => {
  await assert.rejects(() => call(plainAdmin, 'appcrane_platform_policy'), /platform admin/i,
    'a global admin could read the levers that override every app owner on the platform');
  await assert.rejects(() => call(plainAdmin, 'appcrane_platform_policy', { ban_public_apps: true }), /platform admin/i,
    'a global admin could set platform policy');
  assert.equal(unwrap(await call(platformAdmin, 'appcrane_platform_policy')).policy.ban_public_apps, false,
    'the refused write took effect anyway');
});

test('the platform-admin check is the FIRST statement in the policy handler', () => {
  // Asserted against the source the same way the backup tools are: once the
  // ordering is right no functional test can see it, and anything placed above
  // the check runs for a caller who is about to be refused.
  const src = readFileSync('server/services/mcpTools.js', 'utf8');
  const from = src.indexOf("name: 'appcrane_platform_policy'");
  assert.notEqual(from, -1, 'appcrane_platform_policy is no longer registered');
  assert.match(src.slice(from, from + 9000),
    /handler: async \(user(?:, args)?\) => \{\s*if \(user\.role !== 'platform_admin'\)/,
    'the platform_admin check is no longer the first thing the policy handler does');
});

// ---------------------------------------------------------------------------
// Catalog and descriptions — the whole interface the model is handed
// ---------------------------------------------------------------------------

test('only the report is read-only; scanning and policy are writes', () => {
  assert.equal(byName.get('appcrane_scan_report').readOnly, true,
    'the report writes nothing and should be callable by a read-only key');
  assert.ok(!byName.get('appcrane_scan_app').readOnly,
    'an on-demand scan records a row and feeds the digest; it is not a read');
  assert.ok(!byName.get('appcrane_platform_policy').readOnly,
    'the policy tool can set both levers, so a read-only key must not reach it');
});

test('all three schemas are closed', () => {
  for (const name of TOOLS) {
    assert.equal(byName.get(name).inputSchema.additionalProperties, false,
      `${name} accepts unknown properties`);
  }
});

test('the report description warns that scanning never blocks a deploy', () => {
  const d = byName.get('appcrane_scan_report').description;
  assert.match(d, /REPORT ONLY/);
  assert.match(d, /never blocked a deploy and cannot/,
    'nothing tells the agent a finding is not a deploy failure');
});

test('the report description says skipped and error are not "no vulnerabilities"', () => {
  const d = byName.get('appcrane_scan_report').description;
  assert.match(d, /`skipped`/);
  assert.match(d, /`error`/);
  assert.match(d, /NOT SCANNED/,
    'the description never states that a non-result status means the app was not scanned');
  assert.match(d, /"no vulnerabilities found" is only ever true/,
    'the description does not name the wrong conclusion it exists to prevent');
});

test('the report description says a null fixed means OSV published no fix', () => {
  const d = byName.get('appcrane_scan_report').description;
  assert.match(d, /`ecosystem` AND `fixed`/,
    'the description never mentions the two fields an agent needs to act on a finding');
  assert.match(d, /OSV PUBLISHED NO FIXED VERSION/,
    'a null fixed version is undocumented, so an agent is free to read it as "no fix needed"');
  assert.match(d, /never that AppCrane did not look/,
    'the description does not rule out the other wrong reading of null — that the field was not filled in');
});

test('the report description says coverage is per manifest, not per app', () => {
  const d = byName.get('appcrane_scan_report').description;
  assert.match(d, /`manifests_scanned`/,
    'nothing points the agent at the field saying which manifests were actually read');
  assert.match(d, /one scan row reads ONE manifest/i,
    'the description does not state the coverage unit, so an app-level clean reads as covering the whole app');
  assert.match(d, /Go service was never read/,
    'the description does not name the false clean it exists to prevent — an unscanned service beside a scanned one');
});

test('the policy description says policy is not retroactive and defaults off', () => {
  const d = byName.get('appcrane_platform_policy').description;
  assert.match(d, /NOT RETROACTIVE/,
    'an agent enabling a lever is not told that existing rows are untouched');
  assert.match(d, /NEXT write/i,
    'the description does not say what enabling a lever actually does — refuse the next write');
  assert.match(d, /default OFF/,
    'the description does not say the levers are off by default, so an agent cannot tell an upgrade changed nothing');
});

// ---------------------------------------------------------------------------
// Fleet mode must respect the MCP scope ceiling (found in review)
// ---------------------------------------------------------------------------
//
// callTool enforces mcp_app_scope on args.slug, so the per-app branch was
// covered. The fleet branch takes no slug and called fleetScanSummary(), an
// unfiltered SELECT over apps — so a key scoped to one app received the slug,
// name, status and full findings of every app on the platform. Other teams'
// CVE inventories, from a key explicitly denied access to them.
//
// The v2.42.1 note in mcpTools.js says it: a ceiling that holds on one path and
// not another is not a ceiling.

test('SECURITY: fleet mode does not leak apps outside the key\'s MCP scope', async () => {
  const scopedId = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind,mcp_app_scope) VALUES ('S','s@x.io','admin',?,1,'human',?)"
  ).run(hashApiKey(generateApiKey('dhk_mcp')), JSON.stringify(['scoped-mine'])).lastInsertRowid;
  const scoped = db.prepare('SELECT * FROM users WHERE id = ?').get(scopedId);

  for (const slug of ['scoped-mine', 'scoped-other']) {
    db.prepare("INSERT OR IGNORE INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'managed')")
      .run(slug, slug, 8000 + slug.length + (slug === 'scoped-other' ? 1 : 0));
  }

  const r = await callTool(scoped, 'appcrane_scan_report', {});
  const out = typeof r === 'string' ? JSON.parse(r) : (r?.content ? JSON.parse(r.content[0].text) : r);
  const blob = JSON.stringify(out);

  assert.doesNotMatch(blob, /scoped-other/,
    'fleet mode returned an app outside the key\'s scope — the same key is correctly refused that ' +
    'app by slug, so the ceiling holds on one path and not the other');
});
