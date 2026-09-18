import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Scan-coverage honesty (v2.79.0).
//
// MEASURED ON A PRODUCTION INSTANCE: 69 of 99 app/stage rows had no usable scan
// result — 67 skipped, 2 never scanned — and the fleet report's headline was
// `assurance: "partial"`. Every number beside it was correct; the word was the
// part people read, and "partial" is also what you would call 98 of 99. The
// skips were not even mysterious: each row records WHY it was skipped, and
// nothing ever aggregated those reasons, so an operator's next move after
// reading "67 skipped" was 67 lookups.
//
// The fix is arithmetic, not adjectives, so the tests are arithmetic too. The
// 69-of-99 shape is reproduced exactly and the rendered sentence is asserted
// character for character — a coverage report whose wording is only spot-checked
// by regex is how "30 of 99" becomes "30 of 30" in a refactor and nothing goes
// red.
//
// `assurance` is deliberately NOT redefined here: it still means complete /
// none / partial over the same rows, because silently changing what a published
// word denotes is the same defect as overstating it. What is asserted is that
// the word never travels alone.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-scancov-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { callTool } = await import('../server/services/mcpTools.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const {
  coverageOf, coverageSentence, assuranceNote, reasonCounts, normalizeReason, isScannedRow, TOP_REASONS,
} = await import('../server/services/scanCoverage.js');

function mkUser(role, email) {
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(role, email, role, hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}
const admin = mkUser('admin', 'admin@example.com');

let slot = 0;
const mkApp = (slug) => db.prepare('INSERT INTO apps (name,slug,slot,source_type,visibility) VALUES (?,?,?,?,?)')
  .run(slug, slug, ++slot, 'managed', 'private').lastInsertRowid;
const scanRow = (appId, env, status, error = null) => db.prepare(
  `INSERT INTO app_vuln_scans (app_id, env, source, ecosystem, status, package_count, findings_json, error, scanned_at)
   VALUES (?,?,'scheduled',?,?,?,NULL,?,datetime('now'))`
).run(appId, env, status === 'skipped' || status === 'error' ? null : 'npm', status, status === 'ok' ? 12 : 0, error);
const clearAll = () => { db.prepare('DELETE FROM app_vuln_scans').run(); db.prepare('DELETE FROM apps').run(); };

const unwrap = (r) => (typeof r === 'string' ? JSON.parse(r) : (r?.content ? JSON.parse(r.content[0].text) : r));
const fleet = async () => unwrap(await callTool(admin, 'appcrane_scan_report', {}));

const NO_MANIFEST = 'no recognised manifest in the live release';
const NO_DEPLOYMENT = 'no live deployment, so there is no image to scan';

/**
 * The measured shape, rebuilt row for row: 99 app/stage rows, 30 with a usable
 * result, 67 skipped (for two different recorded reasons) and 2 apps that have
 * never been scanned at all.
 */
function seed69of99() {
  clearAll();
  // 48 apps x 2 stages = 96 rows, plus one app with a production row only = 97.
  const statuses = [];
  for (let i = 0; i < 30; i++) statuses.push(['ok', null]);
  for (let i = 0; i < 60; i++) statuses.push(['skipped', NO_MANIFEST]);
  for (let i = 0; i < 7; i++) statuses.push(['skipped', NO_DEPLOYMENT]);
  assert.equal(statuses.length, 97);

  let n = 0;
  for (let a = 0; a < 48; a++) {
    const id = mkApp(`app-${String(a).padStart(3, '0')}`);
    for (const env of ['production', 'sandbox']) {
      const [st, err] = statuses[n++];
      scanRow(id, env, st, err);
    }
  }
  const [st, err] = statuses[n++];
  scanRow(mkApp('app-solo'), 'production', st, err);
  // Two apps with no scan row at all: one LEFT JOIN row each.
  mkApp('never-a');
  mkApp('never-b');
}

// ---------------------------------------------------------------------------
// The 69-of-99 shape, end to end
// ---------------------------------------------------------------------------

test('the fleet report counts covered / skipped / never-scanned explicitly', async () => {
  seed69of99();
  const r = await fleet();

  assert.equal(r.row_count, 99, 'precondition: the seeded fleet is the measured shape');
  assert.deepEqual(r.coverage, {
    rows: 99,
    covered: 30,
    not_covered: 69,
    skipped: 67,
    errored: 0,
    never_scanned: 2,
    percent: 30,
  });
  assert.equal(r.unscanned_count, 69);
  assert.deepEqual(r.unscanned_by_status, { skipped: 67, 'no scan on record': 2 });
});

test('the summary OPENS with the ratio, in these exact words', async () => {
  seed69of99();
  const r = await fleet();
  const expected =
    'COVERAGE: 30 of 99 app/stage rows have a usable scan result (30%) — 69 do not: ' +
    '67 skipped, 2 never scanned. Nothing is known about those.';
  assert.ok(r.summary.startsWith(expected),
    `the coverage sentence must lead the summary verbatim.\nexpected start: ${expected}\nactual start:   ${r.summary.slice(0, expected.length)}`);
});

test('the top skip REASONS are named and counted, not left as a bare "67 skipped"', async () => {
  seed69of99();
  const r = await fleet();
  assert.deepEqual(r.skip_reasons, [
    { reason: NO_MANIFEST, rows: 60 },
    { reason: NO_DEPLOYMENT, rows: 7 },
  ]);
  assert.deepEqual(r.error_reasons, []);
  assert.match(r.summary, new RegExp(`Why rows were skipped: ${NO_MANIFEST} \\(60\\); ${NO_DEPLOYMENT} \\(7\\)\\.`));
});

test('"partial" is kept for API consumers but can no longer be read as "mostly covered"', async () => {
  seed69of99();
  const r = await fleet();
  assert.equal(r.assurance, 'partial', 'the published values are unchanged: none / partial / complete');
  assert.equal(r.assurance_note,
    'assurance "partial" means SOME rows are covered, anywhere from 1% to 99% — it is not a synonym for "most". ' +
    'Here it is 30 of 99 (30%); read the coverage counts, not the word.');
  assert.match(r.summary, /not a synonym for "most"/);
  assert.doesNotMatch(r.summary, /mostly (covered|scanned)/i);
});

test('a nearly-covered fleet and a barely-covered one are both "partial" and read differently', async () => {
  seed69of99();
  const low = await fleet();

  clearAll();
  for (let a = 0; a < 49; a++) {
    const id = mkApp(`ok-${a}`);
    scanRow(id, 'production', 'ok');
    scanRow(id, 'sandbox', 'ok');
  }
  scanRow(mkApp('ok-last'), 'production', 'skipped', NO_MANIFEST);
  const high = await fleet();

  assert.equal(low.assurance, high.assurance, 'precondition: one word covers both fleets');
  assert.equal(low.coverage.percent, 30);
  assert.equal(high.coverage.percent, 98);
  assert.notEqual(low.summary.split('.')[0], high.summary.split('.')[0],
    'the leading sentence must distinguish 30% coverage from 98% coverage');
});

// ---------------------------------------------------------------------------
// Denominator and edges
// ---------------------------------------------------------------------------

test('the percentage is computed over ALL rows, never over the scanned ones', () => {
  const rows = [
    ...Array.from({ length: 30 }, () => ({ status: 'ok' })),
    ...Array.from({ length: 67 }, () => ({ status: 'skipped', error: NO_MANIFEST })),
    ...Array.from({ length: 2 }, () => ({})),
  ];
  const c = coverageOf(rows);
  assert.equal(c.rows, 99);
  assert.equal(c.percent, 30, 'covered/rows — covered/covered is 100% and is the mistake being guarded');
  assert.equal(coverageOf([]).percent, 0);
});

test('the percentage floors, so a sliver of coverage never rounds up into looking like coverage', () => {
  const rows = [{ status: 'ok' }, ...Array.from({ length: 199 }, () => ({ status: 'skipped' }))];
  assert.equal(coverageOf(rows).percent, 0, '1 of 200 is 0.5% and must not render as 1%');
});

test('findings are COVERAGE — a vulnerable row was scanned, and hiding it behind a coverage complaint is the mirror mistake', () => {
  const c = coverageOf([{ status: 'findings' }, { status: 'ok' }, { status: 'error', error: 'OSV unreachable' }]);
  assert.equal(c.covered, 2);
  assert.equal(c.errored, 1);
  assert.equal(isScannedRow({ status: 'findings' }), true);
  assert.equal(isScannedRow({ status: 'skipped' }), false);
  assert.equal(isScannedRow(null), false);
});

test('a fully covered fleet says so without the caveat', async () => {
  clearAll();
  const id = mkApp('clean');
  scanRow(id, 'production', 'ok');
  scanRow(id, 'sandbox', 'ok');
  const r = await fleet();
  assert.deepEqual(r.coverage, {
    rows: 2, covered: 2, not_covered: 0, skipped: 0, errored: 0, never_scanned: 0, percent: 100,
  });
  assert.equal(r.assurance, 'complete');
  assert.ok(r.summary.startsWith('COVERAGE: 2 of 2 app/stage rows have a usable scan result (100%).'));
});

test('a fleet with nothing covered reports 0%, and never in the language of a clean result', async () => {
  clearAll();
  const id = mkApp('dark');
  scanRow(id, 'production', 'skipped', NO_MANIFEST);
  scanRow(id, 'sandbox', 'error', 'OSV unreachable: fetch failed');
  const r = await fleet();
  assert.equal(r.coverage.percent, 0);
  assert.equal(r.assurance, 'none');
  assert.deepEqual(r.error_reasons, [{ reason: 'OSV unreachable: fetch failed', rows: 1 }]);
  assert.match(r.summary, /Why rows errored: OSV unreachable: fetch failed \(1\)\./);
  assert.doesNotMatch(r.summary, /no vulnerabilities|are clean|is clean/i);
});

// ---------------------------------------------------------------------------
// Reason aggregation
// ---------------------------------------------------------------------------

test('reasons are ordered by how many rows they explain, and the tail is grouped', () => {
  const rows = [];
  for (let i = 0; i < TOP_REASONS + 3; i++) {
    for (let n = 0; n <= i; n++) rows.push({ status: 'skipped', error: `reason ${i}` });
  }
  const counts = reasonCounts(rows);
  assert.equal(counts.length, TOP_REASONS + 1);
  assert.equal(counts[0].reason, `reason ${TOP_REASONS + 2}`, 'most common first');
  assert.equal(counts.at(-1).reason, '3 other reason(s)');
  assert.equal(counts.reduce((n, c) => n + c.rows, 0), rows.length,
    'grouping the tail must not lose rows');
});

test('a missing or oversized reason is reported, never dropped', () => {
  assert.deepEqual(reasonCounts([{ status: 'skipped' }, { status: 'skipped', error: '  ' }]),
    [{ reason: 'reason not recorded', rows: 2 }]);
  const long = normalizeReason('x'.repeat(500));
  assert.equal(long.length, 160);
  assert.ok(long.endsWith('…'));
});

// ---------------------------------------------------------------------------
// One app
// ---------------------------------------------------------------------------

test('a single app reports its own coverage and each unscanned stage\'s recorded reason', async () => {
  clearAll();
  const id = mkApp('halfway');
  scanRow(id, 'production', 'skipped', NO_MANIFEST);
  scanRow(id, 'sandbox', 'ok');
  const r = unwrap(await callTool(admin, 'appcrane_scan_report', { slug: 'halfway' }));

  assert.deepEqual(r.coverage, {
    rows: 2, covered: 1, not_covered: 1, skipped: 1, errored: 0, never_scanned: 0, percent: 50,
  });
  assert.deepEqual(r.unscanned_reasons, { production: NO_MANIFEST });
  assert.ok(r.summary.startsWith(
    `COVERAGE: 1 of 2 stages have a usable scan result (50%) — 1 do not: 1 skipped. Nothing is known about those.`));
  assert.match(r.summary, new RegExp(`NOT SCANNED: production \\(skipped: ${NO_MANIFEST}\\)`));
});

test('an app that was never scanned says so for both stages', async () => {
  clearAll();
  mkApp('untouched');
  const r = unwrap(await callTool(admin, 'appcrane_scan_report', { slug: 'untouched' }));
  assert.equal(r.coverage.never_scanned, 2);
  assert.equal(r.coverage.percent, 0);
  assert.deepEqual(r.unscanned_reasons, { production: 'no scan on record', sandbox: 'no scan on record' });
  assert.equal(r.assurance, 'none');
});

// ---------------------------------------------------------------------------
// The helpers, directly
// ---------------------------------------------------------------------------

test('coverageSentence and assuranceNote are single-sourced, so two surfaces cannot word it differently', () => {
  const c = coverageOf([{ status: 'ok' }, { status: 'skipped' }, {}]);
  assert.equal(coverageSentence(c),
    'COVERAGE: 1 of 3 app/stage rows have a usable scan result (33%) — 2 do not: 1 skipped, 1 never scanned. Nothing is known about those.');
  assert.equal(coverageSentence(c, 'stage'),
    'COVERAGE: 1 of 3 stages have a usable scan result (33%) — 2 do not: 1 skipped, 1 never scanned. Nothing is known about those.');
  assert.match(assuranceNote(coverageOf([])), /describes nothing/);
  assert.match(assuranceNote(coverageOf([{ status: 'ok' }])), /"complete" means every row/);
  assert.match(assuranceNote(coverageOf([{ status: 'skipped' }])), /"none" means NO row/);
});
