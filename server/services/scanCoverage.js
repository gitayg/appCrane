/**
 * How much of the fleet a scan report actually covers (v2.79.0).
 *
 * WHAT WENT WRONG. Measured on a production instance: 69 of 99 app/stage rows
 * had no usable scan result — 67 skipped, 2 never scanned — and the fleet
 * report's one-word verdict was `assurance: "partial"`. Every number beside it
 * was true and the word was the thing people read, and "partial" is what you
 * would also call 95 of 99. A reader came away believing the fleet was mostly
 * covered when under a third of it was, and the skips were not even mysterious:
 * each one records WHY in its own row, and nothing aggregated them.
 *
 * WHAT `assurance` NOW MEANS. Exactly what it always meant: `complete` when
 * every row is covered, `none` when no row is, `partial` for everything
 * between. It was NOT redefined and no fourth value was added — a consumer
 * switching on those three strings keeps working, and quietly changing what a
 * word denotes is the same defect as overstating it. What changed is that the
 * word no longer travels alone: `coverage` carries the counts, `assurance_note`
 * says in words that `partial` spans 1% to 99%, and the summary now OPENS with
 * the ratio instead of reaching it in its third clause.
 *
 * COVERED means a scan completed: `ok` or `findings`. `findings` is a completed
 * scan and counting it as unscanned would hide the rows that are actually
 * vulnerable behind a coverage complaint. `skipped` (nothing AppCrane can read)
 * and `error` (OSV unreachable, unparseable manifest) are not results, and
 * neither is the absence of a row.
 */

/** A row whose scan COMPLETED. Everything else is an absence of evidence. */
export const isScannedRow = (r) => r?.status === 'ok' || r?.status === 'findings';

/** Reason strings come from the scanner and can quote an image ref; bound them. */
const REASON_MAX = 160;
const NO_REASON = 'reason not recorded';

/** How many reasons are named before the tail is grouped. */
export const TOP_REASONS = 5;

export function normalizeReason(text) {
  const s = String(text ?? '').trim().replace(/\s+/g, ' ');
  if (!s) return NO_REASON;
  return s.length > REASON_MAX ? `${s.slice(0, REASON_MAX - 1)}…` : s;
}

/**
 * Count rows by their recorded reason, most common first.
 *
 * The reason lives in the scan row's `error` column for BOTH `skipped` and
 * `error` — the scanner writes the sentence it would want read there. Dropping
 * it and reporting only "67 skipped" leaves an operator with 67 lookups to find
 * out that most of them are the same one-line cause.
 *
 * @returns {Array<{ reason: string, rows: number }>} at most TOP_REASONS + 1
 *   entries; the tail is grouped as "N other reason(s)".
 */
export function reasonCounts(rows) {
  const counts = new Map();
  for (const r of rows) {
    const k = normalizeReason(r?.error);
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  const sorted = [...counts.entries()]
    .map(([reason, n]) => ({ reason, rows: n }))
    .sort((a, b) => (b.rows - a.rows) || a.reason.localeCompare(b.reason));
  if (sorted.length <= TOP_REASONS + 1) return sorted;
  const head = sorted.slice(0, TOP_REASONS);
  const tail = sorted.slice(TOP_REASONS);
  head.push({
    reason: `${tail.length} other reason(s)`,
    rows: tail.reduce((n, t) => n + t.rows, 0),
  });
  return head;
}

/**
 * Explicit counts for a set of scan rows.
 *
 * `percent` is floored, not rounded: 30 of 99 reports 30%, and a fleet with one
 * covered row out of 200 must not round up to a number that looks like coverage.
 * The denominator is always `rows`, the total the caller was asked about —
 * computing a percentage over anything smaller (the scanned rows, the apps with
 * a row at all) is the specific arithmetic that turns 30% into 100%.
 */
export function coverageOf(rows) {
  const total = rows.length;
  const covered = rows.filter(isScannedRow).length;
  const skipped = rows.filter((r) => r?.status === 'skipped').length;
  const errored = rows.filter((r) => r?.status === 'error').length;
  const neverScanned = rows.filter((r) => !r?.status).length;
  return {
    rows: total,
    covered,
    not_covered: total - covered,
    skipped,
    errored,
    never_scanned: neverScanned,
    percent: total ? Math.floor((covered / total) * 100) : 0,
  };
}

/** The sentence a coverage report opens with. */
export function coverageSentence(c, unit = 'app/stage row') {
  const plural = (n) => (n === 1 ? unit : `${unit}s`);
  if (c.rows === 0) return `COVERAGE: no ${plural(0)} to report on.`;
  if (c.covered === c.rows) {
    return `COVERAGE: ${c.covered} of ${c.rows} ${plural(c.rows)} have a usable scan result (100%).`;
  }
  const parts = [];
  if (c.skipped) parts.push(`${c.skipped} skipped`);
  if (c.errored) parts.push(`${c.errored} errored`);
  if (c.never_scanned) parts.push(`${c.never_scanned} never scanned`);
  return `COVERAGE: ${c.covered} of ${c.rows} ${plural(c.rows)} have a usable scan result (${c.percent}%) — ` +
    `${c.not_covered} do not: ${parts.join(', ')}. Nothing is known about those.`;
}

/**
 * Said beside `assurance` so the word cannot be read as a proportion. Kept as
 * one function so the API surface and the per-app branch cannot word it
 * differently.
 */
export function assuranceNote(c) {
  if (c.rows === 0) return 'assurance is reported over zero rows: it describes nothing.';
  if (c.covered === c.rows) return 'assurance "complete" means every row has a usable scan result.';
  if (c.covered === 0) return 'assurance "none" means NO row has a usable scan result.';
  return 'assurance "partial" means SOME rows are covered, anywhere from 1% to 99% — it is not a synonym for "most". ' +
    `Here it is ${c.covered} of ${c.rows} (${c.percent}%); read the coverage counts, not the word.`;
}
