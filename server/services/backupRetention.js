/**
 * Off-site backup retention: which backup sets to keep in the bucket.
 *
 * Grandfather-father-son over UTC calendar periods. The newest complete set of
 * each of the most recent `daily` days, `weekly` ISO weeks and `monthly`
 * months is kept; one set can fill several slots. The newest complete set is
 * always kept. An incomplete set (no manifest: an upload that died part-way)
 * is deleted once a newer complete set exists, and kept otherwise, because it
 * may be an upload still in flight.
 *
 * Pure: takes sets, returns a plan. Listing, ownership and the refusal rules
 * live in backupScheduler.js.
 */

export const RETENTION_DEFAULTS = { daily: 7, weekly: 4, monthly: 6 };

export function isoWeek(d) {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = t.getUTCDay() || 7;
  t.setUTCDate(t.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((t - yearStart) / 86400000 + 1) / 7);
  return `${t.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
}

/**
 * @param {{id:string, at:string, complete:boolean}[]} sets
 * @param {{daily:number, weekly:number, monthly:number}} policy
 * @returns {{ keep: {id, reasons: string[]}[], remove: string[] }}
 */
export function planRetention(sets, policy = RETENTION_DEFAULTS) {
  const sorted = [...sets].sort((a, b) => (a.at === b.at ? (a.id < b.id ? 1 : -1) : (a.at < b.at ? 1 : -1)));
  const complete = sorted.filter((s) => s.complete);
  const reasons = new Map();
  const add = (id, r) => { if (!reasons.has(id)) reasons.set(id, []); reasons.get(id).push(r); };

  const slots = [
    ['daily', policy.daily, (d) => d.toISOString().slice(0, 10)],
    ['weekly', policy.weekly, isoWeek],
    ['monthly', policy.monthly, (d) => d.toISOString().slice(0, 7)],
  ];
  for (const [name, count, period] of slots) {
    const seen = new Set();
    for (const s of complete) {
      if (seen.size >= count) break;
      const p = period(new Date(s.at));
      if (seen.has(p)) continue;
      seen.add(p);
      add(s.id, name);
    }
  }
  if (complete.length) add(complete[0].id, 'newest');

  const newestComplete = complete[0]?.at || null;
  for (const s of sorted) {
    if (!s.complete && (newestComplete === null || s.at > newestComplete)) add(s.id, 'incomplete-newer-than-last-complete');
  }

  const keep = sorted.filter((s) => reasons.has(s.id)).map((s) => ({ id: s.id, reasons: reasons.get(s.id) }));
  const remove = sorted.filter((s) => !reasons.has(s.id)).map((s) => s.id);
  return { keep, remove };
}
