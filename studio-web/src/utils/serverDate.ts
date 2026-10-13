/**
 * A timestamp from the AppCrane API as a Date.
 *
 * SQLite's datetime('now') stores UTC as 'YYYY-MM-DD HH:MM:SS' with NO zone
 * marker, and `new Date()` reads a zone-less string as the BROWSER's local time.
 * Every such time was shifted by the viewer's UTC offset: a deploy made a moment
 * ago showed as "4h ago" for a user four hours behind UTC (reported from the
 * request queue). A value that already carries a zone ('Z' or ±hh:mm) is left
 * alone; a numeric epoch passes through.
 */
export function serverDate(v: string | number | null | undefined): Date {
  if (v == null || v === '') return new Date(NaN)
  if (typeof v === 'number') return new Date(v)
  const s = String(v).trim()
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) return new Date(s.replace(' ', 'T') + 'Z')
  return new Date(s)
}
