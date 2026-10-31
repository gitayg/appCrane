// Host alert thresholds and the level they put a free-vs-total pair at.
//
// Split out of hostResources.js so updateSnapshot.js can apply the same disk
// floor: db.js imports updateSnapshot.js, and hostResources.js pulls
// in the mail, event and job-health services, none of which should load while
// the database itself is still being opened.

export const MiB = 1024 * 1024;
export const GiB = 1024 * MiB;

export const THRESHOLD_DEFAULTS = Object.freeze({
  mem_warn_pct: 10, mem_crit_pct: 5, mem_floor_mb: 512,
  disk_warn_pct: 10, disk_crit_pct: 5, disk_floor_gb: 5,
});

export function readThresholds(db) {
  const out = {};
  for (const [k, def] of Object.entries(THRESHOLD_DEFAULTS)) {
    let v = null;
    try { v = db.prepare('SELECT value FROM settings WHERE key = ?').get(`host_alert_${k}`)?.value ?? null; } catch (_) {}
    const n = v === null || v === '' ? NaN : Number(v);
    out[k] = Number.isFinite(n) && n >= 0 ? n : def;
  }
  return out;
}

/** ok / warning / critical for a free-vs-total pair; unknown when either is missing. */
export function levelFor({ freeBytes, totalBytes }, { warnPct, critPct, floorBytes }) {
  if (!Number.isFinite(freeBytes) || !Number.isFinite(totalBytes) || totalBytes <= 0) return 'unknown';
  const pct = (freeBytes / totalBytes) * 100;
  if (pct < critPct || freeBytes < floorBytes) return 'critical';
  if (pct < warnPct) return 'warning';
  return 'ok';
}

export function diskLevel(freeBytes, totalBytes, t) {
  return levelFor({ freeBytes, totalBytes }, { warnPct: t.disk_warn_pct, critPct: t.disk_crit_pct, floorBytes: t.disk_floor_gb * GiB });
}

export function fmtBytes(bytes) {
  return bytes >= GiB ? `${(bytes / GiB).toFixed(1)} GB` : `${Math.round(bytes / MiB)} MB`;
}

// Refusing work (a deploy, a self-update, a snapshot) uses the absolute floor
// only. The percent rule is for alerts: 5% of a 2 TB disk is 100 GB, and
// refusing a deploy with 90 GB free is wrong.
export function belowDiskFloor(freeBytes, t) {
  return Number.isFinite(freeBytes) && freeBytes < t.disk_floor_gb * GiB;
}

export function diskFloorText(t) {
  return `${t.disk_floor_gb} GB`;
}
