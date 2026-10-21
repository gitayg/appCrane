import { join, resolve, sep } from 'path';
import { mkdir, readdir, rm, stat } from 'fs/promises';
import { existsSync, statSync } from 'fs';
import { randomBytes } from 'crypto';
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { dataDir, backupsDir, freeBytes, repoRoot } from './backupFiles.js';
import { listLocalBackups, localBackupsDir } from './localBackup.js';
import { listLocalRepoSlugs, reposRoot } from './localGit.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';
import { recordEvent } from './eventStore.js';
import {
  check, assertInside, extractInto, verifyDataTree, verifyRepoArchive, summarizeRepos, defaultPgRestoreList,
} from './restoreDrillChecks.js';

// Scheduled restore drills. A drill takes the newest local nightly backup and,
// when an off-site destination is configured, the newest complete off-site set
// (downloaded and verified by backupScheduler.fetchS3Backup), restores each
// into its own scratch directory under DATA_DIR/drills, checks what came back
// (restoreDrillChecks.js) and deletes the scratch directory. It never opens
// the live database for writing, never reads or writes the live .env, and
// never touches DATA_DIR/repos: the repository checks unbundle into the
// scratch directory through localGit's staging helper.
//
// Evidence per source is one restore_drills row: backup age at the start
// (RPO), restore + verification time (RTO), every check, and whether the
// scratch directory is gone afterwards.

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const HISTORY_KEEP = 200;

const K = {
  enabled: 'restore_drill_enabled',
  interval: 'restore_drill_interval_days',
  hour: 'restore_drill_hour',
  tolerance: 'restore_drill_tolerance_pct',
};
export const INTERVAL_DEFAULT = 7;
export const HOUR_DEFAULT = 5;
export const TOLERANCE_DEFAULT = 20;

const REPO_ARCHIVE_RE = /^appcrane-repo-([a-z0-9][a-z0-9-]{0,99})-[0-9a-f]{12}-\d{4}-\d{2}-\d{2}\.tar$/;

const defaultDeps = {
  freeBytes: (dir) => freeBytes(dir),
  offSite: async () => (await import('./backupScheduler.js')).offSiteState(),
  listS3: async () => (await import('./backupScheduler.js')).listS3Backups(),
  fetchS3: async (setId, dir) => (await import('./backupScheduler.js')).fetchS3Backup(setId, dir),
  pgRestoreList: defaultPgRestoreList,
};
let deps = { ...defaultDeps };
export function _setDrillDepsForTests(d) { deps = { ...defaultDeps, ...(d || {}) }; }

export const drillsRoot = () => resolve(join(dataDir(), 'drills'));

function get(db, k) { return db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value ?? null; }
function set(db, k, v, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(k, String(v), userId ?? null);
}
const clampInt = (v, lo, hi, dflt) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt;
};

export function getDrillConfig() {
  const db = getDb();
  const raw = get(db, K.enabled);
  return {
    enabled: raw === null || raw === '' ? true : raw === '1',
    interval_days: clampInt(get(db, K.interval), 1, 90, INTERVAL_DEFAULT),
    hour: clampInt(get(db, K.hour), 0, 23, HOUR_DEFAULT),
    tolerance_pct: clampInt(get(db, K.tolerance), 0, 100, TOLERANCE_DEFAULT),
  };
}

export function setDrillConfig(patch, userId) {
  const db = getDb();
  if (patch.enabled !== undefined) set(db, K.enabled, patch.enabled ? '1' : '0', userId);
  if (patch.interval_days !== undefined) set(db, K.interval, clampInt(patch.interval_days, 1, 90, INTERVAL_DEFAULT), userId);
  if (patch.hour !== undefined) set(db, K.hour, clampInt(patch.hour, 0, 23, HOUR_DEFAULT), userId);
  if (patch.tolerance_pct !== undefined) set(db, K.tolerance, clampInt(patch.tolerance_pct, 0, 100, TOLERANCE_DEFAULT), userId);
  const cfg = getDrillConfig();
  if (_timer) jobStarted('restore-drill', { enabled: () => getDrillConfig().enabled, cadenceMs: cfg.interval_days * DAY });
  return cfg;
}

const rowView = (r) => ({
  id: r.id, run_id: r.run_id, source: r.source, trigger: r.trigger, status: r.status,
  backup_ref: r.backup_ref, backup_created_at: r.backup_created_at, backup_bytes: r.backup_bytes,
  rpo_seconds: r.rpo_seconds, rto_ms: r.rto_ms, checks: JSON.parse(r.checks_json || '[]'),
  error: r.error, cleaned_up: r.cleaned_up === 1, triggered_by: r.triggered_by,
  started_at: r.started_at, finished_at: r.finished_at,
});

export function listDrills({ limit = 50, from = null, to = null } = {}) {
  const db = getDb();
  const where = [];
  const args = [];
  if (from) { where.push('started_at >= ?'); args.push(from); }
  if (to) { where.push('started_at <= ?'); args.push(to); }
  const sql = `SELECT * FROM restore_drills ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`;
  return db.prepare(sql).all(...args, Math.min(Math.max(1, limit), 5000)).map(rowView);
}

let running = null;
export const isDrillRunning = () => !!running;

function insertRow(db, { runId, source, trigger, userId }) {
  return Number(db.prepare(`INSERT INTO restore_drills (run_id, source, trigger, status, triggered_by, started_at)
    VALUES (?, ?, ?, 'running', ?, ?)`).run(runId, source, trigger, userId ?? null, new Date().toISOString()).lastInsertRowid);
}

function finishRow(db, id, r) {
  db.prepare(`UPDATE restore_drills SET status = ?, backup_ref = ?, backup_created_at = ?, backup_bytes = ?,
      rpo_seconds = ?, rto_ms = ?, checks_json = ?, error = ?, cleaned_up = ?, finished_at = ? WHERE id = ?`)
    .run(r.status, r.backup_ref ?? null, r.backup_created_at ?? null, r.backup_bytes ?? null,
      r.rpo_seconds ?? null, r.rto_ms ?? null, JSON.stringify(r.checks || []), r.error ? String(r.error).slice(0, 500) : null,
      r.cleaned_up ? 1 : 0, new Date().toISOString(), id);
}

async function newScratch(runId, source) {
  const root = drillsRoot();
  await mkdir(root, { recursive: true, mode: 0o700 });
  const dir = assertInside(root, join(root, `${runId}-${source}`));
  for (const live of [join(dataDir(), 'deployhub.db'), join(repoRoot, '.env'), reposRoot()]) {
    const l = resolve(live);
    if (dir === l || dir.startsWith(l + sep) || l.startsWith(dir + sep)) throw new Error('scratch area overlaps live data');
  }
  await mkdir(dir, { mode: 0o700 });
  return dir;
}

function liveDbBytes() {
  try { return statSync(join(dataDir(), 'deployhub.db')).size; } catch (_) { return 0; }
}

/** null when room is fine, else the refusal text. Needs 2x the larger of the backup and the live DB. */
function diskRefusal(backupBytes) {
  const estimate = Math.max(backupBytes || 0, liveDbBytes());
  const need = 2 * estimate;
  const free = deps.freeBytes(dataDir());
  if (free === null || free === undefined) return { refusal: null, free: null, need };
  return { refusal: free < need ? `Not enough free disk for a drill: ${free} bytes free, ${need} needed (2x the backup size)` : null, free, need };
}

async function localRepoArchives() {
  let names = [];
  try { names = await readdir(backupsDir()); } catch (_) { return new Map(); }
  const newest = new Map();
  for (const name of names) {
    const m = REPO_ARCHIVE_RE.exec(name);
    if (!m) continue;
    let st;
    try { st = await stat(join(backupsDir(), name)); } catch (_) { continue; }
    if (!st.isFile()) continue;
    const prev = newest.get(m[1]);
    if (!prev || st.mtimeMs > prev.mtimeMs) newest.set(m[1], { path: join(backupsDir(), name), mtimeMs: st.mtimeMs });
  }
  return newest;
}

function liveSlugs() {
  try { return listLocalRepoSlugs(); } catch (_) { return []; }
}

const rpoSeconds = (createdAt, startedMs) => {
  const t = Date.parse(createdAt);
  return Number.isFinite(t) ? Math.max(0, Math.round((startedMs - t) / 1000)) : null;
};

function outcome(checks) {
  return checks.some((c) => c.status === 'fail') ? 'failed' : 'passed';
}

async function withScratch(runId, source, fn) {
  const scratch = await newScratch(runId, source);
  let result;
  try {
    result = await fn(scratch);
    deps.observe?.(source, scratch);
  } finally {
    await rm(scratch, { recursive: true, force: true }).catch(() => {});
  }
  const cleaned = !existsSync(scratch);
  result.cleaned_up = cleaned;
  result.checks.push(check('cleanup', 'Scratch area removed', cleaned ? 'pass' : 'fail'));
  if (!cleaned) result.status = 'failed';
  return result;
}

async function drillLocal(ctx) {
  const list = await listLocalBackups();
  if (!list.length) {
    return { status: 'failed', error: 'No local backup archive exists to restore.', checks: [check('backup_exists', 'A local backup exists', 'fail')] };
  }
  const b = list[0];
  const base = { backup_ref: b.file, backup_created_at: b.modified_at, backup_bytes: b.bytes, rpo_seconds: rpoSeconds(b.modified_at, ctx.startedMs) };
  const disk = diskRefusal(b.bytes);
  if (disk.refusal) return { ...base, status: 'refused', error: disk.refusal, checks: [check('disk_space', 'Free disk at least 2x the backup', 'fail', { free_bytes: disk.free, needed_bytes: disk.need })] };
  return withScratch(ctx.runId, 'local', async (scratch) => {
    const t0 = Date.now();
    const checks = [disk.free === null
      ? check('disk_space', 'Free disk at least 2x the backup', 'warn', 'free space could not be measured')
      : check('disk_space', 'Free disk at least 2x the backup', 'pass', { free_bytes: disk.free, needed_bytes: disk.need })];
    const ex = await extractInto(join(localBackupsDir(), b.file), join(scratch, 'data'), { gzip: true });
    checks.push(ex);
    if (ex.status === 'pass') {
      checks.push(...(await verifyDataTree(join(scratch, 'data'), { liveDb: ctx.db, tolerancePct: ctx.cfg.tolerance_pct, pgRestoreList: deps.pgRestoreList })).checks);
    }
    const archives = await localRepoArchives();
    const slugs = liveSlugs();
    const results = [];
    for (const slug of slugs) {
      const a = archives.get(slug);
      if (a) results.push(await verifyRepoArchive(a.path, scratch, { slug }));
    }
    checks.push(...summarizeRepos(results, slugs.filter((s) => !archives.has(s))));
    return { ...base, status: outcome(checks), rto_ms: Date.now() - t0, checks };
  });
}

async function drillS3(ctx) {
  let st;
  try { st = await deps.offSite(); } catch (e) { st = { configured: false }; }
  if (!st?.configured) {
    return { status: 'skipped', error: 'No off-site destination is configured.', checks: [check('offsite_configured', 'Off-site destination configured', 'skipped')] };
  }
  let listing;
  try { listing = await deps.listS3(); } catch (e) {
    return { status: 'failed', error: `Could not list off-site backups: ${String(e.message).slice(0, 200)}`, checks: [check('offsite_list', 'Off-site backups list', 'fail')] };
  }
  const sets = (listing.backups || []).filter((s) => s.own && s.complete && !s.legacy)
    .sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
  if (!sets.length) {
    return { status: 'failed', error: 'Off-site is configured but holds no complete backup set from this host.', checks: [check('offsite_set_exists', 'A complete off-site set exists', 'fail')] };
  }
  const s = sets[0];
  const base = { backup_ref: s.id, backup_created_at: s.created_at, backup_bytes: s.bytes, rpo_seconds: rpoSeconds(s.created_at, ctx.startedMs) };
  const disk = diskRefusal(s.bytes);
  if (disk.refusal) return { ...base, status: 'refused', error: disk.refusal, checks: [check('disk_space', 'Free disk at least 2x the backup', 'fail', { free_bytes: disk.free, needed_bytes: disk.need })] };
  return withScratch(ctx.runId, 's3', async (scratch) => {
    const t0 = Date.now();
    const checks = [check('disk_space', 'Free disk at least 2x the backup', disk.free === null ? 'warn' : 'pass', { free_bytes: disk.free, needed_bytes: disk.need })];
    let fetched;
    try {
      fetched = await deps.fetchS3(s.id, assertInside(scratch, join(scratch, 'fetch')));
      checks.push(check('offsite_fetch', 'Set downloads and verifies against its manifest', 'pass', { artifacts: fetched.files.length, encrypted: !!fetched.manifest?.encryption }));
    } catch (e) {
      checks.push(check('offsite_fetch', 'Set downloads and verifies against its manifest', 'fail', String(e.message).slice(0, 300)));
      return { ...base, status: 'failed', rto_ms: Date.now() - t0, checks };
    }
    for (const f of fetched.files) assertInside(scratch, f.path);
    const data = fetched.files.find((f) => f.kind === 'data');
    if (!data) checks.push(check('archive_extract', 'Archive extracts', 'fail', 'the set has no data archive'));
    else {
      const ex = await extractInto(data.path, join(scratch, 'data'), { gzip: true });
      checks.push(ex);
      if (ex.status === 'pass') {
        checks.push(...(await verifyDataTree(join(scratch, 'data'), { liveDb: ctx.db, tolerancePct: ctx.cfg.tolerance_pct, pgRestoreList: deps.pgRestoreList })).checks);
      }
    }
    const results = [];
    for (const f of fetched.files.filter((x) => x.kind === 'repo')) results.push(await verifyRepoArchive(f.path, scratch, { slug: f.slug }));
    const covered = new Set(results.map((r) => r.slug));
    checks.push(...summarizeRepos(results, fetched.manifest?.repos?.included === false ? [] : liveSlugs().filter((x) => !covered.has(x))));
    return { ...base, status: outcome(checks), rto_ms: Date.now() - t0, checks };
  });
}

function platformAdminEmails(db) {
  return db.prepare("SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL").all().map((r) => r.email);
}

async function alertFailure(db, runId, rows) {
  const bad = rows.filter((r) => r.status === 'failed' || r.status === 'refused');
  const lines = bad.map((r) => {
    const failed = r.checks.filter((c) => c.status === 'fail').map((c) => c.label);
    return `- ${r.source}: ${r.status}${r.error ? ` (${r.error})` : ''}${failed.length ? `; failed checks: ${failed.join(', ')}` : ''}`;
  });
  recordEvent({
    kind: 'backup.restore_drill', severity: 'critical',
    summary: `Restore drill failed: ${bad.map((r) => `${r.source} ${r.status}`).join(', ')}`,
    refTable: 'restore_drills', refId: bad[0]?.id,
    data: { run_id: runId, sources: bad.map((r) => ({ source: r.source, status: r.status, failed_checks: r.checks.filter((c) => c.status === 'fail').map((c) => c.id) })) },
  });
  const { enqueueEmail } = await import('./emailQueue.js');
  const day = new Date().toISOString().slice(0, 10);
  for (const to of platformAdminEmails(db)) {
    try {
      enqueueEmail({
        to, appId: null, source: 'restore-drill', idempotencyKey: `restore-drill:${day}:${to}`,
        subject: 'AppCrane restore drill failed',
        text: `A restore drill could not prove that a backup restores.\n\n${lines.join('\n')}\n\nNothing live was touched. See Settings > Backup > Restore drills.`,
      });
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[restore-drill] alert skipped: ${e.message}`);
    }
  }
}

/**
 * Run one drill now. Resolves with { run_id, status, results } and does not
 * throw for a failed drill: the outcome is the evidence, recorded per source.
 */
export async function runRestoreDrill({ trigger = 'manual', userId = null } = {}) {
  if (running) throw Object.assign(new Error('A restore drill is already running'), { status: 409, code: 'ALREADY_RUNNING' });
  const runId = `${new Date().toISOString().replace(/[:.]/g, '-')}-${randomBytes(4).toString('hex')}`;
  running = runId;
  const db = getDb();
  const cfg = getDrillConfig();
  const ctx = { runId, db, cfg, startedMs: Date.now() };
  const results = [];
  try {
    for (const [source, fn] of [['local', drillLocal], ['s3', drillS3]]) {
      const id = insertRow(db, { runId, source, trigger, userId });
      let r;
      try {
        r = await fn(ctx);
      } catch (e) {
        r = { status: 'failed', error: String(e.message).slice(0, 300), checks: [check('drill', 'Drill ran', 'fail', String(e.message).slice(0, 300))] };
      }
      finishRow(db, id, r);
      results.push({ id, source, ...r });
    }
    const status = results.some((r) => r.status === 'failed' || r.status === 'refused')
      ? 'failed' : results.every((r) => r.status === 'skipped') ? 'skipped' : 'passed';
    if (status === 'failed') await alertFailure(db, runId, results).catch((e) => log.warn(`[restore-drill] alert failed: ${e.message}`));
    else if (status === 'passed') {
      recordEvent({ kind: 'backup.restore_drill', severity: 'info', summary: 'Restore drill passed', refTable: 'restore_drills', refId: results[0].id, data: { run_id: runId } });
    }
    setJobDetail('restore-drill', { last_run_id: runId, last_status: status, sources: results.map((r) => ({ source: r.source, status: r.status, rpo_seconds: r.rpo_seconds ?? null, rto_ms: r.rto_ms ?? null })) });
    db.prepare('DELETE FROM restore_drills WHERE id NOT IN (SELECT id FROM restore_drills ORDER BY id DESC LIMIT ?)').run(HISTORY_KEEP);
    log.info(`[restore-drill] ${runId}: ${status} (${results.map((r) => `${r.source}=${r.status}`).join(', ')})`);
    return { run_id: runId, status, results: results.map(({ id }) => rowView(db.prepare('SELECT * FROM restore_drills WHERE id = ?').get(id))) };
  } finally {
    running = null;
  }
}

/** A drill interrupted by a restart leaves a 'running' row and a scratch dir; close both. */
export async function sweepInterruptedDrills() {
  if (running) return;
  const db = getDb();
  db.prepare(`UPDATE restore_drills SET status = 'failed', error = 'Interrupted (the server stopped during the drill)', finished_at = ?
              WHERE status = 'running'`).run(new Date().toISOString());
  await rm(drillsRoot(), { recursive: true, force: true }).catch(() => {});
}

function lastStartedMs(db) {
  const r = db.prepare("SELECT started_at FROM restore_drills WHERE status != 'running' ORDER BY id DESC LIMIT 1").get();
  const t = r ? Date.parse(r.started_at) : NaN;
  return Number.isFinite(t) ? t : null;
}

export function drillDue(now = new Date()) {
  const cfg = getDrillConfig();
  if (!cfg.enabled || running) return false;
  if (now.getHours() < cfg.hour) return false;
  const last = lastStartedMs(getDb());
  return last === null || now.getTime() - last >= cfg.interval_days * DAY - HOUR;
}

let _timer = null;
export function startRestoreDrillScheduler() {
  if (_timer) return;
  jobStarted('restore-drill', { enabled: () => getDrillConfig().enabled, cadenceMs: getDrillConfig().interval_days * DAY });
  const tick = async () => {
    try {
      if (!drillDue()) return;
      await trackJob('restore-drill', () => runRestoreDrill({ trigger: 'schedule' }));
    } catch (e) {
      log.warn(`[restore-drill] scheduler tick failed: ${e.message}`);
    }
  };
  sweepInterruptedDrills().catch(() => {}).finally(() => { tick(); });
  _timer = setInterval(() => { tick().catch(() => {}); }, HOUR);
  _timer.unref?.();
  log.info('[restore-drill] scheduler started (hourly check)');
}

export function stopRestoreDrillScheduler() {
  if (_timer) { clearInterval(_timer); _timer = null; }
}
