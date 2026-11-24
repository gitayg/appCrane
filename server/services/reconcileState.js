import { execFile } from 'child_process';
import { existsSync, lstatSync, readdirSync, readFileSync, readlinkSync } from 'fs';
import { join, resolve, sep } from 'path';
import { promisify } from 'util';
import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { regularFileInside } from '../utils/paths.js';
import log from '../utils/logger.js';
import { APP_DIR_KINDS, KIND_OF_TREE, dataRoot, isAppDirName, moveToTrash, purgeTrash } from './appTrash.js';
import { jobStarted, trackJob } from './jobHealth.js';

// What the database says against what Docker and the disk hold.
//
// Three outages had one cause: a row saying something exists that does not.
// A production env with no container probed every 30 s for months; a deleted
// app's directories and probes left behind; a sandbox whose deploys failed
// skipped by a later job with only a log line. collectFindings() names each
// such mismatch as a typed finding, runReconcile() stores them
// (reconcile_findings, migration 275) and fixes only the two that touch no
// data: it pauses a probe that has nothing to probe, and marks older 'live'
// rows of an env as replaced. Everything else waits for a platform admin
// (routes/stateReconcile.js), and a directory is only ever moved to the trash.

const execFileAsync = promisify(execFile);
const ENVS = ['production', 'sandbox'];
const CONTAINER_RE = /^appcrane-([a-z0-9][a-z0-9-]*)-(production|sandbox)$/;
const SLUG_DIR_RE = /^[a-z0-9][a-z0-9-]{0,99}$/;

// Per-app trees besides apps/ and repos/: finding kind for a directory there with no app.
const ORPHAN_KIND = {
  backups: 'orphan_backups_dir',
  'app-containers': 'orphan_coder_dir',
  attestations: 'orphan_attestations_dir',
  'appstudio-npm-cache': 'orphan_npm_cache_dir',
};

// Rows that still name a file under `dir` (a rename before renames moved
// these directories leaves the row pointing at the old slug's directory).
// routes/backups.js joins from DATA_DIR as configured, so a stored path may be relative.
function referencedBy(db, tree, name) {
  const n = (sql, ...a) => db.prepare(sql).get(...a).n;
  const tail = `%${sep}${tree}${sep}${name}${sep}%`;
  if (tree === 'backups') return n("SELECT COUNT(*) n FROM backups WHERE ('/' || file_path) LIKE ? OR databases LIKE ?", tail, tail);
  if (tree === 'attestations') return n('SELECT COUNT(*) n FROM deploy_attestations WHERE dir LIKE ?', tail);
  return 0;
}

function dirSummary(dir) {
  let files = 0;
  let bytes = 0;
  const walk = (d, depth) => {
    let entries = [];
    try { entries = readdirSync(d, { withFileTypes: true }); } catch (_) { return; }
    for (const e of entries) {
      if (files >= 10000) return;
      const p = join(d, e.name);
      if (e.isDirectory() && depth < 8) walk(p, depth + 1);
      else if (e.isFile()) { files++; bytes += lstatSync(p).size; }
    }
  };
  walk(dir, 0);
  return { files, bytes };
}

export const JOB_ID = 'state-reconcile';
export const SWEEP_MS = 10 * 60_000;
export const BOOT_DELAY_MS = 2 * 60_000;
export const FAILED_STREAK = 3;

// Kinds whose evaluation needs Docker: not resolved on a sweep Docker missed.
const DOCKER_KINDS = new Set(['live_without_container', 'probe_without_container', 'container_without_app']);

export const FIXES = {
  recover: 'Run container recovery now',
  remove_container: 'Remove the container (its volumes and data directory stay)',
  trash_dir: 'Move the directory to the trash',
  delete_rows: 'Delete the orphan rows',
  set_github_url: 'Set github_url to the repository the GitHub App is attached to',
  purge_trash: 'Permanently delete this trash entry',
};

let scheduled = false;
let timer = null;
let bootTimer = null;
let running = null;

/** True once the scheduler runs in this process (a booted server, not a test importing a module). */
export const reconcilerLive = () => scheduled;

async function listContainers() {
  const { stdout } = await execFileAsync('docker',
    ['ps', '-a', '--filter', 'label=appcrane=true', '--format', '{{.Names}}|{{.State}}'], { timeout: 15000 });
  const map = new Map();
  for (const line of stdout.trim().split('\n')) {
    if (!line) continue;
    const [name, state] = line.split('|');
    map.set(name, state);
  }
  return map;
}

/** Stop and re-arm every probe: a paused or deleted config keeps its timer until then. */
export async function rescheduleHealthChecks() {
  const hc = await import('./healthChecker.js');
  hc.stopHealthChecker();
  hc.startHealthChecker();
}

async function defaultDeps() {
  const { envIsSleeping } = await import('./envSleepState.js');
  const { restoreInProgress } = await import('./managedDbRestoreGuard.js');
  return {
    db: getDb(),
    listContainers,
    sleeping: envIsSleeping,
    restoring: restoreInProgress,
    rescheduleHealth: rescheduleHealthChecks,
    resumeHealth: async (appId) => (await import('./healthChecker.js')).refreshAppChecks(appId),
  };
}

const fingerprint = (f) => [f.kind, f.app_id ?? '', f.env ?? '', f.subject ?? ''].join('|');

function readJson(dir, file) {
  const p = join(dir, file);
  if (!regularFileInside(dir, p)) return null;
  try { return JSON.parse(readFileSync(p, 'utf8')); } catch (_) { return null; }
}

function subdirs(dir) {
  try {
    return readdirSync(dir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
  } catch (_) {
    return [];
  }
}

function aliasMap(apps) {
  const m = new Map();
  for (const a of apps) {
    let list = [];
    try { list = JSON.parse(a.slug_aliases || '[]'); } catch (_) {}
    for (const s of list) m.set(s, a.slug);
  }
  return m;
}

/**
 * Every mismatch, as { kind, severity, app_id, slug, env, subject, detail, fix }.
 * `containers` is null when Docker did not answer; then nothing about
 * containers is concluded.
 */
export function collectFindings(db, { containers, sleeping = () => false, restoring = () => false } = {}) {
  const out = [];
  const add = (f) => out.push({ app_id: null, slug: null, env: null, subject: null, fix: null, detail: {}, ...f });
  const root = dataRoot();
  const apps = db.prepare('SELECT id, slug, source_type, github_url, repo_backend, slug_aliases FROM apps').all();
  const bySlug = new Map(apps.map((a) => [a.slug, a]));
  const aliases = aliasMap(apps);
  const renamedFrom = new Map(db.prepare('SELECT old_slug, new_slug FROM app_slug_renames ORDER BY id').all().map((r) => [r.old_slug, r.new_slug]));

  for (const app of apps) {
    for (const env of ENVS) {
      const live = db.prepare(`SELECT id, version, release_path, image_ref, finished_at, started_at FROM deployments
        WHERE app_id = ? AND env = ? AND status = 'live' ORDER BY id DESC LIMIT 1`).get(app.id, env);
      const liveCount = db.prepare("SELECT COUNT(*) AS n FROM deployments WHERE app_id = ? AND env = ? AND status = 'live'").get(app.id, env).n;
      const inflight = !!db.prepare("SELECT 1 FROM deployments WHERE app_id = ? AND env = ? AND status IN ('pending','building','deploying')").get(app.id, env);
      const hc = db.prepare('SELECT enabled FROM health_configs WHERE app_id = ? AND env = ?').get(app.id, env);
      const hs = db.prepare('SELECT consecutive_fails, is_down, last_check_at FROM health_state WHERE app_id = ? AND env = ?').get(app.id, env);
      const pause = db.prepare('SELECT reason, paused_at FROM health_probe_pauses WHERE app_id = ? AND env = ?').get(app.id, env);
      const name = `appcrane-${app.slug}-${env}`;
      const state = containers ? (containers.get(name) || 'absent') : null;
      const quiet = sleeping(app.slug, env) || restoring(app.slug, env) || inflight;

      if (state === 'absent' && !quiet) {
        if (live) {
          add({
            kind: 'live_without_container', severity: 'error', app_id: app.id, slug: app.slug, env, fix: 'recover',
            detail: { deployment_id: live.id, version: live.version, live_since: live.finished_at || live.started_at, consecutive_fails: hs?.consecutive_fails ?? null },
          });
        }
        if (hc?.enabled && (!live || hs?.is_down)) {
          add({
            kind: 'probe_without_container', severity: 'warning', app_id: app.id, slug: app.slug, env,
            detail: {
              reason: live ? `no container for live deployment #${live.id}; probe failing (${hs?.consecutive_fails ?? 0} in a row)` : 'never deployed: no live deployment and no container',
              consecutive_fails: hs?.consecutive_fails ?? null,
            },
          });
        }
      }
      if (pause) {
        add({ kind: 'probe_paused', severity: 'info', app_id: app.id, slug: app.slug, env, detail: { reason: pause.reason, paused_at: pause.paused_at } });
      }

      if (live && app.source_type !== 'image' && !live.image_ref) {
        const releases = resolve(root, 'apps', app.slug, env, 'releases');
        const p = live.release_path ? resolve(live.release_path) : null;
        const problem = !p ? 'no release_path recorded'
          : !p.startsWith(releases + sep) ? 'release_path is outside this app\'s releases directory'
            : !existsSync(p) ? 'release directory is gone from disk' : null;
        if (problem) {
          add({
            kind: 'live_release_missing', severity: 'error', app_id: app.id, slug: app.slug, env,
            detail: { deployment_id: live.id, problem, release_path: live.release_path, affects: 'rollback, container recovery and upload conversion skip this release' },
          });
        }
      }

      const recent = db.prepare(`SELECT id, status, failure_reason, started_at FROM deployments
        WHERE app_id = ? AND env = ? ORDER BY id DESC LIMIT ?`).all(app.id, env, FAILED_STREAK);
      if (recent.length === FAILED_STREAK && recent.every((r) => r.status === 'failed')) {
        add({
          kind: 'failed_streak', severity: 'warning', app_id: app.id, slug: app.slug, env, subject: String(recent[0].id),
          detail: {
            last_live_id: live?.id ?? null,
            failures: recent.map((r) => ({ id: r.id, started_at: r.started_at, failure_reason: r.failure_reason ? String(r.failure_reason).slice(0, 300) : null })),
          },
        });
      }

      if (liveCount > 1) {
        add({ kind: 'stale_live_rows', severity: 'info', app_id: app.id, slug: app.slug, env, detail: { live_rows: liveCount, current_id: live.id } });
      }

      const current = join(root, 'apps', app.slug, env, 'current');
      const cst = lstatSync(current, { throwIfNoEntry: false });
      if (cst?.isSymbolicLink() && !existsSync(current)) {
        add({ kind: 'dangling_current', severity: 'warning', app_id: app.id, slug: app.slug, env, detail: { points_to: readlinkSync(current) } });
      }
    }

    const inst = db.prepare('SELECT repo_full_name FROM app_github_installations WHERE app_id = ?').get(app.id);
    if (inst && app.github_url) {
      const m = /^https?:\/\/[^/]+\/([^/]+\/[^/]+?)(?:\.git)?\/?$/.exec(app.github_url);
      if (!m || m[1].toLowerCase() !== String(inst.repo_full_name).toLowerCase()) {
        add({
          kind: 'github_url_mismatch', severity: 'warning', app_id: app.id, slug: app.slug, subject: inst.repo_full_name, fix: 'set_github_url',
          detail: { github_url: app.github_url, attached_repo: inst.repo_full_name, source: 'github_app_installation' },
        });
      }
    }
    if (app.source_type === 'github' && app.github_url) {
      for (const env of ENVS) {
        const meta = readJson(join(root, 'apps', app.slug, env, 'current'), 'deployhub.json');
        const declared = typeof meta?.github_url === 'string' ? meta.github_url.replace(/\.git$|\/$/g, '') : null;
        if (declared && declared.toLowerCase() !== app.github_url.replace(/\.git$|\/$/g, '').toLowerCase()) {
          add({
            kind: 'github_url_differs_from_release', severity: 'info', app_id: app.id, slug: app.slug, env, subject: declared,
            detail: { github_url: app.github_url, release_declares: declared, source: 'deployhub.json in the running release (written by the app, not verified)' },
          });
        }
      }
    }
  }

  if (containers) {
    for (const [name, state] of containers) {
      const m = CONTAINER_RE.exec(name);
      if (!m || bySlug.has(m[1])) continue;
      add({
        kind: 'container_without_app', severity: 'warning', slug: m[1], env: m[2], subject: name, fix: 'remove_container',
        detail: { container: name, state, renamed_to: aliases.get(m[1]) || renamedFrom.get(m[1]) || null },
      });
    }
  }

  for (const dir of subdirs(join(root, 'apps'))) {
    if (!SLUG_DIR_RE.test(dir) || bySlug.has(dir)) continue;
    const renamedTo = aliases.get(dir) || renamedFrom.get(dir) || null;
    add({
      kind: renamedTo ? 'rename_leftover_dir' : 'orphan_app_dir', severity: 'warning', slug: dir, subject: `apps/${dir}`, fix: 'trash_dir',
      detail: { path: `apps/${dir}`, renamed_to: renamedTo, mtime: lstatSync(join(root, 'apps', dir)).mtime.toISOString() },
    });
  }
  for (const dir of subdirs(join(root, 'repos'))) {
    const slug = dir.endsWith('.git') ? dir.slice(0, -4) : null;
    if (!slug || !SLUG_DIR_RE.test(slug) || bySlug.has(slug)) continue;
    const renamedTo = aliases.get(slug) || renamedFrom.get(slug) || null;
    add({
      kind: renamedTo ? 'rename_leftover_repo' : 'orphan_repo', severity: 'warning', slug, subject: `repos/${dir}`, fix: 'trash_dir',
      detail: { path: `repos/${dir}`, renamed_to: renamedTo },
    });
  }

  for (const [tree, kind] of Object.entries(ORPHAN_KIND)) {
    for (const dir of subdirs(join(root, tree))) {
      if (!isAppDirName(tree, dir) || bySlug.has(dir)) continue;
      const renamedTo = aliases.get(dir) || renamedFrom.get(dir) || null;
      const refs = referencedBy(db, tree, dir);
      add({
        kind, severity: 'warning', slug: dir, subject: `${tree}/${dir}`, fix: refs ? null : 'trash_dir',
        detail: {
          path: `${tree}/${dir}`, renamed_to: renamedTo, mtime: lstatSync(join(root, tree, dir)).mtime.toISOString(),
          ...dirSummary(join(root, tree, dir)), referenced_by_rows: refs,
        },
      });
    }
  }

  for (const t of ['health_configs', 'health_state', 'app_host_ports']) {
    const rows = db.prepare(`SELECT DISTINCT app_id FROM ${t} WHERE app_id NOT IN (SELECT id FROM apps)`).all();
    for (const r of rows) {
      add({ kind: 'orphan_rows', severity: 'info', app_id: r.app_id, subject: t, fix: 'delete_rows', detail: { table: t, app_id: r.app_id } });
    }
  }

  for (const r of db.prepare("SELECT app_id, slug, status, error_code, error, finished_at FROM upload_conversions WHERE status IN ('skipped','failed') AND app_id IN (SELECT id FROM apps)").all()) {
    add({
      kind: 'upload_conversion_skipped', severity: 'warning', app_id: r.app_id, slug: r.slug, subject: r.error_code || r.status,
      detail: { status: r.status, error_code: r.error_code, error: r.error ? String(r.error).slice(0, 500) : null, at: r.finished_at },
    });
  }

  for (const t of db.prepare("SELECT id, kind, slug, expires_at FROM app_trash WHERE purged_at IS NULL AND restored_at IS NULL AND expires_at <= datetime('now')").all()) {
    add({ kind: 'trash_expired', severity: 'info', slug: t.slug, subject: String(t.id), fix: 'purge_trash', detail: { trash_id: t.id, kind: t.kind, expired_at: t.expires_at } });
  }

  return out;
}

function pauseProbe(db, f) {
  const changed = db.transaction(() => {
    const n = db.prepare('UPDATE health_configs SET enabled = 0 WHERE app_id = ? AND env = ? AND enabled = 1').run(f.app_id, f.env).changes;
    if (n) {
      db.prepare('INSERT OR REPLACE INTO health_probe_pauses (app_id, env, reason) VALUES (?, ?, ?)').run(f.app_id, f.env, f.detail.reason);
    }
    return n;
  })();
  if (changed) logAudit(null, f.app_id, 'reconcile-auto-fix', { kind: f.kind, env: f.env, action: 'health probe paused', reason: f.detail.reason });
  return changed > 0;
}

function demoteStaleLive(db, f) {
  const n = db.prepare("UPDATE deployments SET status = 'rolled_back' WHERE app_id = ? AND env = ? AND status = 'live' AND id < ?")
    .run(f.app_id, f.env, f.detail.current_id).changes;
  if (n) logAudit(null, f.app_id, 'reconcile-auto-fix', { kind: f.kind, env: f.env, action: 'older live rows marked replaced', rows: n, current_id: f.detail.current_id });
  return n;
}

/** Paused probes whose env has a container again. */
function resumable(db, containers) {
  if (!containers) return [];
  return db.prepare('SELECT p.app_id, p.env, a.slug FROM health_probe_pauses p JOIN apps a ON a.id = p.app_id').all()
    .filter((p) => (containers.get(`appcrane-${p.slug}-${p.env}`) || 'absent') !== 'absent');
}

function store(db, runId, findings, evaluatedDocker) {
  const upsert = db.prepare(`
    INSERT INTO reconcile_findings (fingerprint, kind, severity, app_id, slug, env, subject, detail_json, fix, status, fix_result)
    VALUES (@fingerprint, @kind, @severity, @app_id, @slug, @env, @subject, @detail_json, @fix, @status, @fix_result)
    ON CONFLICT(fingerprint) DO UPDATE SET
      severity = excluded.severity, detail_json = excluded.detail_json, fix = excluded.fix,
      last_seen_at = datetime('now'), resolved_at = NULL,
      status = CASE WHEN reconcile_findings.status = 'dismissed' THEN 'dismissed' ELSE excluded.status END,
      fix_result = COALESCE(excluded.fix_result, CASE WHEN reconcile_findings.status = 'dismissed' THEN reconcile_findings.fix_result END)
  `);
  db.transaction(() => {
    const seen = [];
    for (const f of findings) {
      const fp = fingerprint(f);
      seen.push(fp);
      upsert.run({
        fingerprint: fp, kind: f.kind, severity: f.severity, app_id: f.app_id, slug: f.slug, env: f.env, subject: f.subject,
        detail_json: JSON.stringify(f.detail || {}), fix: f.fix, status: f.status || 'open', fix_result: f.fix_result || null,
      });
    }
    const open = db.prepare("SELECT id, fingerprint, kind FROM reconcile_findings WHERE status IN ('open','auto_fixed')").all();
    const seenSet = new Set(seen);
    const resolveRow = db.prepare("UPDATE reconcile_findings SET status = 'resolved', resolved_at = datetime('now') WHERE id = ?");
    for (const r of open) {
      if (seenSet.has(r.fingerprint)) continue;
      if (!evaluatedDocker && DOCKER_KINDS.has(r.kind)) continue;
      resolveRow.run(r.id);
    }
  })();
}

/** One sweep: detect, apply the safe fixes, store. */
export async function reconcileOnce({ trigger = 'schedule', deps } = {}) {
  const d = { ...(await defaultDeps()), ...(deps || {}) };
  const db = d.db;
  const runId = db.prepare('INSERT INTO reconcile_runs (trigger_by) VALUES (?)').run(trigger).lastInsertRowid;
  let containers = null;
  try {
    containers = await d.listContainers();
  } catch (e) {
    log.warn(`[reconcile] Docker did not answer, container findings skipped: ${e.message}`);
  }
  try {
    const findings = collectFindings(db, { containers, sleeping: d.sleeping, restoring: d.restoring });
    let paused = 0;
    let demoted = 0;
    for (const f of findings) {
      if (f.kind === 'probe_without_container' && pauseProbe(db, f)) {
        paused++;
        f.status = 'auto_fixed';
        f.fix_result = 'health probe paused; it resumes when a container appears';
        findings.push({
          kind: 'probe_paused', severity: 'info', app_id: f.app_id, slug: f.slug, env: f.env, subject: null, fix: null,
          detail: { reason: f.detail.reason, paused_at: new Date().toISOString().slice(0, 19).replace('T', ' ') },
        });
      } else if (f.kind === 'stale_live_rows') {
        const n = demoteStaleLive(db, f);
        demoted += n;
        f.status = 'auto_fixed';
        f.fix_result = `${n} older live row(s) marked replaced (rolled_back)`;
      }
    }
    const resumed = [];
    for (const p of resumable(db, containers)) {
      db.transaction(() => {
        db.prepare('UPDATE health_configs SET enabled = 1 WHERE app_id = ? AND env = ?').run(p.app_id, p.env);
        db.prepare('DELETE FROM health_probe_pauses WHERE app_id = ? AND env = ?').run(p.app_id, p.env);
      })();
      logAudit(null, p.app_id, 'reconcile-auto-fix', { kind: 'probe_paused', env: p.env, action: 'health probe resumed: container present' });
      resumed.push(p);
    }
    const shown = findings.filter((f) => !(f.kind === 'probe_paused' && resumed.some((p) => p.app_id === f.app_id && p.env === f.env)));
    store(db, runId, shown, !!containers);
    if (paused) await d.rescheduleHealth();
    for (const appId of new Set(resumed.map((p) => p.app_id))) await d.resumeHealth(appId);
    const counts = { findings: shown.length, paused, resumed: resumed.length, demoted_rows: demoted };
    db.prepare("UPDATE reconcile_runs SET finished_at = datetime('now'), docker_ok = ?, counts_json = ? WHERE id = ?")
      .run(containers ? 1 : 0, JSON.stringify(counts), runId);
    return { run_id: runId, docker_ok: !!containers, ...counts };
  } catch (e) {
    db.prepare("UPDATE reconcile_runs SET finished_at = datetime('now'), error = ? WHERE id = ?").run(String(e.message).slice(0, 1000), runId);
    throw e;
  }
}

/** One sweep at a time; a caller during a sweep gets that sweep's result. */
export function runReconcile(opts = {}) {
  if (!running) {
    running = trackJob(JOB_ID, () => reconcileOnce(opts)).finally(() => { running = null; });
  }
  return running;
}

export function startStateReconcile() {
  if (scheduled) return;
  scheduled = true;
  jobStarted(JOB_ID, { cadenceMs: SWEEP_MS });
  const tick = () => runReconcile({ trigger: 'schedule' }).catch((e) => log.error(`[reconcile] sweep failed: ${e.message}`));
  bootTimer = setTimeout(() => runReconcile({ trigger: 'boot' }).catch((e) => log.error(`[reconcile] boot sweep failed: ${e.message}`)), BOOT_DELAY_MS);
  bootTimer.unref();
  timer = setInterval(tick, SWEEP_MS);
  timer.unref();
}

export function stopStateReconcile() {
  if (timer) clearInterval(timer);
  if (bootTimer) clearTimeout(bootTimer);
  timer = null;
  bootTimer = null;
  scheduled = false;
}

export function listFindings(db, { status = 'active' } = {}) {
  const where = status === 'all' ? '1 = 1' : status === 'active' ? "status IN ('open','auto_fixed')" : 'status = ?';
  const args = status === 'all' || status === 'active' ? [] : [status];
  return db.prepare(`SELECT * FROM reconcile_findings WHERE ${where} ORDER BY
      CASE severity WHEN 'error' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, last_seen_at DESC LIMIT 500`).all(...args)
    .map(({ detail_json, ...r }) => ({ ...r, detail: JSON.parse(detail_json || '{}'), fix_label: r.fix ? FIXES[r.fix] : null }));
}

export function lastRun(db) {
  const r = db.prepare('SELECT * FROM reconcile_runs ORDER BY id DESC LIMIT 1').get();
  return r ? { ...r, counts: JSON.parse(r.counts_json || 'null'), counts_json: undefined } : null;
}

// A one-click fix re-checks the finding against the current state first: the
// row is up to ten minutes old, and acting on what it said then could move a
// directory an app created since.
async function applyFix(db, f, user) {
  const detail = JSON.parse(f.detail_json || '{}');
  const root = dataRoot();
  switch (f.fix) {
    case 'recover': {
      const { runSweep } = await import('./containerRecovery.js');
      const out = await runSweep();
      const mine = out?.results?.find((r) => r.name === `appcrane-${f.slug}-${f.env}`);
      return mine ? `${mine.outcome}${mine.error ? `: ${mine.error}` : ''}` : (out?.dockerDown ? 'Docker did not answer' : 'container recovery ran; this env was not due (backing off, or not past its grace window)');
    }
    case 'remove_container': {
      const m = CONTAINER_RE.exec(detail.container || '');
      if (!m) throw new AppError('Not an AppCrane app container name', 400, 'VALIDATION');
      if (db.prepare('SELECT 1 FROM apps WHERE slug = ?').get(m[1])) throw new AppError(`An app '${m[1]}' exists again; the container is no longer an orphan`, 409, 'NO_LONGER_ORPHAN');
      await execFileAsync('docker', ['rm', '-f', detail.container], { timeout: 30000 });
      return `container ${detail.container} removed`;
    }
    case 'trash_dir': {
      const parts = String(detail.path || '').split('/');
      const [tree, name] = parts;
      const kind = KIND_OF_TREE[tree];
      if (parts.length !== 2 || !kind || !isAppDirName(tree, name)) throw new AppError('Not a movable path', 400, 'VALIDATION');
      const slug = tree === 'repos' ? name.replace(/\.git$/, '') : name;
      if (APP_DIR_KINDS[kind][1](slug) !== name) throw new AppError('Not a movable path', 400, 'VALIDATION');
      if (db.prepare('SELECT 1 FROM apps WHERE slug = ?').get(slug)) throw new AppError(`An app '${slug}' exists again; the directory is no longer an orphan`, 409, 'NO_LONGER_ORPHAN');
      const refs = referencedBy(db, tree, name);
      if (refs) throw new AppError(`${refs} row(s) of an existing app still name files in ${tree}/${name}; it is not moved`, 409, 'STILL_REFERENCED');
      const row = moveToTrash(db, { kind, path: join(root, tree, name), slug, reason: `reconcile: ${f.kind}`, userId: user.id });
      return `moved to trash entry #${row.id}, kept until ${row.expires_at} UTC`;
    }
    case 'delete_rows': {
      if (!['health_configs', 'health_state', 'app_host_ports'].includes(detail.table)) throw new AppError('Unknown table', 400, 'VALIDATION');
      const n = db.prepare(`DELETE FROM ${detail.table} WHERE app_id = ? AND app_id NOT IN (SELECT id FROM apps)`).run(detail.app_id).changes;
      return `${n} row(s) deleted from ${detail.table}`;
    }
    case 'set_github_url': {
      const inst = db.prepare('SELECT repo_full_name FROM app_github_installations WHERE app_id = ?').get(f.app_id);
      if (!inst || inst.repo_full_name !== f.subject) throw new AppError('The GitHub App attachment changed since this was found; run the check again', 409, 'STALE_FINDING');
      const { githubWebBase } = await import('./githubApp.js');
      const url = `${githubWebBase().replace(/\/+$/, '')}/${inst.repo_full_name}`;
      db.prepare('UPDATE apps SET github_url = ? WHERE id = ?').run(url, f.app_id);
      return `github_url set to ${url} (was ${detail.github_url})`;
    }
    case 'purge_trash':
      purgeTrash(db, Number(detail.trash_id));
      return `trash entry #${detail.trash_id} purged`;
    default:
      throw new AppError('This finding has no one-click fix', 400, 'NO_FIX');
  }
}

// audit_log.app_id is a foreign key; a finding can name an app that is gone.
const auditAppId = (db, appId) => (appId && db.prepare('SELECT 1 FROM apps WHERE id = ?').get(appId) ? appId : null);

export async function fixFinding(db, id, user) {
  const f = db.prepare('SELECT * FROM reconcile_findings WHERE id = ?').get(id);
  if (!f) throw new AppError('No such finding', 404, 'NOT_FOUND');
  if (f.status !== 'open') throw new AppError(`This finding is ${f.status}`, 409, 'NOT_OPEN');
  if (!f.fix) throw new AppError('This finding has no one-click fix', 400, 'NO_FIX');
  let result;
  try {
    result = await applyFix(db, f, user);
  } catch (e) {
    logAudit(user.id, auditAppId(db, f.app_id), 'reconcile-fix', { finding_id: f.id, kind: f.kind, fix: f.fix, subject: f.subject, ok: false, error: String(e.message).slice(0, 300) });
    throw e;
  }
  db.prepare("UPDATE reconcile_findings SET status = 'fixed', resolved_at = datetime('now'), fixed_by = ?, fix_result = ? WHERE id = ?").run(user.id, result, f.id);
  logAudit(user.id, auditAppId(db, f.app_id), 'reconcile-fix', { finding_id: f.id, kind: f.kind, fix: f.fix, subject: f.subject, ok: true, result });
  return { id: f.id, status: 'fixed', result };
}

export function dismissFinding(db, id, user) {
  const f = db.prepare('SELECT id, kind, app_id, subject, status FROM reconcile_findings WHERE id = ?').get(id);
  if (!f) throw new AppError('No such finding', 404, 'NOT_FOUND');
  db.prepare("UPDATE reconcile_findings SET status = 'dismissed', fixed_by = ? WHERE id = ?").run(user.id, id);
  logAudit(user.id, auditAppId(db, f.app_id), 'reconcile-dismiss', { finding_id: f.id, kind: f.kind, subject: f.subject, was: f.status });
  return { id: f.id, status: 'dismissed' };
}
