/**
 * Phase 3: move every GitHub-backed managed app onto this host, at boot.
 *
 * For each app with source_type='managed' AND repo_backend IS NULL, one at a
 * time, before AppCrane listens:
 *   1. fetch GitHub's branches and tags into <repos>/.migrating-<slug>.git
 *   2. strip it to the shape createAppRepo builds (no remote, heads/tags only,
 *      HEAD = the app's branch, connected object graph)
 *   3. list GitHub's branches and tags AGAIN and require an exact match with
 *      the staged copy: same ref names, same SHAs, nothing extra, nothing
 *      missing. A push that landed on GitHub mid-migration fails this.
 *   4. only then rename it to <repos>/<slug>.git and set repo_backend='local'.
 * Any failure leaves the app on GitHub (marker stays NULL), records why in
 * repo_migrations, and moves on to the next app. The GitHub copy is never
 * modified.
 *
 * NEVER CRASHES BOOT: each app is its own try/catch, and the whole run is
 * wrapped again. A hang is bounded twice: every git process is SIGKILLed at
 * min(app start + per-app timeout, run start + total budget), and apps not
 * reached before the budget are recorded 'deferred' and retried next boot.
 *
 * IDEMPOTENT: an app already 'local' is not selected; a leftover staging dir is
 * deleted before use; an existing <slug>.git for a NULL-marker app is never
 * touched (recorded 'skipped', LOCAL_REPO_EXISTS). The rename happens before
 * the marker UPDATE, so a crash between them leaves a repo on disk and the app
 * on GitHub, which the next boot reports as LOCAL_REPO_EXISTS — never an app
 * marked local with no repo.
 *
 * Escape hatch (default ON): APPCRANE_REPO_MIGRATION=off|0|false in the
 * environment, or settings key repo_migration_disabled = '1'.
 */

import log from '../utils/logger.js';

export const DISABLE_ENV = 'APPCRANE_REPO_MIGRATION';
export const DISABLE_SETTING = 'repo_migration_disabled';
export const APP_TIMEOUT_ENV = 'APPCRANE_REPO_MIGRATION_APP_TIMEOUT_SECONDS';
export const BUDGET_ENV = 'APPCRANE_REPO_MIGRATION_BUDGET_SECONDS';
export const DEFAULT_APP_TIMEOUT_MS = 5 * 60 * 1000;
export const DEFAULT_BUDGET_MS = 30 * 60 * 1000;

const GITHUB_URL_RE = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(\.git)?\/?$/;

function seconds(envName, fallbackMs) {
  const n = Number(process.env[envName]);
  return Number.isFinite(n) && n > 0 ? n * 1000 : fallbackMs;
}

/** Why the migration is off, or null when it should run. */
export function migrationDisabledReason(db) {
  const v = String(process.env[DISABLE_ENV] ?? '').trim().toLowerCase();
  if (['off', '0', 'false', 'no', 'disabled'].includes(v)) return `${DISABLE_ENV}=${process.env[DISABLE_ENV]}`;
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(DISABLE_SETTING);
  if (row && String(row.value).trim() === '1') return `settings.${DISABLE_SETTING}=1`;
  return null;
}

export function candidateApps(db) {
  return db.prepare(
    "SELECT id, slug, branch, github_url, source_type, repo_backend FROM apps WHERE source_type = 'managed' AND repo_backend IS NULL ORDER BY id",
  ).all();
}

/** Production remote: the app's GitHub repo, authenticated as the service account. */
export async function defaultResolveRemote(app) {
  const m = GITHUB_URL_RE.exec(String(app.github_url || ''));
  if (!m) throw Object.assign(new Error(`github_url ${JSON.stringify(app.github_url)} is not a github.com repository URL`), { code: 'NO_GITHUB_URL' });
  const { getServiceTokenInternal } = await import('./githubService.js');
  const token = getServiceTokenInternal();
  if (!token) throw Object.assign(new Error('the GitHub service-account token is not configured'), { code: 'NO_SERVICE_TOKEN' });
  return { url: `https://github.com/${m[1]}/${m[2]}.git`, token };
}

/**
 * Exact comparison of two { ref: sha } maps. `equal` only when both hold the
 * same ref names with the same SHAs and GitHub has at least one ref.
 */
export function compareRefs(github, staged) {
  const diffs = [];
  for (const ref of new Set([...Object.keys(github), ...Object.keys(staged)])) {
    if (github[ref] !== staged[ref]) diffs.push({ ref, github: github[ref] ?? null, local: staged[ref] ?? null });
  }
  return { equal: diffs.length === 0 && Object.keys(github).length > 0, diffs };
}

function scrubber(token) {
  return (s) => {
    let out = String(s ?? '');
    if (token) {
      out = out.replaceAll(token, '[redacted]')
        .replaceAll(Buffer.from(`x-access-token:${token}`).toString('base64'), '[redacted]');
    }
    return out.slice(0, 2000);
  };
}

function record(db, app, fields) {
  db.prepare(`
    INSERT INTO repo_migrations (app_id, slug, status, attempts, error_code, error, refs_json, branch, started_at, finished_at, duration_ms)
    VALUES (@app_id, @slug, @status, @attempts, @error_code, @error, @refs_json, @branch, @started_at, @finished_at, @duration_ms)
    ON CONFLICT(app_id) DO UPDATE SET
      slug = excluded.slug, status = excluded.status, attempts = excluded.attempts,
      error_code = excluded.error_code, error = excluded.error, refs_json = excluded.refs_json,
      branch = excluded.branch, started_at = excluded.started_at,
      finished_at = excluded.finished_at, duration_ms = excluded.duration_ms
  `).run({
    app_id: app.id, slug: String(app.slug), branch: app.branch || 'main',
    attempts: 0, error_code: null, error: null, refs_json: null, started_at: null, finished_at: null, duration_ms: null,
    ...fields,
  });
}

function previousAttempts(db, appId) {
  return db.prepare('SELECT attempts FROM repo_migrations WHERE app_id = ?').get(appId)?.attempts || 0;
}

/**
 * Migrate one app. Never throws: every outcome, including an unexpected
 * exception, is returned and recorded.
 */
export async function migrateOneApp(db, app, opts = {}) {
  const lg = opts.localGit || await import('./localGit.js');
  const resolveRemote = opts.resolveRemote || defaultResolveRemote;
  const startedMs = Date.now();
  const startedAt = new Date(startedMs).toISOString();
  const deadline = Math.min(startedMs + (opts.appTimeoutMs ?? DEFAULT_APP_TIMEOUT_MS), opts.budgetDeadline ?? Infinity);
  const branch = app.branch || 'main';
  const attempts = previousAttempts(db, app.id) + 1;
  let token = null;
  let staging = null;
  const finish = (status, extra = {}) => {
    const scrub = scrubber(token);
    const out = {
      slug: app.slug, status, error_code: extra.error_code ?? null,
      error: extra.error == null ? null : scrub(extra.error),
      refs: extra.refs ?? null, duration_ms: Date.now() - startedMs,
    };
    try {
      record(db, app, {
        status, attempts, branch, started_at: startedAt, finished_at: new Date().toISOString(),
        duration_ms: out.duration_ms, error_code: out.error_code, error: out.error,
        refs_json: out.refs ? scrub(JSON.stringify(out.refs)) : null,
      });
    } catch (e) {
      log.error(`[repo-migration] ${app.slug}: could not record outcome '${status}': ${scrub(e.message)}`);
    }
    const line = `[repo-migration] ${app.slug}: ${status}${out.error_code ? ` (${out.error_code})` : ''} in ${out.duration_ms}ms${out.error ? ` — ${out.error}` : ''}`;
    if (status === 'migrated') log.info(line); else log.warn(line);
    return out;
  };

  try {
    record(db, app, { status: 'running', attempts, branch, started_at: startedAt });
    staging = lg.migrationStagingPath(app.slug);
    if (lg.localRepoExists(app.slug) || (await import('fs')).existsSync(lg.repoPath(app.slug))) {
      return finish('skipped', {
        error_code: 'LOCAL_REPO_EXISTS',
        error: `a local repository already exists for '${app.slug}' while its marker says GitHub; left untouched. Inspect it, then remove it or set repo_backend by hand.`,
      });
    }
    const remote = await resolveRemote(app);
    token = remote.token || null;
    const netOpts = { url: remote.url, token, deadline, allowedSchemes: opts.allowedSchemes || ['https'] };

    await lg.fetchMirrorIntoStaging(staging, { ...netOpts, branch });
    await lg.finalizeStagedMirror(staging, { branch, deadline });
    if (opts.afterStage) await opts.afterStage(app, staging);

    const github = await lg.listRemoteHeadsAndTags(netOpts);
    const staged = await lg.listStagedHeadsAndTags(staging, { deadline });
    const cmp = compareRefs(github, staged);
    if (!cmp.equal) {
      return finish('failed', {
        error_code: 'SHA_MISMATCH',
        error: Object.keys(github).length === 0
          ? 'GitHub reports no branches or tags'
          : `${cmp.diffs.length} ref(s) differ between GitHub and the staged copy`,
        refs: cmp.diffs,
      });
    }
    if (!github[`refs/heads/${branch}`]) {
      return finish('failed', { error_code: 'BRANCH_NOT_ON_GITHUB', error: `branch '${branch}' does not exist on GitHub`, refs: github });
    }

    lg.installMigratedRepo(app.slug, staging);
    staging = null;
    const changed = db.prepare("UPDATE apps SET repo_backend = 'local' WHERE id = ? AND repo_backend IS NULL").run(app.id).changes;
    if (changed !== 1) {
      return finish('failed', { error_code: 'MARKER_NOT_UPDATED', error: 'repo installed but apps.repo_backend was no longer NULL; marker left as found', refs: github });
    }
    return finish('migrated', { refs: github });
  } catch (e) {
    const code = e?.code === 'GIT_TIMEOUT' ? 'TIMEOUT' : (typeof e?.code === 'string' ? e.code : 'ERROR');
    return finish('failed', { error_code: code, error: e?.message || String(e) });
  } finally {
    if (staging) {
      try { (await import('fs')).rmSync(staging, { recursive: true, force: true }); } catch (_) { /* reported by next attempt */ }
    }
  }
}

/**
 * Migrate every candidate app in id order. Never throws. Returns
 * { disabled, results: [...] } where disabled is the reason string or null.
 */
export async function migrateManagedReposToLocal(opts = {}) {
  const startedMs = Date.now();
  try {
    const db = opts.db || (await import('../db.js')).getDb();
    const disabled = migrationDisabledReason(db);
    if (disabled) {
      log.info(`[repo-migration] disabled by ${disabled}; managed apps stay where they are`);
      return { disabled, results: [] };
    }
    const apps = candidateApps(db);
    if (apps.length === 0) return { disabled: null, results: [] };

    const budgetMs = opts.budgetMs ?? seconds(BUDGET_ENV, DEFAULT_BUDGET_MS);
    const appTimeoutMs = opts.appTimeoutMs ?? seconds(APP_TIMEOUT_ENV, DEFAULT_APP_TIMEOUT_MS);
    const budgetDeadline = startedMs + budgetMs;
    log.info(`[repo-migration] ${apps.length} managed app(s) on GitHub; moving them to this host one at a time (per-app limit ${Math.round(appTimeoutMs / 1000)}s, total ${Math.round(budgetMs / 1000)}s)`);

    const results = [];
    for (const app of apps) {
      if (Date.now() >= budgetDeadline) {
        try {
          record(db, app, { status: 'deferred', attempts: previousAttempts(db, app.id), error_code: 'BUDGET_EXHAUSTED', error: 'boot migration budget used up before this app; retried next boot', finished_at: new Date().toISOString() });
        } catch (e) { log.error(`[repo-migration] ${app.slug}: could not record deferral: ${e.message}`); }
        results.push({ slug: app.slug, status: 'deferred', error_code: 'BUDGET_EXHAUSTED' });
        continue;
      }
      try {
        results.push(await migrateOneApp(db, app, { ...opts, appTimeoutMs, budgetDeadline }));
      } catch (e) {
        log.error(`[repo-migration] ${app?.slug}: unexpected failure outside the per-app guard: ${e?.message || e}`);
        results.push({ slug: app?.slug, status: 'failed', error_code: 'ERROR' });
      }
    }
    const count = (s) => results.filter((r) => r.status === s).length;
    log.info(`[repo-migration] done in ${Date.now() - startedMs}ms: ${count('migrated')} migrated, ${count('failed')} failed, ${count('skipped')} skipped, ${count('deferred')} deferred`);
    return { disabled: null, results };
  } catch (e) {
    log.error(`[repo-migration] aborted, boot continues: ${e?.message || e}`);
    return { disabled: null, results: [], error: String(e?.message || e) };
  }
}

/** The boot entry point: same as migrateManagedReposToLocal, and it cannot reject. */
export async function migrateManagedReposAtBoot(opts = {}) {
  try {
    return await migrateManagedReposToLocal(opts);
  } catch (e) {
    try { log.error(`[repo-migration] boot hook failed, boot continues: ${e?.message || e}`); } catch (_) { /* nothing left to do */ }
    return { disabled: null, results: [], error: String(e?.message || e) };
  }
}

/** Per-app outcome for the admin status route. */
export function getRepoMigrationStatus(db) {
  const rows = db.prepare(`
    SELECT m.app_id, m.slug, m.status, m.attempts, m.error_code, m.error, m.refs_json, m.branch,
           m.started_at, m.finished_at, m.duration_ms,
           a.repo_backend, a.source_type, (a.id IS NULL) AS app_deleted
      FROM repo_migrations m LEFT JOIN apps a ON a.id = m.app_id
     ORDER BY m.app_id
  `).all().map(({ refs_json, app_deleted, ...r }) => ({
    ...r,
    app_deleted: !!app_deleted,
    refs: refs_json ? JSON.parse(refs_json) : null,
  }));
  return {
    disabled: migrationDisabledReason(db),
    pending: candidateApps(db).map((a) => a.slug),
    apps: rows,
  };
}
