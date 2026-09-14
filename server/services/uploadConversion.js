/**
 * Convert every UPLOADED app into a CRANE-HOSTED one, at boot.
 *
 * For each app with source_type='upload' or 'managed_legacy' (052 renamed every
 * pre-v2.3.1 upload app to that; deployer.js still redeploys it from the same
 * <ts>-upload release directories), one at a time, after the GitHub repo
 * migration and before AppCrane listens. A legacy app that carries a github_url
 * is skipped (legacy_has_github_url): the owner named a repository, and whether
 * that repo or a Crane-hosted one should become its source is theirs to decide.
 *   1. pick, per environment, the release that environment is running: the live
 *      deployment's release directory, else the newest *upload* release on disk
 *   2. scan it (uploadConversionScan.js): every .env* entry, node_modules and
 *      .git at any depth is EXCLUDED from the repo (paths recorded); symlinks
 *      are committed as symlinks, never followed, and a symlink pointing outside
 *      the release is excluded; special files skipped. The .env* FILES are kept
 *      anyway, outside git: stored encrypted in app_env_files (envFileStore.js)
 *      and written back into that environment's release at every deploy, before
 *      the build (deployer.js), so build-time keys reach the build as before
 *   3. refuse, recording why, an app whose build would change: a bundled
 *      node_modules the build cannot reinstall, a malformed .env to import, a
 *      .env file over 1 MiB, releases missing, nothing left after exclusions, or
 *      more than the size cap
 *   4. build <repos>/.converting-<slug>.git with git fast-import under the same
 *      isolated git environment localGit.js uses: production's release is the
 *      first commit on main, sandbox's (when different) a second commit on top;
 *      git fsck, check the refs
 *   5. record 'installing' + the tip, rename into <repos>/<slug>.git (never over
 *      an existing path), then in ONE transaction guarded by the source_type
 *      the app had when it was selected AND repo_backend IS NULL: flip the app to
 *      managed/local/main, point each live deployment's commit_hash at the
 *      commit holding its release, store each env's .env files encrypted, and
 *      import bundled .env values as encrypted env vars — a key the app already
 *      has in AppCrane is never overwritten.
 *
 * Nothing is deployed and no container is touched. Upload release directories
 * stay on disk. Revert: UPDATE apps SET source_type=<detail_json.original_source_type
 * — 'upload' or 'managed_legacy'; the status route's revert.source_type>, repo_backend=NULL
 * (and restore deployments.commit_hash from commits_json.previous_commit_hash);
 * with <slug>.git left in place the next boot records local_repo_exists and does
 * not convert it again.
 *
 * CRASH BETWEEN RENAME AND FLIP: the row says 'installing' with the tip. The next
 * boot finds the repo, verifies its only ref is main at exactly that tip, fsck
 * passes, and the recorded per-env release identities still match the releases
 * on disk, then performs the flip. Anything else is recorded and left alone.
 *
 * NEVER CRASHES BOOT, bounded by a per-app timeout and a total budget, exactly as
 * repoMigration.js. Off switch: APPCRANE_UPLOAD_CONVERSION=off|0|false, or
 * settings key upload_conversion_disabled = '1'.
 *
 * NO ENV VALUE OR .env CONTENT is ever logged, recorded, or written into git:
 * .env files are excluded before fast-import is fed, their content is stored
 * only encrypted, and records hold key names and paths only.
 */

import { existsSync, lstatSync, mkdirSync, readdirSync, readlinkSync, rmSync } from 'fs';
import { basename, join, resolve, sep } from 'path';
import { spawn } from 'child_process';
import log from '../utils/logger.js';
import { EXCLUDED_CAP, analyzeEnvFiles, dependencyProblem, readNoFollow, scanRelease } from './uploadConversionScan.js';
import { ENV_FILE_MAX_BYTES, captureEnvFiles, encryptEnvFiles, storeEnvFiles, storedEnvFilePaths } from './envFileStore.js';

export const DISABLE_ENV = 'APPCRANE_UPLOAD_CONVERSION';
export const DISABLE_SETTING = 'upload_conversion_disabled';
export const APP_TIMEOUT_ENV = 'APPCRANE_UPLOAD_CONVERSION_APP_TIMEOUT_SECONDS';
export const BUDGET_ENV = 'APPCRANE_UPLOAD_CONVERSION_BUDGET_SECONDS';
export const MAX_BYTES_ENV = 'APPCRANE_UPLOAD_CONVERSION_MAX_BYTES';
export const DEFAULT_APP_TIMEOUT_MS = 5 * 60 * 1000;
export const DEFAULT_BUDGET_MS = 30 * 60 * 1000;
// Tracked bytes across both environments' snapshots, node_modules/.env/.git
// already excluded. The only way these releases reached the host is the upload
// route, capped at 200 MiB COMPRESSED per bundle (routes/deploy.js multer
// limit); two full source snapshots of a bundle that size fit well inside
// 512 MiB. A tree past it is shipping data or build output, and every deploy
// clone and config backup of the repo would carry it.
export const DEFAULT_MAX_BYTES = 512 * 1024 * 1024;
export const DEFAULT_MAX_FILES = 100000;
export const ENVS = ['production', 'sandbox'];
const RECOVERABLE = ['installing', 'flip_failed'];
export const CONVERTIBLE_SOURCE_TYPES = ['upload', 'managed_legacy'];

function positiveNumber(envName, fallback, scale = 1) {
  const n = Number(process.env[envName]);
  return Number.isFinite(n) && n > 0 ? n * scale : fallback;
}

export function conversionDisabledReason(db) {
  const v = String(process.env[DISABLE_ENV] ?? '').trim().toLowerCase();
  if (['off', '0', 'false', 'no', 'disabled'].includes(v)) return `${DISABLE_ENV}=${process.env[DISABLE_ENV]}`;
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(DISABLE_SETTING);
  if (row && String(row.value).trim() === '1') return `settings.${DISABLE_SETTING}=1`;
  return null;
}

export function candidateApps(db) {
  return db.prepare("SELECT * FROM apps WHERE source_type IN ('upload', 'managed_legacy') ORDER BY id").all();
}

/**
 * The refusal an upload endpoint returns for an app this module converted, or
 * null. Keyed on the recorded conversion AND the app still being managed, so a
 * reverted app (source_type back to 'upload' or 'managed_legacy') is not refused.
 */
export function conversionRefusal(db, app) {
  if (!app || app.source_type !== 'managed') return null;
  let row;
  try {
    row = db.prepare("SELECT status FROM upload_conversions WHERE app_id = ? AND status = 'converted'").get(app.id);
  } catch (_) { return null; }
  if (!row) return null;
  return {
    status: 409,
    code: 'APP_IS_CRANE_HOSTED',
    message: `App '${app.slug}' was converted from uploaded bundles to a Crane-hosted repository, so uploads are refused. ` +
      'Push changes with appcrane_push_to_managed_app (they deploy from the repository).',
  };
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

const J = (v) => (v == null ? null : JSON.stringify(v));

function record(db, app, f) {
  db.prepare(`
    INSERT INTO upload_conversions (app_id, slug, status, attempts, error_code, error, tip, commits_json,
      imported_keys_json, kept_existing_json, invalid_keys_json, warnings_json, excluded_json, excluded_count,
      skipped_files_json, detail_json, tracked_bytes, started_at, finished_at, duration_ms)
    VALUES (@app_id, @slug, @status, @attempts, @error_code, @error, @tip, @commits_json,
      @imported_keys_json, @kept_existing_json, @invalid_keys_json, @warnings_json, @excluded_json, @excluded_count,
      @skipped_files_json, @detail_json, @tracked_bytes, @started_at, @finished_at, @duration_ms)
    ON CONFLICT(app_id) DO UPDATE SET
      slug = excluded.slug, status = excluded.status, attempts = excluded.attempts,
      error_code = excluded.error_code, error = excluded.error, tip = excluded.tip, commits_json = excluded.commits_json,
      imported_keys_json = excluded.imported_keys_json, kept_existing_json = excluded.kept_existing_json,
      invalid_keys_json = excluded.invalid_keys_json, warnings_json = excluded.warnings_json,
      excluded_json = excluded.excluded_json, excluded_count = excluded.excluded_count,
      skipped_files_json = excluded.skipped_files_json, detail_json = excluded.detail_json,
      tracked_bytes = excluded.tracked_bytes, started_at = excluded.started_at,
      finished_at = excluded.finished_at, duration_ms = excluded.duration_ms
  `).run({
    app_id: app.id, slug: String(app.slug), status: f.status, attempts: f.attempts ?? 0,
    error_code: f.error_code ?? null, error: f.error == null ? null : String(f.error).slice(0, 2000),
    tip: f.tip ?? null, commits_json: J(f.commits),
    imported_keys_json: J(f.imported_keys), kept_existing_json: J(f.kept_existing), invalid_keys_json: J(f.invalid_keys),
    warnings_json: J(f.warnings?.slice(0, EXCLUDED_CAP)), excluded_json: J(f.excluded?.slice(0, EXCLUDED_CAP)),
    excluded_count: f.excluded ? f.excluded.length : null,
    skipped_files_json: J(f.skipped_files?.slice(0, EXCLUDED_CAP)), detail_json: J(f.detail),
    tracked_bytes: f.tracked_bytes ?? null, started_at: f.started_at ?? null,
    finished_at: f.finished_at ?? null, duration_ms: f.duration_ms ?? null,
  });
}

// ---------------------------------------------------------------------------
// Which release each environment runs
// ---------------------------------------------------------------------------

function isRealDir(p) {
  try { return lstatSync(p).isDirectory(); } catch (_) { return false; }
}

export function planEnv(db, app, env) {
  const dataDir = resolve(process.env.DATA_DIR || './data');
  const releasesDir = resolve(join(dataDir, 'apps', app.slug, env, 'releases'));
  const warnings = [];
  const live = db.prepare(
    "SELECT id, commit_hash, release_path FROM deployments WHERE app_id = ? AND env = ? AND status = 'live' ORDER BY id DESC LIMIT 1",
  ).get(app.id, env);

  let releaseDir = null;
  let source = null;
  let identityRow = null;
  if (live?.release_path) {
    const p = resolve(live.release_path);
    if (p.startsWith(releasesDir + sep) && isRealDir(p)) {
      releaseDir = p; source = 'live_deployment'; identityRow = live;
    } else {
      warnings.push({ env, reason: 'live_release_not_on_disk' });
    }
  }
  if (!releaseDir && isRealDir(releasesDir)) {
    const newest = readdirSync(releasesDir).filter((d) => d.includes('upload')).sort().reverse()
      .find((d) => isRealDir(join(releasesDir, d)));
    if (newest) {
      releaseDir = join(releasesDir, newest);
      source = 'newest_upload_release';
      identityRow = db.prepare('SELECT id, commit_hash FROM deployments WHERE app_id = ? AND env = ? AND release_path = ? ORDER BY id DESC LIMIT 1')
        .get(app.id, env, releaseDir) || null;
    }
  }
  if (!releaseDir) return { env, releaseDir: null, missing: !!live, warnings };
  return {
    env, releaseDir, source, warnings, missing: false,
    deploymentId: source === 'live_deployment' ? live.id : null,
    previousCommitHash: source === 'live_deployment' ? live.commit_hash : null,
    artifactHash: typeof identityRow?.commit_hash === 'string' && identityRow.commit_hash.startsWith('sha256:') ? identityRow.commit_hash : null,
  };
}

// ---------------------------------------------------------------------------
// git
// ---------------------------------------------------------------------------

function runGit(lg, gitDir, args, { deadline, feed } = {}) {
  return new Promise((resolveP, reject) => {
    const remaining = deadline - Date.now();
    if (!(remaining > 0)) {
      return reject(Object.assign(new Error(`git ${args[0]} not started: conversion deadline already passed`), { code: 'GIT_TIMEOUT' }));
    }
    const child = spawn('git', lg.isolatedGitArgs(gitDir, args), { env: lg.isolatedGitEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
    const out = [];
    let err = '';
    let timedOut = false;
    let feedError = null;
    let settled = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, remaining);
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => { if (err.length < 8000) err += c.toString(); });
    child.stdin.on('error', () => {});
    const done = (fn) => { if (!settled) { settled = true; clearTimeout(timer); fn(); } };
    child.on('error', (e) => done(() => reject(Object.assign(new Error(`git ${args[0]}: ${e.message}`), { code: 'GIT_FAILED' }))));
    child.on('close', (code) => done(() => {
      if (timedOut) return reject(Object.assign(new Error(`git ${args[0]} killed at the conversion deadline`), { code: 'GIT_TIMEOUT' }));
      if (feedError) return reject(feedError);
      if (code !== 0) return reject(Object.assign(new Error(`git ${args[0]} failed (exit ${code}): ${err.trim().slice(-2000)}`), { code: 'GIT_FAILED' }));
      resolveP(Buffer.concat(out).toString('utf8'));
    }));
    if (feed) {
      feed(child.stdin).then(() => child.stdin.end(), (e) => { feedError = e; child.kill('SIGKILL'); });
    } else {
      child.stdin.end();
    }
  });
}

function writeTo(stream, chunk) {
  return new Promise((res, rej) => {
    const gone = () => Object.assign(new Error('git fast-import exited while being fed'), { code: 'GIT_FAILED' });
    if (stream.destroyed || stream.writableEnded) return rej(gone());
    if (stream.write(chunk)) return res();
    const cleanup = () => { stream.off('drain', onDrain); stream.off('close', onClose); stream.off('error', onClose); };
    const onDrain = () => { cleanup(); res(); };
    const onClose = () => { cleanup(); rej(gone()); };
    stream.on('drain', onDrain); stream.on('close', onClose); stream.on('error', onClose);
  });
}

export function quotePath(p) {
  let s = '"';
  for (const ch of p) {
    const c = ch.codePointAt(0);
    if (ch === '\\') s += '\\\\';
    else if (ch === '"') s += '\\"';
    else if (c < 0x20 || c === 0x7f) s += `\\${c.toString(8).padStart(3, '0')}`;
    else s += ch;
  }
  return `${s}"`;
}

async function feedSnapshots(stdin, lg, snaps, deadline) {
  const who = `${lg.LOCAL_GIT_IDENTITY.name} <${lg.LOCAL_GIT_IDENTITY.email}>`;
  const now = Math.floor(Date.now() / 1000);
  await writeTo(stdin, 'feature done\n');
  for (let i = 0; i < snaps.length; i++) {
    const s = snaps[i];
    const msg = Buffer.from(s.message);
    await writeTo(stdin, `commit refs/heads/main\nmark :${i + 1}\nauthor ${who} ${now} +0000\ncommitter ${who} ${now} +0000\ndata ${msg.length}\n`);
    await writeTo(stdin, msg);
    await writeTo(stdin, `\n${i > 0 ? `from :${i}\n` : ''}deleteall\n`);
    for (const e of s.scan.entries) {
      if (Date.now() >= deadline) throw Object.assign(new Error('conversion deadline reached while writing the repository'), { code: 'GIT_TIMEOUT' });
      const abs = join(s.releaseDir, e.path);
      let data;
      if (e.kind === 'symlink') {
        const target = readlinkSync(abs);
        if (target !== e.target) throw Object.assign(new Error(`${s.env}: symlink ${e.path} changed during conversion`), { code: 'RELEASE_CHANGED' });
        data = Buffer.from(target);
      } else {
        data = readNoFollow(abs);
        if (data.length !== e.size) throw Object.assign(new Error(`${s.env}: ${e.path} changed size during conversion`), { code: 'RELEASE_CHANGED' });
      }
      await writeTo(stdin, `M ${e.mode} inline ${quotePath(e.path)}\ndata ${data.length}\n`);
      await writeTo(stdin, data);
      await writeTo(stdin, '\n');
    }
    await writeTo(stdin, '\n');
  }
  await writeTo(stdin, 'done\n');
}

async function verifyRepo(lg, gitDir, tip, deadline) {
  const refs = (await runGit(lg, gitDir, ['for-each-ref', '--format=%(objectname) %(refname)'], { deadline })).trim();
  if (refs !== `${tip} refs/heads/main`) {
    throw Object.assign(new Error(`repository refs are not exactly main at ${tip.slice(0, 12)}`), { code: 'REPO_SHAPE' });
  }
  const head = (await runGit(lg, gitDir, ['symbolic-ref', 'HEAD'], { deadline })).trim();
  if (head !== 'refs/heads/main') throw Object.assign(new Error(`HEAD is ${head}, not refs/heads/main`), { code: 'REPO_SHAPE' });
  try {
    await runGit(lg, gitDir, ['fsck', '--strict', '--no-dangling', '--no-progress'], { deadline });
  } catch (e) {
    if (e.code === 'GIT_TIMEOUT') throw e;
    throw Object.assign(new Error(`git fsck failed: ${e.message}`), { code: 'FSCK_FAILED' });
  }
}

// ---------------------------------------------------------------------------
// One app
// ---------------------------------------------------------------------------

export async function convertOneApp(db, app, opts = {}) {
  // The flip is guarded by this value, so it must be one of the two types this
  // module converts; anything else would let the UPDATE match a non-upload app.
  const originalType = app?.source_type;
  if (!CONVERTIBLE_SOURCE_TYPES.includes(originalType)) {
    return { slug: app?.slug, status: 'skipped', error_code: 'not_an_upload_app', error: `source_type is ${JSON.stringify(originalType)}; not converted`, tip: null, duration_ms: 0 };
  }
  const lg = opts.localGit || await import('./localGit.js');
  const startedMs = Date.now();
  const startedAt = new Date(startedMs).toISOString();
  const deadline = Math.min(startedMs + (opts.appTimeoutMs ?? DEFAULT_APP_TIMEOUT_MS), opts.budgetDeadline ?? Infinity);
  const maxBytes = opts.maxBytes ?? positiveNumber(MAX_BYTES_ENV, DEFAULT_MAX_BYTES);
  const maxFiles = opts.maxFiles ?? DEFAULT_MAX_FILES;
  const prior = db.prepare('SELECT status, attempts, tip, commits_json FROM upload_conversions WHERE app_id = ?').get(app.id);
  const attempts = (prior?.attempts || 0) + 1;
  const acc = { excluded: [], skipped_files: [], warnings: [], invalid_keys: {}, tracked_bytes: 0 };
  let staging = null;

  const fields = (status, extra) => ({
    status, attempts, started_at: startedAt, finished_at: new Date().toISOString(), duration_ms: Date.now() - startedMs,
    excluded: acc.excluded, skipped_files: acc.skipped_files, warnings: acc.warnings,
    invalid_keys: Object.keys(acc.invalid_keys).length ? acc.invalid_keys : null, tracked_bytes: acc.tracked_bytes,
    ...extra,
    detail: { original_source_type: originalType, ...(extra?.detail || {}) },
  });
  const logOutcome = (f) => {
    const imported = Object.values(f.imported_keys || {}).reduce((n, a) => n + a.length, 0);
    const kept = Object.values(f.kept_existing || {}).reduce((n, a) => n + a.length, 0);
    const line = `[upload-conversion] ${app.slug}: ${f.status}${f.error_code ? ` (${f.error_code})` : ''} in ${f.duration_ms}ms`
      + (f.status === 'converted' ? ` — tip ${String(f.tip).slice(0, 12)}, excluded ${acc.excluded.length} path(s), imported ${imported} key(s), kept ${kept} existing` : '')
      + (f.error ? ` — ${String(f.error).slice(0, 500)}` : '');
    if (f.status === 'converted') log.info(line); else log.warn(line);
  };
  const finish = (status, extra = {}) => {
    const f = fields(status, extra);
    try { record(db, app, f); } catch (e) { log.error(`[upload-conversion] ${app.slug}: could not record outcome '${status}': ${e.message}`); }
    logOutcome(f);
    return { slug: app.slug, status, error_code: f.error_code ?? null, error: f.error ?? null, tip: f.tip ?? null, duration_ms: f.duration_ms };
  };

  try {
    const recovering = prior && RECOVERABLE.includes(prior.status) && /^[0-9a-f]{40}$/.test(prior.tip || '');
    if (!recovering) record(db, app, { status: 'running', attempts, started_at: startedAt, detail: { original_source_type: originalType } });

    if (app.repo_backend !== null && app.repo_backend !== undefined) {
      return finish('skipped', { error_code: 'unsupported_repo_backend', error: `source_type is '${originalType}' but repo_backend is ${JSON.stringify(app.repo_backend)}; left untouched` });
    }
    if (originalType === 'managed_legacy' && String(app.github_url ?? '').trim()) {
      return finish('skipped', {
        error_code: 'legacy_has_github_url',
        error: "legacy upload app has a github_url; left untouched. Promote it to source_type='github' to deploy from that repository, or clear github_url to allow conversion to a Crane-hosted one.",
      });
    }

    const plans = ENVS.map((env) => planEnv(db, app, env));
    for (const p of plans) acc.warnings.push(...p.warnings);
    const missing = plans.filter((p) => p.missing).map((p) => p.env);
    if (missing.length) {
      return finish('skipped', { error_code: 'releases_missing', error: `live deployment with no uploaded release on disk: ${missing.join(', ')}`, detail: { envs: missing } });
    }
    const present = plans.filter((p) => p.releaseDir);
    if (present.length === 0) return finish('skipped', { error_code: 'releases_missing', error: 'no uploaded release on disk for either environment' });

    let budgetLeft = maxBytes;
    for (const p of present) {
      p.scan = scanRelease(p.releaseDir, { maxBytes: budgetLeft, maxFiles });
      acc.excluded.push(...p.scan.excluded.map((x) => ({ env: p.env, ...x })));
      acc.skipped_files.push(...p.scan.skippedFiles.map((x) => ({ env: p.env, ...x })));
      acc.tracked_bytes += p.scan.trackedBytes;
      if (p.scan.tooLarge) {
        return finish('skipped', {
          error_code: 'too_large',
          error: `${p.env} release goes past the conversion cap (${p.scan.tooLarge.limit}: ${maxBytes === Infinity ? maxFiles : (p.scan.tooLarge.limit === 'bytes' ? maxBytes : maxFiles)})`,
          detail: { env: p.env, ...p.scan.tooLarge, max_bytes: maxBytes, max_files: maxFiles },
        });
      }
      budgetLeft -= p.scan.trackedBytes;
      if (p.scan.entries.length === 0) {
        return finish('skipped', { error_code: 'empty_after_exclusions', error: `${p.env} release holds nothing but excluded content`, detail: { env: p.env } });
      }
    }

    for (const p of present) {
      p.envInfo = analyzeEnvFiles(p.releaseDir, p.scan, p.env);
      acc.warnings.push(...p.envInfo.warnings.map((w) => ({ env: p.env, ...w })));
      if (p.envInfo.invalidKeys.length) acc.invalid_keys[p.env] = p.envInfo.invalidKeys;
    }
    const parseErrors = present.flatMap((p) => p.envInfo.parseErrors.map((e) => ({ env: p.env, ...e })));
    if (parseErrors.length) {
      return finish('skipped', { error_code: 'env_parse_error', error: `${parseErrors.length} problem(s) in bundled .env files to import`, detail: { errors: parseErrors } });
    }
    for (const p of present) {
      const problem = dependencyProblem(p.releaseDir, p.scan);
      if (problem) return finish('skipped', { error_code: 'needs_bundled_node_modules', error: `${p.env}: ${problem}`, detail: { env: p.env, reason: problem } });
    }

    for (const p of present) {
      const cap = captureEnvFiles(p.releaseDir, p.scan.envFiles);
      acc.warnings.push(...cap.warnings.map((w) => ({ env: p.env, ...w })));
      if (cap.tooLarge.length) {
        return finish('skipped', {
          error_code: 'env_file_too_large',
          error: `${p.env}: .env file(s) over ${ENV_FILE_MAX_BYTES} bytes cannot be kept: ${cap.tooLarge.join(', ')}`,
          detail: { env: p.env, paths: cap.tooLarge },
        });
      }
      p.envFiles = cap.files;
    }

    const { digestTree } = await import('./artifactDigest.js');
    for (const p of present) {
      p.identity = p.artifactHash || `tree-sha256:${digestTree(p.releaseDir).sha256}`;
      const name = basename(p.releaseDir);
      p.message = p.artifactHash
        ? `Imported from upload ${p.identity} (${p.env})\n\nRelease directory: ${name}\n`
        : `Imported from upload release ${name} ${p.identity} (${p.env})\n`;
    }

    const { encrypt } = await import('./encryption.js');
    for (const p of present) {
      p.encrypted = new Map();
      for (const [k, v] of p.envInfo.values) {
        try { p.encrypted.set(k, encrypt(v)); } catch (_) {
          throw Object.assign(new Error(`could not encrypt the imported value of ${k} (${p.env}); is ENCRYPTION_KEY set?`), { code: 'ENCRYPTION_FAILED' });
        }
      }
      try { p.envFilesEncrypted = encryptEnvFiles(p.envFiles); } catch (_) {
        throw Object.assign(new Error(`could not encrypt the .env files of ${p.env}; is ENCRYPTION_KEY set?`), { code: 'ENCRYPTION_FAILED' });
      }
    }

    const commitsRecord = (commitByEnv) => Object.fromEntries(present.map((p) => [p.env, {
      commit: commitByEnv[p.env], release: basename(p.releaseDir), source: p.source, identity: p.identity,
      deployment_id: p.deploymentId, previous_commit_hash: p.previousCommitHash,
    }]));

    let tip;
    let commitByEnv;
    let recovered = false;
    if (existsSync(lg.repoPath(app.slug))) {
      if (!recovering) {
        return finish('skipped', {
          error_code: 'local_repo_exists',
          error: `a repository already exists at repos/${app.slug}.git while the app is still '${originalType}'; left untouched. Remove or move it to allow conversion, or keep it to stop conversion.`,
        });
      }
      const priorCommits = JSON.parse(prior.commits_json || '{}');
      const same = Object.keys(priorCommits).sort().join() === present.map((p) => p.env).sort().join()
        && present.every((p) => priorCommits[p.env]?.identity === p.identity && /^[0-9a-f]{40}$/.test(priorCommits[p.env]?.commit || ''));
      if (!same) {
        return finish('failed', { error_code: 'RECOVERY_MISMATCH', error: `the releases on disk no longer match the conversion recorded before the interruption; repository left in place, app left as ${originalType}`, tip: prior.tip, commits: priorCommits });
      }
      await verifyRepo(lg, lg.repoPath(app.slug), prior.tip, deadline);
      tip = prior.tip;
      commitByEnv = Object.fromEntries(present.map((p) => [p.env, priorCommits[p.env].commit]));
      recovered = true;
    } else {
      staging = lg.conversionStagingPath(app.slug);
      rmSync(staging, { recursive: true, force: true });
      mkdirSync(lg.reposRoot(), { recursive: true });
      await runGit(lg, null, ['init', '--quiet', '--bare', '--template=', '--object-format=sha1', '--initial-branch=main', staging], { deadline });
      await runGit(lg, staging, ['fast-import', '--quiet', '--date-format=raw', '--done'], { deadline, feed: (stdin) => feedSnapshots(stdin, lg, present, deadline) });
      const rev = async (r) => (await runGit(lg, staging, ['rev-parse', '--verify', '--end-of-options', r], { deadline })).trim();
      tip = await rev('refs/heads/main');
      commitByEnv = { [present[0].env]: tip };
      if (present.length === 2) {
        const first = await rev('refs/heads/main~1');
        if (await rev('refs/heads/main^{tree}') === await rev('refs/heads/main~1^{tree}')) {
          await runGit(lg, staging, ['update-ref', 'refs/heads/main', first, tip], { deadline });
          tip = first;
          commitByEnv = { [present[0].env]: first, [present[1].env]: first };
        } else {
          commitByEnv = { [present[0].env]: first, [present[1].env]: tip };
        }
      }
      await verifyRepo(lg, staging, tip, deadline);
      if (opts.afterStage) await opts.afterStage(app, staging);
      record(db, app, fields('installing', { tip, commits: commitsRecord(commitByEnv) }));
      lg.installMigratedRepo(app.slug, staging);
      staging = null;
      if (opts.afterInstall) await opts.afterInstall(app);
    }

    const commits = commitsRecord(commitByEnv);
    let outcome;
    try {
      outcome = db.transaction(() => {
        const changed = db.prepare(
          "UPDATE apps SET source_type = 'managed', repo_backend = 'local', branch = 'main', last_managed_push_sha = ? WHERE id = ? AND source_type = ? AND repo_backend IS NULL",
        ).run(tip, app.id, originalType).changes;
        if (changed !== 1) throw Object.assign(new Error(`the app is no longer '${originalType}' with no repo_backend; nothing flipped`), { code: 'FLIP_GUARD' });
        for (const p of present) {
          if (p.deploymentId) db.prepare('UPDATE deployments SET commit_hash = ? WHERE id = ? AND app_id = ?').run(commitByEnv[p.env], p.deploymentId, app.id);
        }
        const has = db.prepare('SELECT 1 FROM env_vars WHERE app_id = ? AND env = ? AND key = ?');
        const ins = db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted, updated_at) VALUES (?, ?, ?, ?, datetime('now'))");
        const imported = {};
        const kept = {};
        for (const p of present) {
          imported[p.env] = [];
          kept[p.env] = [];
          for (const [k, enc] of p.encrypted) {
            if (has.get(app.id, p.env, k)) kept[p.env].push(k);
            else { ins.run(app.id, p.env, k, enc); imported[p.env].push(k); }
          }
          storeEnvFiles(db, app.id, p.env, p.envFilesEncrypted);
        }
        const f = fields('converted', {
          tip, commits, imported_keys: imported, kept_existing: kept,
          detail: {
            recovered,
            imported_from: Object.fromEntries(present.map((p) => [p.env, p.envInfo.importedFrom])),
            stored_env_files: Object.fromEntries(present.map((p) => [p.env, p.envFiles.map((x) => x.rel_path)])),
          },
        });
        record(db, app, f);
        return f;
      })();
    } catch (e) {
      if (e.code === 'FLIP_GUARD') return finish('failed', { error_code: 'FLIP_GUARD', error: e.message, tip, commits });
      return finish('flip_failed', { error_code: typeof e.code === 'string' ? e.code : 'ERROR', error: e.message, tip, commits });
    }
    logOutcome(outcome);
    return { slug: app.slug, status: 'converted', error_code: null, error: null, tip, recovered, duration_ms: outcome.duration_ms };
  } catch (e) {
    const code = e?.code === 'GIT_TIMEOUT' ? 'TIMEOUT' : (typeof e?.code === 'string' ? e.code : 'ERROR');
    return finish('failed', { error_code: code, error: e?.message || String(e) });
  } finally {
    if (staging) {
      try { rmSync(staging, { recursive: true, force: true }); } catch (_) { /* removed by the next attempt */ }
    }
  }
}

// ---------------------------------------------------------------------------
// Every app
// ---------------------------------------------------------------------------

export async function convertUploadedApps(opts = {}) {
  const startedMs = Date.now();
  try {
    const db = opts.db || (await import('../db.js')).getDb();
    const disabled = conversionDisabledReason(db);
    if (disabled) {
      log.info(`[upload-conversion] disabled by ${disabled}; uploaded apps stay as they are`);
      return { disabled, results: [] };
    }
    const apps = candidateApps(db);
    if (apps.length === 0) return { disabled: null, results: [] };

    const budgetMs = opts.budgetMs ?? positiveNumber(BUDGET_ENV, DEFAULT_BUDGET_MS, 1000);
    const appTimeoutMs = opts.appTimeoutMs ?? positiveNumber(APP_TIMEOUT_ENV, DEFAULT_APP_TIMEOUT_MS, 1000);
    const budgetDeadline = startedMs + budgetMs;
    log.info(`[upload-conversion] ${apps.length} uploaded app(s) (${apps.filter((a) => a.source_type === 'managed_legacy').length} legacy); converting to Crane-hosted repositories one at a time (per-app limit ${Math.round(appTimeoutMs / 1000)}s, total ${Math.round(budgetMs / 1000)}s)`);

    const results = [];
    for (const app of apps) {
      if (Date.now() >= budgetDeadline) {
        try {
          const prev = db.prepare('SELECT status, attempts FROM upload_conversions WHERE app_id = ?').get(app.id);
          if (!prev || !RECOVERABLE.includes(prev.status)) {
            record(db, app, { status: 'deferred', attempts: prev?.attempts || 0, error_code: 'BUDGET_EXHAUSTED', error: 'boot conversion budget used up before this app; retried next boot', finished_at: new Date().toISOString(), detail: { original_source_type: app.source_type } });
          }
        } catch (e) { log.error(`[upload-conversion] ${app.slug}: could not record deferral: ${e.message}`); }
        results.push({ slug: app.slug, status: 'deferred', error_code: 'BUDGET_EXHAUSTED' });
        continue;
      }
      try {
        results.push(await convertOneApp(db, app, { ...opts, appTimeoutMs, budgetDeadline }));
      } catch (e) {
        log.error(`[upload-conversion] ${app?.slug}: unexpected failure outside the per-app guard: ${e?.message || e}`);
        results.push({ slug: app?.slug, status: 'failed', error_code: 'ERROR' });
      }
    }
    const count = (s) => results.filter((r) => r.status === s).length;
    log.info(`[upload-conversion] done in ${Date.now() - startedMs}ms: ${count('converted')} converted, ${count('failed') + count('flip_failed')} failed, ${count('skipped')} skipped, ${count('deferred')} deferred`);
    return { disabled: null, results };
  } catch (e) {
    log.error(`[upload-conversion] aborted, boot continues: ${e?.message || e}`);
    return { disabled: null, results: [], error: String(e?.message || e) };
  }
}

/** The boot entry point: cannot reject. */
export async function convertUploadedAppsAtBoot(opts = {}) {
  try {
    return await convertUploadedApps(opts);
  } catch (e) {
    try { log.error(`[upload-conversion] boot hook failed, boot continues: ${e?.message || e}`); } catch (_) { /* nothing left */ }
    return { disabled: null, results: [], error: String(e?.message || e) };
  }
}

const parse = (s) => (s ? JSON.parse(s) : null);

/**
 * Per-app outcome for the admin status route. Key names and paths only (stored_env_files: paths, never contents).
 * original_source_type: what the app was before conversion; a row written before it was recorded can only
 * be an 'upload' app, the one type converted then. revert: the apps columns that undo a conversion.
 */
export function getUploadConversionStatus(db) {
  const apps = db.prepare(`
    SELECT c.*, a.source_type, a.repo_backend, (a.id IS NULL) AS app_deleted
      FROM upload_conversions c LEFT JOIN apps a ON a.id = c.app_id
     ORDER BY c.app_id
  `).all().map((r) => ({ r, detail: parse(r.detail_json) })).map(({ r, detail }) => ({
    app_id: r.app_id, slug: r.slug, status: r.status, attempts: r.attempts,
    skip_reason: r.status === 'skipped' ? r.error_code : null,
    error_code: r.error_code, error: r.error, tip: r.tip,
    commits: parse(r.commits_json),
    imported_keys: parse(r.imported_keys_json), kept_existing: parse(r.kept_existing_json), invalid_keys: parse(r.invalid_keys_json),
    excluded: { count: r.excluded_count ?? 0, paths: parse(r.excluded_json) || [], capped_at: EXCLUDED_CAP },
    skipped_files: parse(r.skipped_files_json) || [], warnings: parse(r.warnings_json) || [], detail,
    tracked_bytes: r.tracked_bytes, started_at: r.started_at, finished_at: r.finished_at, duration_ms: r.duration_ms,
    stored_env_files: storedEnvFilePaths(db, r.app_id),
    source_type: r.source_type, repo_backend: r.repo_backend, app_deleted: !!r.app_deleted,
    original_source_type: detail?.original_source_type || 'upload',
    revert: r.status === 'converted' ? { source_type: detail?.original_source_type || 'upload', repo_backend: null } : null,
  }));
  return { disabled: conversionDisabledReason(db), pending: candidateApps(db).map((a) => a.slug), apps };
}
