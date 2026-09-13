/**
 * Whole-system DATA backup — everything needed to stand AppCrane back up,
 * except code and images, which are their own artifacts.
 *
 * What's in the archive (appcrane-backup-<host>[-<image fp12>]-<stamp>.tar.gz):
 *   - appcrane-backup.json — manifest (version, timestamp, counts, byte totals,
 *                      image_set, repo_set). First member, so it is read
 *                      before anything else is extracted.
 *   - deployhub.db   — the SQLite DB (apps, users, settings, env_vars [encrypted],
 *                      role_permissions, deployments metadata, …), taken with
 *                      VACUUM INTO on a separate read-only connection in a
 *                      worker thread: one WAL read transaction, so a consistent
 *                      point-in-time copy while the server keeps writing.
 *   - .env           — platform env, crucially the ENCRYPTION_KEY. Without it
 *                      the DB's encrypted env_vars / secrets can't be decrypted.
 *   - apps/<slug>/icon.*                    — per-app tile icons.
 *   - apps/<slug>/<env>/shared/data/…       — the app's /data mount.
 *   - apps/<slug>/<env>/shared/volumes/…    — every OTHER declared mount,
 *                      mirroring the container path (v2.70.2).
 *
 * NOT in it:
 *   - managed-app git repositories — one archive per repo, see
 *     services/repoArchive.js. The manifest's `repo_set` names every repo that
 *     existed at export time with its HEAD, every ref's SHA and a fingerprint,
 *     so a restore can say which repo archives it expects and detect a pair
 *     taken across a push. (v2.73.x put the bundles inside this file; those
 *     backups still import, see importDataArchive.)
 *   - container images — services/imageArchive.js, paired via `image_set`.
 *   - build artifacts (`releases/`) and the Caddyfile (regenerated on boot).
 *
 * v2.74.0: NOTHING IS BUILT IN MEMORY AND NOTHING BLOCKS THE EVENT LOOP.
 * Until v2.73 the whole backup was an adm-zip Buffer (built synchronously,
 * sent with res.end, uploaded through a 200 MB multer memory buffer). The DB is
 * now copied in a worker thread, the tree walk uses async fs, and the
 * archive is written by a spawned `tar` straight to a file under
 * DATA_DIR/backups. Import reads a file on disk the same way. See
 * backupFiles.js for why tar.
 *
 * SECURITY: the archive contains the ENCRYPTION_KEY and every encrypted secret.
 * Files are written 0600 in a 0700 directory; routes are platform_admin-only.
 */

import { getDb } from '../db.js';
import { existsSync } from 'fs';
import {
  readFile, writeFile, rename, rm, mkdir, stat, lstat, copyFile, readdir, unlink, readlink, symlink,
} from 'fs/promises';
import { join, resolve, dirname, basename } from 'path';
import { randomBytes } from 'crypto';
import { Worker } from 'worker_threads';
import { createRequire } from 'module';
import { liveDeploymentImages, imageSetFingerprint } from './imageArchive.js';
import { runRepoTask, currentRepoSet, recordExpectedRepoSet, verifyRepoSet } from './repoArchive.js';
import {
  SLUG_RE, repoRoot, dataDir, backupsDir, ensureBackupsDir, newWorkDir, freeBytes,
  createTar, extractTar, walk, treeBytes, readHead, privateFile, readZipDirectory, extractZipEntry,
} from './backupFiles.js';
import log from '../utils/logger.js';

const dbPath = () => join(dataDir(), 'deployhub.db');
const envPath = () => join(repoRoot, '.env');

export const MANIFEST = 'appcrane-backup.json';
const ICON_RE = /^icon\.(png|svg|webp|jpg|jpeg|gif)$/i;
const ENVS = ['sandbox', 'production'];

/**
 * Point-in-time copy of the live DB to `dest`, off the event loop.
 *
 * Not better-sqlite3's backup API, although it is async: it copies pages on
 * the MAIN thread between event-loop turns, and those page writes stall under
 * Linux dirty-page throttling. Measured on node:22-bookworm, 512 MB DB with
 * concurrent writes: event-loop delay 127-129 ms on a clean page cache and
 * 246-406 ms after 1 GB of recent writes. The same copy made by VACUUM INTO on
 * a read-only connection in a worker: 7.7-7.9 ms in both conditions (macOS
 * 6.3-7.1 ms). A read-only WAL reader holds one read transaction for the whole
 * statement, so the copy is consistent while the main connection keeps writing.
 */
const requireCjs = createRequire(import.meta.url);
const SNAPSHOT_WORKER = `
const { parentPort, workerData } = require('worker_threads');
try {
  const Database = require(workerData.driver);
  const d = new Database(workerData.src, { readonly: true, fileMustExist: true });
  try { d.exec("VACUUM INTO '" + workerData.dest.replace(/'/g, "''") + "'"); } finally { d.close(); }
  parentPort.postMessage({ ok: true });
} catch (e) {
  parentPort.postMessage({ ok: false, message: e.message });
}
`;

export function snapshotDatabase(dest) {
  const driver = requireCjs.resolve('better-sqlite3');
  return new Promise((resolveP, reject) => {
    const w = new Worker(SNAPSHOT_WORKER, { eval: true, workerData: { driver, src: dbPath(), dest } });
    let settled = false;
    w.once('message', (m) => { settled = true; m.ok ? resolveP() : reject(new Error(`database snapshot failed: ${m.message}`)); });
    w.once('error', (e) => { if (!settled) { settled = true; reject(e); } });
    w.once('exit', (code) => { if (!settled) reject(new Error(`database snapshot worker exited with ${code}`)); });
  });
}

async function craneVersion() {
  try { return JSON.parse(await readFile(join(repoRoot, 'package.json'), 'utf8')).version; }
  catch (_) { return 'unknown'; }
}

export function dataArchiveFileName(host, imageFingerprint, at = new Date()) {
  const stamp = at.toISOString().replace(/\.\d+Z$/, 'Z').replace(/:/g, '-');
  const fp = imageFingerprint ? `-${imageFingerprint.slice(0, 12)}` : '';
  return `appcrane-backup-${host}${fp}-${stamp}.tar.gz`;
}

const hostLabel = () => (process.env.CRANE_DOMAIN || 'appcrane').replace(/[^a-z0-9.-]/gi, '');

async function isRealDir(p) {
  try { return (await lstat(p)).isDirectory(); } catch (_) { return false; }
}

/** The members under DATA_DIR/apps that a data archive holds, plus their byte total. */
async function collectAppTrees() {
  const appsDir = join(dataDir(), 'apps');
  const members = [];
  const skipped = [];
  let bytes = 0;
  let dataVolumes = 0;
  if (!(await isRealDir(appsDir))) return { members, skipped, bytes, dataVolumes };
  for (const slug of (await readdir(appsDir)).sort()) {
    if (!SLUG_RE.test(slug)) { skipped.push(slug); continue; }
    const appDir = join(appsDir, slug);
    if (!(await isRealDir(appDir))) continue;
    for (const f of await readdir(appDir)) {
      if (!ICON_RE.test(f)) continue;
      const st = await lstat(join(appDir, f));
      if (st.isFile()) { members.push(`apps/${slug}/${f}`); bytes += st.size; }
    }
    for (const env of ENVS) {
      for (const kind of ['data', 'volumes']) {
        const p = join(appDir, env, 'shared', kind);
        if (!(await isRealDir(p))) continue;
        members.push(`apps/${slug}/${env}/shared/${kind}`);
        bytes += await treeBytes(p);
        if (kind === 'data') dataVolumes++;
      }
    }
  }
  return { members, skipped, bytes, dataVolumes };
}

/**
 * Write the data archive to disk.
 *
 * @param {object} opts
 *   dest     — full path to write (default DATA_DIR/backups/<name>)
 *   at       — Date used for the name and manifest
 *   force    — write even if the free-space check fails
 *   version  — override the recorded AppCrane version
 * @returns {{ path, file, bytes, manifest, warnings }}
 */
export async function exportDataArchive(opts = {}) {
  const at = opts.at || new Date();
  const version = opts.version || await craneVersion();
  const db = getDb();
  await ensureBackupsDir();
  const stage = await newWorkDir('data-export');
  try {
    // 1. DB: a point-in-time copy made in a worker (see snapshotDatabase).
    const stagedDb = join(stage, 'deployhub.db');
    await snapshotDatabase(stagedDb);
    const dbBytes = (await stat(stagedDb)).size;

    const hasEnv = existsSync(envPath());
    const envBytes = hasEnv ? (await stat(envPath())).size : 0;
    const trees = await collectAppTrees();

    const repoSet = await currentRepoSet();

    const counts = {};
    for (const t of ['apps', 'users', 'settings', 'env_vars', 'role_permissions']) {
      try { counts[t] = db.prepare(`SELECT COUNT(*) c FROM ${t}`).get().c; } catch (_) {}
    }
    // Which image archive this belongs with (v2.72.0), derived from the DB.
    let imageSet = null;
    try {
      const entries = liveDeploymentImages('live').filter((e) => e.archive_tag);
      imageSet = {
        scope: 'live',
        count: entries.length,
        fingerprint: imageSetFingerprint(entries.map((e) => e.archive_tag)),
        images: entries.map((e) => ({ slug: e.slug, env: e.env, ref: e.ref, archive_tag: e.archive_tag })),
      };
    } catch (e) {
      log.warn(`[config-backup] could not record the image set: ${e.message}`);
    }

    const totalBytes = dbBytes + envBytes + trees.bytes;
    const dir = opts.dest ? dirname(resolve(opts.dest)) : backupsDir();
    const free = freeBytes(dir);
    // Uncompressed total is the ceiling for a gzip archive, plus the DB copy
    // already staged.
    const required = Math.ceil(totalBytes * 1.1) + 64 * 1024 * 1024;
    if (free !== null && free < required && !opts.force) {
      throw Object.assign(new Error(`Not enough free space in ${dir}: the data archive needs up to ${required} bytes and ${free} are free.`), { status: 507 });
    }

    const manifest = {
      kind: 'appcrane-config-backup',
      format: 2,
      archive: 'tar.gz',
      version,
      exported_at: at.toISOString(),
      crane_domain: process.env.CRANE_DOMAIN || null,
      includes: ['deployhub.db', ...(hasEnv ? ['.env'] : []), 'icons', 'appdata', 'appvolumes'],
      counts,
      bytes: { db: dbBytes, env: envBytes, apps: trees.bytes, total: totalBytes },
      repos_included: false,
      repo_set: repoSet,
      image_set: imageSet,
    };
    await writeFile(join(stage, MANIFEST), JSON.stringify(manifest, null, 2), { mode: 0o600 });

    const file = opts.dest ? basename(opts.dest) : dataArchiveFileName(hostLabel(), imageSet?.fingerprint, at);
    const dest = opts.dest ? resolve(opts.dest) : join(backupsDir(), file);
    const partial = `${dest}.partial-${randomBytes(4).toString('hex')}`;
    let warnings;
    try {
      ({ warnings } = await createTar(partial, [
        { cwd: stage, paths: [MANIFEST, 'deployhub.db'] },
        ...(hasEnv ? [{ cwd: repoRoot, paths: ['.env'] }] : []),
        { cwd: dataDir(), paths: trees.members },
      ], { gzip: true }));
      await privateFile(partial);
      await rename(partial, dest);
    } catch (e) {
      await rm(partial, { force: true });
      throw e;
    }
    const bytes = (await stat(dest)).size;
    log.info(`[config-backup] exported data archive (apps=${counts.apps}, users=${counts.users}, env=${hasEnv}, data-volumes=${trees.dataVolumes}, repos-recorded=${repoSet.count}, ${bytes} bytes)`);
    return { path: dest, file, bytes, manifest, warnings, skipped: trees.skipped };
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

const refuse = (msg) => Object.assign(new Error(msg), { status: 400 });

/**
 * Map a v2.9–v2.73 zip entry name to where it lands in the staged tree, or null
 * to ignore it. Names with traversal, absolute or backslash segments are
 * ignored, the same as the old reader.
 */
function legacyTarget(name) {
  if (name.startsWith('/') || name.includes('\\')) return null;
  const segs = name.split('/');
  if (segs.some((s) => s === '' || s === '.' || s === '..')) return null;
  if (name === MANIFEST || name === 'deployhub.db' || name === '.env') return name;
  const [top, ...rest] = segs;
  if (top === 'icons' && rest.length === 2 && SLUG_RE.test(rest[0]) && ICON_RE.test(rest[1])) return `apps/${rest[0]}/${rest[1]}`;
  if ((top === 'appdata' || top === 'appvolumes') && rest.length >= 3 && SLUG_RE.test(rest[0]) && ENVS.includes(rest[1])) {
    return `apps/${rest[0]}/${rest[1]}/shared/${top === 'appdata' ? 'data' : 'volumes'}/${rest.slice(2).join('/')}`;
  }
  const m = /^repos\/([a-z0-9][a-z0-9-]{0,99})\.(HEAD|bundle)$/.exec(name);
  if (m) return `legacy-repos/${m[1]}.${m[2]}`;
  return null;
}

/** Is `rel` (inside the staged tree) something a data archive may contain? */
function allowedStaged(rel, type) {
  if (rel === MANIFEST || rel === 'deployhub.db' || rel === '.env') return type === 'file';
  const s = rel.split('/');
  if (s[0] === 'legacy-repos') return s.length === 1 ? type === 'dir' : (s.length === 2 && type === 'file');
  if (s[0] !== 'apps') return false;
  if (s.length === 1) return type === 'dir';
  if (!SLUG_RE.test(s[1])) return false;
  if (s.length === 2) return type === 'dir';
  if (s.length === 3) return ICON_RE.test(s[2]) ? type === 'file' : (ENVS.includes(s[2]) && type === 'dir');
  if (!ENVS.includes(s[2])) return false;
  if (s.length === 4) return s[3] === 'shared' && type === 'dir';
  if (s[3] !== 'shared' || (s[4] !== 'data' && s[4] !== 'volumes')) return false;
  if (s.length === 5) return type === 'dir';
  return type === 'file' || type === 'dir' || type === 'symlink';
}

/** mkdir each component under `root`, refusing to pass through a symlink. */
async function realDirChain(root, parts) {
  let cur = root;
  for (const p of parts) {
    cur = join(cur, p);
    let st = null;
    try { st = await lstat(cur); } catch (_) {}
    if (!st) { await mkdir(cur); continue; }
    if (!st.isDirectory()) return false;
  }
  return true;
}

async function moveEntry(src, dest, type) {
  try {
    await rename(src, dest);
  } catch (e) {
    if (e.code !== 'EXDEV') throw e;
    await rm(dest, { force: true });
    if (type === 'symlink') await symlink(await readlink(src), dest);
    else await copyFile(src, dest);
  }
}

/**
 * Restore a data archive (tar.gz, or a v2.9–v2.73 zip) that is on disk.
 * DESTRUCTIVE — replaces the live DB (and optionally .env) and writes icons,
 * /data and declared volumes into DATA_DIR/apps. The current DB + .env are
 * copied to pre-import-<ts> first.
 *
 * better-sqlite3 holds the live DB open, so the restored DB takes effect after
 * a process restart — the caller restarts.
 *
 * @param {string} archivePath  file on disk
 * @param {object} opts         { restoreEnv?: boolean (default true) }
 */
export async function importDataArchive(archivePath, opts = {}) {
  const restoreEnv = opts.restoreEnv !== false;
  const magic = await readHead(archivePath, 4);
  const isZip = magic.length === 4 && magic.readUInt32LE(0) === 0x04034b50;
  const isGzip = magic.length >= 2 && magic[0] === 0x1f && magic[1] === 0x8b;
  if (!isZip && !isGzip) throw refuse('Not an AppCrane backup (neither a .tar.gz data archive nor a legacy .zip)');

  const work = await newWorkDir('data-import');
  const tree = join(work, 'tree');
  await mkdir(tree);
  let repoStage = null;
  try {
    // --- 1. Manifest first, then a free-space check against what it declares.
    let manifest;
    let zipDir = null;
    if (isGzip) {
      const mdir = join(work, 'manifest');
      await mkdir(mdir);
      try { await extractTar(archivePath, mdir, { gzip: true, members: [MANIFEST] }); } catch (_) {
        throw refuse('Not an AppCrane backup — manifest missing');
      }
      try { manifest = JSON.parse(await readFile(join(mdir, MANIFEST), 'utf8')); } catch (_) { throw refuse('Backup manifest is corrupt'); }
    } else {
      try { zipDir = await readZipDirectory(archivePath); } catch (e) { throw refuse(e.message === 'Not a valid zip file' ? 'Not a valid zip file' : e.message); }
      const me = zipDir.entries.find((e) => e.name === MANIFEST);
      if (!me) throw refuse('Not an AppCrane backup — manifest missing');
      try {
        await extractZipEntry(archivePath, me, join(work, MANIFEST));
        manifest = JSON.parse(await readFile(join(work, MANIFEST), 'utf8'));
      } catch (_) { throw refuse('Backup manifest is corrupt'); }
    }
    if (manifest.kind !== 'appcrane-config-backup') throw refuse('Unrecognized backup file');

    const expectBytes = isZip
      ? zipDir.entries.reduce((n, e) => n + e.rawSize, 0)
      : Number(manifest.bytes?.total) || 0;
    const free = freeBytes(work);
    const required = Math.ceil(expectBytes * 1.1) + 64 * 1024 * 1024;
    if (free !== null && expectBytes && free < required) {
      throw Object.assign(new Error(`Not enough free space to restore: needs about ${required} bytes, ${free} free in ${dirname(work)}`), { status: 507 });
    }

    // --- 2. Extract into the private staging tree.
    if (isGzip) {
      try { await extractTar(archivePath, tree, { gzip: true }); } catch (e) { throw refuse(`Backup archive is corrupt: ${e.message}`); }
    } else {
      for (const e of zipDir.entries) {
        if (e.isDirectory) continue;
        const target = legacyTarget(e.name);
        if (!target) continue;
        const dest = join(tree, target);
        await mkdir(dirname(dest), { recursive: true });
        try { await extractZipEntry(archivePath, e, dest); } catch (err) { throw refuse(`Backup is corrupt: ${err.message}`); }
      }
    }

    // --- 3. The staged tree may only hold what a data archive holds.
    for await (const e of walk(tree)) {
      if (!allowedStaged(e.rel, e.type)) throw refuse(`Backup contains an unexpected entry ${JSON.stringify(e.rel)} (${e.type}); nothing was restored`);
    }
    const stagedDb = join(tree, 'deployhub.db');
    if (!existsSync(stagedDb)) throw refuse('Backup is missing deployhub.db');
    if ((await readHead(stagedDb, 15)).toString('latin1') !== 'SQLite format 3') {
      throw refuse('Backup deployhub.db is not a valid SQLite file');
    }

    // --- 4. v2.73.x combined backups: verify every repo before anything live changes.
    const legacyRepoDir = join(tree, 'legacy-repos');
    const stagedRepos = [];
    if (existsSync(legacyRepoDir)) {
      const parts = new Map();
      for (const n of await readdir(legacyRepoDir)) {
        const m = /^([a-z0-9][a-z0-9-]{0,99})\.(HEAD|bundle)$/.exec(n);
        if (!m) continue;
        const p = parts.get(m[1]) || {};
        if (m[2] === 'HEAD') p.head = (await readFile(join(legacyRepoDir, n), 'utf8')).trim();
        else p.bundlePath = join(legacyRepoDir, n);
        parts.set(m[1], p);
      }
      if (parts.size) {
        repoStage = await runRepoTask({ op: 'new-stage' });
        try {
          for (const [slug, p] of parts) {
            if (!p.head) throw new Error(`repos/${slug}.bundle has no repos/${slug}.HEAD`);
            stagedRepos.push(await runRepoTask({ op: 'stage', stageDir: repoStage, slug, head: p.head, bundlePath: p.bundlePath || null }));
          }
        } catch (e) {
          throw refuse(`Backup managed-app repository failed verification, nothing was restored: ${e.message}`);
        }
      }
    }

    // --- 5. Point of no return. Keep the current DB + .env.
    const stamp = Date.now();
    const preDir = join(dataDir(), `pre-import-${stamp}`);
    await mkdir(preDir, { recursive: true, mode: 0o700 });
    if (existsSync(dbPath())) await snapshotDatabase(join(preDir, 'deployhub.db'));
    if (existsSync(envPath())) await copyFile(envPath(), join(preDir, '.env'));

    // Swap the DB. The live connection keeps its old inode until restart. Its
    // -wal and -shm MUST go: measured, a restored file renamed over a WAL-mode
    // DB whose -wal still holds frames reopens with those frames replayed — the
    // restore silently comes back as the pre-import data.
    await rename(stagedDb, dbPath());
    for (const suffix of ['-wal', '-shm']) await unlink(`${dbPath()}${suffix}`).catch(() => {});

    let envRestored = false;
    const stagedEnv = join(tree, '.env');
    if (restoreEnv && existsSync(stagedEnv)) { await copyFile(stagedEnv, envPath()); envRestored = true; }

    // --- 6. Apps tree: moved in entry by entry (merge, as before), never
    //        through a symlink already on the host.
    const appsRoot = resolve(join(dataDir(), 'apps'));
    await mkdir(appsRoot, { recursive: true });
    let icons = 0, dataFiles = 0, volumeFiles = 0, refused = 0;
    const stagedApps = join(tree, 'apps');
    if (existsSync(stagedApps)) {
      for await (const e of walk(stagedApps)) {
        const parts = e.rel.split('/');
        const isContent = parts.length > 4;                // <slug>/<env>/shared/<kind>/…
        if (e.type === 'dir') {
          if (!(await realDirChain(appsRoot, parts))) refused++;
          continue;
        }
        if (!(await realDirChain(appsRoot, parts.slice(0, -1)))) { refused++; continue; }
        const dest = join(appsRoot, ...parts);
        let existing = null;
        try { existing = await lstat(dest); } catch (_) {}
        if (existing?.isDirectory()) { refused++; continue; }
        await moveEntry(e.abs, dest, e.type);
        if (parts.length === 2) icons++;
        else if (isContent && parts[3] === 'data') dataFiles++;
        else if (isContent && parts[3] === 'volumes') volumeFiles++;
      }
    }

    // --- 7. Legacy repos go live after the DB swap; replaced repos kept aside.
    let repos = 0;
    if (repoStage && stagedRepos.length) {
      repos = (await runRepoTask({ op: 'install', stageDir: repoStage, slugs: stagedRepos.map((r) => r.slug), preDir })).length;
    }

    // --- 8. Pairing reports.
    let repoSet;
    if (manifest.repo_set) {
      await recordExpectedRepoSet({ ...manifest.repo_set, exported_at: manifest.exported_at }, { data_archive: basename(archivePath) });
      const v = await verifyRepoSet({ ...manifest.repo_set, exported_at: manifest.exported_at });
      repoSet = {
        expected_count: manifest.repo_set.count,
        expected_fingerprint: manifest.repo_set.fingerprint,
        verification: v,
        note: v.matched
          ? 'Every repository this backup expects is on the host at the expected refs.'
          : `Restore each repository from its archive (appcrane-repo-<slug>-<fp12>-*.tar) with POST /api/settings/repos/import, then check GET /api/settings/repos/verify. Missing: ${v.missing.join(', ') || 'none'}; mismatched: ${v.mismatched.join(', ') || 'none'}.`,
      };
    } else if (repos) {
      repoSet = { expected_count: repos, expected_fingerprint: null, note: `Legacy combined backup: ${repos} repositor${repos === 1 ? 'y' : 'ies'} restored in place from the zip.` };
    } else {
      repoSet = { expected_count: 0, expected_fingerprint: null, note: 'This backup predates repository archives and names no repositories.' };
    }

    const imageSet = manifest.image_set
      ? {
        expected_fingerprint: manifest.image_set.fingerprint,
        expected_count: manifest.image_set.count,
        note:
          `This backup pairs with image archive appcrane-images-${String(manifest.image_set.fingerprint).slice(0, 12)}-*.tar. ` +
          'Load it with POST /api/settings/images/import, then check GET /api/settings/images/verify.',
      }
      : { expected_fingerprint: null, expected_count: 0, note: 'This backup predates image archives and names no image set.' };

    log.warn(`[config-backup] IMPORTED backup from ${manifest.exported_at} (format=${isZip ? 'zip' : 'tar.gz'}, env=${envRestored}, icons=${icons}, data-files=${dataFiles}, volume-files=${volumeFiles}, repos=${repos}, refused=${refused}). Restart required. Pre-import copy at ${preDir}`);
    return {
      manifest, format: isZip ? 'legacy-zip' : 'tar.gz',
      envRestored, icons, dataFiles, volumeFiles, refused, preImportDir: preDir, imageSet, repoSet,
      repos,
      repoHeads: stagedRepos.map(({ slug, head, headSha }) => ({ slug, head, headSha })),
    };
  } finally {
    await rm(work, { recursive: true, force: true });
    if (repoStage) await rm(repoStage, { recursive: true, force: true });
  }
}
