/**
 * Whole-system config backup (v2.9.0) — export everything needed to stand
 * AppCrane back up quickly, as one zip, and import it onto a fresh host.
 *
 * What's in the bundle:
 *   - deployhub.db   — the SQLite DB (apps, users, settings, env_vars [encrypted],
 *                      role_permissions, deployments metadata, …). Taken as a
 *                      consistent snapshot via VACUUM INTO so it's never a
 *                      half-written file.
 *   - .env           — platform env, crucially the ENCRYPTION_KEY. Without it
 *                      the DB's encrypted env_vars / secrets can't be decrypted,
 *                      so a backup that omitted it would be useless on restore.
 *   - icons/<slug>/  — per-app tile icons (not stored in the DB).
 *   - appdata/<slug>/<env>/     — the app's /data mount.
 *   - appvolumes/<slug>/<env>/  — every OTHER mount the app declares, laid out
 *                      mirroring the container ('/var/lib/odoo' ->
 *                      volumes/var/lib/odoo). Added v2.70.2 with declared
 *                      volumes; before that an app kept its real state here and
 *                      the backup captured none of it while reporting success.
 *   - appcrane-backup.json — manifest (version, timestamp, counts).
 *
 * SECURITY: the bundle contains the ENCRYPTION_KEY and every encrypted secret.
 * Treat it as a crown-jewel artifact. The routes are platform_admin-only.
 *
 * NOT in the bundle: app code and build artifacts (the `releases/` dirs —
 * redeployable from GitHub), the Caddyfile (regenerated from the DB on boot),
 * and THE CONTAINER IMAGES. The images are deliberately a separate artifact —
 * 5-30 GB for a real box, against a zip this file builds entirely in memory and
 * returns as a Buffer. See services/imageArchive.js. The manifest's `image_set`
 * names the archive this zip belongs with, so the two can be checked as a pair
 * (v2.72.0).
 *
 * This header used to say per-app /data volumes were NOT in the bundle. They
 * always were — section 3 has added them since v2.9.0 — so the sentence
 * described a backup nobody was taking, in the one file where being wrong about
 * what is backed up is worst.
 */

import AdmZip from 'adm-zip';
import { getDb } from '../db.js';
import {
  existsSync, readdirSync, readFileSync, writeFileSync, mkdirSync, copyFileSync, unlinkSync, renameSync,
} from 'fs';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { liveDeploymentImages, imageSetFingerprint } from './imageArchive.js';
import log from '../utils/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(join(__dirname, '..', '..'));

const dataDir = () => resolve(process.env.DATA_DIR || join(repoRoot, 'data'));
const dbPath = () => join(dataDir(), 'deployhub.db');
const envPath = () => join(repoRoot, '.env');

const MANIFEST = 'appcrane-backup.json';
const ICON_RE = /^icon\.(png|svg|webp|jpg|jpeg|gif)$/i;

function craneVersion() {
  try { return JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')).version; }
  catch (_) { return 'unknown'; }
}

/** Build the backup zip in memory and return it as a Buffer. */
export function exportConfig(version) {
  version = version || craneVersion();
  const zip = new AdmZip();
  const db = getDb();

  // 1. Consistent DB snapshot — VACUUM INTO a temp file, add it, delete temp.
  const tmpDb = join(dataDir(), `._export-${Date.now()}.db`);
  try {
    db.exec(`VACUUM INTO '${tmpDb.replace(/'/g, "''")}'`);
    zip.addLocalFile(tmpDb, '', 'deployhub.db');
  } finally {
    try { unlinkSync(tmpDb); } catch (_) {}
  }

  // 2. .env (ENCRYPTION_KEY + platform config).
  const hasEnv = existsSync(envPath());
  if (hasEnv) zip.addLocalFile(envPath(), '', '.env');

  // 3. Per-app: tile icons + the persistent /data volume for each env. We do
  //    NOT back up the app's code or build artifacts (the `releases/` dirs) —
  //    that's redeployable from GitHub — nor anything OS-level. Just config +
  //    the data files an app would lose on a fresh host.
  let dataApps = 0;
  const appsDir = join(dataDir(), 'apps');
  if (existsSync(appsDir)) {
    for (const slug of readdirSync(appsDir)) {
      const appDir = join(appsDir, slug);
      let files = [];
      try { files = readdirSync(appDir); } catch (_) { continue; }
      for (const f of files) {
        if (ICON_RE.test(f)) zip.addLocalFile(join(appDir, f), `icons/${slug}`);
      }
      // The container's /data is mounted from <slug>/<env>/shared/data.
      //
      // v2.70.2: and every OTHER declared mount from <slug>/<env>/shared/volumes,
      // whose layout mirrors the container's ('/var/lib/odoo' ->
      // shared/volumes/var/lib/odoo). Before this, an app that declared a volume
      // kept its real state there and a config backup silently captured none of
      // it -- the backup completed, reported success, and restored an app to an
      // empty data directory. The whole tree is taken rather than a list of
      // declared paths, so a path removed from apps.volume_paths after the data
      // was written is still backed up.
      for (const env of ['sandbox', 'production']) {
        const dataPath = join(appDir, env, 'shared', 'data');
        if (existsSync(dataPath)) {
          zip.addLocalFolder(dataPath, `appdata/${slug}/${env}`);
          dataApps++;
        }
        const volPath = join(appDir, env, 'shared', 'volumes');
        if (existsSync(volPath)) {
          zip.addLocalFolder(volPath, `appvolumes/${slug}/${env}`);
        }
      }
    }
  }

  // 4. Manifest.
  const counts = {};
  for (const t of ['apps', 'users', 'settings', 'env_vars', 'role_permissions']) {
    try { counts[t] = db.prepare(`SELECT COUNT(*) c FROM ${t}`).get().c; } catch (_) {}
  }
  // v2.72.0: which image archive this zip belongs with. Derived from the DB
  // rather than from a token minted at export time, so a zip and an archive
  // taken minutes apart with no deploy in between agree — they ARE
  // interchangeable — while one taken across a deploy does not. Never fatal to
  // compute: a host with no Docker still produces a valid config backup.
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

  const manifest = {
    kind: 'appcrane-config-backup',
    version: version || 'unknown',
    exported_at: new Date().toISOString(),
    crane_domain: process.env.CRANE_DOMAIN || null,
    includes: ['deployhub.db', ...(hasEnv ? ['.env'] : []), 'icons', 'appdata', 'appvolumes'],
    counts,
    image_set: imageSet,
  };
  zip.addFile(MANIFEST, Buffer.from(JSON.stringify(manifest, null, 2)));

  log.info(`[config-backup] exported (apps=${counts.apps}, users=${counts.users}, env=${hasEnv}, data-volumes=${dataApps})`);
  return { buffer: zip.toBuffer(), manifest };
}

/**
 * Restore a backup zip onto this host. DESTRUCTIVE — replaces the live DB
 * (and optionally .env + icons). The current DB + .env are copied to a
 * pre-import-<ts> dir first so it's reversible.
 *
 * better-sqlite3 holds the live DB file open, so the new DB takes effect only
 * after a process restart — the caller is responsible for restarting.
 *
 * @param {Buffer} buffer  the uploaded zip
 * @param {object} opts    { restoreEnv?: boolean }  (.env is sensitive; default true)
 */
export function importConfig(buffer, opts = {}) {
  const restoreEnv = opts.restoreEnv !== false;
  let zip;
  try { zip = new AdmZip(buffer); } catch (_) { throw new Error('Not a valid zip file'); }

  const manifestEntry = zip.getEntry(MANIFEST);
  if (!manifestEntry) throw new Error('Not an AppCrane backup — manifest missing');
  let manifest;
  try { manifest = JSON.parse(manifestEntry.getData().toString('utf8')); } catch (_) {
    throw new Error('Backup manifest is corrupt');
  }
  if (manifest.kind !== 'appcrane-config-backup') throw new Error('Unrecognized backup file');

  const dbEntry = zip.getEntry('deployhub.db');
  if (!dbEntry) throw new Error('Backup is missing deployhub.db');
  const dbData = dbEntry.getData();
  // SQLite files start with the 16-byte magic "SQLite format 3" + NUL.
  // Check the 15 printable bytes to refuse a non-SQLite payload.
  if (dbData.subarray(0, 15).toString('latin1') !== 'SQLite format 3') {
    throw new Error('Backup deployhub.db is not a valid SQLite file');
  }

  const stamp = Date.now();
  const preDir = join(dataDir(), `pre-import-${stamp}`);
  mkdirSync(preDir, { recursive: true });
  if (existsSync(dbPath())) copyFileSync(dbPath(), join(preDir, 'deployhub.db'));
  if (existsSync(envPath())) copyFileSync(envPath(), join(preDir, '.env'));

  // Write new DB to temp on the same fs, then atomically rename over the live
  // file. The running process keeps the old inode open until it restarts.
  const tmp = join(dataDir(), `._import-${stamp}.db`);
  writeFileSync(tmp, dbData);
  renameSync(tmp, dbPath());

  let envRestored = false;
  if (restoreEnv) {
    const envEntry = zip.getEntry('.env');
    if (envEntry) { writeFileSync(envPath(), envEntry.getData()); envRestored = true; }
  }

  // Restore everything under DATA_DIR/apps, with path-traversal guards:
  //   icons/<slug>/<file>            -> apps/<slug>/<file>
  //   appdata/<slug>/<env>/<path...>    -> apps/<slug>/<env>/shared/data/<path...>
  //   appvolumes/<slug>/<env>/<path...> -> apps/<slug>/<env>/shared/volumes/<path...>
  const appsRoot = resolve(join(dataDir(), 'apps'));
  const writeUnderApps = (relParts, data) => {
    const dest = resolve(join(appsRoot, ...relParts));
    if (dest !== appsRoot && !dest.startsWith(appsRoot + '/')) return false;
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, data);
    return true;
  };

  let icons = 0, dataFiles = 0, volumeFiles = 0;
  for (const e of zip.getEntries()) {
    if (e.isDirectory) continue;
    const name = e.entryName;
    if (name.includes('..')) continue;
    if (name.startsWith('icons/')) {
      const rel = name.slice('icons/'.length);
      if (rel && writeUnderApps([rel], e.getData())) icons++;
    } else if (name.startsWith('appdata/')) {
      const segs = name.slice('appdata/'.length).split('/').filter(Boolean);
      if (segs.length < 3) continue;                       // need slug / env / file
      const [slug, env, ...rest] = segs;
      if (env !== 'sandbox' && env !== 'production') continue;
      if (writeUnderApps([slug, env, 'shared', 'data', ...rest], e.getData())) dataFiles++;
    } else if (name.startsWith('appvolumes/')) {
      const segs = name.slice('appvolumes/'.length).split('/').filter(Boolean);
      if (segs.length < 3) continue;                       // need slug / env / file
      const [slug, env, ...rest] = segs;
      if (env !== 'sandbox' && env !== 'production') continue;
      if (writeUnderApps([slug, env, 'shared', 'volumes', ...rest], e.getData())) volumeFiles++;
    }
  }

  // v2.72.0: say plainly whether the image half of this backup is on the host.
  // A config import that restores 40 apps whose images are not here has not
  // restored anything runnable, and the failure would otherwise surface one app
  // at a time as a deploy that cannot pull.
  const imageSet = manifest.image_set
    ? {
      expected_fingerprint: manifest.image_set.fingerprint,
      expected_count: manifest.image_set.count,
      note:
        `This backup pairs with image archive appcrane-images-${String(manifest.image_set.fingerprint).slice(0, 12)}-*.tar. ` +
        'Load it with POST /api/settings/images/import, then check GET /api/settings/images/verify.',
    }
    : { expected_fingerprint: null, expected_count: 0, note: 'This backup predates image archives and names no image set.' };
  if (imageSet.expected_count) {
    log.warn(`[config-backup] this backup expects ${imageSet.expected_count} image(s), archive fingerprint ${String(imageSet.expected_fingerprint).slice(0, 12)}`);
  }

  log.warn(`[config-backup] IMPORTED backup from ${manifest.exported_at} (env=${envRestored}, icons=${icons}, data-files=${dataFiles}, volume-files=${volumeFiles}). Restart required. Pre-import copy at ${preDir}`);
  return { manifest, envRestored, icons, dataFiles, volumeFiles, preImportDir: preDir, imageSet };
}
