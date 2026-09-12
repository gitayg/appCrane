/**
 * Offline image archive (v2.72.0) — the half of a backup that is bytes.
 *
 * THE PROBLEM. configBackup.js saves configuration and data; the images an app
 * runs were assumed to be re-pullable from wherever they came from. They are
 * not. Every `bitnami/*` image 404s since that registry changed, and
 * `medusajs/medusa`, `vendureio/vendure` and `crater/crater` 404 today. A
 * restore that re-pulls `name@sha256:...` fails outright for those apps, and
 * there is nothing an operator can do about it after the fact — the bytes are
 * gone from the internet. So the bytes have to be in the backup.
 *
 * WHY A SEPARATE ARTIFACT. The config zip is built in memory
 * (`zip.toBuffer()`) and handed back through an HTTP response. Measured image
 * sizes on one real box: ghcr.io/windmill-labs/windmill 5.55 GB,
 * ghcr.io/zammad/zammad:stable 1.51 GB, mongo:8.0 1.25 GB — 5-30 GB for a box
 * running 10-20 apps. That cannot be a Buffer and cannot be a browser download.
 * The config zip is small, fast and correct and is left exactly as it was; the
 * images go to their own file, written by `docker save -o`, so not one image
 * byte is ever resident in this process.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * WHY THE ARCHIVE IS SAVED UNDER A RESTORE TAG AND NOT BY DIGEST
 *
 * `deployments.image_ref` is the fully-resolved `name@sha256:...` — the exact
 * bytes that ran, and the obvious thing to hand `docker save`. It is the wrong
 * thing to hand it, twice over, and both were measured rather than reasoned:
 *
 *   1. `docker save name@sha256:...` throws the NAME away. Round-tripped
 *      through `docker load`, the image comes back with RepoTags=[] and
 *      RepoDigests=[] — reachable only by image id, so no configured reference
 *      starts it. (Docker 29.6.1, containerd store: 'Loaded image ID:
 *      sha256:0f2d...', then `docker image inspect alpine@sha256:0f2d...` =>
 *      'No such image'.)
 *
 *   2. Saving by TAG keeps the name, but whether the DIGEST reference works
 *      afterwards depends on the daemon's image store, and the platform's
 *      deploy target is the store where it does NOT:
 *
 *        containerd snapshotter (Docker Desktop 29.6.1, macOS):
 *          after load  RepoDigests=["alpine@sha256:0f2d..."]  -> digest ref runs
 *        classic overlay2 (Docker 27.5.1, Linux, containerd-snapshotter=false):
 *          after load  RepoDigests=[]  RepoTags=["alpine:3.14"] -> digest ref
 *          is 'No such image' and Docker falls through to a pull.
 *
 *      RepoDigests on a classic store live in distribution metadata that only
 *      a pull or a push writes; `docker load` does not. Proven end to end with
 *      a registry that was then stopped: `docker run localhost:5000/fixture@
 *      sha256:170208...` => 'connection refused', while `docker run
 *      localhost:5000/fixture:appcrane-restore-170208aa3b6a` => ran.
 *
 * So every image is saved under a deterministic tag IN ITS OWN REPOSITORY:
 *
 *      odoo@sha256:abcdef012345...   ->   odoo:appcrane-restore-abcdef012345
 *
 * The repository has to be the original one because that is what makes the
 * digest reference resolve too on the stores where it can (RepoDigests is
 * derived from the image's names); the tag is what makes it resolvable on the
 * stores where it cannot. One save satisfies both.
 *
 * The tag is derived from the digest, so it is stable across exports, it names
 * the exact bytes, and re-exporting the same fleet produces the same names.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * WHAT GOES IN
 *
 * The image behind each app's CURRENT LIVE deployment, per environment.
 *
 * Not "the last N deployments": the images those rows name are the first thing
 * `pruneOldImages` deletes (it keeps 2), so most of them are not on disk to
 * save, and the ones that are would multiply the largest artifact in the
 * backup to buy rollback history. A backup restores what was running.
 *
 * Both source types by default (`scope: 'live'`), not just image apps:
 *   - image apps are NOT rebuildable. Mandatory.
 *   - source-built apps are rebuildable in principle, but the rebuild needs
 *     GitHub, the package registries, and a base image that can 404 exactly the
 *     way the app's own image can; `managed_legacy` and `upload` apps may have
 *     no reachable source at all. Their images are also the ones already tagged
 *     `appcrane-<slug>-<env>:<commit>`, which is precisely the tag
 *     `buildImageIfNeeded()` looks for before building — so restoring them
 *     makes a redeploy skip the build entirely, with no change to the deployer.
 * `scope: 'image-apps'` narrows to the irreplaceable half when size forces it.
 *
 * An image that is not on disk at export time is REPORTED, not fatal: it lands
 * in `missing[]`, it is absent from the fingerprint, and `verifyImageSet()`
 * will keep saying that app cannot be restored. `planImageArchive()` shows it
 * before a single byte is written.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * PAIRING THE TWO ARTIFACTS
 *
 * A config zip restored against the wrong image archive must not half-apply.
 * The pairing is derived from content rather than a token minted at export:
 * the fingerprint is sha256 over the sorted restore tags of the included
 * images. configBackup.js writes it into the zip manifest (`image_set`), the
 * archive carries it in its filename, and `importImageArchive()` recomputes it
 * from what `docker load` actually loaded. Two exports taken minutes apart with
 * no deploy in between agree — which is correct, they ARE interchangeable — and
 * an archive from a different fleet state does not.
 */

import { createHash } from 'crypto';
import { existsSync, mkdirSync, statSync, statfsSync } from 'fs';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb } from '../db.js';
import { parseImageRef } from './imageSource.js';
import { imageTagFor, saveImagesTo, loadImagesFrom, tagImage, inspectImages } from './docker.js';
import log from '../utils/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(join(__dirname, '..', '..'));

export const RESTORE_TAG_PREFIX = 'appcrane-restore-';
export const SCOPES = ['live', 'image-apps'];

const dataDir = () => resolve(process.env.DATA_DIR || join(repoRoot, 'data'));
export const archiveDir = () => join(dataDir(), 'backups');

/**
 * The tag an image is archived under: its own repository, plus the WHOLE digest
 * hex.
 *
 * Not a short id. 'appcrane-restore-' + 64 hex is 81 characters against
 * Docker's 128-character tag limit, so the full digest fits — and truncating it
 * to Docker's usual 12 would mean two digests sharing a 12-hex prefix collapsing
 * onto one tag, i.e. an archive holding one image where the fleet runs two, with
 * nothing in the export saying so. There is no reason to accept even a remote
 * chance of that to save 52 characters in a name nobody types.
 *
 * The tag is derived from the digest, so it is stable across exports and names
 * the exact bytes.
 */
export function restoreTagFor(ref) {
  const { registry, name, digest } = parseImageRef(ref);
  if (!digest) return null;
  const repo = registry ? `${registry}/${name}` : name;
  return `${repo}:${RESTORE_TAG_PREFIX}${digest.slice('sha256:'.length)}`;
}

/** sha256 over the sorted archive tags — the identity of an image set. */
export function imageSetFingerprint(archiveTags) {
  const sorted = [...new Set(archiveTags)].sort();
  return createHash('sha256').update(sorted.join('\n')).digest('hex');
}

/**
 * The live deployments an archive covers, straight from the DB.
 *
 * The most recent 'live' row per (app, env) — `status` history keeps older
 * 'live' rows around, so MAX(id) is what "currently running" means.
 */
export function liveDeploymentImages(scope = 'live') {
  if (!SCOPES.includes(scope)) throw new Error(`unknown scope '${scope}' (expected: ${SCOPES.join(', ')})`);
  const db = getDb();
  const rows = db.prepare(`
    SELECT a.slug AS slug, a.source_type AS source_type, d.env AS env,
           d.image_ref AS image_ref, d.commit_hash AS commit_hash, d.id AS deployment_id
    FROM deployments d
    JOIN apps a ON a.id = d.app_id
    WHERE d.id IN (SELECT MAX(id) FROM deployments WHERE status = 'live' GROUP BY app_id, env)
    ORDER BY a.slug, d.env
  `).all();

  const out = [];
  for (const r of rows) {
    if (r.source_type === 'image') {
      // No image_ref means the row predates digest pinning or the deploy never
      // recorded one. There is no way to know which bytes ran, so there is
      // nothing honest to archive — say so rather than guessing from
      // apps.image_ref, which is a moving tag.
      if (!r.image_ref) {
        out.push({ ...r, ref: null, archive_tag: null, skip_reason: 'deployment has no image_ref recorded' });
        continue;
      }
      out.push({ ...r, ref: r.image_ref, archive_tag: restoreTagFor(r.image_ref), skip_reason: null });
      continue;
    }
    if (scope === 'image-apps') continue;
    // A built image is already addressed by a tag this platform chose, and it
    // is the same tag buildImageIfNeeded() probes before rebuilding.
    if (!r.commit_hash || r.commit_hash === 'unknown') {
      out.push({ ...r, ref: null, archive_tag: null, skip_reason: 'deployment has no commit hash, so its build tag cannot be derived' });
      continue;
    }
    const tag = imageTagFor(r.slug, r.env, r.commit_hash);
    out.push({ ...r, ref: tag, archive_tag: tag, skip_reason: null });
  }
  return out;
}

/**
 * What an export would contain and what it would cost, WITHOUT writing a byte.
 *
 * `estimated_bytes` sums each image's unpacked size with layers counted once
 * across the whole set, because `docker save` writes a shared layer once.
 *
 * It is an ESTIMATE and is not called a bound, because it was measured not to
 * be one: a busybox fixture whose unpacked size is 1916245 saved to a 1929216
 * byte archive — tar block padding plus the archive's own manifest, config and
 * index blobs. The ratio measured on real images was 1.05x on a classic
 * overlay2 store (layers stored uncompressed) and 0.26-0.51x on a containerd
 * store (layers stored compressed), so the unpacked total is generous on one
 * store and slightly short on the other.
 *
 * `required_bytes` is what the free-space check actually uses: the estimate
 * plus 10% plus 64 MB, which covers both the per-archive overhead and the
 * classic store's small excess.
 *
 * Cross-image dedup is small in practice and is stated here so nobody plans
 * around it: measured on real images, `docker save a b c` into one archive
 * saved 4% (four alpine-based images), 4.9% (mongo:8.0 + mongo:8) and 0.0003%
 * (node:20 + node:22). Shared bases are a rounding error next to app layers.
 */
export async function planImageArchive(scope = 'live') {
  const entries = liveDeploymentImages(scope);
  const refs = entries.filter((e) => e.ref).map((e) => e.ref);
  const info = await inspectImages([...new Set(refs)]);

  const images = [];
  const missing = [];
  for (const e of entries) {
    const meta = e.ref ? info.get(e.ref) : null;
    const present = !!meta?.present;
    const row = {
      slug: e.slug, env: e.env, source_type: e.source_type, deployment_id: e.deployment_id,
      ref: e.ref, archive_tag: e.archive_tag, present,
      size_bytes: meta?.size || 0,
      reason: e.skip_reason || (present ? null : 'image is not on this host — nothing to save'),
    };
    images.push(row);
    if (!present) missing.push(row);
  }

  // Size, counted once per distinct image (two environments can share one) and
  // discounted for shared layers. Docker does not report a per-layer size here,
  // so an image whose every layer has already been counted contributes nothing
  // and an image with any new layer contributes its whole size. That keeps the
  // total an upper bound instead of inventing per-layer numbers.
  let estimated = 0;
  const countedRefs = new Set();
  const seenLayers = new Set();
  for (const row of images) {
    if (!row.present || countedRefs.has(row.ref)) continue;
    countedRefs.add(row.ref);
    const meta = info.get(row.ref);
    if (!meta.layers.length) { estimated += meta.size; continue; }
    const anyNew = meta.layers.some((l) => !seenLayers.has(l));
    for (const l of meta.layers) seenLayers.add(l);
    if (anyNew) estimated += meta.size;
  }

  const includedTags = images.filter((i) => i.present).map((i) => i.archive_tag);
  const dir = archiveDir();
  let freeBytes = null;
  try {
    const st = statfsSync(existsSync(dir) ? dir : dataDir());
    freeBytes = st.bavail * st.bsize;
  } catch (_) {}

  return {
    scope,
    generated_at: new Date().toISOString(),
    images,
    missing,
    included: includedTags.length,
    fingerprint: imageSetFingerprint(includedTags),
    estimated_bytes: estimated,
    required_bytes: Math.ceil(estimated * 1.1) + 64 * 1024 * 1024,
    free_bytes: freeBytes,
    fits: freeBytes === null ? null : freeBytes > Math.ceil(estimated * 1.1) + 64 * 1024 * 1024,
    dest_dir: dir,
  };
}

/** `appcrane-images-<fingerprint12>-<YYYY-MM-DD>.tar` */
export function archiveFileName(fingerprint, at = new Date()) {
  return `appcrane-images-${fingerprint.slice(0, 12)}-${at.toISOString().slice(0, 10)}.tar`;
}

/**
 * Write the archive. Refuses rather than producing something that cannot
 * restore: no images to save, or not enough free space for the upper bound.
 */
export async function exportImageArchive(opts = {}) {
  const scope = opts.scope || 'live';
  const plan = await planImageArchive(scope);
  const includable = plan.images.filter((i) => i.present);
  if (includable.length === 0) {
    throw new Error(
      'Nothing to archive: no live deployment on this host has its image available locally' +
      (plan.images.length ? ` (${plan.images.length} live deployment(s) checked, all missing)` : ''),
    );
  }
  if (plan.fits === false && !opts.force) {
    throw new Error(
      `Not enough free space in ${plan.dest_dir}: the archive needs about ` +
      `${plan.required_bytes} bytes and ${plan.free_bytes} are free. Free space or pass force.`,
    );
  }

  // Tag first, save second. An image app's reference is a digest and a digest
  // cannot survive `docker save` (see the header), so the archive tag has to
  // exist locally before the save names it.
  for (const img of includable) {
    if (img.archive_tag === img.ref) continue;
    await tagImage(img.ref, img.archive_tag);
  }

  const dir = plan.dest_dir;
  mkdirSync(dir, { recursive: true });
  // `at` is supplied by the route so the name it advertised at 202-time and the
  // name written here cannot disagree — two `new Date()` calls either side of a
  // UTC midnight produce two different filenames, and the caller would then be
  // polling the size of a file that is never created.
  const destPath = join(dir, archiveFileName(plan.fingerprint, opts.at || new Date()));

  const tags = [...new Set(includable.map((i) => i.archive_tag))];
  log.info(`[image-archive] saving ${tags.length} image(s), scope=${scope}, about ${plan.estimated_bytes} bytes -> ${destPath}`);
  await saveImagesTo(tags, destPath);
  const bytes = statSync(destPath).size;

  log.info(`[image-archive] wrote ${destPath} (${bytes} bytes, fingerprint ${plan.fingerprint.slice(0, 12)})`);
  return {
    path: destPath,
    file: archiveFileName(plan.fingerprint),
    bytes,
    scope,
    fingerprint: plan.fingerprint,
    estimated_bytes: plan.estimated_bytes,
    required_bytes: plan.required_bytes,
    images: includable.map((i) => ({ slug: i.slug, env: i.env, ref: i.ref, archive_tag: i.archive_tag, size_bytes: i.size_bytes })),
    missing: plan.missing.map((m) => ({ slug: m.slug, env: m.env, ref: m.ref, reason: m.reason })),
  };
}

/**
 * `docker load` an archive and say what came back.
 *
 * `unnamed` is surfaced as a failure signal rather than folded into the count:
 * an image loaded by id alone is one no reference can start, which is what an
 * archive built by saving digests looks like. An operator who sees a non-empty
 * `unnamed` has an archive that will not restore anything.
 */
export async function importImageArchive(path) {
  const abs = resolve(path);
  if (!existsSync(abs)) throw new Error(`No such archive: ${abs}`);
  const { loaded, unnamed } = await loadImagesFrom(abs);
  // Docker names every image it loads, so this set IS the set of archive tags
  // the export saved — which is what makes the fingerprint comparable to the
  // one in the config zip's manifest without a sidecar file to carry it.
  const fingerprint = imageSetFingerprint(loaded);
  log.warn(`[image-archive] LOADED ${loaded.length} image(s) from ${abs} (fingerprint ${fingerprint.slice(0, 12)}, unnamed ${unnamed.length})`);
  return { path: abs, loaded, unnamed, fingerprint };
}

/**
 * Does this host hold what the live deployments need?
 *
 * The real pair check. It reads the DB that a config import restored and asks
 * Docker about each live deployment, so a config zip restored against an
 * archive from a different fleet state shows up as apps whose image is absent —
 * before anything is started, rather than as a container that will not come up.
 *
 * Two answers per row, because they are genuinely different questions:
 *   digest_ref_resolves — whether `deployments.image_ref` starts as written.
 *     True on a containerd-snapshotter store, FALSE on a classic overlay2 store
 *     after a load, and false on both if the image is simply absent.
 *   archive_tag_present — whether the restore tag is there. This is the one
 *     that holds on every store, and the one an offline restore depends on.
 */
export async function verifyImageSet(scope = 'live') {
  const entries = liveDeploymentImages(scope);
  const probes = [];
  for (const e of entries) {
    if (e.ref) probes.push(e.ref);
    if (e.archive_tag) probes.push(e.archive_tag);
  }
  const info = await inspectImages([...new Set(probes)]);

  const rows = entries.map((e) => {
    const direct = e.ref ? !!info.get(e.ref)?.present : false;
    const viaTag = e.archive_tag ? !!info.get(e.archive_tag)?.present : false;
    return {
      slug: e.slug, env: e.env, source_type: e.source_type,
      ref: e.ref, archive_tag: e.archive_tag,
      digest_ref_resolves: direct,
      archive_tag_present: viaTag,
      restorable: direct || viaTag,
      reason: e.skip_reason,
    };
  });

  const restorable = rows.filter((r) => r.restorable);
  return {
    scope,
    checked: rows.length,
    restorable: restorable.length,
    unrestorable: rows.filter((r) => !r.restorable),
    expected_fingerprint: imageSetFingerprint(entries.filter((e) => e.archive_tag).map((e) => e.archive_tag)),
    present_fingerprint: imageSetFingerprint(restorable.map((r) => r.archive_tag).filter(Boolean)),
    rows,
  };
}
