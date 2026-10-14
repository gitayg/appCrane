// Making a brand-new BIND mount behave like a brand-new NAMED volume.
//
// This is the one semantic difference between the two mount types, and it is
// the difference that destroys data. Measured on this box against an image that
// ships a file at /seeded:
//
//   BIND mount of an empty host dir over /seeded -> ls -A = 0 ; the file is gone
//   NAMED volume over /seeded                    -> ls -A = 1 ; IMAGE-CONTENT
//
// Docker populates a named volume from the image's content the first time it is
// used. A bind mount does not — it MASKS whatever the image put there. AppCrane
// mounts declared volume paths as bind mounts (containerRuntimeSpec.js maps
// '/var/lib/odoo' -> <shared>/volumes/var/lib/odoo) because the host-visible
// layout is what config backup archives, so the layout has to stay. What has to
// change is the seeding.
//
// Without this, declaring a path the image seeds is a destructive act:
// bookstack's /config, odoo's /var/lib/odoo and appsmith's /appsmith-stacks all
// arrive from the image carrying default configuration or application files, and
// the first boot would see an empty directory instead. For several of those
// images that is a first-run re-initialisation; for some it is a container that
// does not start.
//
// THE RULE THIS FILE EXISTS TO ENFORCE: seed a mount exactly once, when it is
// empty. A directory with anything in it is the app's LIVE STATE and is never
// written to here, which is why the gate is an emptiness test on the host
// directory and not a flag file, a database column or a deploy counter — all
// three can disagree with the disk, and the disk is the thing that holds the
// data.

import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, renameSync, lstatSync } from 'fs';
import { join, dirname, basename } from 'path';
import { copyFromImage, chownTreeAsRoot, prepareVolumesInHelper } from './docker.js';
import { resolveImageOwner } from './dbCerts.js';
import log from '../utils/logger.js';

/** The ownership every mount gets, matching the chown deployer.js already
 *  applies to the mount directories themselves. Seeded FILES need it too: a
 *  bind mount inherits host ownership, `docker cp` writes as the user running
 *  AppCrane (measured: uid 502 on macOS here, uid 1001 on the CI runner, never
 *  the image's uid), and an image that drops to a non-root user then cannot
 *  write what was just seeded for it.
 *
 *  Measured on a real Linux filesystem, with the control: a uid-1000 container
 *  writing into a directory of root-owned seeded files gets "Permission denied";
 *  after `chown -R 1000:1000` the same write succeeds.
 *
 *  v2.71.1: applying it is no longer a bare `chown` that may quietly fail.
 *  chown TO ANOTHER UID NEEDS ROOT, and AppCrane is not root on a CI runner or
 *  on any non-root install -- so the call failed, the line was logged as a
 *  warning nobody read, and the seeded tree stayed owned by the AppCrane user
 *  with the app unable to write it. macOS never showed it: Docker Desktop
 *  remaps bind-mount ownership to the invoking user, so uid 502 owning the
 *  files looked identical to uid 1000 owning them from inside the container.
 *  docker.js:chownTreeAsRoot now falls back to a throwaway container, which is
 *  root in its own namespace and can chown the bind mount regardless. */
export const MOUNT_OWNER = '1000:1000';

/**
 * Is this mount's host directory new — nothing has ever been written to it?
 *
 * "Does not exist" and "exists and is empty" are deliberately the SAME answer.
 * deployer.js mkdirs every mount before the container starts, so by the time a
 * container has ever run the directory always exists; an empty one means either
 * a first deploy or a previous seed that failed and was rolled back. Both want
 * seeding, and neither can lose data by getting it.
 *
 * A directory that cannot be read is reported as NOT empty. That is the safe
 * direction: the cost of a wrong "not empty" is an unseeded mount, and the cost
 * of a wrong "empty" is overwritten state.
 */
export function mountIsEmpty(hostDir) {
  if (!existsSync(hostDir)) return true;
  try {
    return readdirSync(hostDir).length === 0;
  } catch (e) {
    log.warn(`could not read ${hostDir} to decide whether to seed it (${e.message}) — treating as non-empty`);
    return false;
  }
}

// `docker cp` extracts on the HOST, as the AppCrane user, and follows any link
// it meets under the destination. /data's directory is one AppCrane made and
// the app cannot replace (it is the container's mount point), but what is
// INSIDE it is the app's: while the old container still runs it can plant a
// link there between the emptiness check and the extraction. So the copy lands
// in a fresh staging directory beside the mount, which no container mounts,
// and each top-level entry is then renamed in. rename(2) never follows its
// last component, and its parent is the mount directory itself.
function stagingFor(hostDir) {
  return mkdtempSync(join(dirname(hostDir), `.seed-${basename(hostDir)}-`));
}

function moveStagedInto(staging, hostDir) {
  for (const entry of readdirSync(staging)) {
    const dest = join(hostDir, entry);
    let exists = true;
    try { lstatSync(dest); } catch (e) { if (e.code === 'ENOENT') exists = false; else throw e; }
    // Something appeared since the emptiness check: the app's, so it wins.
    if (exists) { log.warn(`volume seed: ${dest} appeared during seeding — kept, the image copy was dropped`); continue; }
    renameSync(join(staging, entry), dest);
  }
}

/**
 * Seed every mount whose host directory is still empty from the image's own
 * content at that container path. Call it after the image is available locally
 * and BEFORE the container is created.
 *
 * FAILURE POLICY, stated out loud because the alternative is the bug this file
 * fixes wearing a different hat: a seed that fails THROWS. The image being gone
 * or the disk being full must not produce an empty mount that the deploy then
 * reports as successful — that is exactly the "the app came up with no
 * configuration" outcome, arrived at from the other direction, and it would be
 * indistinguishable from a healthy first boot. The partially-copied directory is
 * cleared first so the next attempt still sees an empty mount and can retry.
 *
 * An image with NOTHING at the path is not a failure: the directory stays empty
 * and the deploy proceeds. That is the majority case (AppCrane's own images ship
 * no /data) and it is also what a named volume does.
 *
 * @param {{image: string, volumes: {host: string, container: string}[], copy?: Function}} args
 * @returns {Promise<{seeded: string[], absent: string[], occupied: string[], log: string[]}>}
 */
/**
 * Who a declared volume belongs to: the image's own USER when it declares a
 * non-root one (read from the image config and its /etc/passwd, never by
 * running it — dbCerts.resolveImageOwner), else MOUNT_OWNER as before. Root or
 * unset keeps 1000:1000 on purpose: images that start as root and drop to a
 * PUID (linuxserver's bookstack defaults it to 1000) relied on it.
 */
export async function declaredVolumeOwner(image, resolveOwner = resolveImageOwner) {
  const o = await Promise.resolve().then(() => resolveOwner(image)).catch(() => null);
  return o && o.uid !== 0 ? `${o.uid}:${o.gid}` : MOUNT_OWNER;
}

export async function seedNewVolumeMounts({ image, volumes = [], copy = copyFromImage, prepare = prepareVolumesInHelper, resolveOwner = resolveImageOwner }) {
  // A declared volume (resolveVolumeMounts gives it a `base`) lives below
  // <shared>/volumes, where the app can replace any component with a link, so
  // the host does not walk its path at all: volumeHelper.js.
  const declared = volumes.filter((v) => v.base);
  const plain = volumes.filter((v) => !v.base);
  const res = await seedPlainMounts({ image, volumes: plain, copy });
  if (!declared.length) return res;

  let report;
  let owner = MOUNT_OWNER;
  try {
    owner = await declaredVolumeOwner(image, resolveOwner);
    report = await prepare({ image, mounts: declared, owner });
  } catch (e) {
    throw new Error(
      `VOLUME_SEED_FAILED: ${e.message}. Refusing to start the container: a bind mount over a path the image ` +
      'seeds would hide the image\'s own content, and an unprepared mount may not exist or be writable.',
    );
  }
  const occupied = [];
  for (const r of report) {
    if (r.state === 'seeded') res.seeded.push(r.path);
    else if (r.state === 'occupied') { res.occupied.push(r.path); occupied.push(r.path); } else if (r.state === 'absent') res.absent.push(r.path);
    if (r.state === 'seeded') {
      res.log.push(`Volume seed: ${r.path} populated from the image, chown ${owner} → ${r.chownOk ? 'ok' : 'failed'} (in a throwaway container)`);
    } else {
      res.log.push(`chown ${owner} ${r.path} → ${r.chownOk ? 'ok' : `failed${r.state === 'unreported' ? ' (helper did not report it)' : ''}. App may hit EACCES on ${r.path} writes if its container runs as a non-root user.`}`);
    }
  }
  if (occupied.length) {
    res.log.push(
      `Volume seed: ${occupied.join(', ')} already holds data — left untouched. ` +
      'A mount is seeded from the image once, when it is empty; after that it is the app\'s state.',
    );
  }
  const absentDeclared = report.filter((r) => r.state === 'absent').map((r) => r.path);
  if (absentDeclared.length) {
    res.log.push(
      `Volume seed: ${absentDeclared.join(', ')} — the image ships nothing there, so the mount starts empty ` +
      '(the same thing a fresh named volume would do).',
    );
  }
  return res;
}

async function seedPlainMounts({ image, volumes, copy }) {
  const lines = [];
  const seeded = [];
  const absent = [];
  const occupied = [];

  const fresh = [];
  for (const vol of volumes) {
    mkdirSync(vol.host, { recursive: true });
    if (mountIsEmpty(vol.host)) fresh.push(vol);
    else occupied.push(vol.container);
  }

  if (occupied.length) {
    lines.push(
      `Volume seed: ${occupied.join(', ')} already holds data — left untouched. ` +
      'A mount is seeded from the image once, when it is empty; after that it is the app\'s state.',
    );
  }
  if (!fresh.length) return { seeded, absent, occupied, log: lines };

  const staged = fresh.map((v) => ({ vol: v, dir: stagingFor(v.host) }));
  const dropStaging = () => { for (const s of staged) rmSync(s.dir, { recursive: true, force: true }); };
  let results;
  try {
    results = await copy({
      image,
      copies: staged.map((s) => ({ containerPath: s.vol.container, destDir: s.dir })),
    });
  } catch (e) {
    // Nothing reached the mount itself, so the next deploy still sees it empty.
    dropStaging();
    throw new Error(
      `VOLUME_SEED_FAILED: could not copy ${fresh.map((v) => v.container).join(', ')} out of ${image} ` +
      `(${e.message}). Refusing to start the container: a bind mount over a path the image seeds ` +
      'would hide the image\'s own content, and starting anyway would look like a healthy first boot ' +
      'with the app\'s default configuration silently missing.',
    );
  }

  try {
    for (const r of results) {
      const s = staged.find((x) => x.vol.container === r.containerPath);
      const vol = s.vol;
      if (!r.found) {
        absent.push(r.containerPath);
        continue;
      }
      // `docker cp` of a directory the image ships but leaves empty succeeds and
      // copies nothing. Reported as absent rather than seeded, because "seeded"
      // is a claim about content and there is none.
      if (mountIsEmpty(s.dir)) {
        absent.push(r.containerPath);
        continue;
      }
      moveStagedInto(s.dir, vol.host);
      seeded.push(r.containerPath);
      // Ownership, immediately, on the files that were just written. deployer.js
      // chowned this directory before the image existed, when it was empty, so
      // that pass could not have covered anything in it.
      try {
        // `image` is the one being seeded FROM, so it is already on this host and
        // the fallback container cannot turn into a registry round-trip.
        const how = await chownTreeAsRoot({ hostDir: vol.host, owner: MOUNT_OWNER, image });
        lines.push(
          `Volume seed: ${r.containerPath} populated from the image, chown ${MOUNT_OWNER} → ok` +
          (how === 'container' ? ' (via a throwaway container: AppCrane is not root here)' : ''),
        );
      } catch (e) {
        // Both mechanisms are gone. Say so at ERROR, not in a log line the deploy
        // output buries: the app IS going to hit EACCES on its own data.
        log.error(`volume seed: could not give ${vol.host} to ${MOUNT_OWNER}: ${e.message}`);
        lines.push(
          `Volume seed: ${r.containerPath} populated from the image, but chown ${MOUNT_OWNER} failed ` +
          `(${e.message}). An image that runs as a non-root user WILL hit EACCES writing ` +
          `${r.containerPath}.`,
        );
      }
    }
  } finally {
    dropStaging();
  }

  if (absent.length) {
    lines.push(
      `Volume seed: ${absent.join(', ')} — the image ships nothing there, so the mount starts empty ` +
      '(the same thing a fresh named volume would do).',
    );
  }
  return { seeded, absent, occupied, log: lines };
}
