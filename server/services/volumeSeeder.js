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

import { existsSync, mkdirSync, readdirSync, rmSync } from 'fs';
import { join } from 'path';
import { execFileSync } from 'child_process';
import { copyFromImage } from './docker.js';
import log from '../utils/logger.js';

/** The ownership every mount gets, matching the chown deployer.js already
 *  applies to the mount directories themselves. Seeded FILES need it too: a
 *  bind mount inherits host ownership, `docker cp` writes as the user running
 *  AppCrane (measured: uid 502 on this box, not the image's uid), and an image
 *  that drops to a non-root user then cannot write what was just seeded for it.
 *
 *  Measured on a real Linux filesystem, with the control: a uid-1000 container
 *  writing into a directory of root-owned seeded files gets "Permission denied";
 *  after `chown -R 1000:1000` the same write succeeds. */
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

/** Put a directory back to empty. Only ever called on a directory this module
 *  found empty moments earlier, so it cannot destroy anything an app wrote —
 *  it removes a half-finished copy so the NEXT deploy sees "empty" and seeds
 *  cleanly, instead of inheriting a truncated tree that looks like live state
 *  forever after. */
function clearDir(hostDir) {
  try {
    for (const entry of readdirSync(hostDir)) rmSync(join(hostDir, entry), { recursive: true, force: true });
  } catch (e) {
    log.warn(`could not clear partially-seeded ${hostDir}: ${e.message}`);
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
export async function seedNewVolumeMounts({ image, volumes = [], copy = copyFromImage }) {
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

  let results;
  try {
    results = await copy({
      image,
      copies: fresh.map((v) => ({ containerPath: v.container, destDir: v.host })),
    });
  } catch (e) {
    for (const v of fresh) clearDir(v.host);
    throw new Error(
      `VOLUME_SEED_FAILED: could not copy ${fresh.map((v) => v.container).join(', ')} out of ${image} ` +
      `(${e.message}). Refusing to start the container: a bind mount over a path the image seeds ` +
      'would hide the image\'s own content, and starting anyway would look like a healthy first boot ' +
      'with the app\'s default configuration silently missing.',
    );
  }

  for (const r of results) {
    const vol = fresh.find((v) => v.container === r.containerPath);
    if (!r.found) {
      absent.push(r.containerPath);
      continue;
    }
    // `docker cp` of a directory the image ships but leaves empty succeeds and
    // copies nothing. Reported as absent rather than seeded, because "seeded"
    // is a claim about content and there is none.
    if (mountIsEmpty(vol.host)) {
      absent.push(r.containerPath);
      continue;
    }
    seeded.push(r.containerPath);
    // Ownership, immediately, on the files that were just written. deployer.js
    // chowned this directory before the image existed, when it was empty, so
    // that pass could not have covered anything in it.
    try {
      execFileSync('chown', ['-R', MOUNT_OWNER, vol.host], { stdio: 'pipe', timeout: 30000 });
      lines.push(`Volume seed: ${r.containerPath} populated from the image, chown ${MOUNT_OWNER} → ok`);
    } catch (e) {
      lines.push(
        `Volume seed: ${r.containerPath} populated from the image, but chown ${MOUNT_OWNER} failed ` +
        `(${e?.stderr?.toString().trim() || e.message}). An image that runs as a non-root user may ` +
        `hit EACCES writing ${r.containerPath}.`,
      );
    }
  }

  if (absent.length) {
    lines.push(
      `Volume seed: ${absent.join(', ')} — the image ships nothing there, so the mount starts empty ` +
      '(the same thing a fresh named volume would do).',
    );
  }
  return { seeded, absent, occupied, log: lines };
}
