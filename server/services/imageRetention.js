/**
 * How many PREVIOUS per-commit images an app keeps on disk.
 *
 * `apps.image_retention` counts the images kept BEHIND the one that is running,
 * so the number handed to pruneOldImages() is always retention + 1. The default
 * is 1 — current plus previous — because that previous image is what makes a
 * rollback to the immediately-preceding release a container restart rather than
 * a full rebuild: deployer.js rolls back by re-running deployApp with the target
 * deployment's commit_hash, and docker.js:buildImageIfNeeded skips the build
 * only while an image tagged for that (slug, env, commit) still exists.
 *
 * Before v2.78.0 the default was 0, which pruned to keep=1 after every
 * successful deploy — the previous commit's image was deleted at the end of the
 * deploy that superseded it, so the one rollback an operator reaches for during
 * an incident was the one guaranteed to rebuild. appcrane_rollback's own
 * description promised "no rebuild when it is still retained", and at the
 * shipped default it never could be.
 *
 * 0 still means 0. An operator who sets it keeps exactly the running image and
 * accepts the rebuild; nothing here re-raises it.
 */
export const DEFAULT_IMAGE_RETENTION = 1;

/**
 * Images to keep per (slug, env) for `app`: the running one, plus its retention.
 *
 * The `??` is for a partially-selected app row, not for the column — it is
 * NOT NULL with a default, so a row read with `SELECT *` always has a number.
 */
export function imagesToKeep(app) {
  return (app?.image_retention ?? DEFAULT_IMAGE_RETENTION) + 1;
}
