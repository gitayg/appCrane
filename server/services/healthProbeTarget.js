/**
 * What to probe after a deploy, and how strictly to read the answer.
 *
 * Two different questions get conflated easily, so they are separated here:
 *
 *   PATH   — which URL proves the container is serving.
 *   STRICT — whether the body must be AppCrane's {status, version} shape.
 *
 * `strict` alone was never enough to make an app deployable. It only governs
 * the BODY: a non-strict probe still requires 200 AT THE PATH, so an app that
 * does not serve /api/health fails identically whether strict is on or off.
 * That is why source_type='image' apps also carry apps.health_path — relaxing
 * the body without moving the path would have changed nothing for them.
 *
 * The rule underneath both is one question: did the app's author write these
 * routes against AppCrane?
 *
 *   - A Node app whose deployhub.json declares be.health: yes. Its author is
 *     writing the route and the {status, version} contract is fair to demand.
 *   - A third-party image: no (v2.66.2). BookStack answered /status with
 *     {"database":true,"cache":true,"session":true} — a richer signal than
 *     {status, version} — and was torn down for missing two field names.
 *   - A PHP app built from composer.json: no. AppCrane generates the
 *     Dockerfile, not the application. Laravel and Symfony ship no
 *     /api/health, so the default would 404 on every deploy, and the body
 *     contract would fail a healthy app for serving HTML at the path it does
 *     have. Demanding either would mean generating routes into someone's
 *     application, which is not AppCrane's to write.
 *
 * So a PHP build probes '/' — the front controller its own generated docroot
 * points at — and is held to "answers 200", exactly the image-app treatment.
 * An author who wants a different path still declares one and it is honoured;
 * they are simply never held to the body shape, because nothing in a generated
 * PHP build ever agreed to it.
 */

export const DEFAULT_HEALTH_PATH = '/api/health';

/**
 * The front controller. A generated PHP image serves DocumentRoot from
 * `public/` when the release has one and from the release root otherwise, so
 * '/' reaches index.php in both layouts.
 */
export const PHP_DEFAULT_HEALTH_PATH = '/';

/**
 * @param {object}  args
 * @param {object}  args.manifest  deployhub.json, may be empty
 * @param {object}  args.app       the apps row
 * @param {string?} args.runtime   'php' | 'node' | null — what actually built
 *                                 this release. Null for an image deploy,
 *                                 which never reaches the generator.
 * @returns {{ path: string, strict: boolean, source: string }}
 */
export function resolveHealthProbe({ manifest, app, runtime = null }) {
  const declared = manifest?.be?.health;
  const column = app?.health_path;

  // Neither an image nor a generated PHP build owes AppCrane a body shape.
  const strict = app?.source_type !== 'image' && runtime !== 'php';

  if (declared) {
    return { path: declared, strict, source: `manifest.be.health="${declared}"` };
  }
  if (column) {
    return { path: column, strict, source: `apps.health_path="${column}"` };
  }
  if (runtime === 'php') {
    return {
      path: PHP_DEFAULT_HEALTH_PATH,
      strict: false,
      source: 'default / (php:8.3-apache build — AppCrane did not write this app\'s routes)',
    };
  }
  return {
    path: DEFAULT_HEALTH_PATH,
    strict,
    source: 'default /api/health (manifest.be.health unset)',
  };
}
