// Which runtime version does an app container really run, and on which base?
//
// The version comes from the IMAGE's environment, not the container's: the
// official php images set ENV PHP_VERSION (measured: php:8.3-apache has
// PHP_VERSION=8.3.36, and `php -r 'echo PHP_VERSION;'` inside it prints
// 8.3.36), while the container's environment also holds the app's own
// variables, which could set PHP_VERSION to anything. When the image does not
// set it (an app Dockerfile on another base), the binary is asked inside the
// running container.

import { execFile } from 'child_process';
import { promisify } from 'util';
import { RUNTIMES, parseVersion } from './runtimeAdvisories.js';
import { BASE_IMAGE_LABEL, BASE_DIGEST_LABEL } from './runtimeImages.js';

const execFileP = promisify(execFile);

async function docker(args, timeout = 15000) {
  const { stdout } = await execFileP('docker', args, { timeout, maxBuffer: 4 * 1024 * 1024 });
  return String(stdout).trim();
}

export const containerFor = (slug, env) => `appcrane-${slug}-${env}`;

export function envValue(envList, key) {
  const hit = (envList || []).find((e) => String(e).startsWith(`${key}=`));
  return hit ? String(hit).slice(key.length + 1) : null;
}

/**
 * { image_id, image_ref, runtime, version, version_source, base_image, base_digest } for the
 * running container, or null when no container is running. `runtime` is the first enabled
 * RUNTIMES entry the image answers for, else null. The binary is asked inside the container
 * only for the runtimes named in `probe` (the caller has a reason to expect them).
 */
export async function inspectContainerRuntime(slug, env, { run = docker, probe = [] } = {}) {
  let c;
  try {
    c = JSON.parse(await run(['inspect', containerFor(slug, env), '--format', '{{json .}}']));
  } catch (_) {
    return null;
  }
  if (!c?.State?.Running) return null;
  const imageId = c.Image;
  let img = {};
  try { img = JSON.parse(await run(['image', 'inspect', imageId, '--format', '{{json .Config}}'])) || {}; } catch (_) { img = {}; }
  const labels = img.Labels || {};
  const out = {
    image_id: imageId, image_ref: c.Config?.Image || null, runtime: null, version: null, version_source: null,
    base_image: labels[BASE_IMAGE_LABEL] || null, base_digest: labels[BASE_DIGEST_LABEL] || null,
  };
  for (const [name, rt] of Object.entries(RUNTIMES)) {
    if (!rt.enabled) continue;
    const v = envValue(img.Env, rt.env);
    if (parseVersion(v)) return { ...out, runtime: name, version: v, version_source: 'image' };
  }
  for (const [name, rt] of Object.entries(RUNTIMES)) {
    if (!rt.enabled || !probe.includes(name)) continue;
    try {
      const v = (await run(['exec', containerFor(slug, env), ...rt.probe], 10000)).split('\n')[0].trim();
      if (/^\d+\.\d+\.\d+\S*$/.test(v)) return { ...out, runtime: name, version: v, version_source: 'exec' };
    } catch (_) { /* not this runtime */ }
  }
  return out;
}

/** PHP_VERSION (or the runtime's env var) of an image, without running it. */
export async function imageRuntimeVersion(ref, runtime, run = docker) {
  try {
    const cfg = JSON.parse(await run(['image', 'inspect', ref, '--format', '{{json .Config}}'])) || {};
    const v = envValue(cfg.Env, RUNTIMES[runtime].env);
    return parseVersion(v) ? v : null;
  } catch (_) {
    return null;
  }
}
