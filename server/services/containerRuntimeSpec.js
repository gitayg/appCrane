// The two runtime facts a pulled image needs that AppCrane could not express:
// the COMMAND it is started with, and WHICH paths inside it hold state.
//
// Both are stored on the app row as JSON text and both are read back here, at
// the one boundary every caller goes through. Neither is ever interpolated into
// a shell — see the array-only rule below, which is the whole security story of
// this file.

import { resolve, join, posix } from 'path';

// --------------------------------------------------------------------------
// Command
// --------------------------------------------------------------------------

// A container command is an ARRAY OF ARGV STRINGS. Never a shell string, and
// this is not a style preference.
//
// The value originates in a catalogue manifest or an operator-typed field and
// ends up on a `docker run` argv. If it were stored as "start-dev --http-port
// 8080" it could only be turned back into argv by splitting it — and the moment
// anything in this repo splits a stored string into a command, the next natural
// step is `sh -c <that string>`, which is command injection with the app row as
// the injection point. The repo already has a standing rule against inlining DB
// or user strings into `sh -c`; a command field is exactly that hazard with a
// friendlier name, so the shape refuses the hazard rather than guarding it.
//
// execFile('docker', args) is exec, not a shell: each element is one argv slot,
// so a space, a quote or a `;` inside an element is DATA to the container's
// process and cannot start a second command. That property only holds while the
// value is an array; a string never gets to be one here.
//
// The second half of the safety argument is positional, and it is measured in
// test/container-command.test.js rather than assumed: `docker run` stops parsing
// its OWN options at the image name, so every element appended after the image
// is a container argument even when it is spelled like a docker flag. A command
// of ["--privileged"] is passed to the container's entrypoint as the literal
// string; it does not privilege the container.
export const MAX_COMMAND_ARGS = 64;
export const MAX_COMMAND_ARG_LENGTH = 1024;

/** Anything the kernel accepts in argv but a log line, a deploy record or
 *  `docker inspect` output would silently reformat. NUL is the hard one (it
 *  truncates argv in C); the rest are refused because a newline inside an argv
 *  element makes every one of those outputs ambiguous about where one argument
 *  ends and the next begins. */
const CONTROL_CHARS = /[\x00-\x1f\x7f]/;

/**
 * Validate a command at the WRITE boundary — the value about to be stored on an
 * app row. Returns the normalised array, or null for "no command" (the default:
 * the image's own ENTRYPOINT/CMD runs untouched).
 *
 * Throws Error with an operator-readable message on anything else. The caller
 * is expected to turn that into a 400; this module has no HTTP knowledge.
 */
export function validateContainerCommand(value) {
  if (value === undefined || value === null) return null;

  // An empty array is "no command", stored as NULL, so there is exactly one
  // representation of the default rather than two that behave alike.
  if (Array.isArray(value) && value.length === 0) return null;

  if (typeof value === 'string') {
    throw new Error(
      'container command must be an array of argument strings, not a shell string — ' +
      'write ["start-dev"] rather than "start-dev". A string would have to be split to ' +
      'be run, and splitting a stored string into a command is how shell injection gets in.',
    );
  }
  if (!Array.isArray(value)) {
    throw new Error('container command must be an array of argument strings');
  }
  if (value.length > MAX_COMMAND_ARGS) {
    throw new Error(`container command may have at most ${MAX_COMMAND_ARGS} arguments (got ${value.length})`);
  }

  const out = [];
  for (const [i, raw] of value.entries()) {
    if (typeof raw !== 'string') {
      throw new Error(`container command argument ${i} must be a string (got ${raw === null ? 'null' : typeof raw})`);
    }
    // NOT trimmed. A deliberate trailing space inside one argv element is legal
    // and meaningful to some programs; silently rewriting an operator's argument
    // is worse than passing it through. Only emptiness and control characters
    // are refused.
    if (raw.length === 0) {
      throw new Error(`container command argument ${i} is empty — an empty argv slot is almost never intended`);
    }
    if (raw.length > MAX_COMMAND_ARG_LENGTH) {
      throw new Error(`container command argument ${i} is longer than ${MAX_COMMAND_ARG_LENGTH} characters`);
    }
    if (CONTROL_CHARS.test(raw)) {
      throw new Error(
        `container command argument ${i} contains a control character (NUL, newline or similar). ` +
        'Those truncate or split argv in ways no log or inspect output can represent unambiguously.',
      );
    }
    out.push(raw);
  }
  return out;
}

/**
 * Read a command back off an app row. The column holds the JSON text
 * validateContainerCommand produced, but a row can also predate the column, be
 * NULL, or have been written by a hand-edited database — so the stored value is
 * re-validated rather than trusted, which is the second of the two boundaries.
 *
 * Returns null (meaning "use the image's own CMD") for anything unusable, and
 * never throws: a malformed column must not be able to make an app undeployable.
 */
export function parseContainerCommand(stored) {
  if (stored === undefined || stored === null || stored === '') return null;
  if (Array.isArray(stored)) {
    try { return validateContainerCommand(stored); } catch { return null; }
  }
  if (typeof stored !== 'string') return null;
  let parsed;
  try { parsed = JSON.parse(stored); } catch { return null; }
  try { return validateContainerCommand(parsed); } catch { return null; }
}

/**
 * The ARGV-BUILD boundary. Called by docker.js immediately before the elements
 * are appended to a `docker run` line, so a caller that bypassed storage
 * entirely — a route, a test, a future scheduler — still cannot put a non-array
 * or a control character on the argv.
 *
 * Throws rather than dropping: at this point the container is about to be
 * created, and starting it with the command silently removed produces exactly
 * the failure this feature exists to fix (an app that boots, exits 0 and never
 * serves) with no explanation anywhere.
 */
export function assertRunnableCommand(command) {
  return validateContainerCommand(command);
}

// --------------------------------------------------------------------------
// Volumes
// --------------------------------------------------------------------------

// AppCrane mounts exactly one path today: /data, from <shared>/data. That is a
// contract an image AppCrane BUILT keeps (DATA_DIR=/data is a platform
// guarantee) and a pulled image has no reason to have heard of — bookstack
// writes /config, odoo writes /var/lib/odoo, appsmith writes /appsmith-stacks.
// None of those is mounted, so all of it lives in the container's writable
// layer, and every redeploy does `docker rm -f` (docker.js stopApp) and throws
// the layer away.
//
// Measured against the shipped catalogue on 2026-09-09, by reading each entry's
// image config straight from its registry: of the 63 entries whose config could
// be read, 25 declare a VOLUME and 22 declare at least one that is not /data.
// That is a FLOOR, not a count — an image that persists without declaring
// VOLUME (any Laravel app writing to /var/www/html/storage) is invisible to it.
//
// So an app may name the paths it actually persists, each mapped to a directory
// under the same per-app shared tree /data already comes from. Nothing about an
// app that declares nothing changes: it gets the one /data mount, byte for byte.
export const MAX_VOLUME_PATHS = 16;
export const MAX_VOLUME_PATH_LENGTH = 512;

/** The mount every app gets, declared or not. */
export const DEFAULT_CONTAINER_PATH = '/data';

/** Subdirectory of the per-app shared tree that holds the declared mounts.
 *  Kept beside `data/` rather than inside it so the existing /data mount does
 *  not contain, and therefore does not expose to the app, every other mount. */
export const VOLUME_SUBDIR = 'volumes';

// Kernel-owned mount points. A bind mount over any of these does not give an
// app access to anything (the host side is the app's own empty directory) — it
// breaks the container, usually in a way that reads as "the image is broken".
// `/` is refused for the same reason, more so.
const FORBIDDEN_CONTAINER_PATHS = new Set(['/', '/proc', '/sys', '/dev']);

/**
 * Validate the declared container paths at the WRITE boundary. Returns a
 * normalised, de-duplicated array (possibly empty), or throws.
 */
export function validateVolumePaths(value) {
  if (value === undefined || value === null) return [];
  if (typeof value === 'string') {
    throw new Error(
      'volume paths must be an array of absolute container paths, not a single string — ' +
      'write ["/config"] rather than "/config"',
    );
  }
  if (!Array.isArray(value)) throw new Error('volume paths must be an array of absolute container paths');
  if (value.length > MAX_VOLUME_PATHS) {
    throw new Error(`at most ${MAX_VOLUME_PATHS} volume paths may be declared (got ${value.length})`);
  }

  const seen = new Set();
  const out = [];
  for (const [i, raw] of value.entries()) {
    if (typeof raw !== 'string' || raw.length === 0) {
      throw new Error(`volume path ${i} must be a non-empty string`);
    }
    if (raw.length > MAX_VOLUME_PATH_LENGTH) {
      throw new Error(`volume path ${i} is longer than ${MAX_VOLUME_PATH_LENGTH} characters`);
    }
    if (CONTROL_CHARS.test(raw)) {
      throw new Error(`volume path ${i} contains a control character`);
    }
    // A colon is the field separator in `-v host:container:options`. A path
    // carrying one would not be a path at all — it would be a way to append
    // `:ro`, or to name a completely different host source, from a stored
    // field. Refused before it can ever reach the argv builder.
    if (raw.includes(':')) {
      throw new Error(
        `volume path ${i} contains ':', which is the field separator in a docker -v argument. ` +
        'A container path may not contain one.',
      );
    }
    if (!raw.startsWith('/')) {
      throw new Error(`volume path ${i} must be absolute (start with '/'), got '${raw}'`);
    }
    if (raw.split('/').includes('..')) {
      throw new Error(`volume path ${i} may not contain a '..' segment, got '${raw}'`);
    }

    // posix.normalize, not path.normalize: these are paths inside a Linux
    // container, and on a Windows host path.normalize would turn '/config'
    // into '\config'. Trailing slashes are dropped so '/config' and '/config/'
    // are one entry rather than two mounts of the same directory.
    let norm = posix.normalize(raw);
    if (norm.length > 1 && norm.endsWith('/')) norm = norm.slice(0, -1);

    if (FORBIDDEN_CONTAINER_PATHS.has(norm)) {
      throw new Error(
        `volume path ${i} ('${norm}') is a kernel mount point or the container root — ` +
        'binding a directory over it breaks the container and persists nothing',
      );
    }
    if (seen.has(norm)) continue;
    seen.add(norm);
    out.push(norm);
  }
  return out;
}

/** Read declared paths back off an app row. Never throws — a malformed column
 *  degrades to today's behaviour (the /data mount alone) rather than making the
 *  app undeployable. */
export function parseVolumePaths(stored) {
  if (stored === undefined || stored === null || stored === '') return [];
  if (Array.isArray(stored)) {
    try { return validateVolumePaths(stored); } catch { return []; }
  }
  if (typeof stored !== 'string') return [];
  let parsed;
  try { parsed = JSON.parse(stored); } catch { return []; }
  try { return validateVolumePaths(parsed); } catch { return []; }
}

const isUnderneath = (child, parent) => child === parent || child.startsWith(parent === '/' ? '/' : `${parent}/`);

/**
 * Turn an app's shared directory plus its declared container paths into the
 * exact `volumes` array startApp() takes.
 *
 * Invariants, in order of how much they matter:
 *
 *  1. The /data mount is ALWAYS first and ALWAYS <shared>/data. That is the
 *     platform guarantee (DATA_DIR=/data) and every live app depends on the
 *     exact argv it produces, so it is emitted before anything declared and is
 *     not reachable by any declared value.
 *  2. Nothing declared can move a mount outside the app's own shared tree. The
 *     host side is built from the validated container path and then re-checked
 *     with a prefix test — the same belt-and-braces deployer.js already applies
 *     to its own appDir/releasesDir/sharedDir.
 *  3. A declared path already covered by another mount is SKIPPED, not merged.
 *     '/data' and '/data/db' are inside mount 1; '/config/cache' is inside a
 *     declared '/config'. Docker would accept the nested bind and resolve it by
 *     mount order, which is a rule nobody reading the app's configuration can
 *     see. Skipping is reported back so the deploy log can say so out loud
 *     rather than the operator discovering it from a missing directory.
 *
 * @returns {{ mounts: {host: string, container: string}[], skipped: {path: string, coveredBy: string}[] }}
 */
export function resolveVolumeMounts({ sharedDir, paths = [] }) {
  const base = resolve(sharedDir);
  const mounts = [{ host: resolve(join(base, 'data')), container: DEFAULT_CONTAINER_PATH }];
  const skipped = [];

  for (const p of validateVolumePaths(paths)) {
    const covering = mounts.find((m) => isUnderneath(p, m.container));
    if (covering) {
      skipped.push({ path: p, coveredBy: covering.container });
      continue;
    }
    // Segment-wise join, so the host layout mirrors the container layout and
    // two different container paths can never land on one host directory:
    // '/var/lib/odoo' -> <shared>/volumes/var/lib/odoo.
    const root = resolve(join(base, VOLUME_SUBDIR));
    const host = resolve(join(root, ...p.split('/').filter(Boolean)));
    if (!host.startsWith(`${root}/`)) {
      throw new Error(`Security: volume host path ${host} for '${p}' is outside ${root}`);
    }
    mounts.push({ host, container: p });
  }
  return { mounts, skipped };
}
