// What a redeploy DESTROYS, computed rather than guessed.
//
// Every deploy runs `docker rm -f` (services/docker.js stopApp) and creates a
// new container. Two kinds of state die with the old one:
//
//   1. The writable layer. Anything the app wrote to a path that is neither
//      bind-mounted nor an image VOLUME. `docker diff` lists exactly this, and
//      Docker excludes mounted content from it automatically, so the paths it
//      reports are by construction the ones nothing is protecting. See the
//      WRITABLE LAYER section below for the measurements and the filtering.
//      This is the half that catches the ~9 Laravel/PHP catalogue apps
//      (akaunting, invoice-ninja, krayin, bagisto, uvdesk, freescout, leantime,
//      limesurvey, easyappointments) whose images declare NO volume at all and
//      which the (2) rule below therefore calls safe.
//   2. Every image-declared VOLUME that AppCrane did NOT bind-mount. Docker
//      gives such a path an ANONYMOUS volume, and `docker rm -f` (no `-v`)
//      leaves that volume behind, unreferenced, while the replacement container
//      is given a fresh empty one. The bytes are still on the disk and the app
//      can never reach them again, which is worse than deletion: the data is
//      gone from the app's point of view AND the disk keeps paying for it.
//
// Both are measurable, and the verdict keeps them apart: they are different
// sentences to an operator and they have different remedies.
//
// MEASURED on this box (2026-09-10), Docker Desktop 4.x, against an image built
// as `FROM alpine:3.20 / RUN echo seed > /state/seed.txt / VOLUME /state`:
//
//   docker image inspect  --format '{{json .Config.Volumes}}'  ->  {"/state":{}}
//     ... and for the identical image with the VOLUME line removed  ->  null
//   docker inspect <container> --format '{{json .Mounts}}'
//     with no -v            ->  [{"Type":"volume","Name":"daebcddf…","Destination":"/state",…}]
//     with -v <host>:/state ->  [{"Type":"bind","Source":"<host>","Destination":"/state",…}]
//   `docker volume ls -q | wc -l` across create + `rm -f`: 163 -> 163. The
//   anonymous volume is NOT reclaimed; it is stranded.
//   write /state/marker, `rm -f`, recreate, `cat /state/marker`
//     -> "No such file or directory". The control write at /elsewhere.txt (plain
//        writable layer) was gone too, and /state/seed.txt was back at the
//        image's own content — i.e. a fresh anonymous volume, re-seeded.
//
// Note `.Config.Volumes` still lists the path when a bind covers it, so the
// image's declaration alone is not the answer. `.Mounts` is: a Destination
// carrying `Type: "bind"` is a path AppCrane pointed at the app's own directory
// under <shared>, and that directory outlives any number of containers.
//
// ---------------------------------------------------------------------------
// Why this reads the RUNNING CONTAINER and not the app row
// ---------------------------------------------------------------------------
//
// The row says what the NEXT container will mount. The question the operator is
// about to answer is about the state the CURRENT one is holding, and the two
// disagree in exactly the case that matters most: an operator who has just added
// `/config` to volume_paths has an app whose live container still keeps /config
// in an anonymous volume. Reading the row would report "safe" and the deploy
// would still lose everything in it. Reading the container reports the truth,
// and the truth is that this particular deploy is the destructive one.
//
// It also means no registry round-trip and no credentials: the image of a
// running container is by definition local.
//
// ---------------------------------------------------------------------------
// What happens when the container cannot be inspected
// ---------------------------------------------------------------------------
//
// Stated out loud because "unknown" quietly becoming "safe" is how a guard
// stops guarding:
//
//   * `No such object` / `No such container` is NOT unknown. It is a definite
//     answer — there is no container, so there is no container state to lose,
//     so a first deploy (and the catalogue's install-then-deploy flow) is never
//     gated. This is the only "no risk" verdict reached without reading a
//     config.
//   * Any other failure (daemon down, docker missing, a template that did not
//     parse, unreadable JSON) is UNKNOWN, and unknown counts as AT RISK. The
//     acknowledgement message says so in those words rather than naming paths
//     it could not read.
//   * The one narrowing: if this app+env has never had a deployment reach
//     `live`, nothing was ever created for it, so an unreadable daemon still
//     produces "no risk". That is a database fact and cannot itself be unknown.
//
// Nothing in this module throws into a deploy. assess() returns a verdict; the
// caller decides what a verdict costs.

import { execFile } from 'child_process';
import { promisify } from 'util';
import { posix } from 'path';

const execFileAsync = promisify(execFile);

const INSPECT_TIMEOUT_MS = 15000;

// `docker diff` is a separate, heavier call than `docker inspect`, so it gets
// its own bounds. MEASURED on this box (2026-09-11), Docker Desktop 29.6.1,
// containerd snapshotter / overlayfs, against a container holding 100,001 files
// in 400 directories (411 MB writable layer):
//
//   $ docker diff big   ->  100,405 lines, 3,741,379 bytes
//   three consecutive runs: 496 ms, 453 ms, 442 ms
//
// So half a second at a hundred thousand files. 10 s is ~20x that, which leaves
// room for a slower disk without leaving a deploy confirmation hanging.
//
// VERIFIED ACROSS STORAGE DRIVERS, because `docker diff` is implemented per
// driver and this box's daemon is not the one CI runs. The same 50,000-file
// container was built on each:
//
//   containerd snapshotter / overlayfs   50,206 lines  1,757,584 bytes  268-281 ms
//   overlay2 / extfs (dind, 29.8.0)      50,206 lines  1,757,584 bytes  220-230 ms
//
// Byte-for-byte identical output and the same order of magnitude in time. The
// only difference observed at all was the ORDER of the entries (overlay2 put the
// mount point first, containerd put it after /tmp), which is why nothing in
// classifyWrittenPaths depends on input order.
const DIFF_TIMEOUT_MS = 10000;

// 3.74 MB at 100k entries, i.e. ~37 bytes per entry. The 4 MB the inspect calls
// use would have overflowed on a container only a third larger than the one
// measured, and an overflow is NOT a small answer — execFile rejects with
// ERR_CHILD_PROCESS_STDIO_MAXBUFFER and hands back a TRUNCATED stdout:
//
//   node -e 'execFile("docker",["diff",big],{maxBuffer:64*1024},cb)'
//     err.code   = ERR_CHILD_PROCESS_STDIO_MAXBUFFER
//     err.message= stdout maxBuffer length exceeded
//     stdout.len = 65536            <- a prefix, silently missing the rest
//
// Parsing that prefix would report a subset of the doomed paths as if it were
// the whole list. 64 MB is ~1.7 million entries, and an overflow past THAT is
// treated as unknown rather than parsed.
const DIFF_MAX_BUFFER = 64 * 1024 * 1024;

// How many leading path segments a reported directory keeps. The operator's
// question is "what do I add to volume_paths", and the answer is a directory
// they can name, not the file that happened to be written. MEASURED against the
// samples in the table below, depth 4 lands on exactly the actionable directory
// every time: /var/www/html/storage, /var/lib/postgresql/data, /srv/app/uploads,
// /data.
const ROLLUP_DEPTH = 4;

/** At most this many directories in a verdict. A real app writes tens of
 *  thousands of paths; a confirmation dialog that lists them is a dialog nobody
 *  reads. The count of what was elided is reported alongside. */
const MAX_REPORTED_PATHS = 12;

// ---------------------------------------------------------------------------
// WRITABLE LAYER — what is noise and what is state, decided by measurement
// ---------------------------------------------------------------------------
//
// `VOLUME` is a floor, not the truth: an app that persists to a path its image
// never declared is invisible to the (2) rule. `docker diff <container>` lists
// the container's writable layer against its image, which is that blind spot
// exactly. MEASURED, alpine:3.20, no VOLUME declared anywhere:
//
//   $ docker run -d --name p alpine:3.20 sh -c 'mkdir -p /var/www/html/storage
//       && echo X > /var/www/html/storage/db.sqlite && echo log > /tmp/noise.log
//       && sleep 300'
//   $ docker inspect alpine:3.20 --format '{{json .Config.Volumes}}'
//   null                                  <- the image declares NOTHING
//   $ docker diff p
//   C /tmp
//   A /tmp/noise.log
//   C /var
//   A /var/www
//   A /var/www/html
//   A /var/www/html/storage
//   A /var/www/html/storage/db.sqlite      <- ...yet the state is plainly there
//
// MOUNTED CONTENT EXCLUDES ITSELF, including nested content. Re-measured here
// rather than taken on faith, because the whole design rests on it:
//
//   $ docker run -d --name p2 -v "$W/mnt:/data" alpine:3.20 sh -c '
//       echo M > /data/inmount.txt
//       mkdir -p /data/nested/deep && echo N > /data/nested/deep/deepfile.txt
//       mkdir -p /var/www/html/storage && echo U > /var/www/html/storage/db.sqlite
//       echo log > /tmp/noise.log; mkdir -p /var/log && echo l > /var/log/app.log
//       sleep 300'
//   $ docker diff p2
//   C /tmp
//   A /tmp/noise.log
//   A /data                        <- the mount POINT, and nothing beneath it
//   C /var
//   A /var/www
//   A /var/www/html
//   A /var/www/html/storage
//   A /var/www/html/storage/db.sqlite
//   A /var/www/html/storage/framework
//   A /var/www/html/storage/framework/cache
//   C /var/log
//   A /var/log/app.log
//
// Neither /data/inmount.txt nor /data/nested/deep/deepfile.txt appears. A path a
// mount protects filters ITSELF out, at any depth — no subtraction needed.
//
// But `A /data` DOES appear: the mount POINT is an entry, because the directory
// did not exist in the image and had to be created for the mount. AppCrane
// bind-mounts /data into every container it starts, so a filter that did not
// drop mount destinations would fire on every app AppCrane runs. Mount
// destinations are therefore dropped explicitly, and that rule is load-bearing
// rather than defensive.
//
// ---------------------------------------------------------------------------
// The ignore rules, and the observation behind each one
// ---------------------------------------------------------------------------
//
// The risk here is not missing state, it is crying wolf: a warning that fires on
// every app trains the click-through that defeats it on the app where it was
// true. Every rule below is here because a REAL image produced the entry it
// suppresses. Images booted for this (all already local; no speculative pulls):
//
//   leantime/leantime:latest       real catalogue app, Laravel   53 diff lines
//   php:8.3-apache                 the base 9 catalogue apps use  3 diff lines
//   mariadb:11.4                   declares VOLUME /var/lib/mysql 4 diff lines
//   redis:8-alpine (bare)          0 diff lines
//   redis:8-alpine --save 20 1     2 diff lines
//   vectorim/element-web:latest    nginx static site            13 diff lines
//   ghcr.io/umami-software/umami   node app                      0 diff lines
//   node:22-slim                   node base                   417 diff lines
//
// EPHEMERAL_ROOTS — a prefix whose contents are scratch by construction:
//
//   /tmp      node:22-slim wrote 400 of its 417 lines under /tmp/node-compile-cache;
//             leantime wrote /tmp/nginx-stdout---supervisor-i89lncyg.log and
//             /tmp/nginx-stderr---supervisor-4zrok956.log; element-web wrote
//             /tmp/{fastcgi,proxy,scgi,uwsgi,client}_temp and /tmp/nginx.pid.
//             This single rule removes more false positives than all the others.
//   /var/tmp  measured: `mkdir -p /var/tmp/scratch` shows up as
//             `C /var/tmp` / `A /var/tmp/scratch` / `A /var/tmp/scratch/t.bin`.
//   /run      mariadb:11.4 -> A /run/mysqld/mysqld.pid, A /run/mysqld/mysqld.sock
//             php:8.3-apache -> A /run/apache2/apache2.pid   (its ENTIRE diff)
//             leantime -> A /run/nginx.pid, A /run/supervisord.pid
//   /var/run  the same directory on images that have not yet symlinked it.
//   /var/log  leantime -> C /var/log/nginx, A /var/log/nginx/error.log.
//   /var/cache measured: A /var/cache/myapp/c.bin. Package and runtime caches.
//   /etc      element-web rewrites C /etc/nginx/conf.d/default.conf at every
//             boot from its entrypoint template, so the NEXT container
//             regenerates it identically. Reporting it would gate a static site
//             that has no state at all. This is the one rule that trades a
//             little recall for precision — see "What still slips through".
//
// NOT ignored, though a plausible-looking list would have included them:
// /proc, /sys and /dev. MEASURED — they never appear, because they are mounts
// rather than writable layer:
//
//   $ docker run ... sh -c 'echo s > /dev/shm/shmfile; echo appended >> /etc/hosts; ...'
//   $ docker diff p
//   C /etc
//   D /etc/motd            <- the one thing that WAS a layer write
//   ...                       no /dev/shm/shmfile, no /etc/hosts
//
// Adding them would have been three rules that never fire, and three rules
// nobody could later tell were dead. Re-measured on an overlay2 daemon, where
// the same probe produces the same absences:
//
//   A /data                                 <- the mount point, on both drivers
//   C /tmp
//   A /tmp/noise.log
//   C /var
//   C /var/log
//   A /var/log/app.log
//   A /var/www/html/storage/db.sqlite
//   A /var/lib/postgresql/data/base/1.db
//   C /etc
//   D /etc/motd                             <- still no /dev/shm, still no /etc/hosts
//
// /var/lib is deliberately NOT a root, even though leantime writes
// /var/lib/nginx/tmp under it: it is also where the canonical data directories
// live. Measured, on an image declaring no VOLUME at all:
//
//   A /var/lib/postgresql/data/base/1.db
//
// Suppressing that is the exact failure this feature exists to fix.
//
// EPHEMERAL_SEGMENTS — a path component that means scratch wherever it appears,
// which is how /var/lib/nginx/tmp is dropped without taking /var/lib with it:
//
//   tmp   leantime -> A /var/lib/nginx/tmp/{client_body,fastcgi,proxy,scgi,uwsgi}
//   temp  element-web -> A /tmp/{fastcgi,proxy,scgi,uwsgi,client}_temp (already
//         under /tmp; the segment form covers the same convention elsewhere)
//   cache leantime -> A /var/www/html/bootstrap/cache/{packages,services}.php
//         and the whole of /var/www/html/storage/framework/cache/... Laravel
//         regenerates both on boot. Without this rule leantime reports
//         /var/www/html/bootstrap alongside /var/www/html/storage; with it, the
//         verdict is the single directory an operator should actually mount.
//
// ---------------------------------------------------------------------------
// Why there is no size threshold and no file-count threshold
// ---------------------------------------------------------------------------
//
// Both were considered and both are MEASURABLY worse than the path rules.
//
// COUNT. The smallest real state and the smallest noise are the same size:
//
//   redis:8-alpine --save 20 1  ->  A /data/dump.rdb            1 entry, a database
//   php:8.3-apache              ->  A /run/apache2/apache2.pid  1 entry, a pid file
//
// A threshold of "more than one entry" throws away a whole Redis dump. Going the
// other way, leantime's noise (/var/lib/nginx/tmp, 6 entries) outnumbers its own
// /var/www/html/bootstrap/cache (2 entries). Count does not track the
// distinction anywhere in the sample, in either direction.
//
// SIZE. `docker ps -s` does report the writable layer's size and is cheap
// (measured: 175 ms; big container 411MB, leantime 545kB) — but it reports ONE
// number for the whole layer, not per path. On node:22-slim that number is
// dominated by the /tmp compile cache this module deliberately ignores, so
// quoting it would put a number in front of the operator that contradicts the
// paths printed under it. A per-directory size needs `docker exec du` inside a
// container that may be stopped and may have no shell. Entry counts come free
// with the diff already being parsed, so those are what the verdict carries.
//
// ---------------------------------------------------------------------------
// What still slips through — stated because a guard's gaps are its contract
// ---------------------------------------------------------------------------
//
//   * State written under an ignored root. An app keeping its database in
//     /var/log or /etc is not reported. Nothing in the sample does this.
//   * State whose every path component is named tmp/temp/cache — e.g. an app
//     storing uploads in /app/cache/uploads.
//   * Anything the container wrote and then the IMAGE also has: `docker diff`
//     reports difference from the image, so a file rewritten with identical
//     content still shows as C, but a file written into a tmpfs the image
//     declares does not appear at all.
//   * A container that has not started yet, or one whose app writes its state
//     only on shutdown.

/** Prefixes whose entire subtree is scratch. Each one is here because a real
 *  image in the sample above wrote into it. */
export const EPHEMERAL_ROOTS = Object.freeze([
  '/tmp', '/var/tmp', '/run', '/var/run', '/var/log', '/var/cache', '/etc',
]);

/** Path components that mean scratch wherever they appear, so that a noisy
 *  subdirectory can be dropped without dropping its parent. */
export const EPHEMERAL_SEGMENTS = Object.freeze(['tmp', 'temp', 'cache']);

/** The parameter a caller passes to say "yes, I know". One spelling, shared by
 *  the REST routes and the MCP tools, so an agent that learns it once from an
 *  error message can use it on either surface. */
export const ACK_PARAM = 'acknowledge_data_loss';

/** Mirrors services/docker.js containerName(), which is not exported.
 *  test/redeploy-guard.test.js asserts the two still agree by reading docker.js,
 *  because a silent divergence here would make every app look container-less
 *  and therefore safe — the guard would disappear with nothing going red. */
export const containerNameFor = (slug, env) => `appcrane-${slug}-${env}`;

/** Normalise a container path the way containerRuntimeSpec does: posix rules
 *  (these are paths inside a Linux container even when AppCrane runs on macOS),
 *  no trailing slash, so '/config' and '/config/' are one path. */
function normPath(p) {
  if (typeof p !== 'string' || !p.startsWith('/')) return null;
  let n = posix.normalize(p);
  if (n.length > 1 && n.endsWith('/')) n = n.slice(0, -1);
  return n;
}

/** Is `child` the same path as `parent`, or inside it? A bind at /data covers
 *  /data/db; a bind at /dataset does NOT cover /data. */
export function covers(parent, child) {
  return child === parent || child.startsWith(parent === '/' ? '/' : `${parent}/`);
}

/**
 * Split an inspected container's image-declared VOLUME paths into the ones a
 * bind mount is protecting and the ones a redeploy strands.
 *
 * Pure, and deliberately so: the daemon facts above are recorded once, at the
 * edge, and every rule about what they MEAN is decided here where a test can
 * drive it with no Docker at all.
 *
 * @param {{imageVolumes: string[], bindDestinations: string[]}} args
 * @returns {{atRisk: string[], persisted: string[]}}
 */
export function classifyVolumePaths({ imageVolumes = [], bindDestinations = [] }) {
  const binds = bindDestinations.map(normPath).filter(Boolean);
  const atRisk = [];
  const persisted = [];
  for (const raw of imageVolumes) {
    const p = normPath(raw);
    if (!p) continue;
    if (binds.some((b) => covers(b, p))) persisted.push(p);
    else atRisk.push(p);
  }
  return { atRisk: atRisk.sort(), persisted: persisted.sort() };
}

/**
 * Parse `docker diff` stdout into entries.
 *
 * The format is one entry per line, `<kind> <path>`, kind in A (added), C
 * (changed) or D (deleted). A path may legitimately contain spaces, so only the
 * first space is a separator.
 *
 * @param {string} stdout
 * @returns {{kind: string, path: string}[]}
 */
export function parseDockerDiff(stdout) {
  const out = [];
  for (const line of String(stdout || '').split('\n')) {
    if (!line) continue;
    const kind = line[0];
    if (kind !== 'A' && kind !== 'C' && kind !== 'D') continue;
    if (line[1] !== ' ') continue;
    const path = normPath(line.slice(2));
    if (path && path !== '/') out.push({ kind, path });
  }
  return out;
}

/** Is any component of `p` one of the scratch names? */
function hasEphemeralSegment(p) {
  return p.split('/').some((seg) => seg && EPHEMERAL_SEGMENTS.includes(seg.toLowerCase()));
}

/** Cut `p` down to at most `depth` leading segments. '/a/b/c/d/e' -> '/a/b/c/d' */
function truncateToDepth(p, depth) {
  const segs = p.split('/').filter(Boolean);
  if (segs.length <= depth) return p;
  return `/${segs.slice(0, depth).join('/')}`;
}

function parentOf(p) {
  const i = p.lastIndexOf('/');
  return i <= 0 ? '/' : p.slice(0, i);
}

/**
 * Turn a parsed `docker diff` into the directories an operator would have to
 * mount, with the raw entry count behind each.
 *
 * Pure, like classifyVolumePaths, and for the same reason: the daemon facts are
 * gathered once at the edge and every rule about what they MEAN is decided here
 * where a test can drive it with no Docker at all.
 *
 * The four steps, in order, each one measured against the sample in the header:
 *
 *   1. Drop interior nodes. `docker diff` emits every ancestor of a change as
 *      its own line, so leantime's real answer arrives as 10 lines of
 *      `C /var`, `C /var/www`, `C /var/www/html` scaffolding wrapped round the
 *      files that actually changed. An entry with a child in the diff carries no
 *      information its children do not. What survives is leaves: the files
 *      written, plus any pre-existing file changed in place (e.g. a sqlite
 *      database shipped in the image and then written to, which appears as a
 *      childless `C` and IS state).
 *   2. Drop mount destinations, and anything beneath one. Docker already
 *      excludes mounted CONTENT, but the mount POINT itself appears when the
 *      image did not already contain that directory — measured as `A /data`,
 *      which is the path AppCrane mounts into every container it starts.
 *   3. Drop the ephemeral roots and segments, each justified in the header.
 *   4. Roll what is left up to a directory. Every surviving leaf is truncated to
 *      ROLLUP_DEPTH segments; a leaf that is already shallower than that is
 *      replaced by its parent, so a lone `/data/dump.rdb` reports as `/data`
 *      rather than as a filename. Reported paths that contain another reported
 *      path are then collapsed onto the outermost one, since mounting that one
 *      covers the rest.
 *
 * @param {{diff: {kind: string, path: string}[], mountDestinations?: string[]}} args
 * @returns {{written: {path: string, entries: number}[], ignored: number,
 *            considered: number, truncated: number}}
 */
export function classifyWrittenPaths({ diff = [], mountDestinations = [] } = {}) {
  const mounts = mountDestinations.map(normPath).filter(Boolean);

  // (1) An entry is interior if some other entry is strictly inside it.
  const all = new Set(diff.map((e) => e.path));
  const isInterior = (p) => {
    for (const other of all) if (other !== p && covers(p, other)) return true;
    return false;
  };

  const kept = [];
  let ignored = 0;
  for (const e of diff) {
    if (isInterior(e.path)) continue;                                  // (1)
    if (mounts.some((m) => covers(m, e.path))) { ignored++; continue; } // (2)
    if (EPHEMERAL_ROOTS.some((r) => covers(r, e.path))) { ignored++; continue; }  // (3)
    if (hasEphemeralSegment(e.path)) { ignored++; continue; }                     // (3)
    kept.push(e.path);
  }

  // (4) Roll each surviving leaf up to a directory.
  const counts = new Map();
  for (const p of kept) {
    let roll = truncateToDepth(p, ROLLUP_DEPTH);
    if (roll === p) roll = parentOf(p);
    if (roll === '/' || !roll) roll = p;
    counts.set(roll, (counts.get(roll) || 0) + 1);
  }

  // Collapse a reported path onto any reported ancestor of it: mounting the
  // ancestor covers the descendant, so naming both is noise.
  const paths = [...counts.keys()];
  const roots = paths.filter((p) => !paths.some((q) => q !== p && covers(q, p)));
  const merged = new Map();
  for (const [p, n] of counts) {
    const root = roots.find((r) => covers(r, p)) || p;
    merged.set(root, (merged.get(root) || 0) + n);
  }

  const written = [...merged.entries()]
    .map(([path, entries]) => ({ path, entries }))
    .sort((a, b) => (b.entries - a.entries) || a.path.localeCompare(b.path));

  const truncated = Math.max(0, written.length - MAX_REPORTED_PATHS);
  return {
    written: written.slice(0, MAX_REPORTED_PATHS),
    ignored,
    considered: diff.length,
    truncated,
  };
}

/**
 * Read the two facts a verdict needs off one container.
 *
 * Two `docker inspect` calls rather than one `{{json .}}`: the full inspect
 * document carries `Config.Env`, which is every decrypted secret the app was
 * started with. Those must not pass through this module's memory, its error
 * messages or anything downstream of them, and the cost of avoiding it is one
 * extra ~50 ms subprocess on a path that is about to spend minutes building an
 * image.
 *
 * The third call, `docker diff`, is what closes the writable-layer blind spot.
 * It is allowed to fail on its own: a container whose declared volumes were read
 * fine but whose diff timed out is reported as "declared volumes known, writable
 * layer UNKNOWN", never as clean. See diff_error / writable_layer_unknown.
 *
 * @returns {Promise<{present: boolean|'unknown', imageVolumes?: string[],
 *                    bindDestinations?: string[], mountDestinations?: string[],
 *                    diff?: {kind: string, path: string}[], diffError?: string,
 *                    error?: string}>}
 */
export async function inspectContainerState(name) {
  const fmt = async (template) => {
    const { stdout } = await execFileAsync(
      'docker', ['inspect', name, '--format', template],
      { timeout: INSPECT_TIMEOUT_MS, maxBuffer: 4 * 1024 * 1024 },
    );
    return (stdout || '').trim();
  };

  let volumesRaw;
  try {
    volumesRaw = await fmt('{{json .Config.Volumes}}');
  } catch (err) {
    const detail = String(err.stderr || err.message || '').trim();
    // Docker's own wording for "that container does not exist". Both spellings
    // are in the wild depending on version and on whether the argument could
    // also have named an image or a network.
    if (/no such (object|container)/i.test(detail)) return { present: false };
    return { present: 'unknown', error: detail.split('\n')[0].slice(0, 300) };
  }

  let mountsRaw;
  try {
    mountsRaw = await fmt('{{json .Mounts}}');
  } catch (err) {
    const detail = String(err.stderr || err.message || '').trim();
    // The container answered a moment ago, so a failure here is not absence —
    // it is a partial read, and a partial read must not produce a clean bill of
    // health. Reported as unknown.
    return { present: 'unknown', error: detail.split('\n')[0].slice(0, 300) };
  }

  let imageVolumes;
  let bindDestinations;
  let mountDestinations;
  try {
    // `null` is what an image with no VOLUME produces, measured above. It is a
    // valid, meaningful answer — not a parse failure — so it maps to [].
    const v = JSON.parse(volumesRaw || 'null');
    imageVolumes = v && typeof v === 'object' ? Object.keys(v) : [];
    const m = JSON.parse(mountsRaw || 'null');
    bindDestinations = Array.isArray(m)
      ? m.filter((x) => x && x.Type === 'bind').map((x) => x.Destination)
      : [];
    // EVERY mount, not only the binds: an anonymous volume's mount point can
    // appear in `docker diff` too, when the image did not already contain that
    // directory. Used solely to subtract mount points from the diff.
    mountDestinations = Array.isArray(m) ? m.map((x) => x && x.Destination).filter(Boolean) : [];
  } catch (e) {
    return { present: 'unknown', error: `could not parse docker inspect output: ${e.message}` };
  }

  let diff;
  let diffError;
  try {
    const { stdout } = await execFileAsync(
      'docker', ['diff', name],
      { timeout: DIFF_TIMEOUT_MS, maxBuffer: DIFF_MAX_BUFFER },
    );
    diff = parseDockerDiff(stdout);
  } catch (err) {
    // Deliberately NOT fatal and deliberately NOT silent. A truncated read
    // (ERR_CHILD_PROCESS_STDIO_MAXBUFFER hands back a prefix of stdout), a
    // timeout kill, or a container that vanished between the inspect and the
    // diff would all otherwise parse as "few or no written paths" — which reads
    // as a clean bill of health for the exact container that was too big to
    // read. Carried through as diffError and surfaced as writable_layer_unknown.
    diffError = String(err.stderr || err.message || err).trim().split('\n')[0].slice(0, 300);
  }

  return { present: true, imageVolumes, bindDestinations, mountDestinations, diff, diffError };
}

/** Has anything for this app+env ever actually reached `live`? Used only to
 *  narrow an unreadable daemon: an app that has never had a live deployment has
 *  never had a container, so there is nothing for a redeploy to destroy. */
function everWentLive(db, appId, env) {
  try {
    return !!db.prepare(
      "SELECT 1 FROM deployments WHERE app_id = ? AND env = ? AND status = 'live' LIMIT 1"
    ).get(appId, env);
  } catch (_) {
    // A caller without a usable database is not a reason to declare safety.
    return true;
  }
}

/**
 * The verdict.
 *
 * @param {{db: object, app: object, env: string, inspect?: Function}} args
 * @returns {Promise<{
 *   at_risk: boolean, unknown: boolean, container: string, env: string, app: string,
 *   at_risk_paths: string[], persisted_paths: string[], always_persisted: string[],
 *   written_paths: string[], written_detail: {path: string, entries: number}[],
 *   writable_layer_unknown: boolean,
 *   reason: string, summary: string, acknowledge_with: string,
 * }>}
 *
 * TWO KINDS OF AT-RISK, kept apart on purpose. `at_risk_paths` is "your image
 * declares /config and nothing mounts it"; `written_paths` is "this app has
 * written 1,204 entries under /var/www/html/storage that no mount covers".
 * Different evidence, different sentence to an operator, and only partly the
 * same remedy — so a caller can render or refuse on either without having to
 * guess which one it is looking at.
 */
export async function assessRedeployRisk({ db, app, env, inspect = inspectContainerState }) {
  const container = containerNameFor(app.slug, env);
  const base = {
    app: app.slug,
    env,
    container,
    at_risk_paths: [],
    persisted_paths: [],
    written_paths: [],
    written_detail: [],
    writable_layer_unknown: false,
    // Always true, on every app, declared or not: <shared>/data is bind-mounted
    // at /data by every code path that creates a container.
    always_persisted: ['/data'],
    acknowledge_with: ACK_PARAM,
  };

  let state;
  try {
    state = await inspect(container);
  } catch (e) {
    state = { present: 'unknown', error: e?.message || String(e) };
  }

  if (state.present === false) {
    return {
      ...base,
      at_risk: false,
      unknown: false,
      reason: 'no-container',
      summary:
        `No container named ${container} exists, so this deploy creates one rather than replacing one. ` +
        'Nothing can be lost.',
    };
  }

  if (state.present === 'unknown') {
    if (!everWentLive(db, app.id, env)) {
      return {
        ...base,
        at_risk: false,
        unknown: false,
        reason: 'never-live',
        summary:
          `Docker could not be inspected (${state.error || 'no detail'}), but no deployment of ` +
          `${app.slug}/${env} has ever reached live, so no container has ever held state for it.`,
      };
    }
    return {
      ...base,
      at_risk: true,
      unknown: true,
      reason: 'inspect-failed',
      summary:
        `Could not read the state of ${container} (${state.error || 'no detail'}). ` +
        `${app.slug}/${env} HAS been live, so a container exists or recently did, and this deploy will ` +
        'destroy and recreate it. Which of its paths are persisted could not be determined, so this is ' +
        'reported as at-risk rather than as safe.',
    };
  }

  const { atRisk, persisted } = classifyVolumePaths(state);
  const { written, ignored, considered, truncated } = classifyWrittenPaths({
    diff: state.diff || [],
    mountDestinations: state.mountDestinations || state.bindDestinations || [],
  });
  const writableUnknown = !!state.diffError;
  const writtenPaths = written.map((w) => w.path);
  const kept = ['/data', ...persisted];

  if (atRisk.length === 0 && writtenPaths.length === 0 && !writableUnknown) {
    return {
      ...base,
      at_risk: false,
      unknown: false,
      persisted_paths: persisted,
      reason: 'all-declared',
      summary:
        (persisted.length
          ? `Every path ${container} declares as a volume (${persisted.join(', ')}) is bind-mounted into this ` +
            "app's own directory, alongside /data. "
          : `${container} declares no volume paths beyond the /data mount every app gets. `) +
        `Its writable layer holds nothing outside the mounts either — ${considered} path` +
        `${considered === 1 ? '' : 's'} in \`docker diff\`, all of them mounted or scratch ` +
        '(/tmp, /run, /var/log and the like). A redeploy has no state to lose.',
    };
  }

  // Sentence 1 — the declared-but-unmounted VOLUMEs. Unchanged wording: this is
  // the half that shipped first and the half the REST and MCP messages quote.
  const volumeSentence = atRisk.length
    ? `These paths hold state that will NOT come back: ${atRisk.join(', ')} — the image declares them as ` +
      'volumes, AppCrane is not mounting them, so Docker is holding them in anonymous volumes that the ' +
      'replacement container will not be given. '
    : '';

  // Sentence 2 — the writable layer. A different claim with different evidence,
  // so it gets its own sentence and its own numbers rather than being folded
  // into the list above.
  const writtenSentence = writtenPaths.length
    ? `This app has ${atRisk.length ? 'also ' : ''}WRITTEN to paths its image never declared as volumes and ` +
      'nothing is mounting, so ' +
      'they live only in the container\'s writable layer and die with it: ' +
      written.map((w) => `${w.path} (${w.entries} written path${w.entries === 1 ? '' : 's'})`).join(', ') +
      (truncated ? `, and ${truncated} more director${truncated === 1 ? 'y' : 'ies'}` : '') +
      `. Measured with \`docker diff ${container}\`, which reports the container's writable layer against ` +
      `its image and excludes everything a mount covers${ignored ? `; ${ignored} further entries were mounted or scratch` : ''}. `
    : '';

  const unknownSentence = writableUnknown
    ? `Its writable layer could NOT be read (${state.diffError}), so whether this app has written state ` +
      'outside its mounts is unknown — reported as at-risk rather than as safe. '
    : '';

  const remedies = [];
  if (atRisk.length) remedies.push(atRisk.join(', '));
  if (writtenPaths.length) remedies.push(writtenPaths.join(', '));

  const reason =
    atRisk.length && (writtenPaths.length || writableUnknown) ? 'undeclared-volumes+writable-layer'
      : atRisk.length ? 'undeclared-volumes'
        : writtenPaths.length ? 'writable-layer'
          : 'writable-layer-unknown';

  return {
    ...base,
    at_risk: true,
    unknown: false,
    at_risk_paths: atRisk,
    persisted_paths: persisted,
    written_paths: writtenPaths,
    written_detail: written,
    writable_layer_unknown: writableUnknown,
    reason,
    summary:
      `Redeploying ${app.slug}/${env} destroys and recreates ${container}. ` +
      volumeSentence + writtenSentence + unknownSentence +
      `These paths DO survive: ${kept.join(', ')}. ` +
      (remedies.length
        ? `To keep ${remedies.join(' and ')} across future deploys, add them to the app's volume_paths first, ` +
          'then deploy — note that doing so does not rescue what is in them now.'
        : "Add whatever this app persists to the app's volume_paths before deploying again."),
  };
}

export default {
  assessRedeployRisk, classifyVolumePaths, classifyWrittenPaths, parseDockerDiff,
  inspectContainerState, containerNameFor, covers, ACK_PARAM,
  EPHEMERAL_ROOTS, EPHEMERAL_SEGMENTS,
};
