// How a declared volume's host directory is prepared and mounted without the
// HOST ever walking a path inside the app-writable tree (security review of
// v2.107.3, "toctou-symlink").
//
// <shared>/volumes/<container path> is written by the app: with '/var'
// declared, the container owns <shared>/volumes/var and everything below it,
// including whether <shared>/volumes/var/lib is a directory or a link to /etc.
// v2.107.3 refused a link found by lstat, but the check and the mkdir -p, the
// chown -R, the seed copy and the bind mount that followed were separate steps,
// and a link swapped in between was followed by every one of them. Measured
// against Docker 29.6.1 before this change: a container toggling that component
// between a directory and a link got an app container's /var/lib/odoo bound to
// a host-only directory outside the app's tree.
//
// So nothing below <shared>/volumes is touched by a host path walk any more:
//
//   * mkdir / seed / chown run in a throwaway helper container that mounts ONLY
//     <shared>/volumes. Every path is resolved by the kernel inside the
//     helper's mount namespace, so a planted link can only lead into the
//     helper's own disposable filesystem, never to the host.
//   * the app container gets each declared path through ONE named volume
//     bound to <shared>/volumes, with `volume-subpath`. The daemon opens the
//     subpath itself and refuses one that resolves outside the volume
//     (measured: "path concatenation escapes the base directory"), instead of
//     handing a host path string to mount(2). Every component of the volume's
//     device path is one AppCrane created and no container mounts.
//
// Node has no openat(2), so an O_NOFOLLOW walk per component from the host
// (the other option considered) would still re-resolve the full path string on
// every call; it cannot be made race-free here, and a helper can.

import { join, resolve } from 'path';
import { Transform } from 'stream';
import { VOLUME_SUBDIR, validateVolumePaths } from './containerRuntimeSpec.js';
import { OOM_APP_FLAG } from './oomPriority.js';

/** Where the helper sees <shared>/volumes. Outside any path an app can declare
 *  that matters, and checked against the declared ones anyway. */
export const HELPER_MOUNT = '/.appcrane-volumes';

/** The helper's image: busybox 1.36, pinned to the multi-arch index digest so
 *  every pull is the same bytes. NOT the app's image: a distroless or scratch
 *  image has no sh, mkdir, tar or chown, and the app's image is the app
 *  author's code, which has no business running as root against its tree.
 *  The repo had no pinned utility image to reuse (runRootHelper takes the
 *  caller's image), so this is the one. */
export const HELPER_IMAGE = 'busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662';

/** Exactly what chown -R and tar -x as root need, and nothing else: CHOWN to
 *  set owners, DAC_OVERRIDE to read and write trees the app owns, FOWNER to
 *  set modes and times on files root does not own. */
export const HELPER_CAPS = ['CHOWN', 'DAC_OVERRIDE', 'FOWNER'];

/** Label on the helper, so a leaked one is recognisable (same as docker.js). */
export const HELPER_LABEL = 'appcrane-roothelper=true';

// A constant: the mode, declared paths and owner arrive as positional
// parameters ("$@"), never spliced into the script text, so no stored value
// can become shell syntax. One status line per path on stdout.
//
//   prep    mkdir -p each path; report it empty or occupied.
//   extract untar stdin into ONE path, only if it is still empty (the
//           emptiness gate volumeSeeder.js documents: content is the app's
//           live state and is never written to). -o: owners come from the
//           chown below, not the archive. A failed extract puts the directory
//           back to empty so the next deploy retries.
//   clear   put one path back to empty (a seed whose SOURCE failed mid-stream).
//   chown   chown -R each path.
export const HELPER_SCRIPT = [
  'mode="$1"; shift',
  `V=${HELPER_MOUNT}`,
  'case "$mode" in',
  'prep) for p in "$@"; do',
  '    mkdir -p "$V$p" || { echo "error mkdir $p"; exit 3; }',
  '    if [ -n "$(ls -A "$V$p")" ]; then echo "occupied $p"; else echo "empty $p"; fi',
  '  done ;;',
  'extract) p="$1"; d="$V$p"',
  '  if [ ! -d "$d" ] || [ -n "$(ls -A "$d")" ]; then cat >/dev/null; echo "occupied $p"; exit 0; fi',
  '  if tar -x -o -f - -C "$d"; then',
  '    if [ -n "$(ls -A "$d")" ]; then echo "seeded $p"; else echo "absent $p"; fi',
  '  else rm -rf "$d"; mkdir -p "$d"; echo "error seed $p"; exit 4; fi ;;',
  'clear) rm -rf "$V$1"; mkdir -p "$V$1"; echo "cleared $1" ;;',
  'chown) owner="$1"; shift',
  '  for p in "$@"; do',
  '    if chown -R "$owner" "$V$p"; then echo "chown-ok $p"; else echo "chown-failed $p"; fi',
  '  done ;;',
  '*) exit 2 ;;',
  'esac',
].join('\n');

const isUnder = (a, b) => a === b || a.startsWith(`${b}/`);

/** <shared>/volumes for a declared mount (one resolveVolumeMounts produced). */
export function volumesRootOf(mount) {
  if (typeof mount?.base !== 'string' || !mount.base) {
    throw new Error(`volume ${mount?.container} has no shared-tree base; only declared volumes are prepared here`);
  }
  return resolve(join(mount.base, VOLUME_SUBDIR));
}

/** The mount's path relative to <shared>/volumes, e.g. 'var/lib/odoo'. */
export function subpathOf(mount) {
  const root = volumesRootOf(mount);
  const host = resolve(mount.host);
  if (!host.startsWith(`${root}/`)) throw new Error(`Security: volume host path ${host} is outside ${root}`);
  return host.slice(root.length + 1);
}

/** The one root every declared mount of a start shares, or throws. */
export function sharedVolumesRoot(mounts) {
  const roots = [...new Set(mounts.map(volumesRootOf))];
  if (roots.length !== 1) throw new Error(`declared volumes must share one volumes root, got ${roots.join(', ')}`);
  return roots[0];
}

/**
 * The helper's docker argv. Mounts nothing but `root`, has no network, cannot
 * gain privileges and holds only HELPER_CAPS. `stdin` adds -i, for `extract`.
 */
export function volumeHelperArgs({ root, mode, paths, owner = null, stdin = false, image = HELPER_IMAGE }) {
  if (typeof image !== 'string' || !image) throw new Error('the volume helper needs an image');
  if (typeof root !== 'string' || !root.startsWith('/') || root.includes(':')) {
    throw new Error(`the volumes root must be an absolute path without ':', got ${JSON.stringify(root)}`);
  }
  if (!['prep', 'extract', 'clear', 'chown'].includes(mode)) throw new Error(`unknown volume helper mode ${mode}`);
  if ((mode === 'extract' || mode === 'clear') && paths.length !== 1) throw new Error(`${mode} takes exactly one path`);
  if (mode === 'chown' && !/^\d+:\d+$/.test(String(owner))) throw new Error(`owner must be uid:gid, got ${JSON.stringify(owner)}`);
  const valid = validateVolumePaths(paths);
  if (valid.length !== paths.length) throw new Error('volume paths must be distinct, normalised container paths');
  for (const p of valid) {
    if (isUnder(p, HELPER_MOUNT) || isUnder(HELPER_MOUNT, p)) {
      throw new Error(`volume path ${p} overlaps the helper's own mount point ${HELPER_MOUNT}`);
    }
  }
  return [
    'run', '--rm',
    OOM_APP_FLAG,
    ...(stdin ? ['-i'] : []),
    '--pull', 'never',
    '--user', '0:0',
    '--network', 'none',
    '--label', HELPER_LABEL,
    '--security-opt', 'no-new-privileges',
    '--cap-drop', 'ALL',
    ...HELPER_CAPS.flatMap((c) => ['--cap-add', c]),
    '--pids-limit', '64',
    '-v', `${root}:${HELPER_MOUNT}`,
    '--entrypoint', 'sh',
    image,
    '-c', HELPER_SCRIPT, 'appcrane-volume-helper', mode, ...(mode === 'chown' ? [String(owner)] : []), ...valid,
  ];
}

const STATUS_LINE = /^(occupied|empty|seeded|absent|cleared|chown-ok|chown-failed) (\/.*)$/;

/** Map the helper's stdout back onto the paths it was given. A path with no
 *  line is reported as unreported rather than guessed at. */
export function parseVolumeHelperOutput(stdout, paths) {
  const byPath = new Map();
  for (const line of String(stdout || '').split('\n')) {
    const m = STATUS_LINE.exec(line.trim());
    if (m && paths.includes(m[2])) byPath.set(m[2], m[1]);
  }
  return paths.map((p) => ({ path: p, state: byPath.get(p) || 'unreported' }));
}

// --------------------------------------------------------------------------
// The seed stream: `docker cp <created>:<path>/. -` -> guard -> helper tar -x
// --------------------------------------------------------------------------

// The archive comes out of the APP's image, so it is the app author's. Inside
// the helper a bad entry can only reach the helper's own filesystem or this
// app's own volumes, but an entry that climbs out of the directory being
// seeded could still write into the app's OTHER volumes, and busybox tar's
// answer to '../x' is to strip it and carry on (measured) rather than refuse.
// So the stream is checked here, header by header, BEFORE a byte of an entry
// reaches tar, and the first bad one aborts the whole seed:
//   * a name (ustar prefix+name, GNU 'L', or pax path=) that is absolute or
//     has a '..' segment;
//   * a hard link whose target is either;
//   * any entry BELOW a symlink the same archive created ('l -> /etc' then
//     'l/passwd' is the classic write-through-a-link);
//   * device nodes, and any type this does not recognise.
// Absolute symlinks themselves are allowed: images ship them, and a link is
// only dangerous when something is written through it, which the third rule
// refuses.

const BLOCK = 512;
const cstr = (b) => { const i = b.indexOf(0); return (i === -1 ? b : b.subarray(0, i)).toString('utf8'); };
function tarSize(h) {
  const f = h.subarray(124, 136);
  if (f[0] & 0x80) {
    let n = 0;
    for (let i = 1; i < 12; i++) n = n * 256 + f[i];
    return n;
  }
  const t = cstr(f).trim();
  return t ? parseInt(t, 8) : 0;
}
function paxRecords(buf) {
  const out = {};
  let rest = buf.toString('utf8');
  while (rest.length) {
    const m = /^(\d+) ([^=]+)=/.exec(rest);
    if (!m) break;
    const len = Number(m[1]);
    out[m[2]] = rest.slice(m[0].length, len - 1);
    rest = rest.slice(len);
  }
  return out;
}
function cleanTarPath(p, what) {
  if (p.startsWith('/')) throw new Error(`tar entry ${what} ${JSON.stringify(p)} is absolute`);
  const segs = p.split('/').filter((s) => s && s !== '.');
  if (segs.includes('..')) throw new Error(`tar entry ${what} ${JSON.stringify(p)} climbs out with '..'`);
  return segs.join('/');
}
const ENTRY_TYPES = new Set(['0', '\0', '1', '2', '5', '6', '7']);

export function createTarGuard() {
  let buf = Buffer.alloc(0);
  let remaining = 0;       // bytes of the current entry's data (+ padding) still to pass
  let collecting = null;   // { type, size, chunks } for x / L / K / g metadata
  let override = {};       // path / linkpath carried to the next real entry
  const links = new Set();
  let entries = 0;

  const header = (h) => {
    if (h.every((b) => b === 0)) return;           // end-of-archive block
    const type = String.fromCharCode(h[156]);
    const size = tarSize(h);
    if (type === 'x' || type === 'g' || type === 'L' || type === 'K') {
      collecting = { type, size, chunks: [] };
      return;
    }
    if (!ENTRY_TYPES.has(type)) throw new Error(`tar entry of type ${JSON.stringify(type)} is not allowed in a seed`);
    const isUstar = h.subarray(257, 262).toString('latin1') === 'ustar';
    const prefix = isUstar ? cstr(h.subarray(345, 500)) : '';
    const raw = override.path ?? (prefix ? `${prefix}/${cstr(h.subarray(0, 100))}` : cstr(h.subarray(0, 100)));
    const link = override.linkpath ?? cstr(h.subarray(157, 257));
    override = {};
    const name = cleanTarPath(raw, 'name');
    const segs = name ? name.split('/') : [];
    for (let i = 1; i < segs.length; i++) {
      if (links.has(segs.slice(0, i).join('/'))) {
        throw new Error(`tar entry ${JSON.stringify(raw)} would be written through a symlink the archive created`);
      }
    }
    if (type === '1') cleanTarPath(link, 'hard link target');
    if (type === '2') links.add(name); else links.delete(name);
    entries++;
  };

  const finishMeta = () => {
    const data = Buffer.concat(collecting.chunks).subarray(0, collecting.size);
    if (collecting.type === 'x') Object.assign(override, paxRecords(data));
    else if (collecting.type === 'L') override.path = cstr(data);
    else if (collecting.type === 'K') override.linkpath = cstr(data);
    else if (collecting.type === 'g') {
      const g = paxRecords(data);
      if ('path' in g || 'linkpath' in g) throw new Error('a global pax header may not set path or linkpath');
    }
    collecting = null;
  };

  const guard = new Transform({
    transform(chunk, _enc, cb) {
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      const out = [];
      try {
        for (;;) {
          if (remaining > 0) {
            if (!buf.length) break;
            const n = Math.min(remaining, buf.length);
            const part = buf.subarray(0, n);
            if (collecting) collecting.chunks.push(part);
            out.push(part);
            buf = buf.subarray(n);
            remaining -= n;
            if (remaining === 0 && collecting) finishMeta();
            continue;
          }
          if (buf.length < BLOCK) break;
          const h = buf.subarray(0, BLOCK);
          header(h);                               // throws before the header is passed on
          out.push(h);
          buf = buf.subarray(BLOCK);
          const typ = String.fromCharCode(h[156]);
          const size = h.every((b) => b === 0) ? 0 : tarSize(h);
          // Hard links, symlinks and directories carry no data whatever size says.
          remaining = ['1', '2', '5'].includes(typ) ? 0 : Math.ceil(size / BLOCK) * BLOCK;
          if (collecting && remaining === 0) finishMeta();
        }
      } catch (e) {
        return cb(e);
      }
      for (const b of out) this.push(b);
      return cb();
    },
    // A stream that stops mid-block or mid-entry is a broken source, not a
    // short seed: fail it so the partial extract is cleared.
    flush(cb) { cb(buf.length || remaining ? new Error('the seed archive is truncated') : null); },
  });
  guard.entryCount = () => entries;
  return guard;
}

/** The named volume a start binds <shared>/volumes through. Per app and env,
 *  so two environments never share one. Slugs are [a-z0-9-]. */
export function volumesVolumeName(slug, env) {
  const name = `appcrane-vols-${slug}-${env}`;
  if (!/^[a-z0-9][a-z0-9_.-]*$/.test(name)) throw new Error(`invalid volume name ${name}`);
  return name;
}

// --mount is a CSV record: a field holding a comma or a quote is quoted, with
// quotes doubled, the way the daemon's encoding/csv reader expects. Container
// paths may contain commas (only ':' is refused where they are stored).
const csvField = (s) => (/[",]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);

/** One declared path, through the volume, with the daemon resolving the
 *  subpath. volume-nocopy: AppCrane seeds the directory itself (the helper),
 *  and the daemon's copy-up would write image content into a live mount. */
export function volumeSubpathMountArg({ volume, subpath, container }) {
  if (!subpath || subpath.split('/').some((s) => !s || s === '.' || s === '..')) {
    throw new Error(`refusing volume subpath ${JSON.stringify(subpath)}`);
  }
  return [
    'type=volume',
    `src=${volume}`,
    csvField(`dst=${container}`),
    csvField(`volume-subpath=${subpath}`),
    'volume-nocopy=true',
  ].join(',');
}

/** volume-subpath arrived in Engine 26.0, API 1.45. */
export function apiSupportsVolumeSubpath(apiVersion) {
  const m = /^(\d+)\.(\d+)$/.exec(String(apiVersion || '').trim());
  if (!m) return false;
  const [maj, min] = [Number(m[1]), Number(m[2])];
  return maj > 1 || (maj === 1 && min >= 45);
}
