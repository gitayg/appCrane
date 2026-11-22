// The served bundle of a built image, for the release check's served_secrets
// step when nothing else shows what a production-only release serves (no
// sandbox runs the commit, and the built output is not committed).
//
// The image is never run: `docker create --pull never` plus `docker cp <dir> -`
// from the never-started container, the same way the pre-flight entry check
// reads an image. The tar stream is unpacked by this file, never by Docker or
// tar, so only regular text files (and .env files) with a plain relative name
// reach the temp dir: no link, device, absolute name or `..` is written. The
// temp dir is scanned with scanBuiltDir, the matcher the committed-output path
// uses, and removed before this returns.
//
// Where the output lives in an image (measured in dockerfileGen.js and
// nixpacks.js): the generated Node Dockerfile copies the repo to /app and runs
// the build there (or in /app/<fe.workdir>), and Nixpacks builds in /app; a
// hand-written static Dockerfile usually serves /usr/share/nginx/html.

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname, extname, posix } from 'path';
import { randomBytes } from 'crypto';
import { docker, tarWalker, PREFLIGHT_LABEL } from './preflightCheck.js';
import { BUILT_DIRS, TEXT_EXT, scanBuiltDir } from './servedOutputScan.js';
import log from '../utils/logger.js';

const DOCKER_TIMEOUT_MS = 15_000;
const DEADLINE_MS = 40_000;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_KEPT_BYTES = 64 * 1024 * 1024;
const MAX_STREAM_BYTES = 256 * 1024 * 1024;
const SAFE_REL = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;

const cleanRel = (p) => {
  const s = String(p || '').replace(/^\.?\/+/, '').replace(/\/+$/, '');
  return s && SAFE_REL.test(s) && !s.split('/').includes('..') ? s : null;
};

/** The in-image directories that can hold served output, most specific first. */
export function imageOutputDirs(manifest = null) {
  const dirs = [];
  const fe = cleanRel(manifest?.fe?.workdir);
  const dist = cleanRel(manifest?.fe?.dist);
  if (fe && dist) dirs.push(`/app/${fe}/${dist}`);
  if (fe) for (const d of BUILT_DIRS) dirs.push(`/app/${fe}/${d}`);
  if (!fe && dist) dirs.push(`/app/${dist}`);
  for (const d of BUILT_DIRS) dirs.push(`/app/${d}`);
  dirs.push('/usr/share/nginx/html');
  return [...new Set(dirs)];
}

function wanted(name) {
  const base = posix.basename(name);
  return /^\.env(?:\..+)?$/.test(base) || TEXT_EXT.has(extname(base).toLowerCase());
}

/**
 * Copy the served output out of `image` and scan it.
 * @returns {Promise<{ ok: boolean, error: string|null, dirs: string[], scan: object|null, truncated: boolean }>}
 *   dirs are the in-image directories found; scan is scanBuiltDir's result
 *   over them (null when none was found or the image could not be read).
 */
export async function scanImageServedOutput({ image, manifest = null, timeoutMs = DOCKER_TIMEOUT_MS, deadlineMs = DEADLINE_MS, runDocker = docker }) {
  const name = `appcrane-preflight-${randomBytes(9).toString('hex')}`;
  const work = mkdtempSync(join(tmpdir(), 'appcrane-served-'));
  const deadline = Date.now() + deadlineMs;
  const out = { ok: false, error: null, dirs: [], scan: null, truncated: false };
  let kept = 0;
  let streamed = 0;
  try {
    const created = await runDocker(['create', '--pull', 'never', '--network', 'none', '--name', name, '--label', PREFLIGHT_LABEL, '--entrypoint', '/appcrane-preflight-never-started', image], { timeoutMs });
    if (created !== 0) { out.error = `docker create exited ${created}`; return out; }

    for (const dir of imageOutputDirs(manifest)) {
      if (Date.now() > deadline || out.truncated) { out.truncated = true; break; }
      const into = join(work, `d${out.dirs.length}`);
      let files = 0;
      const walk = tarWalker((entry) => {
        if (!entry.regular || !entry.body) return;
        // `docker cp <dir> -` names every entry under the directory's own basename.
        const rel = cleanRel(entry.path)?.split('/').slice(1).join('/');
        if (!rel) return;
        const target = join(into, rel);
        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, entry.body);
        files++;
      }, {
        keepBodies: true,
        want: (path, size) => {
          if (!wanted(path)) return false;
          if (size > MAX_FILE_BYTES) { out.truncated = true; return false; }
          if (kept + size > MAX_KEPT_BYTES) { out.truncated = true; return false; }
          kept += size;
          return true;
        },
      });
      const code = await runDocker(['cp', `${name}:${dir}`, '-'], {
        timeoutMs: Math.max(1000, Math.min(timeoutMs, deadline - Date.now())),
        onData: (chunk, stop) => {
          streamed += chunk.length;
          if (streamed > MAX_STREAM_BYTES || Date.now() > deadline) { out.truncated = true; stop(); return; }
          walk(chunk);
        },
      });
      if (code === 0 && files) out.dirs.push(dir);
    }
    out.ok = true;
    if (out.dirs.length) {
      const roots = out.dirs.map((_, i) => join(work, `d${i}`));
      out.scan = scanBuiltDir(work, roots, { deadline: Math.max(deadline, Date.now() + 5000) });
      out.scan.scanned = out.scan.scanned.map((s) => ({ ...s, path: s.path.replace(/^d(\d+)\//, (_, i) => `${out.dirs[Number(i)]}/`) }));
      out.scan.findings = out.scan.findings.map((f) => ({ ...f, file: f.file.replace(/^d(\d+)\//, (_, i) => `${out.dirs[Number(i)]}/`) }));
      if (out.truncated) out.scan.truncated = true;
    }
    return out;
  } catch (e) {
    out.ok = false;
    out.error = e.message;
    return out;
  } finally {
    await runDocker(['rm', '-f', '-v', name], { timeoutMs: DOCKER_TIMEOUT_MS }).catch((e) => log.warn(`served-output scan: could not remove container ${name}: ${e.message}`));
    try { rmSync(work, { recursive: true, force: true }); } catch (e) { log.warn(`served-output scan: could not remove ${work}: ${e.message}`); }
  }
}
