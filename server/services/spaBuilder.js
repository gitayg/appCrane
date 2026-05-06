/**
 * SPA build automation for AppCrane's own admin app.
 *
 * Background: `studio-web/src/` (TS/React source) builds to `docs/admin-app/`
 * (the static bundle the server serves at /dashboard, /applications, etc.).
 * Pre-v2.2.7, the bundle was committed alongside source. If a developer
 * edited source but forgot to also commit a fresh build, every install
 * silently served a stale UI — the bug class v2.2.6 just shipped a
 * validator for in user apps (DIST_OUT_OF_SYNC), now applied to AppCrane
 * itself.
 *
 * This module:
 *   - getSpaSourceHash(repoDir)  — git commit hash of last change to studio-web/
 *   - getStampHash(repoDir)      — hash recorded the last time the SPA was built
 *   - rebuildSpa(repoDir, opts)  — npm install + npm run build:admin
 *   - ensureSpaBuilt(repoDir)    — rebuild if stamp != source hash; no-op otherwise
 *
 * Used at server boot (catch operators who pulled new source but didn't
 * rebuild) and at the end of POST /api/self-update (catch the same in
 * the in-place upgrade path).
 */

import { execFileSync } from 'child_process';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import log from '../utils/logger.js';

const SPA_SOURCE_DIR = 'studio-web';
const SPA_OUT_DIR = 'docs/admin-app';
const STAMP_FILE = '.built-from';

/**
 * Most recent commit hash that touched studio-web/. Returns null if git
 * fails (shallow clone, dubious-ownership, missing repo metadata) — caller
 * treats that as "always rebuild" since we can't verify staleness.
 */
function getSpaSourceHash(repoDir) {
  try {
    return execFileSync(
      'git',
      ['-C', repoDir, 'log', '-1', '--format=%H', '--', SPA_SOURCE_DIR],
      { stdio: 'pipe', timeout: 5000 }
    )
      .toString()
      .trim();
  } catch (e) {
    log.warn(`SPA source-hash lookup failed: ${e.message}`);
    return null;
  }
}

function getStampHash(repoDir) {
  const stampPath = join(repoDir, SPA_OUT_DIR, STAMP_FILE);
  try {
    return readFileSync(stampPath, 'utf8').trim();
  } catch (_) {
    return null;
  }
}

function writeStamp(repoDir, hash) {
  const stampPath = join(repoDir, SPA_OUT_DIR, STAMP_FILE);
  try {
    writeFileSync(stampPath, hash);
  } catch (e) {
    log.warn(`SPA build stamp write failed (${stampPath}): ${e.message}`);
  }
}

/**
 * Force-rebuild the admin SPA. Runs `npm install` then `npm run build:admin`
 * inside `studio-web/`. Writes the stamp file on success.
 *
 * Returns `{ success: true, hash, durationMs }` or
 * `{ success: false, error, durationMs }`.
 *
 * `onLog` is invoked for each major step so the caller can stream progress
 * into the deploy log / self-update log.
 */
export function rebuildSpa(repoDir, { onLog } = {}) {
  const studioDir = join(repoDir, SPA_SOURCE_DIR);
  const start = Date.now();
  const emit = (msg) => (onLog ? onLog(msg) : log.info(msg));

  if (!existsSync(studioDir)) {
    return {
      success: false,
      error: `${SPA_SOURCE_DIR} not found at ${studioDir} — cannot rebuild SPA`,
      durationMs: 0,
    };
  }

  try {
    emit(`SPA rebuild: npm install in ${SPA_SOURCE_DIR}/ ...`);
    execFileSync(
      'npm',
      ['install', '--prefer-offline', '--no-audit', '--no-fund'],
      { cwd: studioDir, stdio: 'pipe', timeout: 240000 }
    );

    emit('SPA rebuild: npm run build:admin ...');
    execFileSync('npm', ['run', 'build:admin'], {
      cwd: studioDir,
      stdio: 'pipe',
      timeout: 240000,
    });

    const hash = getSpaSourceHash(repoDir) || 'unknown';
    writeStamp(repoDir, hash);
    const durationMs = Date.now() - start;
    emit(`SPA rebuild complete in ${durationMs}ms (hash=${hash.slice(0, 7)})`);
    return { success: true, hash, durationMs };
  } catch (e) {
    const detail = e.stderr?.toString?.().trim() || e.stdout?.toString?.().trim() || e.message;
    return { success: false, error: detail, durationMs: Date.now() - start };
  }
}

/**
 * Skip-if-unchanged wrapper. Compares stamp file with current source hash
 * and triggers `rebuildSpa` only when they differ (or the stamp is missing).
 *
 * Force a rebuild via `force: true` (used by /api/self-update on operator
 * request, or by an admin manually triggering "rebuild SPA now").
 *
 * Returns `{ rebuilt, reason, ...rebuildSpa-result-fields }`.
 */
export function ensureSpaBuilt(repoDir, { onLog, force = false } = {}) {
  const sourceHash = getSpaSourceHash(repoDir);
  const stampHash = getStampHash(repoDir);

  if (!force && sourceHash && stampHash && sourceHash === stampHash) {
    return { rebuilt: false, reason: 'up-to-date', hash: sourceHash };
  }

  const reason = force
    ? 'forced'
    : !stampHash
      ? 'no stamp file (first build or pre-v2.2.7 install)'
      : sourceHash
        ? `source changed (stamp=${stampHash.slice(0, 7)}, source=${sourceHash.slice(0, 7)})`
        : 'cannot determine source hash';

  const result = rebuildSpa(repoDir, { onLog });
  return { rebuilt: result.success, reason, ...result };
}
