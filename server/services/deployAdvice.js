// Deploy advice: tells the agent driving AppCrane, inside MCP tool results,
// when the WAY it deploys is costing time or breaking builds, so it can change
// its own behaviour. Real case: a 13-file release pushed one file per call, so
// every push started a full sandbox deploy, builds in between failed on
// missing exports (half the change had landed), and a two-minute release took
// twenty. The agent also believed batching needed an API key; it does not.
//
// Each item: { rule, severity: 'info'|'warn', message, fix, evidence }.
// Nothing here throws: advice is a hint, and a hint must never fail a push or
// a deploy. Callers wrap it anyway.

import { lstatSync } from 'fs';
import { join } from 'path';

export const ADVICE_WINDOW_MS = 10 * 60 * 1000;
export const SMALL_PUSH_MAX_FILES = 2;
export const SMALL_PUSH_COUNT = 3;
export const LARGE_INLINE_BYTES = 64 * 1024;
const RING_CAP = 50;
const MAX_TRACKED_APPS = 2000;

// slug -> [{ files, at, commit }], oldest first. In memory on purpose: it only
// has to remember the last ten minutes, and a restart forgetting them costs
// one missed hint. R2 also reads the managed-push delivery log, which survives.
const rings = new Map();

export function recordPush(slug, { files = 0, at = Date.now(), commit = null } = {}) {
  try {
    if (!slug) return;
    let ring = rings.get(slug);
    if (!ring) {
      if (rings.size >= MAX_TRACKED_APPS) rings.delete(rings.keys().next().value);
      ring = [];
      rings.set(slug, ring);
    }
    ring.push({ files: Number(files) || 0, at: Number(at) || Date.now(), commit: commit || null });
    if (ring.length > RING_CAP) ring.splice(0, ring.length - RING_CAP);
  } catch (_) { /* advice only */ }
}

export function recentPushes(slug) {
  return (rings.get(slug) || []).slice();
}

// Test seam.
export function _resetDeployAdvice() {
  rings.clear();
}

/** SQLite 'YYYY-MM-DD HH:MM:SS' (UTC) or ISO -> epoch ms, or null. */
export function toMs(t) {
  if (t == null) return null;
  if (typeof t === 'number') return t;
  const s = String(t);
  const iso = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(s) ? `${s.replace(' ', 'T')}Z` : s;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}

const minutes = (ms) => Math.round(ms / 60000);

const BATCH_FIX = 'Push every file of a change in ONE appcrane_push_to_managed_app call: it takes up to 200 files (writes plus '
  + 'deletions) as a single commit and starts a single deploy. No API key is needed for that; for a file too large to '
  + 'inline, use appcrane_managed_push_chunk + appcrane_managed_assemble, also over MCP alone.';

/** R1: >= 3 small (<= 2 file) pushes to one app inside the window ending now. */
export function singleFilePushAdvice(slug, { now = Date.now(), pushes = null } = {}) {
  try {
    const list = (pushes || recentPushes(slug))
      .filter((p) => p.at <= now && now - p.at <= ADVICE_WINDOW_MS && p.files <= SMALL_PUSH_MAX_FILES);
    if (list.length < SMALL_PUSH_COUNT) return null;
    const span = list[list.length - 1].at - list[0].at;
    return {
      rule: 'single-file-pushes',
      severity: 'warn',
      message: `${list.length} pushes to '${slug}' in the last ${minutes(ADVICE_WINDOW_MS)} minutes each carried `
        + `${SMALL_PUSH_MAX_FILES} files or fewer. Every push is its own commit and can start its own deploy, so a change `
        + 'split across pushes deploys again and again, and the builds in between run on half of it.',
      fix: BATCH_FIX,
      evidence: {
        pushes: list.length,
        window_minutes: minutes(ADVICE_WINDOW_MS),
        span_seconds: Math.round(span / 1000),
        files_per_push: list.map((p) => p.files),
      },
    };
  } catch (_) { return null; }
}

// What a build says when a module or an export it imports is not there yet.
export const UNRESOLVED_IMPORT_PATTERNS = [
  /MISSING_EXPORT/,
  /is not exported by/i,
  /does not provide an export named/i,
  /Could not resolve/i,
  /Cannot find module/i,
  /Module not found/i,
];

export function unresolvedImportLine(log) {
  const lines = String(log || '').split('\n');
  for (const line of lines) {
    if (UNRESOLVED_IMPORT_PATTERNS.some((re) => re.test(line))) return line.trim().slice(0, 300);
  }
  return null;
}

const sameCommit = (a, b) => {
  if (!a || !b) return false;
  const x = String(a).toLowerCase();
  const y = String(b).toLowerCase();
  const n = Math.min(x.length, y.length);
  return n >= 7 && x.slice(0, n) === y.slice(0, n);
};

/**
 * R2: a FAILED deployment whose log reads like an unresolved import, with
 * another push to the same app inside the window around its start. `pushes`
 * is [{ at, commit }]; a push of the deployment's own commit does not count.
 */
export function halfPushedBuildAdvice(slug, deployment, pushes = []) {
  try {
    if (!deployment || deployment.status !== 'failed') return null;
    const hit = unresolvedImportLine(deployment.log);
    if (!hit) return null;
    const started = toMs(deployment.started_at);
    if (started == null) return null;
    const near = pushes.filter((p) => p && p.at != null
      && Math.abs(p.at - started) <= ADVICE_WINDOW_MS
      && !sameCommit(p.commit, deployment.commit_hash));
    if (!near.length) return null;
    return {
      rule: 'half-pushed-build',
      severity: 'warn',
      message: `Deployment ${deployment.id} of '${slug}' failed on an unresolved import or export while other pushes `
        + `to the app landed within ${minutes(ADVICE_WINDOW_MS)} minutes of its start. The build most likely ran on a `
        + 'partly pushed change: the file that provides the import was in a later push.',
      fix: 'The build ran on a partly pushed change. ' + BATCH_FIX,
      evidence: {
        deployment_id: deployment.id,
        log_line: hit,
        other_pushes: near.length,
        window_minutes: minutes(ADVICE_WINDOW_MS),
      },
    };
  } catch (_) { return null; }
}

/** R3: any single inline file over 64 KB decoded. `files` is [{ path, bytes }]. */
export function largeInlineAdvice(files = []) {
  try {
    const big = files.filter((f) => f && f.bytes > LARGE_INLINE_BYTES);
    if (!big.length) return null;
    return {
      rule: 'large-inline-file',
      severity: 'info',
      message: `${big.length} file(s) in this push were sent inline at over ${LARGE_INLINE_BYTES / 1024} KB. `
        + 'Large inline content is where truncation comes from: a file cut short still commits, and the build fails later.',
      fix: 'For a file this size use appcrane_managed_push_chunk (parts of about 48 KB) + appcrane_managed_assemble with '
        + 'sha256, over MCP alone; or upload it to POST /api/files/staged and push it as { path, staged_token }.',
      evidence: { files: big.map((f) => ({ path: f.path, bytes: f.bytes })), threshold_bytes: LARGE_INLINE_BYTES },
    };
  } catch (_) { return null; }
}

/**
 * Folders on the way to <root>/<rel> that are missing now, read with lstat so
 * nothing the app planted is followed. Measured BEFORE a copy writes. Stops at
 * a link or a non-folder (the copy resolves those itself).
 */
export function missingDataDirs(root, rel) {
  try {
    const segs = String(rel).split('/').filter(Boolean).slice(0, -1);
    let cur = root;
    for (let i = 0; i < segs.length; i++) {
      cur = join(cur, segs[i]);
      let st = null;
      try { st = lstatSync(cur); } catch (e) { if (e.code !== 'ENOENT') return []; }
      if (!st) return segs.slice(i).map((_, k) => segs.slice(0, i + k + 1).join('/'));
      if (!st.isDirectory()) return [];
    }
    return [];
  } catch (_) { return []; }
}

/** R4: appcrane_cp created a /data folder that did not exist before. */
export function uploadCreatedDirAdvice(rel, createdDirs = []) {
  try {
    if (!createdDirs.length) return null;
    const top = createdDirs[0];
    return {
      rule: 'upload-created-state-dir',
      severity: 'info',
      message: `This copy created /data/${top}, which did not exist before. An app that only works once a folder has `
        + 'been uploaded breaks on a fresh environment or after a restore.',
      fix: `Create state folders in the app's own startup code (mkdir -p /data/${top}, or fs.mkdirSync(path, { recursive: true })) `
        + 'so a new environment starts without a manual upload.',
      evidence: { path: `/data/${rel}`, created_dirs: createdDirs.map((d) => `/data/${d}`) },
    };
  } catch (_) { return null; }
}

/** Drop nulls; one item per rule (first wins). Returns [] when there is none. */
export function dedupeAdvice(items = []) {
  const seen = new Set();
  const out = [];
  for (const it of items) {
    if (!it || !it.rule || seen.has(it.rule)) continue;
    seen.add(it.rule);
    out.push(it);
  }
  return out;
}

/** `{ advice }` when there is any, else `{}` — for spreading into a response. */
export function adviceField(items) {
  const list = dedupeAdvice(items);
  return list.length ? { advice: list } : {};
}

export const PERSISTED_RULES = new Set(['single-file-pushes', 'half-pushed-build']);

export const adviceMarker = (rule) => `<!-- appcrane-advice:${rule} -->`;

/**
 * The agent context with a one-time note for `item` appended, or null when the
 * rule is not persisted or its marker is already there (written once per app,
 * ever: deleting the marker is how an operator asks for it again).
 */
export function withAdviceNote(existing, item, { now = new Date() } = {}) {
  if (!item || !PERSISTED_RULES.has(item.rule)) return null;
  const text = String(existing || '');
  const marker = adviceMarker(item.rule);
  if (text.includes(marker)) return null;
  const stamp = now.toISOString().replace('T', ' ').slice(0, 16);
  const block = `${text && !text.endsWith('\n') ? '\n' : ''}\n## AppCrane deploy advice — ${stamp} (AppCrane)\n\n${marker}\n`
    + `${item.fix}\n`;
  return text + block;
}
