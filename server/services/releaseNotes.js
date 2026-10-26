// AppCrane's own release notes, for the platform What's New (v2.93.5).
//
// Every release's commit subject is its user-facing note ("v2.93.4: ..."). They
// are read from this install's own git checkout: `git fetch origin`, then the
// subjects on origin/main. That is the same remote and the same fetch
// self-update already relies on, so it needs no api.github.com (60 calls an
// hour per IP without a token, and blocked on some networks), has no page-size
// cap, and a fork or mirror gets its own notes.
//
// CHANGELOG.md used to be read first and stopped being updated at 2.78.1, so
// every newer release showed "A new version of AppCrane is available." with no
// notes. It is no longer read.
//
// The GitHub commits API stays as the fallback for an install that is not a git
// checkout.
//
// Commit subjects read like a changelog, so release-notes.json (shipped with
// the code, so it works without git) holds 1-4 plain lines per version written
// for app owners. A version listed there uses those lines; a version missing
// from it falls back to its commit subject. origin/main's copy of the file is
// read too, so the upgrade preview gets friendly notes for releases this
// install has not installed yet. test/release-notes-curated.test.js fails when
// package.json's version has no entry.

import { execFile } from 'child_process';
import { readFileSync } from 'fs';
import { promisify } from 'util';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const run = promisify(execFile);
const REPO_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SUBJECT_RE = /^v(\d+\.\d+\.\d+)[:\s-]\s*(.*)$/;
const CACHE_MS = 5 * 60 * 1000;

/** Parse `%H\x1f%aI\x1f%s` lines into notes; newest first, one per version. */
export function parseVersionSubjects(lines) {
  const seen = new Set();
  const notes = [];
  for (const line of lines) {
    const [hash, date, subject = ''] = line.split('\x1f');
    const m = subject.match(SUBJECT_RE);
    if (!m || seen.has(m[1])) continue;
    seen.add(m[1]);
    notes.push({ version: m[1], commit_message: m[2].trim() || subject, commit_hash: hash || null, finished_at: date || null });
  }
  return notes;
}

/** Notes from the checkout's origin/main, after a fetch. [] when not a git checkout. */
export async function gitVersionNotes({ repoDir = REPO_DIR, branch = 'main' } = {}) {
  const opts = { cwd: repoDir, timeout: 30000, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } };
  try {
    await run('git', ['-c', 'credential.helper=', 'fetch', 'origin', branch], opts);
  } catch (_) {
    // Offline or no remote: origin/main from the last fetch is still better than nothing.
  }
  try {
    const { stdout } = await run('git', ['log', `origin/${branch}`, '--format=%H%x1f%aI%x1f%s'], { ...opts, maxBuffer: 32 * 1024 * 1024 });
    return parseVersionSubjects(stdout.split('\n'));
  } catch (_) {
    return [];
  }
}

async function githubVersionNotes(fetchImpl = globalThis.fetch) {
  try {
    const r = await fetchImpl('https://api.github.com/repos/gitayg/appCrane/commits?per_page=100', {
      headers: { 'User-Agent': 'AppCrane', 'Accept': 'application/vnd.github+json' },
      signal: AbortSignal.timeout(6000),
    });
    if (!r.ok) return [];
    const data = await r.json();
    return parseVersionSubjects((Array.isArray(data) ? data : []).map(c =>
      [c.sha, c.commit?.author?.date || c.commit?.committer?.date || '', String(c.commit?.message || '').split('\n')[0]].join('\x1f')));
  } catch (_) {
    return [];
  }
}

export const CURATED_FILE = 'release-notes.json';
const VERSION_RE = /^\d+\.\d+\.\d+$/;

/** { version: [line, ...] } from JSON text; anything malformed is dropped. */
export function parseCurated(text) {
  let data;
  try { data = JSON.parse(text); } catch (_) { return {}; }
  const out = {};
  if (!data || typeof data !== 'object' || Array.isArray(data)) return out;
  for (const [version, lines] of Object.entries(data)) {
    if (!VERSION_RE.test(version) || !Array.isArray(lines)) continue;
    const clean = lines.filter((l) => typeof l === 'string' && l.trim()).map((l) => l.trim());
    if (clean.length) out[version] = clean;
  }
  return out;
}

/** The curated notes shipped with this checkout, plus origin/main's for versions not shipped yet. */
export async function loadCuratedNotes({ repoDir = REPO_DIR, branch = 'main' } = {}) {
  let local = {};
  try { local = parseCurated(readFileSync(join(repoDir, CURATED_FILE), 'utf8')); } catch (_) {}
  let upstream = {};
  try {
    const { stdout } = await run('git', ['show', `origin/${branch}:${CURATED_FILE}`], { cwd: repoDir, timeout: 10000, maxBuffer: 8 * 1024 * 1024 });
    upstream = parseCurated(stdout);
  } catch (_) {}
  return { ...upstream, ...local };
}

const cmpVersion = (a, b) => {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0) ? 1 : -1;
  return 0;
};

/** Curated lines win over the commit subject; versions only one side knows are kept. Newest first. */
export function mergeCuratedNotes(subjectNotes, curated) {
  const byVersion = new Map();
  for (const n of Array.isArray(subjectNotes) ? subjectNotes : []) byVersion.set(n.version, n);
  for (const [version, lines] of Object.entries(curated || {})) {
    const base = byVersion.get(version) || { version, commit_hash: null, finished_at: null };
    byVersion.set(version, {
      ...base,
      lines,
      commit_message: lines.length === 1 ? lines[0] : lines.map((l) => `• ${l}`).join('\n'),
      curated: true,
    });
  }
  return [...byVersion.values()].sort((a, b) => cmpVersion(b.version, a.version));
}

const _cache = new Map();

/** Every release note known, newest first. Cached 5 min. */
export async function getVersionNotes({ repoDir, fetchImpl } = {}) {
  const now = Date.now();
  const key = repoDir || REPO_DIR;
  const hit = _cache.get(key);
  if (hit && now - hit.at < CACHE_MS) return hit.notes;
  let subjects = await gitVersionNotes({ repoDir });
  if (!subjects.length) subjects = await githubVersionNotes(fetchImpl);
  const notes = mergeCuratedNotes(subjects, await loadCuratedNotes({ repoDir: key }));
  if (notes.length) _cache.set(key, { notes, at: now });
  return notes;
}

const JARGON = /\b(TOCTOU|symlinks?|helper container|busybox|node-gyp|idempotency)\b|(^|\s)(server|studio-web|test|scripts)\/\S+|\.(js|tsx?|sql)\b/i;

/** Why `version` cannot ship with these curated notes, or null when it can. */
export function curatedEntryProblem(version, curated) {
  const lines = curated?.[version];
  const how = `Add an entry to ${CURATED_FILE} at the repo root: "${version}": ["one to four short lines for app owners: what they can do now or what changed for them"]. `
    + 'Plain words, no file paths or internal jargon. The platform What\'s New dialog and e-mail show these lines instead of the commit subject.';
  if (!Array.isArray(lines) || !lines.length) return `package.json is at ${version}, but ${CURATED_FILE} has no notes for it. ${how}`;
  if (lines.length > 4) return `${CURATED_FILE} has ${lines.length} lines for ${version}; keep it to 4 or fewer. ${how}`;
  const bad = lines.find((l) => JARGON.test(l));
  if (bad) return `${CURATED_FILE} entry for ${version} reads like a changelog, not a note for app owners: "${bad}". ${how}`;
  return null;
}
