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

import { execFile } from 'child_process';
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

let _cache = null;
let _cacheAt = 0;

/** Every release note known, newest first. Cached 5 min. */
export async function getVersionNotes({ repoDir, fetchImpl } = {}) {
  const now = Date.now();
  if (_cache && now - _cacheAt < CACHE_MS) return _cache;
  let notes = await gitVersionNotes({ repoDir });
  if (!notes.length) notes = await githubVersionNotes(fetchImpl);
  if (notes.length) { _cache = notes; _cacheAt = now; }
  return notes;
}
