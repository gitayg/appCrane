/**
 * Remove GitHub credentials that earlier versions left on disk.
 *
 * Until this release, deploys, AppStudio and the builder cloned with the token
 * in the URL (`https://<token>@github.com/owner/repo`). git writes that URL as
 * `remote.origin.url` into the working copy's .git/config, so every release
 * directory and workspace kept the token in plain text for as long as it
 * existed. The clone paths no longer do that; this removes what is already
 * there, once per boot, without touching anything else.
 *
 * Only the credential part of a URL is removed (`https://<token>@host` becomes
 * `https://host`). Scope is the three places those clones are made, never the
 * rest of DATA_DIR (app data and volumes belong to the apps):
 *   apps/<slug>/<env>/releases/<release>/.git
 *   appstudio-jobs/<job>/.git, appstudio-jobs/<job>/workspace/.git
 *   app-containers/<slug>/workspace/.git
 *
 * Symbolic links are never followed, and a file is rewritten only when it
 * contains a credential, keeping its mode.
 */
import { lstatSync, readdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'fs';
import { join, resolve } from 'path';
import log from '../utils/logger.js';

// scheme://userinfo@ -- userinfo has no slash, whitespace, quote or '@'.
const CREDENTIAL_IN_URL = /\b(https?:\/\/)[^\s/@'"]+@/gi;

/** Files inside .git where git records a remote URL. */
const GIT_TEXT_FILES = ['config', 'FETCH_HEAD', join('logs', 'HEAD')];

export function stripUrlCredentials(text) {
  return String(text).replace(CREDENTIAL_IN_URL, '$1');
}

function isRealDir(p) {
  try { return lstatSync(p).isDirectory(); } catch (_) { return false; }
}

function children(dir) {
  if (!isRealDir(dir)) return [];
  try { return readdirSync(dir).map((n) => join(dir, n)).filter(isRealDir); } catch (_) { return []; }
}

/** Every .git directory the old clone paths could have written. */
export function candidateGitDirs(dataDir) {
  const root = resolve(dataDir);
  const out = [];
  const add = (workTree) => {
    const g = join(workTree, '.git');
    if (isRealDir(g)) out.push(g);
  };
  for (const slugDir of children(join(root, 'apps'))) {
    for (const envDir of children(slugDir)) {
      for (const release of children(join(envDir, 'releases'))) add(release);
    }
  }
  for (const job of children(join(root, 'appstudio-jobs'))) {
    add(job);
    add(join(job, 'workspace'));
  }
  for (const slugDir of children(join(root, 'app-containers'))) add(join(slugDir, 'workspace'));
  return out;
}

function refLogFiles(gitDir) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 6 || !isRealDir(dir)) return;
    let names = [];
    try { names = readdirSync(dir); } catch (_) { return; }
    for (const n of names) {
      const p = join(dir, n);
      let st;
      try { st = lstatSync(p); } catch (_) { continue; }
      if (st.isDirectory()) walk(p, depth + 1);
      else if (st.isFile()) out.push(p);
    }
  };
  walk(join(gitDir, 'logs', 'refs'), 0);
  return out;
}

/** Rewrite one file if it holds a credential. Returns true when it did. */
function scrubFile(path) {
  let st;
  try { st = lstatSync(path); } catch (_) { return false; }
  if (!st.isFile() || st.size > 8 * 1024 * 1024) return false;
  const text = readFileSync(path, 'utf8');
  const clean = stripUrlCredentials(text);
  if (clean === text) return false;
  const tmp = `${path}.appcrane-scrub`;
  writeFileSync(tmp, clean, { mode: st.mode & 0o777 });
  renameSync(tmp, path);
  return true;
}

/**
 * Scrub every candidate working copy under `dataDir`. Never throws; returns
 * counts only (no paths with credentials, no credentials).
 */
export function scrubGitCredentialsOnDisk(dataDir = process.env.DATA_DIR || './data') {
  const result = { scanned: 0, filesScrubbed: 0, dirsScrubbed: 0, errors: 0 };
  if (!existsSync(dataDir)) return result;
  let dirs = [];
  try { dirs = candidateGitDirs(dataDir); } catch (_) { result.errors++; return result; }
  for (const gitDir of dirs) {
    result.scanned++;
    let touched = false;
    for (const f of [...GIT_TEXT_FILES.map((n) => join(gitDir, n)), ...refLogFiles(gitDir)]) {
      try {
        if (scrubFile(f)) { result.filesScrubbed++; touched = true; }
      } catch (_) {
        result.errors++;
      }
    }
    if (touched) result.dirsScrubbed++;
  }
  return result;
}

/** Boot hook: never throws, logs counts only. */
export function scrubGitCredentialsAtBoot() {
  try {
    const r = scrubGitCredentialsOnDisk();
    if (r.dirsScrubbed || r.errors) {
      log.warn(`[git-credential-scrub] removed stored GitHub credentials from ${r.dirsScrubbed} of ${r.scanned} working copies (${r.filesScrubbed} files, ${r.errors} errors)`);
    }
    return r;
  } catch (e) {
    try { log.error(`[git-credential-scrub] failed, boot continues: ${e?.message || e}`); } catch (_) { /* nothing left to do */ }
    return null;
  }
}
