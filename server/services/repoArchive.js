/**
 * Per-repository archives (v2.74.0) — one file per managed-app git repo.
 *
 * Until v2.73 the host-local repos (DATA_DIR/repos, services/localGit.js) rode
 * inside the single config zip. That zip was built in memory, uploaded through
 * a 200 MB multer buffer, and one bad bundle refused the whole restore. Code is
 * now its own artifact, one archive per repo:
 *
 *   appcrane-repo-<slug>-<fingerprint12>-<YYYY-MM-DD>.tar
 *     appcrane-repo.json   manifest: slug, HEAD target, every ref's SHA,
 *                          fingerprint, bundle sha256
 *     repo.bundle          `git bundle --all` (absent for a repo with no refs)
 *
 * Each archive restores on its own: bring back one app's code without touching
 * any other, and a corrupt archive fails alone.
 *
 * PAIRING, following imageArchive.js: the fingerprint is derived from content,
 * not minted. For one repo it is sha256 over its HEAD target and sorted
 * "<sha> <refname>" lines. The data archive's manifest records every repo's
 * fingerprint at its export time (`repo_set`); a data import persists that set
 * to DATA_DIR/backups/expected-repo-set.json, and both a repo import and
 * verifyRepoSet() compare what is live against it. Two exports with no push in
 * between agree — they ARE interchangeable — and an archive taken across a push
 * does not.
 *
 * VERIFIED BEFORE LIVE, exactly as the v2.73 import: the bundle's sha256 and
 * ref list are checked against the manifest, then localGit's
 * stageRepoFromBundleSync unbundles into a staging dir, recreates every ref,
 * sets HEAD and runs `git fsck --full`; only then does installStagedReposSync
 * rename it into place, moving the live repo aside into a pre-import dir.
 *
 * OFF THE EVENT LOOP. localGit's backup functions are synchronous (execFileSync)
 * and are called unmodified, so they run in a worker thread: the git work
 * blocks the worker, not the thread answering HTTP (and the SSO forward_auth
 * checks every hosted app waits on).
 *
 * KNOWN LIMIT: bundleRepoSync returns the bundle as a Buffer and
 * stageRepoFromBundleSync takes one, so ONE repo's bundle is resident in the
 * worker at a time. Removing that needs a file-path variant of each in
 * localGit.js, which this change does not edit.
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { execFile } from 'child_process';
import { createHash, randomBytes } from 'crypto';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { readFile, writeFile, rename, rm, mkdir, stat, open } from 'fs/promises';
import { join } from 'path';
import {
  listLocalRepoSlugs, bundleRepoSync, stageRepoFromBundleSync, installStagedReposSync, newImportStageDir,
  getBranchHeadSha, repoPath, reposRoot,
} from './localGit.js';
import {
  SLUG_RE, dataDir, backupsDir, ensureBackupsDir, newWorkDir, freeBytes, confineToBackups,
  createTar, extractTar, walk, treeBytes, sha256File, privateFile,
} from './backupFiles.js';

export const REPO_MANIFEST = 'appcrane-repo.json';
export const REPO_BUNDLE = 'repo.bundle';
export const EXPECTED_SET_FILE = 'expected-repo-set.json';

const REF_LINE = /^([0-9a-f]{40}) (refs\/\S+)$/;

// ---------------------------------------------------------------------------
// Worker: localGit's synchronous functions, off the main thread
// ---------------------------------------------------------------------------

function doTask(t) {
  switch (t.op) {
    case 'bundle': {
      const { head, bundle } = bundleRepoSync(t.slug);
      if (bundle) writeFileSync(t.out, bundle, { mode: 0o600 });
      return { head, bytes: bundle ? bundle.length : 0 };
    }
    case 'new-stage':
      return newImportStageDir();
    case 'stage':
      return stageRepoFromBundleSync(t.stageDir, t.slug, t.head, t.bundlePath ? readFileSync(t.bundlePath) : null);
    case 'install':
      return installStagedReposSync(t.stageDir, t.slugs, t.preDir);
    default:
      throw new Error(`unknown repo task ${t.op}`);
  }
}

if (!isMainThread && workerData && workerData.appcraneRepoTask) {
  try {
    parentPort.postMessage({ ok: true, value: doTask(workerData.appcraneRepoTask) });
  } catch (e) {
    parentPort.postMessage({ ok: false, message: e.message, code: e.code });
  }
}

export function runRepoTask(task) {
  return new Promise((resolveP, reject) => {
    const w = new Worker(new URL(import.meta.url), { workerData: { appcraneRepoTask: task } });
    let settled = false;
    w.once('message', (m) => {
      settled = true;
      if (m.ok) resolveP(m.value);
      else reject(Object.assign(new Error(m.message), m.code ? { code: m.code } : {}));
    });
    w.once('error', (e) => { if (!settled) { settled = true; reject(e); } });
    w.once('exit', (code) => { if (!settled) reject(new Error(`repo worker exited with ${code} before answering`)); });
  });
}

// ---------------------------------------------------------------------------
// Reading repo state
// ---------------------------------------------------------------------------

/**
 * Read-only git against a live repo, with the isolation localGit applies to
 * every call (no system/global config, no hooks, no fsmonitor). localGit has
 * no exported ref lister, and this module does not edit it.
 */
function gitRead(gitDir, args) {
  return new Promise((resolveP, reject) => {
    execFile('git', [
      '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'protocol.allow=never',
      `--git-dir=${gitDir}`, ...args,
    ], {
      env: { PATH: process.env.PATH || '/usr/bin:/bin', LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' },
      maxBuffer: 64 * 1024 * 1024,
    }, (err, stdout, stderr) => {
      if (err) return reject(Object.assign(new Error(`git ${args[0]} failed: ${String(stderr || err.message).trim()}`), { exitCode: err.code }));
      resolveP(String(stdout));
    });
  });
}

export function repoFingerprint(head, refs) {
  const lines = Object.entries(refs).map(([name, sha]) => `${sha} ${name}`).sort();
  return createHash('sha256').update(`HEAD ${head}\n${lines.join('\n')}`).digest('hex');
}

export function repoSetFingerprint(repos) {
  const lines = repos.map((r) => `${r.slug} ${r.fingerprint}`).sort();
  return createHash('sha256').update(lines.join('\n')).digest('hex');
}

/** { slug, head, head_sha, refs: {refname: sha}, fingerprint } for a live repo. */
export async function readRepoState(slug) {
  if (!SLUG_RE.test(String(slug))) throw new Error(`invalid slug ${JSON.stringify(slug)}`);
  const dir = repoPath(slug);
  let head = 'refs/heads/main';
  try {
    const ref = (await gitRead(dir, ['symbolic-ref', '--quiet', 'HEAD'])).trim();
    if (ref.startsWith('refs/heads/')) head = ref;
  } catch (_) { /* detached or unreadable: keep the default, as bundleRepoSync does */ }
  const refs = {};
  for (const line of (await gitRead(dir, ['for-each-ref', '--format=%(objectname) %(refname)'])).split('\n')) {
    const m = REF_LINE.exec(line.trim());
    if (m) refs[m[2]] = m[1];
  }
  let headSha = null;
  try { headSha = await getBranchHeadSha(slug, head.slice('refs/heads/'.length)); } catch (_) { /* unborn branch */ }
  return { slug, head, head_sha: headSha, refs, fingerprint: repoFingerprint(head, refs) };
}

/** The repo set a data archive records: every local repo at this moment. */
export async function currentRepoSet() {
  const repos = [];
  for (const slug of listLocalRepoSlugs()) repos.push(await readRepoState(slug));
  return {
    count: repos.length,
    fingerprint: repoSetFingerprint(repos),
    repos: repos.map((r) => ({ ...r, archive_prefix: `appcrane-repo-${r.slug}-${r.fingerprint.slice(0, 12)}-` })),
  };
}

/** The "<sha> refs/…" lines of a bundle header, read from the file without loading the pack. */
export async function readBundleRefs(bundlePath) {
  const fh = await open(bundlePath, 'r');
  try {
    let acc = Buffer.alloc(0);
    let pos = 0;
    const chunk = Buffer.alloc(64 * 1024);
    for (;;) {
      const { bytesRead } = await fh.read(chunk, 0, chunk.length, pos);
      if (!bytesRead) throw new Error('bundle header is truncated');
      acc = Buffer.concat([acc, chunk.subarray(0, bytesRead)]);
      pos += bytesRead;
      const end = acc.indexOf('\n\n');
      if (end >= 0) {
        const lines = acc.subarray(0, end).toString('utf8').split('\n');
        if (!/^# v[23] git bundle$/.test(lines[0])) throw new Error('not a git bundle');
        const refs = {};
        for (const l of lines.slice(1)) {
          const m = REF_LINE.exec(l);
          if (m) refs[m[2]] = m[1];
        }
        return refs;
      }
      if (acc.length > 16 * 1024 * 1024) throw new Error('bundle header is implausibly large');
    }
  } finally {
    await fh.close();
  }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/** `appcrane-repo-<slug>-<fingerprint12>-<YYYY-MM-DD>.tar` */
export function repoArchiveFileName(slug, fingerprint, at = new Date()) {
  return `appcrane-repo-${slug}-${fingerprint.slice(0, 12)}-${at.toISOString().slice(0, 10)}.tar`;
}

export async function planRepoArchives() {
  const slugs = listLocalRepoSlugs();
  const repos = [];
  let estimated = 0;
  for (const slug of slugs) {
    const st = await readRepoState(slug);
    const bytes = await treeBytes(repoPath(slug));
    estimated += bytes;
    repos.push({ slug, head: st.head, head_sha: st.head_sha, refs: Object.keys(st.refs).length, fingerprint: st.fingerprint, disk_bytes: bytes });
  }
  const dir = backupsDir();
  const free = freeBytes(dir);
  // The on-disk repo size is the ceiling: a bundle is one pack of the same objects.
  const required = Math.ceil(estimated * 1.1) + 16 * 1024 * 1024;
  return { repos, estimated_bytes: estimated, required_bytes: required, free_bytes: free, fits: free === null ? null : free > required, dest_dir: dir };
}

export async function exportRepoArchive(slug, { at = new Date() } = {}) {
  if (!SLUG_RE.test(String(slug))) throw new Error(`invalid slug ${JSON.stringify(slug)}`);
  if (!listLocalRepoSlugs().includes(slug)) {
    throw Object.assign(new Error(`no local managed repository for '${slug}'`), { status: 404 });
  }
  const dir = await ensureBackupsDir();
  const work = await newWorkDir('repo-export');
  try {
    const bundlePath = join(work, REPO_BUNDLE);
    const { head } = await runRepoTask({ op: 'bundle', slug, out: bundlePath });
    const hasBundle = existsSync(bundlePath);
    // Fingerprint from what the archive actually holds, not from a second read
    // of the live repo that a push could have moved in between.
    const refs = hasBundle ? await readBundleRefs(bundlePath) : {};
    const fingerprint = repoFingerprint(head, refs);
    const manifest = {
      kind: 'appcrane-repo-archive',
      format: 1,
      slug,
      exported_at: at.toISOString(),
      head,
      head_sha: refs[head] || null,
      refs,
      fingerprint,
      bundle: hasBundle ? { file: REPO_BUNDLE, bytes: (await stat(bundlePath)).size, sha256: await sha256File(bundlePath) } : null,
    };
    await writeFile(join(work, REPO_MANIFEST), JSON.stringify(manifest, null, 2), { mode: 0o600 });

    const file = repoArchiveFileName(slug, fingerprint, at);
    const dest = join(dir, file);
    const partial = `${dest}.partial-${randomBytes(4).toString('hex')}`;
    try {
      await createTar(partial, [{ cwd: work, paths: [REPO_MANIFEST, ...(hasBundle ? [REPO_BUNDLE] : [])] }]);
      await privateFile(partial);
      await rename(partial, dest);
    } catch (e) {
      await rm(partial, { force: true });
      throw e;
    }
    const bytes = (await stat(dest)).size;
    return { slug, path: dest, file, bytes, head, head_sha: manifest.head_sha, refs: Object.keys(refs).length, fingerprint };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

/** Every repo (or `slugs`), one archive each. One failure does not stop the rest. */
export async function exportRepoArchives({ slugs, at = new Date(), onProgress } = {}) {
  const targets = slugs && slugs.length ? slugs : listLocalRepoSlugs();
  const exported = [];
  const failed = [];
  for (const slug of targets) {
    try {
      exported.push(await exportRepoArchive(slug, { at }));
    } catch (e) {
      failed.push({ slug, error: e.message });
    }
    onProgress?.({ exported: exported.length, failed: failed.length, total: targets.length });
  }
  return { exported, failed, total: targets.length };
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

export async function readExpectedRepoSet() {
  try {
    return JSON.parse(await readFile(join(backupsDir(), EXPECTED_SET_FILE), 'utf8'));
  } catch (_) {
    return null;
  }
}

export async function recordExpectedRepoSet(repoSet, source) {
  const dir = await ensureBackupsDir();
  const dest = join(dir, EXPECTED_SET_FILE);
  const tmp = `${dest}.tmp-${randomBytes(4).toString('hex')}`;
  await writeFile(tmp, JSON.stringify({ recorded_at: new Date().toISOString(), source, ...repoSet }, null, 2), { mode: 0o600 });
  await rename(tmp, dest);
}

const repoFail = (msg) => new Error(`Repository archive failed verification, nothing was restored: ${msg}`);

/**
 * Restore ONE repo from its archive. Every check runs before the live repo is
 * touched; any failure leaves the host exactly as it was.
 *
 * @param {string} path   archive inside DATA_DIR/backups
 * @param {object} opts   { slug?: expected slug — refuse an archive for a different app }
 */
export async function importRepoArchive(path, { slug: expectSlug } = {}) {
  const abs = await confineToBackups(path);
  if (expectSlug !== undefined && !SLUG_RE.test(String(expectSlug))) throw new Error(`invalid slug ${JSON.stringify(expectSlug)}`);

  const work = await newWorkDir('repo-import');
  let stageDir = null;
  try {
    try {
      await extractTar(abs, work);
    } catch (e) {
      throw repoFail(e.message);
    }
    // Exactly the two names this format writes, as regular files. A symlink or
    // extra member is refused rather than skipped.
    const seen = new Set();
    for await (const e of walk(work)) {
      if (e.type !== 'file' || (e.rel !== REPO_MANIFEST && e.rel !== REPO_BUNDLE)) {
        throw repoFail(`unexpected member ${JSON.stringify(e.rel)} (${e.type})`);
      }
      seen.add(e.rel);
    }
    if (!seen.has(REPO_MANIFEST)) throw repoFail(`${REPO_MANIFEST} missing — not an AppCrane repository archive`);

    let m;
    try { m = JSON.parse(await readFile(join(work, REPO_MANIFEST), 'utf8')); } catch (_) { throw repoFail('manifest is corrupt'); }
    if (m.kind !== 'appcrane-repo-archive') throw repoFail('not an AppCrane repository archive');
    if (!SLUG_RE.test(String(m.slug))) throw repoFail(`invalid slug ${JSON.stringify(m.slug)}`);
    if (expectSlug !== undefined && m.slug !== expectSlug) {
      throw repoFail(`archive is for '${m.slug}', not '${expectSlug}'`);
    }
    if (typeof m.head !== 'string' || !m.head.startsWith('refs/heads/')) throw repoFail(`invalid HEAD ${JSON.stringify(m.head)}`);

    const bundlePath = join(work, REPO_BUNDLE);
    const hasBundle = seen.has(REPO_BUNDLE);
    if (!!m.bundle !== hasBundle) throw repoFail(hasBundle ? 'bundle present but manifest names none' : 'manifest names a bundle the archive does not hold');
    let refs = {};
    if (hasBundle) {
      const got = await sha256File(bundlePath);
      if (got !== m.bundle.sha256) throw repoFail('bundle sha256 does not match the manifest');
      try { refs = await readBundleRefs(bundlePath); } catch (e) { throw repoFail(e.message); }
    }
    const fingerprint = repoFingerprint(m.head, refs);
    if (fingerprint !== m.fingerprint) throw repoFail('the bundle\'s refs do not match the manifest fingerprint');
    // The manifest's ref list is what an operator reads; it must be the bundle's, not a claim beside it.
    const listed = m.refs && typeof m.refs === 'object' ? m.refs : {};
    if (repoFingerprint(m.head, listed) !== fingerprint || Object.keys(listed).length !== Object.keys(refs).length) {
      throw repoFail('the manifest\'s refs do not match the bundle\'s refs');
    }

    stageDir = await runRepoTask({ op: 'new-stage' });
    let staged;
    try {
      staged = await runRepoTask({ op: 'stage', stageDir, slug: m.slug, head: m.head, bundlePath: hasBundle ? bundlePath : null });
    } catch (e) {
      throw repoFail(e.message);
    }
    if ((staged.headSha || null) !== (m.head_sha || null)) {
      throw repoFail(`staged HEAD ${staged.headSha} is not the manifest's ${m.head_sha}`);
    }

    const preDir = join(dataDir(), `pre-import-${Date.now()}-repo-${m.slug}`);
    await mkdir(preDir, { recursive: true, mode: 0o700 });
    await runRepoTask({ op: 'install', stageDir, slugs: [m.slug], preDir });

    // Prove what went live is what the archive holds, ref for ref.
    const live = await readRepoState(m.slug);
    const expected = await readExpectedRepoSet();
    const exp = expected?.repos?.find((r) => r.slug === m.slug) || null;
    return {
      slug: m.slug,
      path: abs,
      head: m.head,
      head_sha: live.head_sha,
      refs: Object.keys(live.refs).length,
      fingerprint: live.fingerprint,
      verified: live.fingerprint === m.fingerprint,
      replaced_repo_kept_at: existsSync(join(preDir, 'repos', `${m.slug}.git`)) ? join(preDir, 'repos', `${m.slug}.git`) : null,
      pairing: exp
        ? { expected_fingerprint: exp.fingerprint, matched: exp.fingerprint === live.fingerprint, data_exported_at: expected.exported_at || null }
        : { expected_fingerprint: null, matched: null, note: 'No data-archive import has recorded which repositories to expect.' },
    };
  } finally {
    await rm(work, { recursive: true, force: true });
    if (stageDir) await rm(stageDir, { recursive: true, force: true });
  }
}

/**
 * Do the live repos match what the last imported data archive expects?
 * `expected` defaults to the persisted set.
 */
export async function verifyRepoSet(expected) {
  const set = expected || await readExpectedRepoSet();
  const live = new Map();
  for (const slug of listLocalRepoSlugs()) live.set(slug, await readRepoState(slug));
  if (!set) {
    return { expected: null, matched: null, rows: [], extra: [...live.keys()], note: 'No data-archive import has recorded which repositories to expect.' };
  }
  const rows = (set.repos || []).map((r) => {
    const l = live.get(r.slug);
    return {
      slug: r.slug,
      expected_fingerprint: r.fingerprint,
      present_fingerprint: l ? l.fingerprint : null,
      expected_head_sha: r.head_sha,
      present_head_sha: l ? l.head_sha : null,
      state: !l ? 'missing' : l.fingerprint === r.fingerprint ? 'matched' : 'mismatched',
      archive_prefix: r.archive_prefix || `appcrane-repo-${r.slug}-${String(r.fingerprint).slice(0, 12)}-`,
    };
  });
  const extra = [...live.keys()].filter((s) => !rows.some((r) => r.slug === s));
  return {
    expected_fingerprint: set.fingerprint,
    exported_at: set.exported_at || null,
    matched: rows.every((r) => r.state === 'matched'),
    missing: rows.filter((r) => r.state === 'missing').map((r) => r.slug),
    mismatched: rows.filter((r) => r.state === 'mismatched').map((r) => r.slug),
    extra,
    rows,
  };
}

export { reposRoot };
