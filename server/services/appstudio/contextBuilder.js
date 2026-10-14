import { execFileSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { regularFileInside } from '../../utils/paths.js';
import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { runAgentOneShot } from '../llm/runAgent.js';
import { ensureStudioImage } from './generator.js';
import { runWorkspaceGit } from '../builder/workspaceRunner.js';
import { readWorkspaceFiles } from '../builder/workspaceReader.js';
import { isCoderWorkspace, liveContainerNameFor } from '../builder/appContainer.js';

const MODEL        = process.env.APPSTUDIO_PLANNER_MODEL || 'claude-sonnet-4-6';
const STUDIO_IMAGE = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';

// A coder workspace is written by the container's user, so to the host's git
// it has "dubious ownership" and every read failed quietly: the summary was
// built with no commit (so it was never cached) and an empty file tree.
// Measured on a real instance: `context BUILD for tiny-barons @ undefined`.
//
// And it is the agent's to rewrite, .git/ included, while its container runs —
// builderSession calls this for the coder workspace on every first turn. So
// for a coder workspace the git runs inside the session's container (or a
// throwaway helper), never on the host (builder/workspaceRunner.js). Every
// other caller passes production/current, a release directory AppCrane cloned
// and no agent has mounted, which keeps host git.
function repoGit(repoDir, args, timeout) {
  if (isCoderWorkspace(repoDir)) {
    return runWorkspaceGit(repoDir, args, { container: liveContainerNameFor(repoDir), timeout }).toString('utf8');
  }
  return execFileSync('git', ['-c', `safe.directory=${repoDir}`, ...args], { // host-git-ok: release dir, never a coder workspace
    cwd: repoDir, encoding: 'utf8', timeout, stdio: 'pipe',
  });
}

function getGitHash(repoDir) {
  try {
    return repoGit(repoDir, ['rev-parse', 'HEAD'], 5000).trim();
  } catch (_) { return null; }
}

function getFileTree(repoDir) {
  try {
    return repoGit(repoDir, ['ls-tree', '-r', '--name-only', 'HEAD'], 10000).trim();
  } catch (_) { return ''; }
}

/** What one key file contributes to the prompt, in characters. */
const KEY_FILE_MAX_CHARS = 8000;

/**
 * Bytes read per key file. A utf-8 character is at most 4 bytes, so a 32 KiB
 * prefix always holds the first KEY_FILE_MAX_CHARS characters whole — the
 * truncated text is the same one reading the whole file would give.
 */
const KEY_FILE_READ_BYTES = 4 * KEY_FILE_MAX_CHARS + 768;

/** Ceiling on everything one context build reads (18 key files at most). */
const KEY_FILES_BATCH_BYTES = 2 * 1024 * 1024;

function clip(c) {
  return c.length > KEY_FILE_MAX_CHARS ? c.slice(0, KEY_FILE_MAX_CHARS) + '\n...(truncated)' : c;
}

function readKeySafe(path) {
  try {
    return clip(readFileSync(path, 'utf8')); // host-read-ok: release directory only — readKeyFiles never calls this for a coder workspace
  } catch (_) { return null; }
}

/**
 * The text of `paths` (repo-relative), as Map<path, string|null>; null means
 * absent, unreadable, or not a regular file.
 *
 * A coder workspace is the agent's to rewrite while its container runs, and
 * builderSession calls this on every first turn: the host reading a path in it
 * could be raced into reading a host file (a symlink, or a parent directory
 * swapped for one, between the check and the read) and the bytes would go
 * straight into an LLM prompt. So for a coder workspace the files are read
 * INSIDE the container (builder/workspaceReader.js), in one round trip, from
 * git's object store at the commit the document is cached under — not the
 * working tree. That is also the right content: the cache key is that hash,
 * and the file tree beside it is `ls-tree` of the same commit. A symlink comes
 * back as a symlink and is shown as one; its target is never read.
 *
 * Every other caller passes production/current, a release directory AppCrane
 * cloned and no agent has mounted, which keeps the host read.
 */
function readKeyFiles(repoDir, paths, commit) {
  const out = new Map();
  if (!paths.length) return out;
  if (!isCoderWorkspace(repoDir)) {
    for (const p of paths) {
      const abs = join(repoDir, p); // nosemgrep: path-join-resolve-traversal — p is a hardcoded name or from git ls-tree/diff output
      // A release dir is a git checkout, and git checks a committed symlink out
      // as one: following it would put a host file in the context document.
      out.set(p, regularFileInside(repoDir, abs) ? readKeySafe(abs) : null); // host-read-ok: release directory only (see above)
    }
    return out;
  }
  // No commit means rev-parse already failed in this workspace: there is
  // nothing to read at, and another round trip would only fail the same way.
  if (!commit) return out;
  let recs;
  try {
    recs = readWorkspaceFiles(repoDir, paths, {
      source: 'commit', commit, truncate: true,
      maxFileBytes: KEY_FILE_READ_BYTES, maxBatchBytes: KEY_FILES_BATCH_BYTES,
      // The same budget as the ls-tree beside it.
      container: liveContainerNameFor(repoDir), timeout: 10000,
    });
  } catch (err) {
    log.warn(`[contextBuilder] reading key files from the workspace failed: ${err.message}`);
    return out;
  }
  for (const p of paths) {
    const r = recs.get(p);
    if (r?.kind === 'F' || r?.kind === 'P') out.set(p, clip(r.body.toString('utf8')));
    else if (r?.kind === 'L') out.set(p, `(symlink to ${JSON.stringify(r.target)} — not followed)`);
    else out.set(p, null);
  }
  return out;
}

/** git paths here come from the agent's repository: only plain relative ones are asked for. */
function plainPath(p) {
  return typeof p === 'string' && p && !p.startsWith('/') && !p.includes('\0')
    && !p.split('/').some((s) => s === '' || s === '.' || s === '..');
}

function collectKeyFiles(repoDir, fileTree, commit) {
  const priority = [
    'README.md', 'package.json', 'crane.yaml', 'deployhub.json',
    'server/index.js', 'src/index.js', 'src/main.js', 'src/app.js',
    'app.js', 'index.js', 'main.py', 'app.py',
  ];
  const lines = fileTree.split('\n').filter(Boolean);
  const seen = new Set(priority);

  // Add up to 6 more files: entry points, routes, DB schemas
  const extras = lines.filter(f =>
    !seen.has(f) && plainPath(f) &&
    /\.(js|ts|py|go|sql)$/.test(f) &&
    !f.includes('node_modules') && !f.includes('.git') &&
    (/route|model|schema|controller|service|store|api|App\.[jt]sx?$|\/pages\/|\/views\/|\/screens\//i.test(f))
  ).slice(0, 6);

  // One read for all of them — for a coder workspace, one container round
  // trip, and only for paths in the tree: it reads that commit's objects, so
  // anything else would come back missing anyway.
  const inTree = new Set(lines);
  const wanted = [...priority, ...extras].filter((p) => !isCoderWorkspace(repoDir) || inTree.has(p));
  const texts = readKeyFiles(repoDir, wanted, commit);
  const result = [];
  for (const p of wanted) {
    const content = texts.get(p);
    if (content) result.push({ path: p, content });
  }
  return result;
}

async function callClaude(prompt, repoDir, appSlug, actingUserId = null) {
  // Make sure the studio image exists before spawning — without this,
  // a fresh prod fails contextBuilder with exit-125 (no image to run).
  await ensureStudioImage((m) => log.info(`[contextBuilder] ${m}`));
  const { text } = await runAgentOneShot({
    image:         STUDIO_IMAGE,
    workspaceDir:  repoDir,
    workspaceMode: 'ro',
    prompt,
    apiKey:        process.env.ANTHROPIC_API_KEY,
    model:         MODEL,
    timeoutMs:     parseInt(process.env.APPSTUDIO_CONTEXT_TIMEOUT_MS || '300000', 10),
    appSlug,
    // Same credential as the turn it prepares: without this a user on their
    // own subscription had the summary built on the platform key instead.
    actingUserId,
    labels:        { 'appcrane.container.type': 'context' },
  });
  return text;
}

async function buildContextDoc(repoDir, fileTree, keyFiles, appSlug, actingUserId = null) {
  const filesSection = keyFiles
    .map(f => `### ${f.path}\n\`\`\`\n${f.content}\n\`\`\``)
    .join('\n\n');

  const prompt = `You are analyzing a software project to create a concise technical reference for an AI coding assistant.

## File tree
\`\`\`
${fileTree}
\`\`\`

## Key files
${filesSection}

---

Write a structured technical reference document that covers:

1. **App purpose & tech stack** — what it does, language/framework, key dependencies
2. **Directory structure** — what each major directory and key file does
3. **Architecture & patterns** — how the code is organized (MVC, functional, layered, etc.), naming conventions
4. **Data flows** — how a typical request flows through the system, database/state interactions
5. **Key APIs and entry points** — main routes, functions, or modules an agent would likely touch
6. **Constraints & gotchas** — things an agent must NOT break, known limitations, important invariants

Be concise (aim for ~500-800 words). Focus on what an AI needs to make precise surgical changes without breaking things. Do not include generic advice — only facts specific to this codebase.`;

  return callClaude(prompt, repoDir, appSlug, actingUserId);
}

async function updateContextDoc(existingDoc, changedFiles, repoDir, appSlug, actingUserId = null, newHash = null) {
  if (!changedFiles.length) return existingDoc;

  const shown = changedFiles.slice(0, 10);
  const wanted = [...new Set(shown.filter((f) => f.status !== 'D').map((f) => f.newPath || f.path).filter(plainPath))];
  const texts = readKeyFiles(repoDir, wanted, newHash);
  const diffs = shown.map(({ status, path, newPath }) => {
    if (status === 'D') return `DELETED: ${path}`;
    const target = newPath || path;
    const content = texts.get(target) || null;
    const prefix = status.startsWith('R') ? `RENAMED ${path} → ${target}` : `MODIFIED: ${target}`;
    return content ? `${prefix}\n\`\`\`\n${content}\n\`\`\`` : `${prefix} (unreadable)`;
  }).join('\n\n');

  const prompt = `You maintain a codebase context document for an AI coding assistant.

## Existing context document
${existingDoc}

## Files that changed since this document was written
${diffs}

Update the context document to reflect these changes. Update only the sections affected by the changes. Preserve the structure and everything that is still accurate. Return the full updated document.`;

  return callClaude(prompt, repoDir, appSlug, actingUserId);
}

function getChangedFiles(repoDir, oldHash, newHash) {
  try {
    const out = repoGit(repoDir, ['diff', '--name-status', oldHash, newHash], 10000).trim();
    return out.split('\n').filter(Boolean).map(line => {
      const [status, ...parts] = line.split('\t');
      return status.startsWith('R')
        ? { status, path: parts[0], newPath: parts[1] }
        : { status, path: parts[0] };
    });
  } catch (_) { return null; }
}

function saveContext(appSlug, gitHash, fileTree, contextDoc) {
  getDb().prepare(`
    INSERT INTO app_codebase_context (app_slug, git_hash, built_at, file_tree, context_doc)
    VALUES (?, ?, datetime('now'), ?, ?)
    ON CONFLICT(app_slug) DO UPDATE SET
      git_hash = excluded.git_hash,
      built_at = excluded.built_at,
      file_tree = excluded.file_tree,
      context_doc = excluded.context_doc
  `).run(appSlug, gitHash, fileTree, contextDoc);
}

/**
 * Returns the cached context document for this app, building or updating it as needed.
 * Returns { contextDoc, fileTree, gitHash, fromCache }
 */
export async function ensureCodebaseContext(appSlug, repoDir, { actingUserId = null } = {}) {
  // host-read-ok: metadata only — the workspace directory itself, which AppCrane creates and the agent cannot replace (its parent is AppCrane's)
  if (!existsSync(repoDir)) return { contextDoc: null, fileTree: '', gitHash: null, fromCache: false };

  const db = getDb();
  const gitHash = getGitHash(repoDir);
  const cached = db.prepare('SELECT * FROM app_codebase_context WHERE app_slug = ?').get(appSlug);

  // Cache hit — same git hash
  if (cached && gitHash && cached.git_hash === gitHash) {
    log.info(`AppStudio context HIT for ${appSlug} @ ${gitHash.slice(0, 8)}`);
    return { contextDoc: cached.context_doc, fileTree: cached.file_tree || '', gitHash, fromCache: true, builtAt: cached.built_at };
  }

  const fileTree = getFileTree(repoDir);

  // Existing context but hash changed — try incremental update
  if (cached && gitHash) {
    log.info(`AppStudio context STALE for ${appSlug} — updating (${cached.git_hash.slice(0, 8)} → ${gitHash.slice(0, 8)})`);
    const changedFiles = getChangedFiles(repoDir, cached.git_hash, gitHash);

    if (changedFiles !== null) {
      const updatedDoc = await updateContextDoc(cached.context_doc, changedFiles, repoDir, appSlug, actingUserId, gitHash);
      saveContext(appSlug, gitHash, fileTree, updatedDoc);
      return { contextDoc: updatedDoc, fileTree, gitHash, fromCache: false, builtAt: new Date().toISOString() };
    }
    // Diff unavailable — fall through to full rebuild
  }

  // No cache or unreachable old hash — full build
  log.info(`AppStudio context BUILD for ${appSlug} @ ${gitHash?.slice(0, 8)}`);
  const keyFiles = collectKeyFiles(repoDir, fileTree, gitHash);
  const contextDoc = await buildContextDoc(repoDir, fileTree, keyFiles, appSlug, actingUserId);
  if (gitHash) saveContext(appSlug, gitHash, fileTree, contextDoc);

  return { contextDoc, fileTree, gitHash, fromCache: false, builtAt: new Date().toISOString() };
}
