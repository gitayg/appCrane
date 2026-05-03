import { execFileSync, spawn } from 'child_process';
import { mkdirSync, existsSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'fs';
import { join, resolve } from 'path';
import { decrypt } from '../encryption.js';
import { assertCapacity } from '../containerLimit.js';
import { runAgentNew } from '../llm/runAgent.js';
import { writeSnapshot } from '../github/snapshot.js';
import { renderOpenCommentsSection } from '../enhancementComments.js';
import { formatToolBreadcrumb } from './toolBreadcrumb.js';
import log from '../../utils/logger.js';

const GEN_MODEL       = process.env.APPSTUDIO_CODER_MODEL || 'claude-sonnet-4-6';
const GEN_TIMEOUT_MS  = parseInt(process.env.APPSTUDIO_TIMEOUT_MS || '1800000', 10);
const STUDIO_IMAGE    = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';

/**
 * `git ls-remote --heads <url> <branch>` — returns true iff the branch
 * exists on the remote. Silent on errors (treats unreachable / auth
 * failure as "doesn't exist" so coding still attempts the normal path
 * and fails loudly via the clone instead).
 */
function checkRemoteBranchExists(cloneUrl, branch, onLog) {
  try {
    const out = execFileSync('git', ['ls-remote', '--heads', cloneUrl, branch], {
      stdio: 'pipe', timeout: 30000,
    }).toString().trim();
    return out.length > 0;
  } catch (err) {
    onLog?.(`[studio:git] ls-remote check failed (treating as no-branch): ${(err.stderr?.toString() || err.message).slice(0, 120)}`);
    return false;
  }
}

/**
 * GitHub API: returns the first OPEN PR whose head ref matches `branch`,
 * or null if none open / the API call fails. Used to refuse a re-coding
 * attempt that would otherwise rewrite an active PR's history.
 */
async function checkOpenPr(app, branch, token, onLog) {
  if (!app?.github_url) return null;
  const m = app.github_url.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (!m) return null;
  const [, owner, repo] = m;
  try {
    const headers = { 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'AppCrane-Coder' };
    if (token) headers.Authorization = `token ${token}`;
    const url = `https://api.github.com/repos/${owner}/${repo}/pulls?state=open&head=${owner}:${encodeURIComponent(branch)}&per_page=1`;
    const r = await fetch(url, { headers });
    if (!r.ok) return null;
    const arr = await r.json();
    return Array.isArray(arr) && arr.length ? arr[0] : null;
  } catch (err) {
    onLog?.(`[studio:git] open-PR check failed (proceeding without it): ${err.message}`);
    return null;
  }
}

/**
 * Safety net for the planner-prompt rule that says "if deployhub.json
 * exists, bump it to match package.json's version". The agent sometimes
 * forgets to touch deployhub.json even though the prompt asks for both;
 * this post-process sync rewrites deployhub.json's version field to
 * match package.json's whenever they drift.
 *
 * Skips silently when either file is missing or unreadable — never
 * throws. Failures log a non-fatal warning via onLog.
 */
function syncDeployhubVersion(workspaceDir, onLog) {
  const pkgPath = join(workspaceDir, 'package.json');     // nosemgrep: path-join-resolve-traversal — workspaceDir is internal
  const dhPath  = join(workspaceDir, 'deployhub.json');   // nosemgrep
  if (!existsSync(pkgPath) || !existsSync(dhPath)) return;
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  const dh  = JSON.parse(readFileSync(dhPath,  'utf8'));
  if (!pkg?.version) return;
  if (dh.version === pkg.version) return;
  const before = dh.version;
  dh.version = pkg.version;
  writeFileSync(dhPath, JSON.stringify(dh, null, 2) + '\n');
  onLog?.(`[studio] Synced deployhub.json version ${before} → ${pkg.version} (matches package.json)`);
}

function workspaceRoot() {
  return join(resolve(process.env.DATA_DIR || './data'), 'appstudio-jobs');
}

function jobDir(jobId) {
  return join(workspaceRoot(), String(jobId)); // nosemgrep: path-join-resolve-traversal — jobId is an integer from DB
}

export function cleanupWorkspace(jobId) {
  try { rmSync(jobDir(jobId), { recursive: true, force: true }); } catch (_) {}
}

const STUDIO_IMAGE_VERSION = '3'; // bump to force image rebuild
// v3 (2026-05-03): rebuild to pull latest @anthropic-ai/claude-code in
// case a cached older CLI looks at a different credentials.json path
// than what AppCrane mounts. Symptom: "Not logged in · Please run /login"
// even with valid OAuth credentials uploaded.

// Build the studio Docker image when missing or outdated.
//
// Recipe lives in infra/studio.Dockerfile (checked into git so the build
// path is reviewable + re-runnable by hand via scripts/build-studio-image.sh).
// We copy the file into a scratch build context and pass STUDIO_IMAGE_VERSION
// as a build-arg so the label tracks the JS const here.
//
// Falls back to writing the recipe inline if the checked-in file is somehow
// missing — keeps dev hosts running before they pull the latest tree.
export async function ensureStudioImage(onLog) {
  try {
    const info = execFileSync('docker', ['image', 'inspect', '--format', '{{index .Config.Labels "appcrane.studio.version"}}', STUDIO_IMAGE], { stdio: 'pipe', timeout: 10000 });
    if (info.toString().trim() === STUDIO_IMAGE_VERSION) return;
    onLog?.('[studio] Studio image outdated, rebuilding…');
  } catch (_) {
    onLog?.('[studio] Building studio image (one-time setup, ~2 min)…');
  }

  const buildDir = join(workspaceRoot(), '_image-build');
  mkdirSync(buildDir, { recursive: true });

  // Resolve infra/studio.Dockerfile relative to this file
  // (server/services/appstudio/generator.js → ../../../infra/studio.Dockerfile)
  const checkedInDockerfile = resolve(import.meta.dirname, '..', '..', '..', 'infra', 'studio.Dockerfile');
  const buildDockerfile = join(buildDir, 'Dockerfile');
  if (existsSync(checkedInDockerfile)) {
    writeFileSync(buildDockerfile, readFileSync(checkedInDockerfile, 'utf8'));
  } else {
    onLog?.('[studio] infra/studio.Dockerfile missing — using inline recipe');
    writeFileSync(buildDockerfile, [
      'ARG STUDIO_IMAGE_VERSION=3',
      'FROM node:20-alpine',
      'ARG STUDIO_IMAGE_VERSION',
      'LABEL appcrane.studio.version="${STUDIO_IMAGE_VERSION}"',
      'RUN apk add --no-cache git',
      'RUN npm install -g @anthropic-ai/claude-code',
      'RUN addgroup -S studio && adduser -S -G studio studio \\',
      '    && mkdir -p /home/studio /workspace \\',
      '    && chown studio:studio /home/studio /workspace',
      'USER studio',
    ].join('\n'));
  }

  await new Promise((res, rej) => {
    const build = spawn('docker', [
      'build',
      '--build-arg', `STUDIO_IMAGE_VERSION=${STUDIO_IMAGE_VERSION}`,
      '-t', STUDIO_IMAGE,
      buildDir,
    ], { stdio: 'pipe' });
    const emit = (l) => { if (l.trim()) onLog?.(`[build] ${l}`); };
    build.stdout.on('data', (c) => c.toString().split('\n').forEach(emit));
    build.stderr.on('data', (c) => c.toString().split('\n').forEach(emit));
    build.on('error', rej);
    build.on('close', (code) => code === 0 ? res() : rej(new Error(`docker build failed (exit ${code})`)));
  });

  onLog?.('[studio] Studio image ready');
}

async function cloneForCode(dir, app, baseBranch, branchName, onLog) {
  const workspaceDir = join(dir, 'workspace');
  mkdirSync(workspaceDir, { recursive: true });
  chmodSync(workspaceDir, 0o777); // explicit chmod — mkdirSync mode is clipped by umask

  let cloneUrl = app.github_url;
  let token = null;
  if (app.github_token_encrypted) {
    try {
      token = decrypt(app.github_token_encrypted);
      const url = new URL(app.github_url);
      url.username = token;
      cloneUrl = url.toString();
    } catch (_) {}
  }

  // Detect whether the branch already exists on the remote — happens when a
  // prior coder run pushed the branch and this is a re-coding attempt for
  // the same enhancement. Three cases:
  //   1. Branch exists AND has an open PR  → REFUSE. Force-pushing would
  //      rewrite the PR's history; we don't want to silently destroy review
  //      comments / approvals tied to the original commits.
  //   2. Branch exists, no open PR         → clone FROM that branch so the
  //      agent's new work goes on top of the prior commits. push then
  //      fast-forwards naturally — no force needed.
  //   3. Branch does not exist             → clone baseBranch + create the
  //      new branch (original behavior).
  // Avoids the previous bug where every re-coding attempt force-pushed and
  // wiped out the prior coder's commits (and any open PR's history).
  const remoteBranchExists = checkRemoteBranchExists(cloneUrl, branchName, onLog);
  let cloneFromBranch = baseBranch;
  let isContinuation  = false;
  if (remoteBranchExists) {
    const openPr = await checkOpenPr(app, branchName, token, onLog);
    if (openPr) {
      throw new Error(
        `Branch ${branchName} already has open PR #${openPr.number} (${openPr.html_url}). ` +
        `Re-coding would overwrite the PR's history. Close or merge the PR first, ` +
        `then re-trigger coding.`,
      );
    }
    onLog?.(`[studio:git] Branch ${branchName} already exists on remote — continuing on top of prior commits`);
    cloneFromBranch = branchName;
    isContinuation  = true;
  }

  onLog?.(`[studio:git] Cloning ${app.github_url} (${cloneFromBranch})…`);
  try {
    execFileSync('git', ['clone', '--depth', '1', '--branch', cloneFromBranch, cloneUrl, workspaceDir], {
      timeout: 120000, stdio: 'pipe',
    });
  } catch (err) {
    throw new Error(err.message.replaceAll(cloneUrl, app.github_url));
  }

  execFileSync('git', ['-C', workspaceDir, 'config', 'user.email', 'appstudio@appcrane.local'], { stdio: 'pipe' });
  execFileSync('git', ['-C', workspaceDir, 'config', 'user.name', 'AppStudio'], { stdio: 'pipe' });
  if (isContinuation) {
    // Already on the right branch from --branch above; nothing to create.
    onLog?.(`[studio:git] On branch ${branchName} (continuation)`);
  } else {
    onLog?.(`[studio:git] Creating branch ${branchName}…`);
    execFileSync('git', ['-C', workspaceDir, 'checkout', '-b', branchName], { stdio: 'pipe' });
  }

  // Make workspace fully accessible to the container's studio user.
  // chmod 777 works regardless of who runs AppCrane (no root needed) and
  // ensures directory execute bits are set so the studio user can traverse all paths.
  try { execFileSync('chmod', ['-R', '777', workspaceDir], { stdio: 'pipe' }); } catch (_) {}
  try { execFileSync('chown', ['-R', '1000:1000', workspaceDir], { stdio: 'pipe' }); } catch (_) {}

  writeFileSync(join(workspaceDir, 'CLAUDE.md'), buildWorkspaceClaude(), { mode: 0o644 }); // nosemgrep

  // Drop a GitHub-state snapshot into .appcrane/ before the container starts.
  // The token stays on the host. Fail-soft: snapshot errors do not block coding.
  try { await writeSnapshot(app, workspaceDir, onLog); } catch (err) {
    log.warn(`AppStudio: snapshot write failed for ${app.slug}: ${err.message}`);
  }

  onLog?.(`[studio:git] Workspace ready at host path ${workspaceDir}`);
  return workspaceDir;
}

function buildWorkspaceClaude() {
  return `# AppStudio Coder Agent — Environment Guide

## Where you are
You are running inside a Docker container as the \`studio\` user.
- Your working directory is \`/workspace\` — the full app codebase, pre-cloned from GitHub.
- You can read and write all files in \`/workspace\`.
- \`/studio/prompt.txt\` contains the full task description (already loaded as your prompt).

## Your job
Implement exactly the files described in the approved plan.
Make all changes directly in \`/workspace\`.

## When you are done
Run \`git add\` to stage every file you changed or created — nothing more.
Do NOT commit. Do NOT push. The host handles commit, push, and deploy automatically after you exit.

Example:
\`\`\`
git add path/to/changed/file.js path/to/new/file.jsx
\`\`\`
Or to stage everything you touched:
\`\`\`
git add -A
\`\`\`

Then exit. That's it.

## Version bump (required)
Always apply a patch version bump to \`package.json\` — increment the last digit of the \`version\` field (e.g. \`1.2.3\` → \`1.2.4\`). Do this even if the plan does not list it. This is mandatory for every enhancement.

## Hard constraints
- Do NOT run \`npm install\` or \`yarn\` for a full install — the host regenerates \`package-lock.json\` automatically after you finish if you modified \`package.json\`.
- Do NOT start or restart any server or process.
- Do NOT run tests.
- Do NOT push to git.
- Do NOT modify files outside the plan unless fixing a direct dependency.
- Do NOT add unrelated refactoring or "improvements".
- Do NOT modify database schemas or deploy configs unless the plan explicitly lists them.

## Git safe directory
If git warns about safe.directory, run:
\`\`\`
git config --global --add safe.directory /workspace
\`\`\`
`;
}

function buildPrompt({ plan, summary, agentContext, contextDoc, enhancementMessage, enhancementId }) {
  const testSection = plan?.test_files?.length
    ? `# Test files to write\nThe plan requires these test files (create or update each one):\n${
        plan.test_files.map(f => `- ${f.path} (${f.action}): ${f.what}`).join('\n')
      }\nFollow the testing framework and style already used in the repo.`
    : '# Tests\nNo specific test files were planned. If you can identify an appropriate test file to add coverage for your changes, create it.';

  const contextSection = contextDoc
    ? `# Codebase context\nUse this architectural overview to skip broad exploration. Read specific files directly when you need exact details.\n\n${contextDoc}\n`
    : '';

  // Open feedback comments (bugs / notes / reviews) the operator added on
  // the request since the last code attempt. Empty when nothing's open.
  const openFeedback = enhancementId ? renderOpenCommentsSection(enhancementId) : '';

  return `You are implementing an approved change to an existing application.
The codebase is already cloned into the current working directory.

${contextSection}# Project history
A GitHub state snapshot has been written to \`.appcrane/github-snapshot.md\` in
the workspace. It contains recent commits, open pull requests, open feature
requests, and recent releases. Read it if you need to understand what has
already shipped or what is in flight before changing files.

# Enhancement request
${enhancementMessage}
${openFeedback ? '\n' + openFeedback + '\n' : ''}
# Approved plan
\`\`\`json
${JSON.stringify(plan, null, 2)}
\`\`\`

# Plan summary
${summary}

${testSection}

# Per-app context from the operator
${agentContext || '(none)'}

# Rules
- Implement all files listed in files_to_change AND all files listed in test_files.
- Do NOT modify database schemas or deploy configs unless the plan explicitly lists them.
- Do NOT add unrelated refactoring or "improvements".
- Do NOT run tests, npm install, or any server — just write the files.
- Stage all changes when done — the runner will commit and push.
- Do NOT push.`;
}

// (No embedded runner.js — runAgentNew invokes claude directly inside the
// container, parses stream-json on the host, and uses container exit code
// in place of the previous /sentinel/done file.)

/**
 * Clone a specific branch from GitHub to a local dir for the build/deploy phase.
 */
export function cloneForBuild(jobId, app, branch) {
  const dir = join(workspaceRoot(), `build-${jobId}`); // nosemgrep: path-join-resolve-traversal — jobId is integer
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });

  let cloneUrl = app.github_url;
  if (app.github_token_encrypted) {
    try {
      const token = decrypt(app.github_token_encrypted);
      const url = new URL(app.github_url);
      url.username = token;
      cloneUrl = url.toString();
    } catch (_) {}
  }

  try {
    execFileSync('git', ['clone', '--depth', '1', '--branch', branch, cloneUrl, dir], {
      timeout: 120000, stdio: 'pipe',
    });
  } catch (err) {
    throw new Error(err.message.replaceAll(cloneUrl, app.github_url));
  }
  log.info(`AppStudio: cloned branch ${branch} for build into ${dir}`);
  return dir;
}

/**
 * Run Claude Code inside a Docker container to implement the plan.
 * The repo is cloned on the host before the container starts — no git credentials
 * are passed into the container. When Claude Code finishes writing files it writes
 * a sentinel file; the host detects it and calls onCodingDone(workspaceDir, branchName)
 * to run git add/commit/push. Returns { branchName }.
 */
export async function generateCode({ jobId, app, enhancementId, plan, summary, agentContext, contextDoc, enhancementMessage, onLog, onCodingDone }) {
  const dir = jobDir(jobId);
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });

  await ensureStudioImage(onLog);

  const branchName   = `appstudio/${enhancementId}-${app.slug}`;

  // Clone the repo on the host — no credentials reach the container
  const workspaceDir = await cloneForCode(dir, app, app.branch || 'main', branchName, onLog);
  const prompt = buildPrompt({ plan, summary, agentContext, contextDoc, enhancementMessage, enhancementId });
  if (contextDoc) onLog?.(`[studio] Injected codebase context (${contextDoc.length} chars) — coder will skip orientation exploration`);

  const containerName = `appcrane-studio-${jobId}`;
  assertCapacity();
  onLog?.(`[studio] Starting container ${containerName} (git credentials stay on host)`);
  log.info(`AppStudio: running container ${containerName}`);

  const runner = runAgentNew({
    image:         STUDIO_IMAGE,
    containerName,
    workspaceDir,
    prompt,
    apiKey:        process.env.ANTHROPIC_API_KEY,
    model:         GEN_MODEL,
    timeoutMs:     GEN_TIMEOUT_MS + 60000,
    appSlug:       app.slug,
    labels:        {
      'appcrane.container.type': 'job',
      'enhancement_id':          String(enhancementId),
    },
    memory: '2g',
    cpus:   '1',
  });

  return new Promise((resolve, reject) => {
    let timedOut = false;

    runner.on('data', (ev) => {
      if (ev.type === 'text')      onLog?.(ev.text);
      else if (ev.type === 'tool') {
        const crumb = formatToolBreadcrumb(ev);
        if (crumb) onLog?.(`[studio:tool] ${crumb}`);
      }
    });
    runner.on('result', (ev) => {
      onLog?.(`[studio:result] ${ev.inputTokens + ev.outputTokens} tokens · $${(ev.costUsdCents / 100).toFixed(3)}`);
    });
    runner.on('error', (err) => {
      timedOut = /timed out/i.test(err.message);
      // Best-effort container kill on timeout
      if (timedOut) {
        try { execFileSync('docker', ['stop', '-t', '5', containerName], { stdio: 'pipe', timeout: 15000 }); } catch (_) {}
      }
      reject(timedOut ? new Error('Code generation timed out') : err);
    });
    runner.on('exit', async (code) => {
      if (timedOut) return; // already rejected via 'error'
      if (code !== 0) return reject(new Error(`Studio container exited with code ${code}`));
      // Container exit 0 = claude finished cleanly. This replaces the prior
      // /sentinel/done file: a clean exit IS the success signal.
      try { syncDeployhubVersion(workspaceDir, onLog); } catch (e) { onLog?.(`[studio] deployhub.json sync failed (non-fatal): ${e.message}`); }
      onLog?.('[studio] Coding complete — committing and pushing…');
      try {
        await onCodingDone?.(workspaceDir, branchName);
      } catch (err) {
        return reject(err);
      }
      resolve({ branchName });
    });

    runner.start();
  });
}
