import { execFileSync } from 'child_process';
import { mkdirSync, chmodSync, existsSync, rmSync, readdirSync } from 'fs';
import { join, resolve } from 'path';
import { getDb } from '../../db.js';
import { usesLocalRepo, cloneLocalRepoForDeploy } from '../managedRepo.js';
import { isEnvFilePath } from '../envFilePushGuard.js';
import { ensureStudioImage } from '../appstudio/generator.js';
import { writeSnapshot } from '../github/snapshot.js';
import { prepareSkillsMount } from '../skills.js';
import { prepareClaudeCredentialsMount } from '../claudeCredentials.js';
import log from '../../utils/logger.js';

const STUDIO_IMAGE  = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';
const IDLE_EVICT_MS = parseInt(process.env.CODER_IDLE_MS || '1800000', 10); // 30 min
const SWEEP_MS      = 5 * 60 * 1000;

// slug -> AppContainer state
const containers = new Map();
// slug -> Promise (in-flight create — multiple callers wait on the same one)
const creating = new Map();
// Subscribers notified when a container is evicted: fn(slug, reason)
const evictSubs = new Set();

function rootDir() {
  return resolve(join(process.env.DATA_DIR || './data', 'app-containers'));
}
function appDir(slug) { return join(rootDir(), slug); }
function workspaceDirFor(slug) { return join(appDir(slug), 'workspace'); }

/**
 * Where Claude Code keeps conversation transcripts inside the container.
 *
 * MEASURED, not assumed, inside the real appcrane-studio image (CLI 2.1.197),
 * with HOME=/home/studio and cwd=/workspace:
 *
 *   - `claude -p --resume <uuid>` with nothing on disk        -> "No conversation
 *     found with session ID: <uuid>"
 *   - the same id planted at $HOME/.claude/sessions/<uuid>.jsonl -> still "No
 *     conversation found" (that directory holds IPC key/json files, not chats)
 *   - the same id planted at $HOME/.claude/projects/-workspace/<uuid>.jsonl ->
 *     the lookup SUCCEEDS and the CLI advances to the next stage ("Not logged
 *     in · Please run /login")
 *
 * So the transcript a `--resume` needs lives under $HOME/.claude/projects, in a
 * per-cwd subdirectory. The whole `projects` directory is mounted rather than
 * one cwd subdirectory, so the path the CLI derives from cwd never has to be
 * reproduced here.
 *
 * Nothing else in ~/.claude is mounted: credentials (already mounted) and
 * skills are the only other things AppCrane puts there, and ~/.claude.json
 * holds CLI-local preferences a fresh container is happy to rebuild.
 */
export const CONTAINER_CLAUDE_PROJECTS_DIR = '/home/studio/.claude/projects';

/**
 * Host side of that mount. Per app, because the container is per app, under
 * DATA_DIR next to the workspace — NOT inside it, or the workspace wipe below
 * would take the transcripts with it, which is the whole point.
 */
export function transcriptDirFor(slug) { return join(appDir(slug), 'claude-projects'); }

/**
 * Files a user attached to coder messages, per session. Kept across restarts
 * like the transcripts, because a queued follow-up or a resumed session still
 * refers to them. Never inside the workspace: an attachment is not a change to
 * the app, and must not appear in the Changes tab or be released.
 */
export function attachmentsDirFor(slug, sessionId) { return join(appDir(slug), 'attachments', sessionId); }

/**
 * Exactly the treatment the workspace gets, for the same reason: this directory
 * holds a record of the source the agent read and wrote, so it is no less
 * sensitive than /workspace and gets no weaker containment — same per-app
 * parent under DATA_DIR (0755, owned by the AppCrane process), same 0777 on the
 * directory itself.
 *
 * The chown is to the image's studio user, pinned to 100:101 in
 * infra/studio.Dockerfile. Before v2.90.4 it was `chown -R 1000:1000`, which is
 * not that user: Claude writes its transcripts mode 0600, so every container
 * start handed the agent's own conversation to a uid it does not run as.
 * Measured on a real instance: the transcript `-rw------- node node`, the
 * agent `uid=100(studio)`, and `cat` of it refused. Every turn after that
 * resumed a conversation it could not read or extend. Recursive, so a
 * directory already re-owned by an older release is repaired on the next
 * start. Best-effort: it fails when AppCrane does not run as root, and then the
 * files are already owned by the uid the container wrote them as.
 */
export const STUDIO_UID = 100;
export const STUDIO_GID = 101;

function prepareTranscriptDir(slug) {
  const dir = transcriptDirFor(slug);
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o777);
  try { execFileSync('chown', ['-R', `${STUDIO_UID}:${STUDIO_GID}`, dir], { stdio: 'pipe' }); } catch (_) {}
  return dir;
}

export function onEvict(fn) {
  evictSubs.add(fn);
  return () => evictSubs.delete(fn);
}

// `preserved` is additive — existing subscribers take (slug, reason) and are
// unaffected; a subscriber that wants to tell the user where their work went
// can read it.
function notifyEvict(slug, reason, preserved = null) {
  for (const fn of evictSubs) {
    try { fn(slug, reason, preserved); } catch (err) { log.warn(`appContainer evict subscriber error: ${err.message}`); }
  }
}

export function getContainer(slug) {
  const c = containers.get(slug);
  return c?.ready ? c : null;
}

export function listContainers() {
  return [...containers.values()].filter(c => c.ready).map(c => ({
    slug: c.appSlug,
    containerId: c.containerId,
    workspaceDir: c.workspaceDir,
    branchName: c.branchName,
    claudeSessionId: c.claudeSessionId,
    lastActivityAt: c.lastActivityAt,
    busy: c.busy,
  }));
}

export function heartbeat(slug) {
  const c = containers.get(slug);
  if (c?.ready) c.lastActivityAt = Date.now();
}

export function setBusy(slug, busy) {
  const c = containers.get(slug);
  if (c?.ready) c.busy = !!busy;
}

export function setClaudeSessionId(slug, id) {
  const c = containers.get(slug);
  if (c?.ready && id && c.claudeSessionId !== id) c.claudeSessionId = id;
}

async function cloneWorkspace(app, onLog) {
  const workspaceDir = workspaceDirFor(app.slug);
  // No workspace caching — start fresh every time the container is created
  if (existsSync(workspaceDir)) {
    try { rmSync(workspaceDir, { recursive: true, force: true }); } catch (_) {}
  }
  mkdirSync(workspaceDir, { recursive: true });
  chmodSync(workspaceDir, 0o777);

  // The coder works on Crane-hosted apps only. Both routes that create a
  // container (POST /api/coder/:slug/session and .../resume) run
  // assertCraneHosted first, so a GitHub-backed app cannot get here; this is
  // the second check, not the first. The GitHub clone branch that stood here
  // (and the token handling it needed) was removed in v2.92.1: v2.83.0
  // retired /api/agents and gated resume, which left it unreachable.
  if (!usesLocalRepo(app)) {
    throw new Error(`The coder works on Crane-hosted apps only, and ${app.slug} is not one.`);
  }
  // Crane-hosted source: the repo is a bare repo on this host, reached by
  // path. There is no remote, so there is no credential. localGit's clone runs
  // git with the host's config, hooks and credential helpers cut off, exactly
  // as a deploy clone does.
  onLog?.(`[appContainer:git] Cloning Crane-hosted repo for ${app.slug} (${app.branch || 'main'})…`);
  await cloneLocalRepoForDeploy(app, workspaceDir, app.branch || 'main');

  execFileSync('git', ['-C', workspaceDir, 'config', 'user.email', 'builder@appcrane.local'], { stdio: 'pipe' });
  execFileSync('git', ['-C', workspaceDir, 'config', 'user.name', 'AppCrane Builder'], { stdio: 'pipe' });

  try { execFileSync('chmod', ['-R', '777', workspaceDir], { stdio: 'pipe' }); } catch (_) {}
  try { execFileSync('chown', ['-R', '1000:1000', workspaceDir], { stdio: 'pipe' }); } catch (_) {}

  return workspaceDir;
}

function startContainer(slug, workspaceDir, onLog) {
  const containerName = `appcrane-app-${slug}`;
  // Clean up any leftover container with the same name (previous AppCrane process)
  try { execFileSync('docker', ['rm', '-f', containerName], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}

  const skillsMount = prepareSkillsMount(slug);
  // Per-app Claude OAuth credentials override the global API key. The
  // mount is read-write so the CLI can refresh the access token in place;
  // the credsMount.cleanup callback (registered on the container teardown
  // path below) reads the file back and updates the encrypted DB column
  // so the next container start gets the freshest tokens.
  const credsMount = prepareClaudeCredentialsMount(slug);
  // The conversation, kept on the host. Without this the transcript dies with
  // the container while coder_sessions.claude_session_id keeps pointing at it,
  // so the next `claude -p --resume <id>` fails and the model starts over
  // behind a chat log the user still sees in full.
  const transcriptDir = prepareTranscriptDir(slug);
  // SECURITY hardening (v1.27.34 H7): drop all caps, no-new-privs, pids-limit.
  // Network stays default — agent needs GitHub + npm.
  const args = [
    'run', '-d', '--rm',
    '--name', containerName,
    '--label', 'appcrane=true',
    '--label', 'appcrane.container.type=app',
    '--label', `app.slug=${slug}`,
    '--memory=2g', '--cpus=1',
    '--cap-drop=ALL',
    '--security-opt', 'no-new-privileges:true',
    '--pids-limit=512',
    '-v', `${workspaceDir}:/workspace`,
    '-v', `${transcriptDir}:${CONTAINER_CLAUDE_PROJECTS_DIR}`,
  ];
  // Mount creds at BOTH credentials.json and .credentials.json — newer
  // Claude Code releases moved to the dot-prefixed path. Mount both so a
  // CLI version bump in the studio image doesn't silently break auth.
  if (credsMount)  args.push('-v', `${credsMount.tmpFile}:/home/studio/.claude/credentials.json`);
  if (credsMount)  args.push('-v', `${credsMount.tmpFile}:/home/studio/.claude/.credentials.json`);
  if (skillsMount) args.push('-v', `${skillsMount.dir}:/home/studio/.claude/skills:ro`);
  args.push(STUDIO_IMAGE, 'tail', '-f', '/dev/null');

  onLog?.(`[appContainer] Starting ${containerName}…`);
  const out = execFileSync('docker', args, { stdio: 'pipe', timeout: 30000 });
  const containerId = out.toString().trim();
  onLog?.(`[appContainer] Mounted conversation transcripts at ${CONTAINER_CLAUDE_PROJECTS_DIR}`);
  if (credsMount)  onLog?.(`[appContainer] Mounted Claude OAuth credentials (per-app)`);
  if (skillsMount) onLog?.(`[appContainer] Mounted skills dir`);
  onLog?.(`[appContainer] Container ready: ${containerId.slice(0, 12)}`);
  return {
    containerId,
    skillsCleanup: skillsMount?.cleanup || null,
    credsCleanup:  credsMount?.cleanup  || null,
  };
}

/**
 * Returns the live AppContainer for `app.slug`, creating it if necessary.
 * Concurrent calls during creation share the same in-flight promise.
 */
export async function getOrCreate(app, onLog) {
  const slug = app.slug;

  // Live + healthy → return as-is
  const existing = containers.get(slug);
  if (existing?.ready) {
    try {
      execFileSync('docker', ['inspect', '--format', '{{.State.Running}}', existing.containerId], { stdio: 'pipe', timeout: 5000 });
      heartbeat(slug);
      return existing;
    } catch (_) {
      log.warn(`appContainer: ${slug} container disappeared, recreating`);
      containers.delete(slug);
      notifyEvict(slug, 'container-vanished');
    }
  }

  // Already being created — share the in-flight promise
  if (creating.has(slug)) return creating.get(slug);

  const branchName = `builder/${slug}`;
  const promise = (async () => {
    await ensureStudioImage(onLog);
    const workspaceDir = await cloneWorkspace(app, onLog);
    try {
      await writeSnapshot(app, workspaceDir, onLog);
    } catch (err) {
      log.warn(`appContainer snapshot write failed for ${slug}: ${err.message}`);
    }

    // Create the shared builder branch in the workspace before the container starts
    try {
      execFileSync('git', ['-C', workspaceDir, 'checkout', '-B', branchName], { stdio: 'pipe' });
    } catch (err) {
      log.warn(`appContainer: failed to create branch ${branchName}: ${err.message}`);
    }

    const { containerId, skillsCleanup, credsCleanup } = startContainer(slug, workspaceDir, onLog);

    const c = {
      ready: true,
      busy: false,
      appSlug: slug,
      containerId,
      workspaceDir,
      branchName,
      claudeSessionId: null,
      lastActivityAt: Date.now(),
      skillsCleanup,
      credsCleanup,
    };
    containers.set(slug, c);
    log.info(`appContainer: created for ${slug} (container ${containerId.slice(0, 12)}, branch ${branchName})`);
    return c;
  })();

  creating.set(slug, promise);
  try {
    return await promise;
  } finally {
    creating.delete(slug);
  }
}

// ---------------------------------------------------------------------------
// Auto-commit on evict
// ---------------------------------------------------------------------------
//
// The workspace is wiped on eviction and the container runs with --rm, so an
// idle sweep 30 minutes into a coffee break used to delete every edit the agent
// had made and the user had not released. For a Crane-hosted app the managed
// repo is right here on this host, so the work is committed to a side branch
// first. It is a SAFETY NET, not a release: it never moves the default branch,
// never deploys, and is named so that both facts are visible from the ref.

const SAFE_BRANCH_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/**
 * The branch one session's rescued work goes to. `agent/` prefix so a reader
 * (and `git branch --list 'agent/*'`) can tell it from `builder/<slug>` — the
 * branch the session works on — and from anything a person chose to release.
 */
export function agentPreserveBranch(userId, sessionId) {
  const u = String(userId);
  const s = String(sessionId);
  if (!SAFE_BRANCH_ID_RE.test(u) || !SAFE_BRANCH_ID_RE.test(s)) {
    throw new Error(`appContainer: refusing to build a preserve branch from ${JSON.stringify(u)}/${JSON.stringify(s)}`);
  }
  return `agent/${u}/${s}`;
}

/**
 * Refuse any branch a push would deploy.
 *
 * deployTrigger.evaluatePush deploys a push whose branch equals
 * `webhook_configs.branch_filter || apps.branch || 'main'`, and branch_filter
 * defaults to 'main'. A preserve commit landing there would ship unreleased,
 * unreviewed agent work to sandbox the moment the user stepped away — the exact
 * opposite of a safety net. So the same three-way expression is re-read here
 * and matched against, rather than 'main' being assumed.
 */
export function assertPreserveBranchSafe(branch, app) {
  if (typeof branch !== 'string' || !branch.startsWith('agent/') || branch.split('/').length !== 3) {
    throw new Error(`appContainer: refusing preserve branch ${JSON.stringify(branch)} — it must be agent/<userId>/<sessionId>`);
  }
  let filter = null;
  try { filter = getDb().prepare('SELECT branch_filter FROM webhook_configs WHERE app_id = ?').get(app?.id)?.branch_filter; } catch (_) {}
  const deployBranch = filter || app?.branch || 'main';
  if (branch === deployBranch || branch === 'main' || branch === 'master') {
    throw new Error(`appContainer: refusing preserve branch ${JSON.stringify(branch)} — a push to it would deploy ${app?.slug}`);
  }
  return branch;
}

/**
 * `core.fileMode=false` is not a preference, it is a correction for something
 * this file does two hundred lines up: cloneWorkspace runs `chmod -R 777` so
 * the container user can write, which sets the executable bit on every tracked
 * file. Measured on a freshly created workspace, before the container even
 * starts:
 *
 *     $ git diff -- README.md
 *     old mode 100644
 *     new mode 100755
 *
 * So `git status` calls every file in the repo modified, and without this a
 * preserve commit would carry a mode flip for the entire tree and "no
 * uncommitted changes" would never be true. Set per invocation rather than in
 * the workspace's config, so the only git that sees it is this one. The one
 * other reader of worktree state left sets it the same way, per invocation
 * (builder/gitOps.js: workspaceGit). The third — the GitHub ship path's own
 * helper — went with /api/agents in v2.83.0.
 *
 * The cost: a file the agent newly creates is recorded 100644 even if it made
 * it executable. A rescue commit that has to have its `chmod +x` redone is a
 * far better outcome than no rescue commit.
 */
function gitIn(dir, args) {
  return execFileSync('git', ['-c', `safe.directory=${dir}`, '-c', 'core.fileMode=false', '-C', dir, ...args], {
    stdio: 'pipe', timeout: 60000,
  }).toString();
}

function stagedPaths(dir) {
  return gitIn(dir, ['diff', '--cached', '--name-only', '-z']).split('\0').filter(Boolean);
}

/**
 * Commit and push whatever the workspace has that the managed repo does not.
 * Returns a description of what happened; the caller logs it. Throws only on a
 * genuine git failure — evict() catches that, because eviction must complete.
 */
function preserveWorkspace(slug, workspaceDir) {
  if (!workspaceDir || !existsSync(join(workspaceDir, '.git'))) return { preserved: false, reason: 'no_workspace' };

  const db = getDb();
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  // A GitHub-backed app is untouched: its source lives behind a remote it has
  // its own branch-and-push flow for, and a credentialed push is not something
  // to start from a timer.
  if (!app || !usesLocalRepo(app)) return { preserved: false, reason: 'not_crane_hosted' };

  const session = db.prepare(`
    SELECT id, user_id FROM coder_sessions
    WHERE app_slug = ? AND workspace_dir = ?
    ORDER BY last_activity_at DESC, rowid DESC LIMIT 1
  `).get(slug, workspaceDir);
  if (!session) return { preserved: false, reason: 'no_session' };

  const branch = assertPreserveBranchSafe(agentPreserveBranch(session.user_id, session.id), app);

  gitIn(workspaceDir, ['add', '-A']);
  let staged = stagedPaths(workspaceDir);
  // Two kinds of path never go into a preserve commit:
  //
  //  - .env*, because envFilePushGuard refuses it on every other route into
  //    this repo and it is refusing a real problem — the secret would sit in
  //    git and in every backup forever. Un-staged rather than allowed to fail
  //    the whole rescue: one file the user still has nowhere is better than all
  //    of them.
  //  - .appcrane/, because AppCrane writes it into the workspace itself
  //    (github/snapshot.js) at container creation. It is untracked in every
  //    repo that has not deliberately committed it, so without this EVERY
  //    eviction would produce a preserve commit containing nothing but
  //    AppCrane's own scaffolding — and "no changes" would never be true.
  const excluded = staged.filter((p) => isEnvFilePath(p) || p === '.appcrane' || p.startsWith('.appcrane/'));
  const skippedEnvFiles = excluded.filter(isEnvFilePath);
  if (excluded.length) {
    gitIn(workspaceDir, ['reset', '-q', '--', ...excluded]);
    staged = stagedPaths(workspaceDir);
  }

  if (staged.length) {
    gitIn(workspaceDir, ['commit', '-m',
      `wip(agent): automatic snapshot of session ${session.id}\n\n` +
      'AppCrane committed this automatically when the Builder container for ' +
      `'${slug}' was evicted, so uncommitted work was not lost. It is NOT a ` +
      'release: nothing was reviewed, built or deployed.']);
  }

  const head = gitIn(workspaceDir, ['rev-parse', 'HEAD']).trim();
  // Nothing new at all — neither an uncommitted edit nor a commit the agent made
  // itself — so there is nothing to write. An empty ref would be noise a user
  // has to read and dismiss.
  let upstream = null;
  try { upstream = gitIn(workspaceDir, ['rev-parse', `refs/remotes/origin/${app.branch || 'main'}`]).trim(); } catch (_) {}
  if (!staged.length && head === upstream) return { preserved: false, reason: 'no_changes', skippedEnvFiles };

  // A session can be evicted more than once: it is resumed, gets a FRESH clone
  // of the deploy branch, and is evicted again. That second commit is not a
  // descendant of the first rescue, so pushing it to the same ref is a
  // non-fast-forward — which git rejects, and which --force would "fix" by
  // deleting the earlier rescue. Neither outcome is acceptable for a safety
  // net, so a rejected push moves to the next free `.N` suffix instead. Still
  // three slash-separated segments, so the deploy-branch guard applies to each.
  // Bounded: after ten rescues for one session, something is wrong and silently
  // creating refs forever is not the answer.
  const targets = [branch, ...Array.from({ length: 9 }, (_, i) => `${branch}.${i + 2}`)];
  let lastErr = null;
  for (const target of targets) {
    try {
      gitIn(workspaceDir, ['push', 'origin', `HEAD:refs/heads/${assertPreserveBranchSafe(target, app)}`]);
      return { preserved: true, branch: target, commit: head, files: staged.length, skippedEnvFiles };
    } catch (err) {
      lastErr = err;
      const why = String(err.stderr || err.message);
      // Only a ref that is already taken is worth another ref. Anything else
      // (repo gone, disk full, permissions) fails the same way ten times over.
      if (!/non-fast-forward|fetch first|\[rejected\]/i.test(why)) throw err;
    }
  }
  throw lastErr;
}

/**
 * Tear down the container for an app and delete its workspace.
 * Notifies subscribers so they can mark dependent rows.
 *
 * The transcript directory is deliberately NOT wiped — it is the session's
 * conversation, and `--resume` needs it after the container is gone.
 */
export function evict(slug, reason = 'manual') {
  const c = containers.get(slug);
  const workspaceDir = c?.workspaceDir || workspaceDirFor(slug);
  if (c) containers.delete(slug);

  if (c?.containerId) {
    try { execFileSync('docker', ['stop', '-t', '5', c.containerId], { stdio: 'pipe', timeout: 15000 }); } catch (_) {}
    try { execFileSync('docker', ['rm', '-f', c.containerId], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}
  } else {
    // Nothing in memory — still kill any leftover container from a previous process
    try { execFileSync('docker', ['rm', '-f', `appcrane-app-${slug}`], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}
  }

  // After the container is stopped, so nothing inside it is writing to the
  // workspace while it is staged; before the wipe, which is the whole point.
  // Eviction runs from a 5-minute sweeper and from route handlers: a failure
  // here must never stop the container being reclaimed, so it is logged and
  // carried in the notification, never thrown.
  let preserved = { preserved: false, reason: 'skipped' };
  try {
    preserved = preserveWorkspace(slug, workspaceDir);
    if (preserved.preserved) {
      log.info(`appContainer: ${slug} — ${preserved.files} uncommitted file(s) preserved on ${preserved.branch} (${preserved.commit.slice(0, 12)})`);
    }
    if (preserved.skippedEnvFiles?.length) {
      log.warn(`appContainer: ${slug} — left ${preserved.skippedEnvFiles.length} .env file(s) out of the preserve commit: ${preserved.skippedEnvFiles.join(', ')}`);
    }
  } catch (err) {
    log.warn(`appContainer: could not preserve ${slug}'s workspace before evicting it: ${err.message}`);
    preserved = { preserved: false, reason: 'error', error: err.message };
  }

  if (c) {
    // credsCleanup must run BEFORE skillsCleanup so the refreshed credentials
    // file (rewritten by the in-container CLI on token refresh) gets read
    // back and persisted to the encrypted DB column. Wiping the tmpdir
    // first would lose the refreshed token.
    if (c.credsCleanup)  { try { c.credsCleanup();  } catch (_) {} }
    if (c.skillsCleanup) { try { c.skillsCleanup(); } catch (_) {} }
  }
  // No workspace caching — wipe the directory so the next session re-clones fresh
  try { rmSync(workspaceDir, { recursive: true, force: true }); } catch (_) {}
  if (c) log.info(`appContainer: evicted ${slug} (${reason})`);
  notifyEvict(slug, reason, preserved);
  return !!c;
}

setInterval(() => {
  const threshold = Date.now() - IDLE_EVICT_MS;
  for (const [slug, c] of containers) {
    if (!c.ready || c.busy) continue;
    if (c.lastActivityAt > threshold) continue;
    evict(slug, 'idle');
  }
}, SWEEP_MS).unref();

/**
 * Called once on AppCrane startup. Kills any leftover app containers from a
 * previous process and clears the on-disk workspaces (no caching across
 * restart) -- but KEEPS every app's `claude-projects` transcripts.
 *
 * Wiping the whole root was what made transcripts survive an idle eviction and
 * die on `systemctl restart appcrane`: the mount was preserved for 30 minutes
 * and then silently lost at the next deploy of AppCrane itself, so `--resume`
 * failed on an id the database still held. Transcripts are retained
 * indefinitely by decision -- there is no retention limit yet, so this
 * directory grows without bound and is a GC question to answer later, not an
 * oversight.
 */
export function recoverOrphans() {
  try {
    const out = execFileSync(
      'docker',
      ['ps', '-a', '--format', '{{.Names}}', '--filter', 'label=appcrane.container.type=app'],
      { stdio: 'pipe', timeout: 8000 }
    );
    const names = out.toString().split('\n').map(s => s.trim()).filter(Boolean);
    for (const n of names) {
      try { execFileSync('docker', ['rm', '-f', n], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}
    }
    if (names.length) log.info(`appContainer: removed ${names.length} orphan container(s) on startup`);
  } catch (_) {}
  try {
    const root = rootDir();
    if (!existsSync(root)) return;
    // Per app, remove everything except the transcripts and attachments.
    for (const slug of readdirSync(root)) {
      const dir = join(root, slug);
      let entries = [];
      try { entries = readdirSync(dir); } catch (_) { continue; }
      for (const entry of entries) {
        if (entry === 'claude-projects' || entry === 'attachments') continue;
        try { rmSync(join(dir, entry), { recursive: true, force: true }); } catch (_) {}
      }
    }
  } catch (_) {}
}
