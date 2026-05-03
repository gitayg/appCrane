import { execFileSync } from 'child_process';
import { mkdirSync, chmodSync, existsSync, rmSync } from 'fs';
import { join, resolve } from 'path';
import { decrypt } from '../encryption.js';
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

export function onEvict(fn) {
  evictSubs.add(fn);
  return () => evictSubs.delete(fn);
}

function notifyEvict(slug, reason) {
  for (const fn of evictSubs) {
    try { fn(slug, reason); } catch (err) { log.warn(`appContainer evict subscriber error: ${err.message}`); }
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

function cloneWorkspace(app, onLog) {
  const workspaceDir = workspaceDirFor(app.slug);
  // No workspace caching — start fresh every time the container is created
  if (existsSync(workspaceDir)) {
    try { rmSync(workspaceDir, { recursive: true, force: true }); } catch (_) {}
  }
  mkdirSync(workspaceDir, { recursive: true });
  chmodSync(workspaceDir, 0o777);

  let cloneUrl = app.github_url;
  if (app.github_token_encrypted) {
    try {
      const token = decrypt(app.github_token_encrypted);
      const url = new URL(app.github_url);
      url.username = token;
      cloneUrl = url.toString();
    } catch (_) {}
  }

  onLog?.(`[appContainer:git] Cloning ${app.github_url} (${app.branch || 'main'})…`);
  try {
    execFileSync('git', ['clone', '--depth', '1', '--branch', app.branch || 'main', cloneUrl, workspaceDir], {
      stdio: 'pipe', timeout: 120000,
    });
  } catch (err) {
    throw new Error(err.message.replaceAll(cloneUrl, app.github_url));
  }

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
  const args = [
    'run', '-d', '--rm',
    '--name', containerName,
    '--label', 'appcrane=true',
    '--label', 'appcrane.container.type=app',
    '--label', `app.slug=${slug}`,
    '--memory=2g', '--cpus=1',
    '-v', `${workspaceDir}:/workspace`,
  ];
  if (credsMount)  args.push('-v', `${credsMount.tmpFile}:/home/studio/.claude/credentials.json`);
  if (skillsMount) args.push('-v', `${skillsMount.dir}:/home/studio/.claude/skills:ro`);
  args.push(STUDIO_IMAGE, 'tail', '-f', '/dev/null');

  onLog?.(`[appContainer] Starting ${containerName}…`);
  const out = execFileSync('docker', args, { stdio: 'pipe', timeout: 30000 });
  const containerId = out.toString().trim();
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
    const workspaceDir = cloneWorkspace(app, onLog);
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

/**
 * Tear down the container for an app and delete its workspace.
 * Notifies subscribers so they can mark dependent rows.
 */
export function evict(slug, reason = 'manual') {
  const c = containers.get(slug);
  if (!c) {
    // Nothing in memory — still try to kill any leftover container + workspace dir
    const containerName = `appcrane-app-${slug}`;
    try { execFileSync('docker', ['rm', '-f', containerName], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}
    try { rmSync(workspaceDirFor(slug), { recursive: true, force: true }); } catch (_) {}
    notifyEvict(slug, reason);
    return false;
  }
  containers.delete(slug);
  if (c.containerId) {
    try { execFileSync('docker', ['stop', '-t', '5', c.containerId], { stdio: 'pipe', timeout: 15000 }); } catch (_) {}
    try { execFileSync('docker', ['rm', '-f', c.containerId], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}
  }
  // credsCleanup must run BEFORE skillsCleanup so the refreshed credentials
  // file (rewritten by the in-container CLI on token refresh) gets read
  // back and persisted to the encrypted DB column. Wiping the tmpdir
  // first would lose the refreshed token.
  if (c.credsCleanup)  { try { c.credsCleanup();  } catch (_) {} }
  if (c.skillsCleanup) { try { c.skillsCleanup(); } catch (_) {} }
  // No workspace caching — wipe the directory so the next session re-clones fresh
  try { rmSync(workspaceDirFor(slug), { recursive: true, force: true }); } catch (_) {}
  log.info(`appContainer: evicted ${slug} (${reason})`);
  notifyEvict(slug, reason);
  return true;
}

setInterval(() => {
  const threshold = Date.now() - IDLE_EVICT_MS;
  for (const [slug, c] of containers) {
    if (!c.ready || c.busy) continue;
    if (c.lastActivityAt > threshold) continue;
    evict(slug, 'idle');
  }
}, SWEEP_MS);

/**
 * Called once on AppCrane startup. Kills any leftover app containers from a
 * previous process and clears the on-disk workspace root (no caching across
 * restart).
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
    if (existsSync(root)) rmSync(root, { recursive: true, force: true });
  } catch (_) {}
}
