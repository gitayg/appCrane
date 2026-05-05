/**
 * Per-user GitHub MCP container manager.
 *
 * Each user's MCP client passes their GitHub PAT in an X-Github-Token header
 * (set in their `claude mcp add` command). On the first github_* tool call,
 * AppCrane spawns a github-mcp-server Docker container scoped to that user
 * with their PAT in env. Subsequent calls reuse the running container.
 * Idle reaper kills containers after settings.github_mcp_idle_timeout
 * seconds. A configurable cap (max_concurrent) limits total concurrent
 * containers across all users; the cap-busting user gets a friendly
 * "retry in N minutes" error.
 *
 * State is in-memory only (Map<user_id, entry>). On AppCrane restart we
 * stop any orphaned containers labeled appcrane.gh-mcp=1 to avoid leaks.
 */

import { execFileSync } from 'child_process';
import { StdioMcpClient } from './mcpStdioBridge.js';
import { getDb } from '../db.js';
import log from '../utils/logger.js';

/** user_id → { client, startedAt, lastActiveAt, tokenHash, toolsCache } */
const containers = new Map();

let _reaperInterval = null;

function getSettings() {
  const db = getDb();
  const get = (key, fallback) => {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
    return row?.value || fallback;
  };
  return {
    idleTimeoutMs:  parseInt(get('github_mcp_idle_timeout',   '600'), 10) * 1000,
    maxConcurrent:  parseInt(get('github_mcp_max_concurrent', '10'),  10),
    image:          get('github_mcp_image', 'ghcr.io/github/github-mcp-server:latest'),
  };
}

/** Quick hash so we can detect PAT rotation without storing the PAT. */
function tokenHashShort(token) {
  let h = 0;
  for (let i = 0; i < token.length; i++) h = (h * 31 + token.charCodeAt(i)) | 0;
  return String(h);
}

/**
 * Get-or-spawn a container for `userId`. Returns the live StdioMcpClient.
 * Throws CapacityError if the global cap is reached.
 */
export async function getOrSpawn(userId, githubToken) {
  if (!githubToken) {
    throw new Error('No GitHub token provided. Add `--header "X-Github-Token: ghp_..."` to your AppCrane MCP setup command.');
  }
  const tHash = tokenHashShort(githubToken);

  const existing = containers.get(userId);
  if (existing && existing.client.isAlive() && existing.tokenHash === tHash) {
    existing.lastActiveAt = Date.now();
    return existing;
  }
  // PAT rotated — kill the old container so a fresh one spawns with the new token
  if (existing && existing.tokenHash !== tHash) {
    log.info(`[gh-mcp] PAT rotated for user ${userId} — respawning`);
    existing.client.kill();
    containers.delete(userId);
  }

  const { image, maxConcurrent, idleTimeoutMs } = getSettings();
  if (containers.size >= maxConcurrent) {
    const retryMin = Math.max(1, Math.round(idleTimeoutMs / 1000 / 60 / 2));
    const err = new Error(
      `GitHub MCP is at capacity (${maxConcurrent} active users). ` +
      `Try again in about ${retryMin} minute${retryMin === 1 ? '' : 's'} — idle containers free up automatically.`
    );
    err.code = 'GH_MCP_CAPACITY';
    throw err;
  }

  log.info(`[gh-mcp] spawning container for user ${userId} (image=${image})`);
  const client = new StdioMcpClient({
    image,
    env: { GITHUB_PERSONAL_ACCESS_TOKEN: githubToken },
    label: `user-${userId}`,
  });
  await client.start(); // initialize handshake or throw

  const entry = {
    client,
    startedAt: Date.now(),
    lastActiveAt: Date.now(),
    tokenHash: tHash,
    toolsCache: null,
  };
  containers.set(userId, entry);
  return entry;
}

/**
 * Cached tools/list for a user. First call spawns + asks the container; later
 * calls return the cached result (within the same container lifetime).
 */
export async function listToolsForUser(userId, githubToken) {
  const entry = await getOrSpawn(userId, githubToken);
  if (!entry.toolsCache) {
    const r = await entry.client.call('tools/list');
    entry.toolsCache = r?.tools || [];
  }
  return entry.toolsCache;
}

export async function callToolForUser(userId, githubToken, name, args) {
  const entry = await getOrSpawn(userId, githubToken);
  entry.lastActiveAt = Date.now();
  return entry.client.call('tools/call', { name, arguments: args || {} });
}

export function killUserContainer(userId) {
  const entry = containers.get(userId);
  if (!entry) return false;
  entry.client.kill();
  containers.delete(userId);
  return true;
}

/** Roster snapshot for the admin UI. */
export function listActive() {
  const out = [];
  for (const [userId, e] of containers) {
    out.push({
      user_id: userId,
      started_at: new Date(e.startedAt).toISOString(),
      last_active_at: new Date(e.lastActiveAt).toISOString(),
      idle_seconds: Math.floor((Date.now() - e.lastActiveAt) / 1000),
      alive: e.client.isAlive(),
    });
  }
  return out;
}

/** Reaper — kill containers idle longer than idleTimeoutMs. */
export function reaperTick() {
  const { idleTimeoutMs } = getSettings();
  const now = Date.now();
  for (const [userId, entry] of containers) {
    if (now - entry.lastActiveAt > idleTimeoutMs || !entry.client.isAlive()) {
      entry.client.kill();
      containers.delete(userId);
      log.info(`[gh-mcp] reaped container for user ${userId} (idle ${Math.round((now - entry.lastActiveAt)/1000)}s)`);
    }
  }
}

/** Stop any orphan containers from a previous AppCrane process. */
function killOrphans() {
  try {
    const out = execFileSync('docker', ['ps', '-q', '--filter', 'label=appcrane.gh-mcp=1'], { stdio: 'pipe', timeout: 5000 }).toString().trim();
    if (!out) return;
    const ids = out.split('\n').filter(Boolean);
    for (const id of ids) {
      try { execFileSync('docker', ['stop', id], { stdio: 'pipe', timeout: 8000 }); } catch (_) {}
    }
    log.info(`[gh-mcp] killed ${ids.length} orphan container(s) on startup`);
  } catch (_) {
    // docker not available or no containers — fine
  }
}

export function startContainerManager() {
  if (_reaperInterval) return;
  killOrphans();
  _reaperInterval = setInterval(reaperTick, 60_000);
  log.info('GitHub MCP container manager started');
}

export function stopContainerManager() {
  if (_reaperInterval) clearInterval(_reaperInterval);
  _reaperInterval = null;
  for (const [userId] of containers) killUserContainer(userId);
}
