/**
 * Minimal MCP JSON-RPC client over stdio (NDJSON-framed).
 *
 * Wraps `docker run -i --rm <image>` as a child process. The container's
 * stdin/stdout become the MCP transport: one JSON object per line in each
 * direction. Used by services/githubMcpContainers.js to talk to a per-user
 * github-mcp-server.
 *
 * Lifecycle:
 *   const c = new StdioMcpClient({ image, env, label });
 *   await c.start();              // spawns docker, runs initialize
 *   const r = await c.call('tools/list');
 *   c.kill();                     // SIGTERM the container
 *
 * Pending calls are matched by JSON-RPC id. A 30-second per-call timeout
 * rejects stuck requests so a hung container can't deadlock AppCrane.
 */

import { spawn } from 'child_process';
import log from '../utils/logger.js';

const CALL_TIMEOUT_MS = parseInt(process.env.APPCRANE_GH_MCP_CALL_TIMEOUT_MS || '30000', 10);

// Must match APP_NETWORK in services/docker.js. Deliberately duplicated rather
// than imported: docker.js pulls in the deploy path, and this module is loaded
// by the MCP request path. test/mcp-bridge-secret-argv.test.js asserts the two
// strings are still equal, so drift fails a test instead of silently putting
// this container back on the default bridge.
const APP_NETWORK = 'appcrane-apps';

/**
 * Build the `docker run` argv and the environment to spawn it with.
 *
 * SECRETS ARE NOT ARGUMENTS. This used to interpolate `-e NAME=value` straight
 * into argv, which put a user's GitHub PAT into the docker process's command
 * line — readable from the host process list by any local user, and retained in
 * `docker inspect` for the life of the container. Docker's `-e NAME` form (no
 * `=`) reads the value from the CLI's own environment instead, so the token
 * reaches the container through the env block and never appears in argv.
 *
 * The environment handed to spawn is built from scratch rather than inherited.
 * AppCrane's process env holds ENCRYPTION_KEY — the master key for every stored
 * secret on the instance — and there is no reason for it to be one `docker
 * inspect` or one compromised entrypoint away from a container running someone
 * else's MCP server image.
 *
 * Exported for the test: the property under test is "this string is absent from
 * that array", and proving it through a real container would skip everywhere
 * Docker is not installed, which is exactly where a regression would land.
 */
export function buildDockerArgs({ image, env = {}, label = 'gh-mcp', extraDockerArgs = [] }) {
  const names = Object.keys(env);

  const args = [
    'run', '-i', '--rm',
    '--label', 'appcrane.gh-mcp=1',
    `--label`, `appcrane.label=${label}`,

    // Same isolation the app containers get (v2.42.1). Without --network this
    // container landed on Docker's default bridge, where inter-container
    // connectivity is ON — the one thing that change exists to prevent. The
    // shared network still allows egress, which this image needs to reach the
    // GitHub API.
    '--network', APP_NETWORK,

    // A container spawned on demand by an authenticated user, with no cap on
    // anything, is a denial-of-service primitive against every app on the box.
    '--memory', '512m', '--memory-swap', '512m',
    '--cpus', '1',
    '--pids-limit', '256',

    // It talks JSON-RPC over stdio to an HTTP API. It needs no capabilities,
    // and nothing it runs should be able to acquire more than it started with.
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',

    // Name only — the value travels in the env block below, not in argv.
    ...names.flatMap((k) => ['-e', k]),
    ...extraDockerArgs,
    image,
  ];

  // The docker CLI needs enough to find the daemon and its own config, and
  // nothing else. DOCKER_* is forwarded when set so a non-default socket or
  // context keeps working.
  const spawnEnv = { PATH: process.env.PATH, HOME: process.env.HOME };
  for (const k of ['DOCKER_HOST', 'DOCKER_CONFIG', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY']) {
    if (process.env[k] !== undefined) spawnEnv[k] = process.env[k];
  }
  Object.assign(spawnEnv, env);

  return { args, env: spawnEnv };
}

export class StdioMcpClient {
  constructor({ image, env = {}, label = 'gh-mcp', extraDockerArgs = [] }) {
    this.image = image;
    this.env = env;
    this.label = label;
    this.extraDockerArgs = extraDockerArgs;
    this.proc = null;
    this.containerId = null;
    this.pending = new Map();
    this.nextId = 1;
    this.buffer = '';
    this.closed = false;
    this.startedAt = null;
  }

  /**
   * Spawn the container and run the MCP `initialize` handshake. Throws if
   * docker exits before initialize completes (image pull failure, missing
   * binary, bad env vars).
   */
  async start() {
    const { args, env } = buildDockerArgs(this);
    this.proc = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'], env });
    this.startedAt = Date.now();

    this.proc.stdout.on('data', (d) => this._onStdout(d));
    this.proc.stderr.on('data', (d) => {
      const s = d.toString().trim();
      if (s) log.debug(`[gh-mcp ${this.label}] stderr: ${s}`);
    });
    this.proc.on('exit', (code, signal) => {
      this.closed = true;
      const err = new Error(`Container exited (code=${code}, signal=${signal})`);
      for (const { reject } of this.pending.values()) reject(err);
      this.pending.clear();
      log.info(`[gh-mcp ${this.label}] exited code=${code} signal=${signal}`);
    });
    this.proc.on('error', (err) => {
      this.closed = true;
      log.warn(`[gh-mcp ${this.label}] proc error: ${err.message}`);
    });

    // Initialize handshake — must succeed within 15s or we tear down
    try {
      await this._withTimeout(this.call('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'AppCrane-MCP-Proxy', version: '1.0.0' },
      }), 15000, 'initialize');
    } catch (e) {
      this.kill();
      throw new Error(`GitHub MCP init failed: ${e.message}`);
    }
    return this;
  }

  _onStdout(data) {
    this.buffer += data.toString('utf8');
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop(); // keep partial line for next chunk
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let msg;
      try {
        msg = JSON.parse(trimmed);
      } catch (_) {
        log.debug(`[gh-mcp ${this.label}] non-JSON line: ${trimmed.slice(0, 200)}`);
        continue;
      }
      if (msg.id != null && this.pending.has(msg.id)) {
        const { resolve, reject, timer } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        clearTimeout(timer);
        if (msg.error) reject(new Error(msg.error.message || 'GitHub MCP error'));
        else resolve(msg.result);
      }
      // Notifications (no id) are ignored for now.
    }
  }

  /**
   * Send a JSON-RPC request and resolve to the result. Rejects on error
   * response, container death, or per-call timeout.
   */
  call(method, params = {}) {
    if (this.closed) return Promise.reject(new Error('Container is closed'));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`Timeout after ${CALL_TIMEOUT_MS}ms: ${method}`));
        }
      }, CALL_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      const req = JSON.stringify({ jsonrpc: '2.0', id, method, params });
      try {
        this.proc.stdin.write(req + '\n');
      } catch (e) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(e);
      }
    });
  }

  _withTimeout(promise, ms, label) {
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      promise.then(v => { clearTimeout(t); resolve(v); },
                   e => { clearTimeout(t); reject(e); });
    });
  }

  kill() {
    if (this.closed) return;
    this.closed = true;
    try { this.proc?.kill('SIGTERM'); } catch (_) {}
  }

  isAlive() {
    return !this.closed && this.proc != null && this.proc.exitCode == null;
  }
}
