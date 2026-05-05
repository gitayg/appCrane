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
    const dockerEnv = [];
    for (const [k, v] of Object.entries(this.env)) {
      dockerEnv.push('-e', `${k}=${v}`);
    }
    const args = [
      'run', '-i', '--rm',
      '--label', 'appcrane.gh-mcp=1',
      '--label', `appcrane.label=${this.label}`,
      ...dockerEnv,
      ...this.extraDockerArgs,
      this.image,
    ];

    this.proc = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'] });
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
