// Single helper for tool-using Claude agent calls.
// All callers go through here so docker invocation, stream-json parsing,
// timeouts, process-group lifecycle, and event normalization live in one
// place. Mirrors the SDK consolidation in oneShot.js but for the
// CLI-in-Docker substrate.
//
// Two modes:
//   exec — `docker exec` into an existing container (used by Studio chat)
//   run  — `docker run` a fresh container (used by enhancement coder + Ask)
//
// Events emitted by both modes:
//   'system' — stream-json system event (incl. session_id on init)
//   'data'   — non-result stream-json event (text, tool_use, tool_result)
//   'result' — final stream-json result event (tokens / cost)
//   'error'  — Error
//   'exit'   — exit code

import { spawn } from 'child_process';
import { EventEmitter } from 'events';
import { parseLine } from '../builder/streamJsonParser.js';
import log from '../../utils/logger.js';

const DEFAULT_MODEL   = process.env.APPSTUDIO_CODER_MODEL || 'claude-sonnet-4-6';
const DEFAULT_TIMEOUT = parseInt(process.env.CODER_TIMEOUT_MS || '1800000', 10);

function shellQuote(str) {
  // Single-quote for sh -c, escaping any embedded single quotes.
  return "'" + str.replace(/'/g, "'\\''") + "'";
}

// Build the `claude -p ...` shell command that runs inside the container.
// `resume` (session id) is for chat continuity (v1.23.0); ignored when undefined.
// `systemPrompt` appends to Claude Code's default system prompt — used for
// non-tool-using callers (planner, contextBuilder) that need specialized
// instructions instead of the default coding-agent priming.
function buildClaudeCmd({ prompt, model, resume, addDir = '/workspace', systemPrompt }) {
  const parts = [
    `claude -p ${shellQuote(prompt)}`,
    `--model ${model}`,
    `--dangerously-skip-permissions`,
    `--output-format stream-json --verbose`,
    `--add-dir ${addDir}`,
  ];
  if (systemPrompt) parts.push(`--append-system-prompt ${shellQuote(systemPrompt)}`);
  if (resume)       parts.push(`--resume ${resume}`);
  return parts.join(' ');
}

// Common stdout pipeline: line-buffer NDJSON, parse each line, emit events.
function attachStdoutParser(child, emitter) {
  let buf = '';
  child.stdout.on('data', (chunk) => {
    buf += chunk.toString();
    const lines = buf.split('\n');
    buf = lines.pop(); // keep partial line
    for (const line of lines) {
      const ev = parseLine(line);
      if (!ev) continue;
      if (ev.type === 'system') emitter.emit('system', ev);
      else if (ev.type === 'result') emitter.emit('result', ev);
      else emitter.emit('data', ev);
    }
  });
  child.stderr.on('data', (chunk) => {
    const t = chunk.toString().trim();
    if (t) log.debug(`[agent] stderr: ${t}`);
  });
}

class Agent extends EventEmitter {
  constructor(dockerArgs, timeoutMs) {
    super();
    this._dockerArgs = dockerArgs;
    this._timeoutMs  = timeoutMs;
    this._child      = null;
    this._timer      = null;
    this._stopped    = false;
  }

  start() {
    // detached: true → process group leader so stop() can kill grandchildren too
    this._child = spawn('docker', this._dockerArgs, { stdio: 'pipe', detached: true });
    this._timer = setTimeout(() => {
      this.stop();
      this.emit('error', new Error('Agent timed out'));
    }, this._timeoutMs);

    attachStdoutParser(this._child, this);

    this._child.on('error', (err) => { clearTimeout(this._timer); this.emit('error', err); });
    this._child.on('close', (code) => { clearTimeout(this._timer); if (!this._stopped) this.emit('exit', code); });
    this._child.unref();
  }

  stop() {
    this._stopped = true;
    clearTimeout(this._timer);
    if (this._child?.pid) {
      try { process.kill(-this._child.pid, 'SIGTERM'); } catch (_) {}
    }
  }
}

// ── exec mode — used by Studio chat (long-lived container) ──────────────

export function runAgentExec({
  containerId,
  prompt,
  apiKey,
  model        = DEFAULT_MODEL,
  resume,
  systemPrompt,
  workdir      = '/workspace',
  addDir       = '/workspace',
  homeDir      = '/home/studio',
  timeoutMs    = DEFAULT_TIMEOUT,
}) {
  const args = [
    'exec', '-i',
    '--workdir', workdir,
    '-e', `HOME=${homeDir}`,
    '-e', `ANTHROPIC_API_KEY=${apiKey}`,
    containerId,
    'sh', '-c',
    buildClaudeCmd({ prompt, model, resume, addDir, systemPrompt }),
  ];
  return new Agent(args, timeoutMs);
}

// ── run mode — used by enhancement coder + Ask (fresh container per job) ──

export function runAgentNew({
  image,
  containerName,
  prompt,
  apiKey,
  model         = DEFAULT_MODEL,
  resume,
  systemPrompt,                          // appends to claude's default system prompt
  workspaceDir,                          // host path → mounted as /workspace
  workspaceMode = 'rw',                  // 'rw' (default, for coders) or 'ro' (planner/contextBuilder — read-only)
  workdir       = '/workspace',          // container cwd
  extraMounts   = [],                    // [{host, container, mode?}]
  envVars       = {},                    // extra -e VAR=val pairs
  labels        = {},                    // extra --label key=val pairs
  memory        = '2g',
  cpus          = '1',
  timeoutMs     = DEFAULT_TIMEOUT,
  addDir        = '/workspace',
  homeDir       = '/home/studio',
}) {
  if (!image) throw new Error('runAgentNew: image required');
  if (!workspaceDir) throw new Error('runAgentNew: workspaceDir required');

  const args = ['run', '--rm'];
  if (containerName) args.push('--name', containerName);
  args.push('--label', 'appcrane=true');
  for (const [k, v] of Object.entries(labels)) args.push('--label', `${k}=${v}`);
  args.push(`--memory=${memory}`, `--cpus=${cpus}`);
  args.push('--workdir', workdir);
  args.push('-e', `HOME=${homeDir}`);
  args.push('-e', `ANTHROPIC_API_KEY=${apiKey}`);
  for (const [k, v] of Object.entries(envVars)) args.push('-e', `${k}=${v}`);
  args.push('-v', `${workspaceDir}:/workspace${workspaceMode === 'ro' ? ':ro' : ''}`);
  for (const m of extraMounts) {
    args.push('-v', `${m.host}:${m.container}${m.mode ? `:${m.mode}` : ''}`);
  }
  args.push(image, 'sh', '-c', buildClaudeCmd({ prompt, model, resume, addDir, systemPrompt }));
  return new Agent(args, timeoutMs);
}

// One-shot wrapper: run a fresh container, collect text + usage into a Promise.
// Used by callers that previously went through oneShot.js (planner,
// contextBuilder) but now share the CLI substrate so skills load uniformly.
// Resolves with { text, usage, costUsd }; rejects on non-zero exit or timeout.
export function runAgentOneShot(opts) {
  return new Promise((resolve, reject) => {
    let text = '';
    let usage = null;
    let costUsd = 0;
    const runner = runAgentNew(opts);

    runner.on('data', (ev) => {
      if (ev.type === 'text') {
        text += ev.text;
        opts.onChunk?.(text);
      }
    });
    runner.on('result', (ev) => {
      usage = { input_tokens: ev.inputTokens, output_tokens: ev.outputTokens };
      costUsd = (ev.costUsdCents || 0) / 100;
      opts.onTokens?.(ev.inputTokens + ev.outputTokens);
    });
    runner.on('error', reject);
    runner.on('exit', (code) => {
      if (code !== 0) return reject(new Error(`Agent exited with code ${code}`));
      resolve({ text, usage, costUsd });
    });

    runner.start();
  });
}
