// Single helper for tool-using Claude agent calls.
// All callers go through here so docker invocation, stream-json parsing,
// timeouts, process-group lifecycle, and event normalization live in one
// place.
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
import { prepareSkillsMount } from '../skills.js';
import { prepareClaudeCredentialsMount } from '../claudeCredentials.js';
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
// Claude session IDs are UUIDs (or short opaque strings). Reject anything
// outside a strict alnum/dash/underscore set so a poisoned stream-json
// event can't smuggle shell metacharacters through `--resume`.
// See feedback memory: "Never interpolate user-controlled strings into sh -c".
const SESSION_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

/**
 * Build a shell preflight that verifies every mounted path is accessible
 * by the container's user before invoking claude. Failures abort the
 * dispatch with a clear `[preflight] <path>: <reason>` line that gets
 * captured in stderrTail and surfaced to the operator — much better than
 * letting Claude CLI swallow the underlying EACCES and emit a generic
 * "Not logged in" / "tool failed" message.
 *
 * `checks` is an array of { path, mode, label } where mode is:
 *   'r'  — file must be readable
 *   'rw' — file must be readable AND writable (e.g. credentials.json
 *          which Claude rewrites on token refresh)
 *   'd'  — directory must exist and be enterable (x bit)
 *   'dw' — directory must be writable too
 */
function buildPreflightShell(checks) {
  if (!checks?.length) return '';
  const lines = [
    'preflight_fail() { echo "[preflight] $1" >&2; exit 75; }',
    'preflight_meta() { echo "uid=$(id -u) gid=$(id -g) mode=$(stat -c %a "$1" 2>/dev/null || echo ?) owner=$(stat -c %U:%G "$1" 2>/dev/null || echo ?:?)"; }',
  ];
  for (const c of checks) {
    const path  = shellQuote(c.path);
    const label = c.label || c.path;
    if (c.mode === 'r') {
      lines.push(`{ [ -e ${path} ] && [ -r ${path} ]; } || preflight_fail "${label} (${c.path}) not readable: $(preflight_meta ${path})";`);
    } else if (c.mode === 'rw') {
      lines.push(`{ [ -e ${path} ] && [ -r ${path} ] && [ -w ${path} ]; } || preflight_fail "${label} (${c.path}) not read+writable (Claude needs to refresh tokens): $(preflight_meta ${path})";`);
    } else if (c.mode === 'd') {
      lines.push(`{ [ -d ${path} ] && [ -x ${path} ]; } || preflight_fail "${label} (${c.path}) not an enterable directory: $(preflight_meta ${path})";`);
    } else if (c.mode === 'dw') {
      lines.push(`{ [ -d ${path} ] && [ -x ${path} ] && [ -w ${path} ]; } || preflight_fail "${label} (${c.path}) not a writable directory: $(preflight_meta ${path})";`);
    }
  }
  return lines.join(' ') + ' ';
}

function buildClaudeCmd({ prompt, model, resume, addDir = '/workspace', systemPrompt, preflight = [] }) {
  const parts = [
    `claude -p ${shellQuote(prompt)}`,
    `--model ${model}`,
    `--dangerously-skip-permissions`,
    `--output-format stream-json --verbose`,
    `--add-dir ${addDir}`,
  ];
  if (systemPrompt) parts.push(`--append-system-prompt ${shellQuote(systemPrompt)}`);
  if (resume) {
    if (!SESSION_ID_RE.test(String(resume))) {
      // Defense in depth — the writer in builderSession.js already validates
      // before persisting, but anything that loaded a stale or attacker-
      // injected session_id would otherwise hit this command unescaped.
      throw new Error('Refusing to pass unsafe resume id to shell');
    }
    parts.push(`--resume ${resume}`);
  }
  const preflightSh = buildPreflightShell(preflight);
  // Optional one-line diagnostic to stderr — set APPCRANE_DEBUG_CREDS=1
  // on AppCrane to investigate "Not logged in" issues. Output is captured
  // in the agent's stderrTail and shown back to the operator on failure.
  // Never logs credential CONTENT, only path / version / file metadata.
  if (process.env.APPCRANE_DEBUG_CREDS === '1') {
    const diag =
      'echo "[creds-diag] uid=$(id -u) home=$HOME" >&2; ' +
      'ls -la "$HOME/.claude/" >&2 2>&1 || echo "[creds-diag] no .claude dir" >&2; ' +
      'claude --version >&2 2>&1 || echo "[creds-diag] claude --version failed" >&2; ';
    return preflightSh + diag + parts.join(' ');
  }
  return preflightSh + parts.join(' ');
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
    if (!t) return;
    log.debug(`[agent] stderr: ${t}`);
    // Capture last few stderr lines on the emitter so the exit handler
    // can surface them in error messages (e.g. exit-125 → image missing).
    if (Array.isArray(emitter._stderrTail)) {
      for (const line of t.split('\n')) {
        emitter._stderrTail.push(line);
        if (emitter._stderrTail.length > 20) emitter._stderrTail.shift();
      }
    }
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
    this._cleanups   = [];
    this._cleanedUp  = false;
    this._stderrTail = [];
  }

  /** Last ~20 lines of docker/agent stderr — useful for diagnosing nonzero exit codes. */
  getStderrTail() { return this._stderrTail.slice(); }

  // Register a cleanup callback that runs exactly once on exit/error/stop.
  // Used by skills mount preparation to remove the per-call symlink dir.
  registerCleanup(fn) {
    if (typeof fn === 'function') this._cleanups.push(fn);
  }

  _runCleanups() {
    if (this._cleanedUp) return;
    this._cleanedUp = true;
    for (const fn of this._cleanups) {
      try { fn(); } catch (e) { log.warn(`Agent cleanup failed: ${e.message}`); }
    }
  }

  start() {
    // detached: true → process group leader so stop() can kill grandchildren too
    this._child = spawn('docker', this._dockerArgs, { stdio: 'pipe', detached: true });
    this._timer = setTimeout(() => {
      this.stop();
      this.emit('error', new Error('Agent timed out'));
    }, this._timeoutMs);

    attachStdoutParser(this._child, this);

    this._child.on('error', (err) => {
      clearTimeout(this._timer);
      this._runCleanups();
      this.emit('error', err);
    });
    this._child.on('close', (code) => {
      clearTimeout(this._timer);
      this._runCleanups();
      if (!this._stopped) this.emit('exit', code);
    });
    this._child.unref();
  }

  stop() {
    this._stopped = true;
    clearTimeout(this._timer);
    this._runCleanups();
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
  hasAppCredentials = false,  // when true, omit ANTHROPIC_API_KEY so the
                              // mounted ~/.claude/credentials.json wins
}) {
  const args = [
    'exec', '-i',
    '--workdir', workdir,
    '-e', `HOME=${homeDir}`,
  ];
  // Same precedence rule as runAgentNew — see comment there. Passing the
  // env var makes Claude CLI prefer the API key over the OAuth file.
  if (!hasAppCredentials) {
    args.push('-e', `ANTHROPIC_API_KEY=${apiKey}`);
  }
  // Preflight what we expect to be mounted in the container that was
  // started by appContainer.startContainer. This catches mode/uid issues
  // (umask-stripped perms, wrong owner) before claude swallows EACCES
  // and emits a misleading "Not logged in" / generic auth error.
  const preflight = [{ path: workdir, mode: 'dw', label: 'Workspace' }];
  if (hasAppCredentials) {
    preflight.push({ path: `${homeDir}/.claude/credentials.json`, mode: 'rw', label: 'Claude credentials' });
  }
  args.push(
    containerId,
    'sh', '-c',
    buildClaudeCmd({ prompt, model, resume, addDir, systemPrompt, preflight }),
  );
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
  appSlug,                               // scopes which skills get bind-mounted; required for skill loading
}) {
  if (!image) throw new Error('runAgentNew: image required');
  if (!workspaceDir) throw new Error('runAgentNew: workspaceDir required');

  // SECURITY hardening (v1.27.34 H7): drop all Linux capabilities,
  // forbid suid escalation, cap PIDs. Network stays default because
  // the agent needs to reach GitHub + npm; further isolation would
  // require a per-app outbound proxy (out of scope today).
  const args = [
    'run', '--rm',
    '--cap-drop=ALL',
    '--security-opt', 'no-new-privileges:true',
    '--pids-limit=256',
  ];
  if (containerName) args.push('--name', containerName);
  args.push('--label', 'appcrane=true');
  for (const [k, v] of Object.entries(labels)) args.push('--label', `${k}=${v}`);
  args.push(`--memory=${memory}`, `--cpus=${cpus}`);
  args.push('--workdir', workdir);
  args.push('-e', `HOME=${homeDir}`);
  // Preflight checks built up alongside the mounts so each has the
  // matching access expectation. Workspace gets 'd' for ro, 'dw' for rw.
  const preflight = [
    { path: workdir, mode: workspaceMode === 'ro' ? 'd' : 'dw', label: 'Workspace' },
  ];
  // If the app has its own Claude OAuth credentials, mount the file AND
  // suppress ANTHROPIC_API_KEY entirely — Claude Code's auth precedence
  // is API key > credentials.json, so leaving the env var set means the
  // global key wins and the operator's per-app subscription is ignored
  // (manifested as "Credit balance is too low" against the wrong account).
  const credsMount = prepareClaudeCredentialsMount(appSlug);
  if (credsMount) {
    args.push('-v', `${credsMount.tmpFile}:${homeDir}/.claude/credentials.json`);
    preflight.push({ path: `${homeDir}/.claude/credentials.json`, mode: 'rw', label: 'Claude credentials' });
  } else {
    args.push('-e', `ANTHROPIC_API_KEY=${apiKey || ''}`);
  }
  for (const [k, v] of Object.entries(envVars)) args.push('-e', `${k}=${v}`);
  args.push('-v', `${workspaceDir}:/workspace${workspaceMode === 'ro' ? ':ro' : ''}`);
  for (const m of extraMounts) {
    args.push('-v', `${m.host}:${m.container}${m.mode ? `:${m.mode}` : ''}`);
    preflight.push({ path: m.container, mode: m.mode === 'ro' ? 'r' : 'rw', label: 'Extra mount' });
  }

  // Bind skills assigned to this app under ~/.claude/skills/ so the CLI's
  // native loader discovers them. The mount dir is a per-call symlink farm;
  // cleanup runs when the agent exits/errors/is stopped. Skips entirely
  // when no appSlug is passed — callers without a slug get no skills (we
  // don't fall back to a global set anymore).
  const skillsMount = prepareSkillsMount(appSlug);
  if (skillsMount) {
    args.push('-v', `${skillsMount.dir}:${homeDir}/.claude/skills:ro`);
    preflight.push({ path: `${homeDir}/.claude/skills`, mode: 'd', label: 'Skills dir' });
  }

  args.push(image, 'sh', '-c', buildClaudeCmd({ prompt, model, resume, addDir, systemPrompt, preflight }));
  const agent = new Agent(args, timeoutMs);
  if (credsMount)  agent.registerCleanup(credsMount.cleanup);
  if (skillsMount) agent.registerCleanup(skillsMount.cleanup);
  return agent;
}

// One-shot wrapper: run a fresh container, collect text + usage into a Promise.
// Used by planner + contextBuilder so they share the CLI substrate (skills
// load uniformly, tool-use available if a prompt asks for it).
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
      if (code === 0) return resolve({ text, usage, costUsd });
      // Exit 125 = docker daemon couldn't start the container at all (image
      // missing / pull denied / daemon down). Surface that explicitly so it
      // doesn't read like a Claude failure. For other codes, include the
      // stderr tail so the operator sees why.
      const tail = (typeof runner.getStderrTail === 'function' ? runner.getStderrTail() : []).join('\n').trim();
      if (code === 125) {
        const detail = tail ? `\n\nDocker stderr:\n${tail}` : '';
        return reject(new Error(
          `Agent could not start: docker run exited 125 (image '${opts.image}' missing, pull denied, or daemon down). Build/pull the image on this host before retrying.${detail}`
        ));
      }
      const detail = tail ? ` — ${tail.split('\n').slice(-3).join(' | ')}` : '';
      return reject(new Error(`Agent exited with code ${code}${detail}`));
    });

    runner.start();
  });
}
