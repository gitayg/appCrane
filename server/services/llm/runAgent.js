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
import { prepareClaudeCredentialsMount, credentialsInfo } from '../claudeCredentials.js';
import { getUserClaudeToken, userClaudeTokenMeta } from '../userClaudeToken.js';
import { defaultCoderModel } from './coderModels.js';
import log from '../../utils/logger.js';

const DEFAULT_TIMEOUT = parseInt(process.env.CODER_TIMEOUT_MS || '1800000', 10);

// Read per call, not captured at import: a test (and an operator restarting
// with a different APPSTUDIO_CODER_MODEL) must not be answered from a value
// frozen when this module first loaded.
const DEFAULT_MODEL = () => defaultCoderModel();

// ── credential precedence ───────────────────────────────────────────────────
//
// Anthropic documents Claude Code's auth precedence, highest first:
//   (2) ANTHROPIC_AUTH_TOKEN  (3) ANTHROPIC_API_KEY  (4) apiKeyHelper
//   (5) CLAUDE_CODE_OAUTH_TOKEN  (7) subscription OAuth from `claude /login`
//   — https://code.claude.com/docs/en/authentication
//
// So CLAUDE_CODE_OAUTH_TOKEN ranks BELOW ANTHROPIC_API_KEY. A container handed
// both uses the API key and silently ignores the user's subscription — the same
// failure the credentials.json mount already documents in runAgentNew ("Credit
// balance is too low" billed against the wrong account). The only safe rule is
// therefore: exactly one credential reaches the container, chosen here, once,
// for every caller.
//
// AppCrane's order, highest first:
//   1. 'user_oauth'       — the acting user's Claude subscription token, passed
//                           as CLAUDE_CODE_OAUTH_TOKEN (from `claude setup-token`)
//   2. 'app_credentials'  — the app's uploaded credentials.json, bind-mounted
//   3. 'api_key'          — the platform ANTHROPIC_API_KEY
//   4. 'none'             — nothing usable; callers refuse the request
export const CREDENTIAL_KINDS = ['user_oauth', 'app_credentials', 'api_key', 'none'];

/**
 * What every caller says when agentCredentialKind() comes back 'none'. One
 * string so the three ways out are always listed together — before v2.81.0
 * each gate named only ANTHROPIC_API_KEY and refused callers who had a
 * perfectly good credential of their own.
 */
export const NO_CREDENTIAL_MESSAGE =
  'No Claude credential available. Connect your Claude subscription on your profile, '
  + 'upload credentials.json for this app, or configure ANTHROPIC_API_KEY on the platform.';

function platformApiKey(apiKey) {
  // `undefined` means "caller didn't say" → fall back to the platform key.
  // An explicit '' or null means "deliberately no key".
  return (apiKey === undefined ? process.env.ANTHROPIC_API_KEY : apiKey) || '';
}

// A credential lookup must never turn a dispatch into a 500. If the store is
// unreadable we fall through to the next credential instead, and say so. These
// messages are about the STORE (missing table, bad ENCRYPTION_KEY) and never
// carry the secret itself.
function probe(what, fn) {
  try { return fn(); } catch (err) {
    log.warn(`[agent] ${what} unavailable: ${err.message}`);
    return null;
  }
}

/**
 * Which credential a dispatch will use — decided from PRESENCE only, so this is
 * safe to call from a route gate: it reads no secret value.
 *
 * `deps` is the injection point (also used by the tests) for the two presence
 * lookups; production callers pass nothing.
 */
export function agentCredentialKind({
  actingUserId      = null,
  appSlug           = null,
  oauthToken        = null,
  hasAppCredentials = null,   // exec-mode callers already know; null = look it up
  apiKey            = undefined,
} = {}, deps = {}) {
  const tokenMeta = deps.userClaudeTokenMeta || userClaudeTokenMeta;
  const appCreds  = deps.credentialsInfo     || credentialsInfo;

  if (oauthToken) return 'user_oauth';
  if (actingUserId !== null && actingUserId !== undefined) {
    if (probe('user Claude token', () => tokenMeta(actingUserId))?.present) return 'user_oauth';
  }
  if (hasAppCredentials === true) return 'app_credentials';
  if (hasAppCredentials === null && appSlug) {
    if (probe(`app credentials for ${appSlug}`, () => appCreds(appSlug))?.present) return 'app_credentials';
  }
  if (platformApiKey(apiKey)) return 'api_key';
  return 'none';
}

/**
 * The same decision, plus the secret it needs:
 *   { kind: 'user_oauth',      oauthToken }
 *   { kind: 'app_credentials' }            — the value is a bind-mounted file
 *   { kind: 'api_key',         apiKey }
 *   { kind: 'none' }
 *
 * Never log the return value.
 */
export function resolveAgentCredential(opts = {}, deps = {}) {
  const kind = agentCredentialKind(opts, deps);
  if (kind === 'user_oauth') {
    const read = deps.getUserClaudeToken || getUserClaudeToken;
    const token = opts.oauthToken
      || probe('user Claude token', () => read(opts.actingUserId));
    if (token) return { kind, oauthToken: token };
    // Presence said yes and the read came back empty (rotated out mid-flight,
    // unreadable ciphertext). Decide again without it rather than dispatch a
    // container with no credential at all.
    return resolveAgentCredential({ ...opts, actingUserId: null, oauthToken: null }, deps);
  }
  if (kind === 'app_credentials') return { kind };
  if (kind === 'api_key') return { kind, apiKey: platformApiKey(opts.apiKey) };
  return { kind: 'none' };
}

/**
 * Remove secret values from anything on its way to a log line, an Error or a
 * stream event. Split/join rather than a RegExp so no escaping of the secret is
 * needed. Callers scrub whole LINES (never raw chunks) so a value can't survive
 * by straddling a chunk boundary.
 */
function scrubSecrets(text, secrets) {
  let out = String(text);
  if (!secrets?.length) return out;
  for (const s of secrets) {
    if (s) out = out.split(s).join('[redacted]');
  }
  return out;
}

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
  // Statements separated by `;` not space — Alpine ash needs an explicit
  // terminator after `}` before the next command. Each check uses `if … fi`
  // (not `… || preflight_fail`) so the failure path is inside the function
  // body where parsing is unambiguous.
  // `echo unknown` instead of `echo ?` because `?` is a single-char glob
  // that some shells expand or warn about.
  const lines = [
    'preflight_fail() { echo "[preflight] $1" >&2; exit 75; }',
    'preflight_meta() { echo "uid=$(id -u) gid=$(id -g) mode=$(stat -c %a "$1" 2>/dev/null || echo unknown) owner=$(stat -c %U:%G "$1" 2>/dev/null || echo unknown)"; }',
  ];
  for (const c of checks) {
    const path  = shellQuote(c.path);
    const label = c.label || c.path;
    let test;
    let reason;
    if (c.mode === 'r') {
      test = `[ -e ${path} ] && [ -r ${path} ]`;
      reason = 'not readable';
    } else if (c.mode === 'rw') {
      test = `[ -e ${path} ] && [ -r ${path} ] && [ -w ${path} ]`;
      reason = 'not read+writable (Claude needs to refresh tokens)';
    } else if (c.mode === 'd') {
      test = `[ -d ${path} ] && [ -x ${path} ]`;
      reason = 'not an enterable directory';
    } else if (c.mode === 'dw') {
      test = `[ -d ${path} ] && [ -x ${path} ] && [ -w ${path} ]`;
      reason = 'not a writable directory';
    } else {
      continue;
    }
    lines.push(`if ! ${test}; then preflight_fail "${label} (${c.path}) ${reason}: $(preflight_meta ${path})"; fi`);
  }
  return lines.join('; ') + '; ';
}

// The only permission modes a caller may ask for. Anything else is refused
// here, independently of coderModes.js, because the value reaches `sh -c`.
const PERMISSION_MODES = new Set(['bypassPermissions', 'acceptEdits', 'plan']);

function buildClaudeCmd({ prompt, model, resume, addDir = '/workspace', systemPrompt, preflight = [], permissionMode }) {
  if (permissionMode != null && !PERMISSION_MODES.has(permissionMode)) {
    throw new Error(`Refusing unsupported permission mode '${permissionMode}'`);
  }
  const parts = [
    `claude -p`,
    // SECURITY: quoted since v2.85.0, when the browser gained a model picker.
    // The route validates against the coderModels allowlist first; this is the
    // second, independent defence, so a list someone edits later is not the
    // only thing between a request body and `sh -c`.
    `--model ${shellQuote(String(model))}`,
    // Auto (and every caller that does not choose) keeps the flag it always
    // had; Edits only and Plan hand the CLI a mode, and with no terminal to
    // answer prompts, whatever that mode would ask about is refused.
    !permissionMode || permissionMode === 'bypassPermissions'
      ? `--dangerously-skip-permissions`
      : `--permission-mode ${shellQuote(permissionMode)}`,
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
  // The prompt goes LAST, after `--`. Before v2.90.2 it followed `-p` directly,
  // so a message starting with a dash was parsed as a flag: the element
  // picker's "--- Pointed element ---" prefix failed every turn with
  // `error: unknown option`, and a message like `--mcp-config …` would have been
  // read as a real option. Shell quoting cannot help there; the CLI's own
  // argument parser is the one that reads it.
  parts.push(`-- ${shellQuote(prompt)}`);
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
//
// Both streams are scrubbed a WHOLE LINE AT A TIME. A credential can't contain
// a newline, so line-at-a-time is the granularity at which a replace is
// guaranteed to see the value intact — scrubbing raw chunks would miss a token
// that happened to straddle two reads, and neither an agent's stdout (it can
// run `env`) nor its stderr is trusted to keep the value to itself.
function attachStdoutParser(child, emitter) {
  const secrets = emitter._secrets || [];
  let buf = '';
  child.stdout.on('data', (chunk) => {
    buf += chunk.toString();
    const lines = buf.split('\n');
    buf = lines.pop(); // keep partial line
    for (const line of lines) {
      const ev = parseLine(scrubSecrets(line, secrets));
      if (!ev) continue;
      if (ev.type === 'system') emitter.emit('system', ev);
      else if (ev.type === 'result') emitter.emit('result', ev);
      else emitter.emit('data', ev);
    }
  });

  // Capture the last few stderr lines on the emitter so the exit handler can
  // surface them in error messages (e.g. exit-125 → image missing).
  const takeStderrLine = (raw) => {
    const t = scrubSecrets(raw, secrets).trim();
    if (!t) return;
    log.debug(`[agent] stderr: ${t}`);
    if (Array.isArray(emitter._stderrTail)) {
      emitter._stderrTail.push(t);
      if (emitter._stderrTail.length > 20) emitter._stderrTail.shift();
    }
  };
  let errBuf = '';
  child.stderr.on('data', (chunk) => {
    errBuf += chunk.toString();
    const lines = errBuf.split('\n');
    errBuf = lines.pop();
    for (const line of lines) takeStderrLine(line);
  });
  child.stderr.on('end', () => {
    if (errBuf) { takeStderrLine(errBuf); errBuf = ''; }
  });
}

class Agent extends EventEmitter {
  constructor(dockerArgs, timeoutMs, secrets = []) {
    super();
    // Values that must not reach a log line, an Error, a stream event or the
    // stderr tail. Today that is the caller's CLAUDE_CODE_OAUTH_TOKEN.
    this._secrets    = secrets.filter(Boolean);
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
  getStderrTail() { return this._stderrTail.map((l) => scrubSecrets(l, this._secrets)); }

  /**
   * The argv this agent will hand to docker. It CONTAINS the credential, so
   * this is for tests and in-process assertions only — never log it.
   */
  getDockerArgs() { return this._dockerArgs.slice(); }

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
  model        = DEFAULT_MODEL(),
  resume,
  systemPrompt,
  workdir      = '/workspace',
  addDir       = '/workspace',
  homeDir      = '/home/studio',
  timeoutMs    = DEFAULT_TIMEOUT,
  hasAppCredentials = false,  // when true, omit ANTHROPIC_API_KEY so the
                              // mounted ~/.claude/credentials.json wins
  actingUserId = null,        // whose subscription this dispatch bills to
  oauthToken   = null,        // an already-resolved CLAUDE_CODE_OAUTH_TOKEN
  credentialDeps = {},        // injection point for resolveAgentCredential
  permissionMode = null,      // coderModes.permissionModeFor(); null = skip permissions (Auto)
}) {
  // One decision, shared with runAgentNew — see the precedence block above.
  const cred = resolveAgentCredential(
    { actingUserId, oauthToken, hasAppCredentials, apiKey }, credentialDeps,
  );
  const args = [
    'exec', '-i',
    '--workdir', workdir,
    '-e', `HOME=${homeDir}`,
  ];
  if (cred.kind === 'user_oauth') {
    // ANTHROPIC_API_KEY deliberately absent: it outranks CLAUDE_CODE_OAUTH_TOKEN,
    // so setting both would bill the platform key and ignore the subscription.
    args.push('-e', `CLAUDE_CODE_OAUTH_TOKEN=${cred.oauthToken}`);
  } else if (cred.kind !== 'app_credentials') {
    args.push('-e', `ANTHROPIC_API_KEY=${cred.apiKey || ''}`);
  }
  // Preflight what we expect to be mounted in the container that was
  // started by appContainer.startContainer. This catches mode/uid issues
  // (umask-stripped perms, wrong owner) before claude swallows EACCES
  // and emits a misleading "Not logged in" / generic auth error.
  const preflight = [{ path: workdir, mode: 'dw', label: 'Workspace' }];
  if (cred.kind === 'app_credentials') {
    preflight.push({ path: `${homeDir}/.claude/credentials.json`, mode: 'rw', label: 'Claude credentials' });
  }
  args.push(
    containerId,
    'sh', '-c',
    buildClaudeCmd({ prompt, model, resume, addDir, systemPrompt, preflight, permissionMode }),
  );
  return new Agent(args, timeoutMs, [cred.oauthToken]);
}

// ── run mode — used by enhancement coder + Ask (fresh container per job) ──

export function runAgentNew({
  image,
  containerName,
  prompt,
  apiKey,
  model         = DEFAULT_MODEL(),
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
  actingUserId  = null,                  // whose subscription this dispatch bills to
  oauthToken    = null,                  // an already-resolved CLAUDE_CODE_OAUTH_TOKEN
  credentialDeps = {},                   // injection point for resolveAgentCredential
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
  // One decision, shared with runAgentExec — see the precedence block above.
  // Whichever credential wins, the other two are left off the container:
  // Claude Code's auth precedence is API key > credentials.json > OAuth token,
  // so any second credential silently outranks the one the caller meant to use
  // (manifested as "Credit balance is too low" against the wrong account).
  const cred = resolveAgentCredential({ actingUserId, oauthToken, appSlug, apiKey }, credentialDeps);
  let credsMount = null;
  if (cred.kind === 'user_oauth') {
    args.push('-e', `CLAUDE_CODE_OAUTH_TOKEN=${cred.oauthToken}`);
  } else {
    credsMount = cred.kind === 'app_credentials' ? prepareClaudeCredentialsMount(appSlug) : null;
    if (credsMount) {
      // Mount at BOTH the legacy ~/.claude/credentials.json AND the
      // newer dot-prefixed ~/.claude/.credentials.json — recent Claude
      // Code releases switched paths and we don't want a CLI version
      // upgrade in the studio image to silently break auth.
      args.push('-v', `${credsMount.tmpFile}:${homeDir}/.claude/credentials.json`);
      args.push('-v', `${credsMount.tmpFile}:${homeDir}/.claude/.credentials.json`);
      preflight.push({ path: `${homeDir}/.claude/credentials.json`, mode: 'rw', label: 'Claude credentials' });
    } else {
      // Includes the 'app_credentials' row that turned out to be unreadable —
      // prepareClaudeCredentialsMount logs and returns null, and the platform
      // key is still better than dispatching with nothing.
      args.push('-e', `ANTHROPIC_API_KEY=${platformApiKey(apiKey)}`);
    }
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
  const agent = new Agent(args, timeoutMs, [cred.oauthToken]);
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
      } else if (ev.type === 'tool') {
        // Bubble tool-use events up so callers can show "Reading foo.ts /
        // Grepping 'X'" breadcrumbs while the model is exploring before
        // it starts emitting the plan text. Without this, users see a
        // long blank wait between "started" and the first plan chunk.
        opts.onTool?.({ name: ev.name, input: ev.input });
      }
    });
    runner.on('result', (ev) => {
      usage = { input_tokens: ev.inputTokens, output_tokens: ev.outputTokens };
      costUsd = (ev.costUsdCents || 0) / 100;
      opts.onTokens?.(ev.inputTokens + ev.outputTokens);
    });
    // The CLI retries a rejected credential ten times over about three minutes
    // (measured: api_retry x10, error_status 401). It never recovers, so stop
    // at the first one instead of making every caller wait out the loop.
    runner.on('system', (ev) => {
      const d = ev?.data;
      if (d?.subtype !== 'api_retry' || (d.error_status !== 401 && d.error_status !== 403)) return;
      runner.stop();
      reject(new Error(`Claude rejected the credential (HTTP ${d.error_status}, ${d.error || 'authentication failed'}); stopped instead of retrying`));
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
      // The CLI reports most failures (a key with no credit, a bad model, not
      // logged in) as its reply on stdout, not on stderr, so a bare exit code
      // told the user nothing. Say what it said.
      const said = text.trim().split('\n').slice(-3).join(' | ').slice(-400);
      const detail = tail ? ` — ${tail.split('\n').slice(-3).join(' | ')}` : (said ? ` — ${said}` : '');
      return reject(new Error(`Agent exited with code ${code}${detail}`));
    });

    runner.start();
  });
}
