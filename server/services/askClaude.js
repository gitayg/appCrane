import { execFile, execFileSync } from 'child_process';
import { rmSync } from 'fs';
import { join, resolve } from 'path';
import { decrypt } from './encryption.js';
import { tokenGitEnv, scrubToken } from './githubGitAuth.js';
import { ensureStudioImage } from './appstudio/generator.js';
import { assertCapacity } from './containerLimit.js';
import { runAgentExec } from './llm/runAgent.js';
import { prepareSkillsMount } from './skills.js';
import { prepareClaudeCredentialsMount } from './claudeCredentials.js';
import log from '../utils/logger.js';
import { usesLocalRepo } from './managedRepo.js';
import { runLocalAskJob } from './askLocalRepo.js';
import { OOM_APP_FLAG } from './oomPriority.js';
import { CPU_APP_FLAG } from './cpuPriority.js';
import { getPlatformAnthropicKey } from './platformAnthropicKey.js';

const ASK_IMAGE      = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';
const ASK_MODEL      = process.env.APPSTUDIO_CODER_MODEL || 'claude-sonnet-4-6';
const ASK_TIMEOUT_MS = parseInt(process.env.ASK_TIMEOUT_MS || '300000', 10);
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;   // 5 minutes idle
const MAX_SESSION_MS  = 2 * 60 * 60 * 1000; // 2 hour hard cap
const CLONE_TIMEOUT_MS = 120000;
const READY_MARKER    = '/tmp/appcrane-ask-ready';

// Runs by `docker exec` in the idle container, before any agent exists. The auth
// header arrives on stdin, so it is in no argv and no file, and it lives only in
// the environment of this exec and its git children, all gone before the agent
// starts. The marker is the last link: /workspace itself is in the image, so its
// presence says nothing about the clone (infra/studio.Dockerfile).
const CLONE_SCRIPT = 'IFS= read -r ASK_GIT_AUTH; '
  + 'if [ -n "$ASK_GIT_AUTH" ]; then export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="$GIT_AUTH_KEY" GIT_CONFIG_VALUE_0="$ASK_GIT_AUTH"; fi; '
  + 'unset ASK_GIT_AUTH; '
  + 'git clone --depth 1 --branch "$BRANCH" -- "$REPO_URL" /workspace '
  + '&& git -C /workspace remote remove origin '
  + '&& git -C /workspace config --local credential.helper "" '
  + `&& touch ${READY_MARKER}`;

// sessionId -> { containerName, idleTimer, maxTimer }
const liveSessions = new Map();

// Earlier versions wrote the tokenized clone URL to ask-sessions/<id>/clone_url,
// mode 0644, and a failed clone left it there. Nothing uses the directory now.
export function sweepLegacyAskSessions() {
  try {
    rmSync(join(resolve(process.env.DATA_DIR || './data'), 'ask-sessions'), { recursive: true, force: true });
  } catch (e) {
    log.warn(`AskClaude: could not remove the old ask-sessions directory: ${e.message}`);
  }
}

function cloneAuth(app) {
  if (!app.github_token_encrypted) return null;
  try {
    const token = decrypt(app.github_token_encrypted);
    const env = tokenGitEnv(app.github_url, token, {});
    return { token, key: env.GIT_CONFIG_KEY_0, value: env.GIT_CONFIG_VALUE_0 };
  } catch (_) { return null; }
}

function buildPrompt({ contextDoc, agentContext, history, question }) {
  let prompt = '';
  if (contextDoc) prompt += '# Codebase context\n' + contextDoc + '\n\n';
  if (agentContext) prompt += '# Operator notes\n' + agentContext + '\n\n';
  if (history && history.length > 0) {
    prompt += '# Previous conversation\n';
    for (const m of history) prompt += (m.role === 'user' ? 'User' : 'Assistant') + ': ' + m.content + '\n\n';
    prompt += '---\n\n';
  }
  prompt += '# Question\n' + question + '\n\n';
  prompt += '# Instructions\nAnswer based on the codebase in /workspace. The context doc above gives the architecture overview — read specific source files as needed for details. Be concise and accurate. Do NOT modify any files.';
  return prompt;
}

function cloneInContainer(containerName, app, branch, onLog) {
  const auth = cloneAuth(app);
  return new Promise((res, rej) => {
    const child = execFile('docker', [
      'exec', '-i',
      '-e', `BRANCH=${branch}`,
      '-e', `REPO_URL=${app.github_url}`,
      '-e', `GIT_AUTH_KEY=${auth?.key || ''}`,
      '-e', 'GIT_TERMINAL_PROMPT=0',
      containerName, 'sh', '-c', CLONE_SCRIPT,
    ], { timeout: CLONE_TIMEOUT_MS, maxBuffer: 1024 * 1024 }, (err, _stdout, stderr) => {
      if (!err) {
        try {
          execFileSync('docker', ['exec', containerName, 'test', '-f', READY_MARKER], { stdio: 'pipe', timeout: 5000 });
        } catch (_) { return rej(new Error('Repository clone did not finish')); }
        onLog?.('[ask] Repository ready');
        return res();
      }
      if (err.killed) return rej(new Error('Timed out waiting for repository clone'));
      rej(new Error(`Repository clone failed: ${scrubToken(String(stderr || err.message), auth?.token).trim().slice(-300)}`));
    });
    child.stdin.on('error', () => {}); // docker gone: the callback above reports it
    child.stdin.end(`${auth?.value || ''}\n`);
  });
}

async function ensureSessionContainer(sessionId, app, onLog) {
  if (liveSessions.has(sessionId)) {
    const s = liveSessions.get(sessionId);
    clearTimeout(s.idleTimer);
    s.idleTimer = null;
    // Verify container still running
    try {
      const status = execFileSync('docker', ['inspect', '--format', '{{.State.Status}}', s.containerName], { stdio: 'pipe', timeout: 5000 }).toString().trim();
      if (status === 'running') return s;
    } catch (_) {}
    // Container is gone — remove stale entry and fall through to recreate
    liveSessions.delete(sessionId);
  }

  assertCapacity();
  await ensureStudioImage(onLog);

  const containerName = `appcrane-ask-s${sessionId}`;

  // Kill any existing container with this name (e.g. from a previous server run)
  try { execFileSync('docker', ['rm', '-f', containerName], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}

  onLog?.('[ask] Cloning repository...');
  log.info(`AskClaude: starting session container ${containerName}`);

  // SECURITY: app.branch reaches a `sh -c` command as an env var, never inline.
  // If a writer ever bypasses the validation in routes/apps.js, refuse to
  // start the container rather than open up command injection. The regex
  // matches what git accepts as a valid ref char (alnum + . _ / -).
  // See feedback memory: "Never interpolate user-controlled strings into sh -c".
  const branch = String(app.branch || 'main');
  if (!/^[A-Za-z0-9._/\-]{1,200}$/.test(branch)) {
    throw new Error(`Refusing to start ask container for ${app.slug}: unsafe branch name`);
  }
  // reconcile.js can store a github_url it read from a release unvalidated.
  if (!/^https?:\/\//.test(String(app.github_url))) {
    throw new Error(`Refusing to start ask container for ${app.slug}: github_url is not http(s)`);
  }

  // Bind skills assigned to this app as ~/.claude/skills/ — same mechanism
  // as the builder session container, so Ask gets the same skill set the
  // app's Builder uses.
  const skillsMount = prepareSkillsMount(app.slug);
  // Per-app Claude OAuth credentials (if uploaded) override the global API key.
  const credsMount = prepareClaudeCredentialsMount(app.slug);

  // The container starts idle; CLONE_SCRIPT then clones, strips the remote and
  // disables the credential helper — ask containers cannot commit or push.
  // BRANCH and REPO_URL are env vars instead of inline-interpolated into the
  // shell command so a parser slip in the validators above can't escalate
  // to command injection (the inner shell expands "$BRANCH", which docker
  // sets verbatim from the -e flag — no extra shell parsing pass).
  // SECURITY hardening (v1.27.34 H7): drop all caps, no-new-privs, pids-limit.
  // Network stays default — clone needs GitHub access.
  const dockerArgs = [
    'run', '-d',
    '--name', containerName,
    '--label', 'appcrane=true',
    '--label', 'appcrane.container.type=ask',
    OOM_APP_FLAG,
    CPU_APP_FLAG,
    '--memory=1g', '--cpus=0.5',
    '--cap-drop=ALL',
    '--security-opt', 'no-new-privileges:true',
    '--pids-limit=256',
    '-e', `ASK_MODEL=${ASK_MODEL}`,
  ];
  // No ANTHROPIC_API_KEY on the container itself: only runAgentExec runs
  // claude here, and it hands the key to that one `docker exec` in an
  // --env-file. A key set at `docker run` would sit in the container's config
  // for `docker inspect` for the whole session.
  // Mount creds at BOTH credentials.json and .credentials.json — newer
  // Claude Code releases moved to the dot-prefixed path.
  if (credsMount)  dockerArgs.push('-v', `${credsMount.tmpFile}:/home/studio/.claude/credentials.json`);
  if (credsMount)  dockerArgs.push('-v', `${credsMount.tmpFile}:/home/studio/.claude/.credentials.json`);
  if (skillsMount) dockerArgs.push('-v', `${skillsMount.dir}:/home/studio/.claude/skills:ro`);
  dockerArgs.push(ASK_IMAGE, 'tail', '-f', '/dev/null');

  try {
    execFileSync('docker', dockerArgs, { stdio: 'pipe', timeout: 15000 });
    await cloneInContainer(containerName, app, branch, onLog);
  } catch (err) {
    // No session exists yet, so stopSession cannot clean up after a failed start.
    try { execFileSync('docker', ['rm', '-f', containerName], { stdio: 'pipe', timeout: 15000 }); } catch (_) {}
    if (credsMount)  { try { credsMount.cleanup();  } catch (_) {} }
    if (skillsMount) { try { skillsMount.cleanup(); } catch (_) {} }
    throw err;
  }

  const session = {
    containerName, appSlug: app.slug,
    idleTimer: null, maxTimer: null,
    skillsCleanup: skillsMount?.cleanup || null,
    credsCleanup:  credsMount?.cleanup  || null,
  };
  session.maxTimer = setTimeout(() => stopSession(sessionId), MAX_SESSION_MS);
  liveSessions.set(sessionId, session);
  return session;
}

export async function runAskJob({ sessionId, app, question, history, agentContext, contextDoc, onLog, onTokens }) {
  // A local-backed managed app is answered from its repository on this host
  // by a direct Messages API call with read-only git tools — no container.
  // Every other app, including a managed app with repo_backend NULL, takes the
  // container path below unchanged.
  if (usesLocalRepo(app)) {
    return runLocalAskJob({ app, question, history, agentContext, contextDoc, onLog, onTokens, model: ASK_MODEL });
  }
  const session = await ensureSessionContainer(sessionId, app, onLog);
  const prompt = buildPrompt({ contextDoc, agentContext, history, question });

  onLog?.('[ask] Running Claude Code...');

  return new Promise((resolve, reject) => {
    let answer = '';
    let timedOut = false;

    const runner = runAgentExec({
      containerId: session.containerName,
      prompt,
      apiKey: getPlatformAnthropicKey(),
      model: ASK_MODEL,
      timeoutMs: ASK_TIMEOUT_MS + 60000,
      hasAppCredentials: !!session.credsCleanup,
    });

    runner.on('data', (ev) => {
      if (ev.type === 'text') answer += ev.text;
      else if (ev.type === 'tool') onLog?.(`[ask:tool] ${ev.name}`);
    });

    runner.on('result', (ev) => {
      onTokens?.(ev.inputTokens + ev.outputTokens);
    });

    runner.on('error', (err) => {
      timedOut = /timed out/i.test(err.message);
      reject(timedOut ? new Error('Ask Claude timed out') : err);
    });

    runner.on('exit', (code) => {
      if (timedOut) return; // already rejected via 'error'
      if (code !== 0) return reject(new Error(`Ask Claude exited with code ${code}`));

      // Reset idle timer — container stays alive for 5 more minutes
      clearTimeout(session.idleTimer);
      session.idleTimer = setTimeout(() => stopSession(sessionId), IDLE_TIMEOUT_MS);

      resolve(answer.trim());
    });

    runner.start();
  });
}

export function hasActiveContainer(appSlug) {
  for (const [, session] of liveSessions) {
    if (session.appSlug === appSlug) return true;
  }
  return false;
}

export function stopSession(sessionId) {
  const session = liveSessions.get(sessionId);
  if (!session) return;
  liveSessions.delete(sessionId);
  clearTimeout(session.idleTimer);
  clearTimeout(session.maxTimer);
  try { execFileSync('docker', ['rm', '-f', session.containerName], { stdio: 'pipe', timeout: 15000 }); } catch (_) {}
  // credsCleanup before skillsCleanup so refreshed Claude tokens get
  // captured back to the DB before the tmpdir is wiped.
  if (session.credsCleanup)  { try { session.credsCleanup();  } catch (_) {} }
  if (session.skillsCleanup) { try { session.skillsCleanup(); } catch (_) {} }
  log.info(`AskClaude: session ${sessionId} container stopped (idle timeout)`);
}
