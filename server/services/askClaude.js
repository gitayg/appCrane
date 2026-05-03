import { execFileSync } from 'child_process';
import { mkdirSync, existsSync, writeFileSync, rmSync } from 'fs';
import { join, resolve } from 'path';
import { decrypt } from './encryption.js';
import { ensureStudioImage } from './appstudio/generator.js';
import { assertCapacity } from './containerLimit.js';
import { runAgentExec } from './llm/runAgent.js';
import { prepareSkillsMount } from './skills.js';
import { prepareClaudeCredentialsMount } from './claudeCredentials.js';
import log from '../utils/logger.js';

const ASK_IMAGE      = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';
const ASK_MODEL      = process.env.APPSTUDIO_CODER_MODEL || 'claude-sonnet-4-6';
const ASK_TIMEOUT_MS = parseInt(process.env.ASK_TIMEOUT_MS || '300000', 10);
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;   // 5 minutes idle
const MAX_SESSION_MS  = 2 * 60 * 60 * 1000; // 2 hour hard cap

// sessionId -> { containerName, dir, idleTimer, maxTimer }
const liveSessions = new Map();

function sessionDir(sessionId) {
  const root = join(resolve(process.env.DATA_DIR || './data'), 'ask-sessions');
  return join(root, String(sessionId)); // nosemgrep: path-join-resolve-traversal — sessionId is integer PK from DB
}

function buildCloneUrl(app) {
  if (!app.github_token_encrypted) return app.github_url;
  try {
    const token = decrypt(app.github_token_encrypted);
    const url = new URL(app.github_url);
    url.username = token;
    return url.toString();
  } catch (_) { return app.github_url; }
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

async function waitForWorkspace(containerName, onLog) {
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 2000));
    try {
      const status = execFileSync('docker', ['inspect', '--format', '{{.State.Status}}', containerName], { stdio: 'pipe', timeout: 5000 }).toString().trim();
      if (status === 'exited' || status === 'dead') throw new Error('Container exited during clone');
      execFileSync('docker', ['exec', containerName, 'test', '-d', '/workspace'], { stdio: 'pipe', timeout: 5000 });
      onLog?.('[ask] Repository ready');
      return;
    } catch (e) {
      if (e.message.includes('Container exited')) throw e;
    }
  }
  throw new Error('Timed out waiting for repository clone');
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
  const dir = sessionDir(sessionId);
  mkdirSync(dir, { recursive: true });

  // Kill any existing container with this name (e.g. from a previous server run)
  try { execFileSync('docker', ['rm', '-f', containerName], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}

  const cloneUrl = buildCloneUrl(app);

  onLog?.('[ask] Cloning repository...');
  log.info(`AskClaude: starting session container ${containerName}`);

  // Write token URL to a file — never put it in an env var (would persist in /proc/environ)
  writeFileSync(join(dir, 'clone_url'), cloneUrl, { mode: 0o644 }); // nosemgrep: container runs as non-root, needs read access

  // Bind skills assigned to this app as ~/.claude/skills/ — same mechanism
  // as the builder session container, so Ask gets the same skill set the
  // app's Builder uses.
  const skillsMount = prepareSkillsMount(app.slug);
  // Per-app Claude OAuth credentials (if uploaded) override the global API key.
  const credsMount = prepareClaudeCredentialsMount(app.slug);

  // Clone, strip remote, disable credential helper — ask containers cannot commit or push
  const dockerArgs = [
    'run', '-d',
    '--name', containerName,
    '--label', 'appcrane=true',
    '--label', 'appcrane.container.type=ask',
    '--memory=1g', '--cpus=0.5',
    '-e', `ANTHROPIC_API_KEY=${process.env.ANTHROPIC_API_KEY || ''}`,
    '-e', `ASK_MODEL=${ASK_MODEL}`,
    '-v', `${dir}:/studio:ro`,
  ];
  if (credsMount)  dockerArgs.push('-v', `${credsMount.tmpFile}:/home/studio/.claude/credentials.json`);
  if (skillsMount) dockerArgs.push('-v', `${skillsMount.dir}:/home/studio/.claude/skills:ro`);
  dockerArgs.push(
    ASK_IMAGE,
    'sh', '-c',
    `CLONE_URL=$(cat /studio/clone_url) && git clone --depth 1 --branch "${app.branch || 'main'}" "$CLONE_URL" /workspace && git -C /workspace remote remove origin && git -C /workspace config --local credential.helper '' && tail -f /dev/null`,
  );
  execFileSync('docker', dockerArgs, { stdio: 'pipe', timeout: 15000 });

  await waitForWorkspace(containerName, onLog);

  // Clear the token from the mounted file — clone is done, container no longer needs it
  writeFileSync(join(dir, 'clone_url'), '', { mode: 0o644 }); // nosemgrep

  const session = {
    containerName, dir, appSlug: app.slug,
    idleTimer: null, maxTimer: null,
    skillsCleanup: skillsMount?.cleanup || null,
    credsCleanup:  credsMount?.cleanup  || null,
  };
  session.maxTimer = setTimeout(() => stopSession(sessionId), MAX_SESSION_MS);
  liveSessions.set(sessionId, session);
  return session;
}

export async function runAskJob({ sessionId, app, question, history, agentContext, contextDoc, onLog, onTokens }) {
  const session = await ensureSessionContainer(sessionId, app, onLog);
  const prompt = buildPrompt({ contextDoc, agentContext, history, question });

  onLog?.('[ask] Running Claude Code...');

  return new Promise((resolve, reject) => {
    let answer = '';
    let timedOut = false;

    const runner = runAgentExec({
      containerId: session.containerName,
      prompt,
      apiKey: process.env.ANTHROPIC_API_KEY,
      model: ASK_MODEL,
      timeoutMs: ASK_TIMEOUT_MS + 60000,
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
  try { rmSync(session.dir, { recursive: true, force: true }); } catch (_) {}
  // credsCleanup before skillsCleanup so refreshed Claude tokens get
  // captured back to the DB before the tmpdir is wiped.
  if (session.credsCleanup)  { try { session.credsCleanup();  } catch (_) {} }
  if (session.skillsCleanup) { try { session.skillsCleanup(); } catch (_) {} }
  log.info(`AskClaude: session ${sessionId} container stopped (idle timeout)`);
}
