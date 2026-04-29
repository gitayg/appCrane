import { spawn, execFileSync } from 'child_process';
import { mkdirSync, existsSync, writeFileSync, rmSync } from 'fs';
import { join, resolve } from 'path';
import { decrypt } from './encryption.js';
import { ensureStudioImage } from './appstudio/generator.js';
import { assertCapacity } from './containerLimit.js';
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

// Runner script executed via `docker exec` — reads /studio/prompt.txt, runs Claude,
// emits [tokens:N] lines for live tracking, then emits the answer between sentinels.
function buildRunnerScript() {
  return `#!/usr/bin/env node
'use strict';
const { spawn } = require('child_process');
const { createInterface } = require('readline');
const fs = require('fs');

const model = process.env.ASK_MODEL;
const prompt = fs.readFileSync('/studio/prompt.txt', 'utf8');
const claudeEnv = { ...process.env, HOME: '/home/studio', PATH: '/usr/local/bin:/usr/bin:/bin' };

const child = spawn('claude', [
  '-p', prompt,
  '--model', model,
  '--dangerously-skip-permissions',
  '--output-format', 'stream-json',
  '--verbose',
], { stdio: ['ignore', 'pipe', 'pipe'], cwd: '/workspace', env: claudeEnv });

let answer = '';
let totalTokens = 0;
let lastEmittedTokens = -1;

const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
rl.on('line', (line) => {
  if (!line.trim()) return;
  try {
    const evt = JSON.parse(line);
    if (evt.type === 'result') {
      answer = evt.result || '';
      if (evt.usage) {
        totalTokens = (evt.usage.input_tokens || 0) + (evt.usage.output_tokens || 0)
          + (evt.usage.cache_read_input_tokens || 0);
      }
    } else if (evt.type === 'assistant' && evt.message && evt.message.usage) {
      const u = evt.message.usage;
      totalTokens = (u.input_tokens || 0) + (u.output_tokens || 0) + (u.cache_read_input_tokens || 0);
      if (totalTokens !== lastEmittedTokens) {
        lastEmittedTokens = totalTokens;
        process.stdout.write('[tokens:' + totalTokens + ']\\n');
      }
    }
  } catch (_) {}
});

child.stderr.on('data', (c) => process.stderr.write(c));

const killTimer = setTimeout(() => { child.kill('SIGTERM'); }, ${ASK_TIMEOUT_MS});
child.on('error', (err) => { clearTimeout(killTimer); console.error('[ask] Error: ' + err.message); process.exit(1); });
child.on('close', (code) => {
  clearTimeout(killTimer);
  if (code !== 0 && code !== null) { console.error('[ask] Claude exited with code ' + code); process.exit(code || 1); }
  if (totalTokens > 0 && totalTokens !== lastEmittedTokens) {
    process.stdout.write('[tokens:' + totalTokens + ']\\n');
  }
  process.stdout.write('\\x00ASK_START\\x00' + answer + '\\x00ASK_END\\x00\\n');
});
`;
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
  writeFileSync(join(dir, 'runner.js'), buildRunnerScript()); // nosemgrep

  // Kill any existing container with this name (e.g. from a previous server run)
  try { execFileSync('docker', ['rm', '-f', containerName], { stdio: 'pipe', timeout: 10000 }); } catch (_) {}

  const cloneUrl = buildCloneUrl(app);

  onLog?.('[ask] Cloning repository...');
  log.info(`AskClaude: starting session container ${containerName}`);

  // Write token URL to a file — never put it in an env var (would persist in /proc/environ)
  writeFileSync(join(dir, 'clone_url'), cloneUrl, { mode: 0o644 }); // nosemgrep: container runs as non-root, needs read access

  // Clone, strip remote, disable credential helper — ask containers cannot commit or push
  execFileSync('docker', [
    'run', '-d',
    '--name', containerName,
    '--label', 'appcrane=true',
    '--label', 'appcrane.container.type=ask',
    '--memory=1g', '--cpus=0.5',
    '-e', `ANTHROPIC_API_KEY=${process.env.ANTHROPIC_API_KEY}`,
    '-e', `ASK_MODEL=${ASK_MODEL}`,
    '-v', `${dir}:/studio:ro`,
    ASK_IMAGE,
    'sh', '-c',
    `CLONE_URL=$(cat /studio/clone_url) && git clone --depth 1 --branch "${app.branch || 'main'}" "$CLONE_URL" /workspace && git -C /workspace remote remove origin && git -C /workspace config --local credential.helper '' && tail -f /dev/null`,
  ], { stdio: 'pipe', timeout: 15000 });

  await waitForWorkspace(containerName, onLog);

  // Clear the token from the mounted file — clone is done, container no longer needs it
  writeFileSync(join(dir, 'clone_url'), '', { mode: 0o644 }); // nosemgrep

  const session = { containerName, dir, appSlug: app.slug, idleTimer: null, maxTimer: null };
  session.maxTimer = setTimeout(() => stopSession(sessionId), MAX_SESSION_MS);
  liveSessions.set(sessionId, session);
  return session;
}

function extractAnswer(stdout) {
  const startMark = '\x00ASK_START\x00';
  const endMark   = '\x00ASK_END\x00';
  const si = stdout.indexOf(startMark);
  const ei = stdout.indexOf(endMark);
  return (si !== -1 && ei !== -1)
    ? stdout.slice(si + startMark.length, ei).trim()
    : stdout.split('\n').filter(l => !l.startsWith('[ask]') && !l.startsWith('[stderr]')).join('\n').trim();
}

export async function runAskJob({ sessionId, app, question, history, agentContext, contextDoc, onLog, onTokens }) {
  const session = await ensureSessionContainer(sessionId, app, onLog);

  const prompt = buildPrompt({ contextDoc, agentContext, history, question });
  writeFileSync(join(session.dir, 'prompt.txt'), prompt); // nosemgrep

  onLog?.('[ask] Running Claude Code...');

  return new Promise((resolve, reject) => {
    const child = spawn('docker', ['exec', session.containerName, 'node', '/studio/runner.js'], { stdio: 'pipe' });
    let stdout = '';
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, ASK_TIMEOUT_MS + 60000);

    child.stdout.on('data', (c) => {
      const text = c.toString();
      stdout += text;
      text.split('\n').forEach(line => {
        if (!line.trim() || line.startsWith('\x00')) return;
        const tm = line.match(/^\[tokens:(\d+)\]$/);
        if (tm) { onTokens?.(parseInt(tm[1], 10)); return; }
        onLog?.(line);
      });
    });
    child.stderr.on('data', (c) => c.toString().split('\n').forEach(l => { if (l.trim()) onLog?.(`[stderr] ${l}`); }));

    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (timedOut) return reject(new Error('Ask Claude timed out'));
      if (code !== 0) return reject(new Error(`Runner exited with code ${code}`));

      // Reset idle timer — container stays alive for 5 more minutes
      clearTimeout(session.idleTimer);
      session.idleTimer = setTimeout(() => stopSession(sessionId), IDLE_TIMEOUT_MS);

      resolve(extractAnswer(stdout));
    });
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
  log.info(`AskClaude: session ${sessionId} container stopped (idle timeout)`);
}
