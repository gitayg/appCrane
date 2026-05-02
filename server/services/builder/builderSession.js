import { execFileSync } from 'child_process';
import { mkdirSync, chmodSync, existsSync, readFileSync, readdirSync } from 'fs';
import { join, resolve } from 'path';
import { randomUUID } from 'crypto';
import { getDb } from '../../db.js';
import { decrypt } from '../encryption.js';
import { ensureStudioImage } from '../appstudio/generator.js';
import { ensureCodebaseContext } from '../appstudio/contextBuilder.js';
import { writeSnapshot } from '../github/snapshot.js';
import { runAgentExec } from '../llm/runAgent.js';
import { prepareSkillsMount } from '../skills.js';
import log from '../../utils/logger.js';

const STUDIO_IMAGE  = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';
const BUILDER_MODEL = process.env.APPSTUDIO_CODER_MODEL || 'claude-sonnet-4-6';
const IDLE_EVICT_MS = parseInt(process.env.CODER_IDLE_MS || '1800000', 10); // 30 min

// On-disk dir name kept as 'coder-sessions' for backward compatibility
// with existing workspaces on production. Function renamed; the legacy
// path string is a stable artifact.
function builderRoot() {
  return resolve(join(process.env.DATA_DIR || './data', 'coder-sessions'));
}

function sessionDir(sessionId) {
  return join(builderRoot(), sessionId);
}

/** In-memory map of active sessions { sessionId → SessionState } */
const sessions = new Map();

/** SSE subscriber lists { sessionId → Set<(event)=>void> } */
const subscribers = new Map();

function publish(sessionId, event) {
  const subs = subscribers.get(sessionId);
  if (subs) for (const fn of subs) fn(event);
}

export function subscribe(sessionId, fn) {
  if (!subscribers.has(sessionId)) subscribers.set(sessionId, new Set());
  subscribers.get(sessionId).add(fn);
  return () => subscribers.get(sessionId)?.delete(fn);
}

function updateDb(sessionId, fields) {
  const db = getDb();
  const sets = Object.keys(fields).map(k => `${k} = ?`).join(', ');
  db.prepare(`UPDATE coder_sessions SET ${sets} WHERE id = ?`)
    .run(...Object.values(fields), sessionId);
}

// Build a one-time intro message that the chat panel renders as the first
// 'agent' bubble. Tells the user who the agent is, what it can see, and
// what skills are loaded. Inserted on createSession only — NOT on resume
// (the chat history already contains it from the original create).
function buildIntroMessage(app, workspaceDir, branchName, containerId, skillsMounted) {
  const lines = [];
  lines.push(`👋 AppCrane Builder for ${app.name} (${app.slug})`);
  lines.push('');
  lines.push('I read and edit the code in your repo, run shell commands, and ship branches back to GitHub. You can ask me to add features, fix bugs, refactor, or explain how something works.');
  lines.push('');

  lines.push('── Runtime ──');
  lines.push(`Model:      ${BUILDER_MODEL}`);
  lines.push(`Container:  ${containerId.slice(0, 12)}  (image ${STUDIO_IMAGE})`);
  lines.push('Substrate:  Claude Code CLI (claude -p … --resume) — conversational continuity across turns');
  lines.push('');

  lines.push('── Workspace ──');
  lines.push(`Cloned branch:  ${app.branch || 'main'}`);
  lines.push(`Working branch: ${branchName}`);
  let topEntries = [];
  try {
    topEntries = readdirSync(workspaceDir).filter(n => !n.startsWith('.')).sort();
  } catch (_) {}
  if (topEntries.length) {
    const shown = topEntries.slice(0, 14).join(', ');
    const more = topEntries.length > 14 ? ` … +${topEntries.length - 14} more` : '';
    lines.push(`Top-level:      ${shown}${more}`);
  }
  let hasSnapshot = false;
  try { hasSnapshot = existsSync(join(workspaceDir, '.appcrane', 'github-snapshot.md')); } catch (_) {}
  if (hasSnapshot) {
    lines.push(`GitHub snapshot: .appcrane/github-snapshot.md (commits, PRs, requests, releases)`);
  }
  lines.push('');

  let skills = [];
  try {
    skills = getDb().prepare('SELECT slug, name, description FROM skills WHERE enabled = 1 ORDER BY name').all();
  } catch (_) {}
  lines.push('── Skills loaded ──');
  if (!skillsMounted || !skills.length) {
    lines.push('(none enabled — manage skills under Settings → Skills)');
  } else {
    for (const s of skills) {
      lines.push(`• ${s.name} (${s.slug})${s.description ? ` — ${s.description}` : ''}`);
    }
  }
  lines.push('');
  lines.push('What would you like to work on?');
  return lines.join('\n');
}

function appendMessage(sessionId, role, content, tokens) {
  const db = getDb();
  const row = db.prepare(
    'INSERT INTO coder_session_messages (session_id, role, content, tokens) VALUES (?, ?, ?, ?) RETURNING id'
  ).get(sessionId, role, content, tokens ?? null);
  return row?.id;
}

function touchActivity(sessionId) {
  updateDb(sessionId, { last_activity_at: new Date().toISOString() });
  const state = sessions.get(sessionId);
  if (state) state.lastActivityAt = Date.now();
}

// ── Idle eviction timer ──────────────────────────────────────────────────

setInterval(() => {
  const threshold = Date.now() - IDLE_EVICT_MS;
  for (const [sessionId, state] of sessions) {
    if (state.status !== 'idle') continue;
    if (state.lastActivityAt > threshold) continue;
    log.info(`Builder: idle evicting session ${sessionId}`);
    _evict(sessionId, state).catch(err => log.warn(`Builder evict error: ${err.message}`));
  }
}, 5 * 60 * 1000);

async function _evict(sessionId, state) {
  state.status = 'paused';
  if (state.containerId) {
    try {
      execFileSync('docker', ['stop', '-t', '10', state.containerId], { stdio: 'pipe', timeout: 20000 });
    } catch (_) {}
  }
  // Free the skills mount dir we created at startContainer time.
  if (state.skillsCleanup) {
    try { state.skillsCleanup(); } catch (_) {}
  }
  updateDb(sessionId, { status: 'paused', container_id: null });
  sessions.delete(sessionId);
  publish(sessionId, { type: 'status', status: 'paused' });
}

// ── On-startup orphan recovery ───────────────────────────────────────────

export function recoverOrphans() {
  const db = getDb();
  const orphans = db.prepare(
    "SELECT * FROM coder_sessions WHERE status IN ('starting', 'idle', 'active')"
  ).all();

  for (const s of orphans) {
    if (!s.container_id) {
      db.prepare("UPDATE coder_sessions SET status = 'paused' WHERE id = ?").run(s.id);
      continue;
    }
    try {
      execFileSync('docker', ['inspect', '--format', '{{.State.Running}}', s.container_id], { stdio: 'pipe', timeout: 5000 });
      // Container still running — re-register in memory.
      // claudeSessionId stays valid as long as the container is alive: the
      // CLI's session log lives at /home/studio/.claude/sessions/<id>.json
      // inside the container's writable layer.
      sessions.set(s.id, {
        appSlug: s.app_slug,
        containerId: s.container_id,
        workspaceDir: s.workspace_dir,
        branch: s.branch_name,
        status: 'idle',
        lastActivityAt: new Date(s.last_activity_at + 'Z').getTime() || Date.now(),
        runner: null,
        claudeSessionId: s.claude_session_id || null,
      });
      log.info(`Builder: recovered session ${s.id} (container ${s.container_id})`);
    } catch (_) {
      db.prepare("UPDATE coder_sessions SET status = 'paused', container_id = NULL WHERE id = ?").run(s.id);
      log.warn(`Builder: orphan session ${s.id} — container gone, marked paused`);
    }
  }
}

// ── Clone helpers ─────────────────────────────────────────────────────────

function cloneWorkspace(sessionId, app, branchName, onLog) {
  const workspaceDir = join(sessionDir(sessionId), 'workspace');
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

  onLog?.(`[builder:git] Cloning ${app.github_url} (${app.branch || 'main'})…`);
  try {
    execFileSync('git', ['clone', '--depth', '1', '--branch', app.branch || 'main', cloneUrl, workspaceDir], {
      stdio: 'pipe', timeout: 120000,
    });
  } catch (err) {
    throw new Error(err.message.replaceAll(cloneUrl, app.github_url));
  }

  execFileSync('git', ['-C', workspaceDir, 'config', 'user.email', 'builder@appcrane.local'], { stdio: 'pipe' });
  execFileSync('git', ['-C', workspaceDir, 'config', 'user.name', 'AppCrane Builder'], { stdio: 'pipe' });
  execFileSync('git', ['-C', workspaceDir, 'checkout', '-b', branchName], { stdio: 'pipe' });

  try { execFileSync('chmod', ['-R', '777', workspaceDir], { stdio: 'pipe' }); } catch (_) {}
  try { execFileSync('chown', ['-R', '1000:1000', workspaceDir], { stdio: 'pipe' }); } catch (_) {}

  onLog?.(`[builder:git] Workspace ready`);
  return workspaceDir;
}

function startContainer(sessionId, workspaceDir, onLog) {
  const containerName = `appcrane-builder-${sessionId}`;

  // Bind any enabled skills as ~/.claude/skills/ so the CLI loads them
  // natively. The mount is captured for the session's lifetime — toggling
  // a skill mid-session won't apply until the user pauses + resumes (which
  // creates a new container with a fresh mount).
  const skillsMount = prepareSkillsMount();

  const args = [
    'run', '-d', '--rm',
    '--name', containerName,
    '--label', 'appcrane=true',
    '--label', 'appcrane.container.type=builder',
    '--label', `builder.session=${sessionId}`,
    '--memory=2g', '--cpus=1',
    '-v', `${workspaceDir}:/workspace`,
  ];
  if (skillsMount) args.push('-v', `${skillsMount.dir}:/home/studio/.claude/skills:ro`);
  args.push(STUDIO_IMAGE, 'tail', '-f', '/dev/null');

  onLog?.(`[builder] Starting container ${containerName}…`);
  const out = execFileSync('docker', args, { stdio: 'pipe', timeout: 30000 });
  const containerId = out.toString().trim();
  if (skillsMount) onLog?.(`[builder] Mounted skills dir ${skillsMount.dir}`);
  onLog?.(`[builder] Container ready: ${containerId.slice(0, 12)}`);
  return { containerId, skillsCleanup: skillsMount?.cleanup || null };
}

// ── Public API ────────────────────────────────────────────────────────────

export async function createSession(app, userId, onLog) {
  if (!process.env.ANTHROPIC_API_KEY) {
    throw new Error('ANTHROPIC_API_KEY not configured');
  }
  const db = getDb();

  const existing = db.prepare(
    "SELECT id FROM coder_sessions WHERE app_slug = ? AND status NOT IN ('shipped', 'paused', 'error')"
  ).get(app.slug);
  if (existing) throw new Error(`Active builder session already exists: ${existing.id}`);

  const sessionId  = randomUUID();
  const branchName = `builder/${sessionId}`;

  db.prepare(`
    INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status)
    VALUES (?, ?, ?, ?, 'starting')
  `).run(sessionId, app.slug, userId, branchName);

  try {
    await ensureStudioImage(onLog);
    const workspaceDir = cloneWorkspace(sessionId, app, branchName, onLog);
    // Drop a GitHub-state snapshot into the workspace BEFORE the container
    // starts. The token stays on the host. Fail-soft: snapshot errors do
    // not block session creation.
    try { await writeSnapshot(app, workspaceDir, onLog); } catch (err) {
      log.warn(`Builder: snapshot write failed for ${app.slug}: ${err.message}`);
    }
    const { containerId, skillsCleanup } = startContainer(sessionId, workspaceDir, onLog);

    sessions.set(sessionId, {
      appSlug: app.slug,
      containerId,
      workspaceDir,
      branch: branchName,
      status: 'idle',
      lastActivityAt: Date.now(),
      runner: null,
      claudeSessionId: null,
      skillsCleanup,
    });

    updateDb(sessionId, {
      status: 'idle',
      container_id: containerId,
      workspace_dir: workspaceDir,
      claude_session_id: null,
    });

    // Insert a one-time intro message so the chat panel opens with an
    // overview of who the agent is, where it's running, and which skills
    // are loaded. Stored as 'assistant' so the UI renders it as an
    // agent bubble. Subsequent resumes don't re-insert (chat history
    // already contains it).
    try {
      const introText = buildIntroMessage(app, workspaceDir, branchName, containerId, !!skillsCleanup);
      appendMessage(sessionId, 'assistant', introText);
    } catch (err) {
      log.warn(`Builder: intro message generation failed: ${err.message}`);
    }

    // Pre-warm the codebase context so the first dispatch doesn't pay the
    // ~30s build cost. Fire-and-forget; the dispatch path will await this
    // anyway and read from cache once it lands.
    ensureCodebaseContext(app.slug, workspaceDir).catch(err =>
      log.warn(`Builder: context pre-warm failed for ${app.slug}: ${err.message}`)
    );

    publish(sessionId, { type: 'status', status: 'idle' });
    return sessionId;
  } catch (err) {
    updateDb(sessionId, { status: 'error' });
    sessions.delete(sessionId);
    throw err;
  }
}

export async function resumeSession(sessionId, onLog) {
  const db = getDb();
  const row = db.prepare('SELECT * FROM coder_sessions WHERE id = ?').get(sessionId);
  if (!row) throw new Error('Session not found');
  if (row.status !== 'paused') throw new Error(`Session status is '${row.status}', expected 'paused'`);
  if (!row.workspace_dir || !existsSync(row.workspace_dir)) {
    throw new Error('Workspace directory no longer exists — session cannot be resumed');
  }

  await ensureStudioImage(onLog);
  // Refresh the GitHub snapshot — the previous one was written when the
  // session was originally created and may be hours/days stale. Look up
  // the app row to get the current github_url and token.
  try {
    const app = db.prepare('SELECT slug, name, branch, github_url, github_token_encrypted FROM apps WHERE slug = ?').get(row.app_slug);
    if (app) await writeSnapshot(app, row.workspace_dir, onLog);
  } catch (err) {
    log.warn(`Builder: snapshot refresh failed for ${row.app_slug}: ${err.message}`);
  }
  const { containerId, skillsCleanup } = startContainer(sessionId, row.workspace_dir, onLog);

  // The previous container is gone, so its in-container CLI session log
  // (~/.claude/sessions/<id>.json) is gone too. Clear claudeSessionId —
  // the next dispatch starts a fresh Claude session.
  sessions.set(sessionId, {
    appSlug: row.app_slug,
    containerId,
    workspaceDir: row.workspace_dir,
    branch: row.branch_name,
    status: 'idle',
    lastActivityAt: Date.now(),
    runner: null,
    claudeSessionId: null,
    skillsCleanup,
  });

  updateDb(sessionId, { status: 'idle', container_id: containerId, claude_session_id: null });
  publish(sessionId, { type: 'status', status: 'idle' });
}

// Mirror the context bundling that AppStudio enhancement builders use
// (server/services/appstudio/generator.js: buildPrompt). Each Studio
// chat dispatch is a one-shot `claude -p`, so we re-supply the context
// every turn — Claude has no in-process memory across dispatches.
function buildChatPrompt({ contextDoc, agentContext, userMessage, includeSnapshotPointer }) {
  const parts = [];
  if (contextDoc?.trim()) {
    parts.push('# Codebase context');
    parts.push('Use this architectural overview to skip broad exploration. Read specific files directly when you need exact details. This overview was generated at an earlier git revision and may be out of date — when its claims affect what you are about to do, verify by reading the live file.');
    parts.push('');
    parts.push(contextDoc);
    parts.push('');
  }
  if (includeSnapshotPointer) {
    parts.push('# GitHub project snapshot');
    parts.push('A snapshot of recent commits, open pull requests, open feature requests (`appcrane:request` issues) and recent releases for this repo was written to `.appcrane/github-snapshot.md` in the workspace before this session started. Read it once when you need historical context for what has shipped, what is in flight, or what users have asked for. It is not refreshed during the session — for live state use `git log` or `git status`.');
    parts.push('');
  }
  if (agentContext?.trim()) {
    parts.push('# Per-app context from the operator');
    parts.push(agentContext);
    parts.push('');
  }
  // Workspace mutability note — important whether or not --resume is used.
  // The user (or git pull, or another process) may have changed files between
  // chat turns; the agent must not rely on its prior reads or the architectural
  // overview for any file it is about to modify.
  parts.push('# Workspace state');
  parts.push('The workspace may have changed since your previous response — files may have been edited by the user, by another process, or pulled from git. Do not rely on memory from prior turns. Before modifying any file, read its current contents. Prefer Glob/Grep over assumptions about file locations or names.');
  parts.push('');
  parts.push('# User message');
  parts.push(userMessage);
  return parts.join('\n');
}

async function loadDispatchContext(appSlug, workspaceDir) {
  let contextDoc = '';
  try {
    const r = await ensureCodebaseContext(appSlug, workspaceDir);
    contextDoc = r?.contextDoc || '';
  } catch (err) {
    log.warn(`Builder: ensureCodebaseContext failed for ${appSlug}: ${err.message}`);
  }
  let agentContext = '';
  try {
    const notesPath = join(resolve(process.env.DATA_DIR || './data'), 'apps', appSlug, 'agent-context.md');
    if (existsSync(notesPath)) agentContext = readFileSync(notesPath, 'utf8');
  } catch (_) {}
  return { contextDoc, agentContext };
}

export async function dispatch(sessionId, prompt) {
  const state = sessions.get(sessionId);
  if (!state) throw new Error('Session not active (start or resume first)');
  if (state.runner) throw new Error('A dispatch is already running');

  touchActivity(sessionId);
  // Persist the ORIGINAL user message so chat history shows what the user typed.
  appendMessage(sessionId, 'user', prompt);
  updateDb(sessionId, { status: 'active' });
  state.status = 'active';
  publish(sessionId, { type: 'status', status: 'active' });

  // Build the augmented prompt. On the FIRST dispatch (no claudeSessionId
  // yet), include the full context bundle — codebase summary, operator
  // notes, workspace-state warning. On SUBSEQUENT dispatches, --resume
  // gives Claude its prior turns from the in-container session log, so we
  // skip the heavy contextDoc (Claude already saw it). agentContext stays
  // since the operator may edit it mid-session.
  const isResume = !!state.claudeSessionId;
  let augmentedPrompt = prompt;
  if (state.appSlug) {
    try {
      const { contextDoc, agentContext } = await loadDispatchContext(state.appSlug, state.workspaceDir);
      const shouldBundle = (!isResume && (contextDoc || agentContext)) ||
                           (isResume && agentContext);
      if (shouldBundle) {
        augmentedPrompt = buildChatPrompt({
          contextDoc:   isResume ? '' : contextDoc, // skip on resume — already seen
          agentContext,
          userMessage:  prompt,
          includeSnapshotPointer: !isResume, // snapshot is mentioned once per session
        });
      }
    } catch (err) {
      log.warn(`Builder: dispatch context load failed: ${err.message}`);
    }
  }

  const runner = runAgentExec({
    containerId:  state.containerId,
    prompt:       augmentedPrompt,
    apiKey:       process.env.ANTHROPIC_API_KEY,
    resume:       state.claudeSessionId || undefined,
  });
  state.runner = runner;

  let assistantBuf = '';

  // Capture Claude's session id from the system init event. Persist on
  // first sighting; subsequent dispatches will pass it via --resume.
  // If Claude returns a different id (e.g. prior session log was lost),
  // we overwrite — continuity is broken for the current turn but the new
  // id keeps subsequent turns chained.
  runner.on('system', (ev) => {
    const sid = ev?.data?.session_id;
    if (sid && sid !== state.claudeSessionId) {
      state.claudeSessionId = sid;
      updateDb(sessionId, { claude_session_id: sid });
    }
  });

  runner.on('data', (ev) => {
    touchActivity(sessionId);
    if (ev.type === 'text') assistantBuf += ev.text;
    const db = getDb();
    db.prepare(`
      INSERT INTO coder_session_messages (session_id, role, content) VALUES (?, 'system', ?)
    `).run(sessionId, JSON.stringify(ev));
    publish(sessionId, { type: 'stream', event: ev });
  });

  runner.on('result', (ev) => {
    const db = getDb();
    const newTokens = (db.prepare('SELECT cost_tokens FROM coder_sessions WHERE id = ?').get(sessionId)?.cost_tokens || 0)
      + ev.inputTokens + ev.outputTokens;
    const newCents = (db.prepare('SELECT cost_usd_cents FROM coder_sessions WHERE id = ?').get(sessionId)?.cost_usd_cents || 0)
      + ev.costUsdCents;
    updateDb(sessionId, { cost_tokens: newTokens, cost_usd_cents: newCents });
    publish(sessionId, { type: 'cost', inputTokens: ev.inputTokens, outputTokens: ev.outputTokens, costUsdCents: ev.costUsdCents });
  });

  runner.on('exit', (code) => {
    if (assistantBuf) appendMessage(sessionId, 'assistant', assistantBuf);
    state.runner = null;
    state.status = 'idle';
    updateDb(sessionId, { status: 'idle' });
    publish(sessionId, { type: 'status', status: 'idle', exitCode: code });
  });

  runner.on('error', (err) => {
    state.runner = null;
    state.status = 'idle';
    updateDb(sessionId, { status: 'idle' });
    publish(sessionId, { type: 'error', message: err.message });
    publish(sessionId, { type: 'status', status: 'idle' });
  });

  runner.start();
}

export function stopDispatch(sessionId) {
  const state = sessions.get(sessionId);
  if (!state?.runner) return;
  state.runner.stop();
  state.runner = null;
  state.status = 'idle';
  updateDb(sessionId, { status: 'idle' });
  publish(sessionId, { type: 'status', status: 'idle' });
}

export function getInMemorySession(sessionId) {
  return sessions.get(sessionId) ?? null;
}
