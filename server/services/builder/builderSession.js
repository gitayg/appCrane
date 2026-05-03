import { execFileSync } from 'child_process';
import { existsSync, readFileSync, readdirSync } from 'fs';
import { join, resolve } from 'path';
import { randomUUID } from 'crypto';
import { getDb } from '../../db.js';
import { ensureCodebaseContext } from '../appstudio/contextBuilder.js';
import { runAgentExec } from '../llm/runAgent.js';
import {
  getOrCreate as ensureAppContainer,
  getContainer,
  evict as evictAppContainer,
  heartbeat as containerHeartbeat,
  setBusy as setContainerBusy,
  setClaudeSessionId as setAppClaudeSessionId,
  onEvict as onAppContainerEvict,
} from './appContainer.js';
import {
  enqueue as enqueueWork,
  subscribeQueue,
  aheadOf,
  PRIORITY,
} from './appQueue.js';
import log from '../../utils/logger.js';

const STUDIO_IMAGE  = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';
const BUILDER_MODEL = process.env.APPSTUDIO_CODER_MODEL || 'claude-sonnet-4-6';

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

// One-time intro message inserted as the first 'assistant' bubble in the
// chat panel. Tells the user what this is, where it's running, and what
// skills are loaded. Inserted on createSession only.
function buildIntroMessage(app, workspaceDir, branchName, containerId, skillsMounted) {
  const lines = [];
  lines.push(`👋 AppCrane Builder for ${app.name} (${app.slug})`);
  lines.push('');
  lines.push('I read and edit the code in your repo, run shell commands, and ship branches back to GitHub. You can ask me to add features, fix bugs, refactor, or explain how something works.');
  lines.push('');

  lines.push('── Runtime ──');
  lines.push(`Model:      ${BUILDER_MODEL}`);
  lines.push(`Container:  ${containerId.slice(0, 12)}  (image ${STUDIO_IMAGE}, shared per app)`);
  lines.push('Substrate:  Claude Code CLI (claude -p … --resume) — single conversation per app, shared across users');
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
  if (state) {
    state.lastActivityAt = Date.now();
    containerHeartbeat(state.appSlug);
  }
}

// When an app container is evicted (idle, manual, or vanished), pause every
// in-memory session that was bound to it and notify subscribers so the chat
// UI updates immediately.
onAppContainerEvict((slug, reason) => {
  for (const [sessionId, state] of sessions) {
    if (state.appSlug !== slug) continue;
    sessions.delete(sessionId);
    try {
      updateDb(sessionId, { status: 'paused', container_id: null });
    } catch (_) {}
    publish(sessionId, { type: 'status', status: 'paused', reason });
  }
});

// ── On-startup orphan recovery ───────────────────────────────────────────

export function recoverOrphans() {
  // Sessions that appeared 'starting'/'idle'/'active' before AppCrane restarted
  // are stale: their app containers are gone (recoverOrphans on appContainer
  // wipes them on boot). Mark all such rows paused.
  const db = getDb();
  const orphans = db.prepare(
    "SELECT id FROM coder_sessions WHERE status IN ('starting', 'idle', 'active')"
  ).all();
  for (const o of orphans) {
    db.prepare("UPDATE coder_sessions SET status = 'paused', container_id = NULL WHERE id = ?").run(o.id);
    log.info(`Builder: marked orphan session ${o.id} as paused on startup`);
  }
}

// ── Public API ────────────────────────────────────────────────────────────

function activeOtherSessionForApp(slug, userId) {
  // "No takeover": at most one interactive Builder session per app.
  // A second user attempting to start a session while another user holds
  // an active/idle one gets blocked here.
  const db = getDb();
  return db.prepare(`
    SELECT s.*, u.name as user_name, u.username as user_username, u.email as user_email
    FROM coder_sessions s
    LEFT JOIN users u ON u.id = s.user_id
    WHERE s.app_slug = ? AND s.user_id != ? AND s.status IN ('starting', 'idle', 'active')
    ORDER BY s.created_at DESC LIMIT 1
  `).get(slug, userId);
}

function existingOwnSessionForApp(slug, userId) {
  const db = getDb();
  return db.prepare(`
    SELECT * FROM coder_sessions
    WHERE app_slug = ? AND user_id = ? AND status IN ('starting', 'idle', 'active')
    ORDER BY created_at DESC LIMIT 1
  `).get(slug, userId);
}

export async function createSession(app, userId, onLog) {
  if (!process.env.ANTHROPIC_API_KEY) {
    throw new Error('ANTHROPIC_API_KEY not configured');
  }

  const blocking = activeOtherSessionForApp(app.slug, userId);
  if (blocking) {
    const who = blocking.user_name || blocking.user_username || blocking.user_email || `user ${blocking.user_id}`;
    const err = new Error(`Builder is occupied by ${who}. Only one interactive Builder session per app — wait for them to finish or evict the container.`);
    err.code = 'BUILDER_OCCUPIED';
    throw err;
  }

  // If THIS user already has a live session for the app, return it (no double-spawn)
  const own = existingOwnSessionForApp(app.slug, userId);
  if (own) return own.id;

  const db = getDb();
  const sessionId = randomUUID();

  db.prepare(`
    INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status)
    VALUES (?, ?, ?, ?, 'starting')
  `).run(sessionId, app.slug, userId, `builder/${app.slug}`);

  try {
    const c = await ensureAppContainer(app, onLog);

    sessions.set(sessionId, {
      appSlug: app.slug,
      status: 'idle',
      lastActivityAt: Date.now(),
      runner: null,
    });

    updateDb(sessionId, {
      status: 'idle',
      container_id: c.containerId,
      workspace_dir: c.workspaceDir,
      claude_session_id: c.claudeSessionId || null,
    });

    try {
      const introText = buildIntroMessage(app, c.workspaceDir, c.branchName, c.containerId, !!c.skillsCleanup);
      appendMessage(sessionId, 'assistant', introText);
    } catch (err) {
      log.warn(`Builder: intro message generation failed: ${err.message}`);
    }

    ensureCodebaseContext(app.slug, c.workspaceDir).catch(err =>
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

  const blocking = activeOtherSessionForApp(row.app_slug, row.user_id);
  if (blocking) {
    const who = blocking.user_name || blocking.user_username || blocking.user_email || `user ${blocking.user_id}`;
    const err = new Error(`Builder is occupied by ${who}.`);
    err.code = 'BUILDER_OCCUPIED';
    throw err;
  }

  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(row.app_slug);
  if (!app) throw new Error(`App ${row.app_slug} no longer exists`);

  const c = await ensureAppContainer(app, onLog);

  sessions.set(sessionId, {
    appSlug: row.app_slug,
    status: 'idle',
    lastActivityAt: Date.now(),
    runner: null,
  });

  updateDb(sessionId, {
    status: 'idle',
    container_id: c.containerId,
    workspace_dir: c.workspaceDir,
    claude_session_id: c.claudeSessionId || null,
  });
  publish(sessionId, { type: 'status', status: 'idle' });
}

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
  if (state.runner || state.queued) throw new Error('A dispatch is already running');

  const c0 = getContainer(state.appSlug);
  if (!c0) throw new Error('App container is no longer available — resume the session first');

  touchActivity(sessionId);
  appendMessage(sessionId, 'user', prompt);

  // Mark queued. If anything is ahead of us — running Improve, or another
  // queued Builder turn (shouldn't normally happen since "no takeover" caps
  // Builder at 1 user, but Improve jobs can stack) — surface the position
  // to the chat UI so the user sees they're waiting in line.
  const ahead = aheadOf(state.appSlug, PRIORITY.BUILDER);
  state.queued = true;
  if (ahead > 0) {
    updateDb(sessionId, { status: 'queued' });
    state.status = 'queued';
    publish(sessionId, { type: 'status', status: 'queued', ahead });
  } else {
    updateDb(sessionId, { status: 'active' });
    state.status = 'active';
    publish(sessionId, { type: 'status', status: 'active' });
  }

  // Subscribe to queue updates so the chat panel can show "N ahead" live.
  // aheadOf(BUILDER) counts running + queued items with priority<=BUILDER —
  // once our own item is enqueued, that count includes us. Subtract 1 to
  // get the true "ahead of me" number. Safe because no-takeover guarantees
  // at most one Builder item per app is ever queued at a time.
  const unsubQueue = subscribeQueue(state.appSlug, (snap) => {
    if (!state.queued) return;
    const raw = aheadOf(state.appSlug, PRIORITY.BUILDER);
    const myAhead = Math.max(0, raw - 1);
    publish(sessionId, { type: 'queue', ahead: myAhead, depth: snap.depth, running: snap.running });
  });

  enqueueWork(state.appSlug, {
    priority:   PRIORITY.BUILDER,
    sourceType: 'builder',
    sourceId:   sessionId,
    label:      `Builder turn (${prompt.slice(0, 60)})`,
    run: () => runBuilderTurn(sessionId, state, prompt),
  }).finally(() => {
    state.queued = false;
    try { unsubQueue(); } catch (_) {}
  });
}

async function runBuilderTurn(sessionId, state, prompt) {
  const c = getContainer(state.appSlug);
  if (!c) {
    publish(sessionId, { type: 'error', message: 'App container vanished while waiting in queue' });
    publish(sessionId, { type: 'status', status: 'paused' });
    return;
  }

  setContainerBusy(state.appSlug, true);
  if (state.status !== 'active') {
    updateDb(sessionId, { status: 'active' });
    state.status = 'active';
    publish(sessionId, { type: 'status', status: 'active' });
  }

  // Pull the latest claudeSessionId from the shared app container so the next
  // dispatch resumes the SAME thread as any previous turn (regardless of
  // which user ran the previous turn).
  const isResume = !!c.claudeSessionId;
  let augmentedPrompt = prompt;
  if (state.appSlug) {
    try {
      const { contextDoc, agentContext } = await loadDispatchContext(state.appSlug, c.workspaceDir);
      const shouldBundle = (!isResume && (contextDoc || agentContext)) ||
                           (isResume && agentContext);
      if (shouldBundle) {
        augmentedPrompt = buildChatPrompt({
          contextDoc:   isResume ? '' : contextDoc,
          agentContext,
          userMessage:  prompt,
          includeSnapshotPointer: !isResume,
        });
      }
    } catch (err) {
      log.warn(`Builder: dispatch context load failed: ${err.message}`);
    }
  }

  return new Promise((resolveRun) => {
    const runner = runAgentExec({
      containerId:  c.containerId,
      prompt:       augmentedPrompt,
      apiKey:       process.env.ANTHROPIC_API_KEY,
      resume:       c.claudeSessionId || undefined,
    });
    state.runner = runner;

    let assistantBuf = '';
    let settled = false;
    const settle = () => { if (!settled) { settled = true; resolveRun(); } };

    runner.on('system', (ev) => {
      const sid = ev?.data?.session_id;
      // SECURITY: session_id flows back into a `sh -c` --resume arg next
      // time. Validate before storing so a poisoned event from a
      // misbehaving CLI/skill can't seed a shell-injection that fires on
      // the next dispatch (across users sharing the per-app container).
      // See feedback memory: "Validate user-controlled strings at the DB
      // write boundary AND at the shell-build boundary."
      if (sid && !/^[A-Za-z0-9_-]{1,128}$/.test(String(sid))) {
        log.warn(`Builder: refusing to store malformed session_id from ${state.appSlug}`);
        return;
      }
      if (sid && sid !== c.claudeSessionId) {
        setAppClaudeSessionId(state.appSlug, sid);
        try {
          getDb().prepare('UPDATE coder_sessions SET claude_session_id = ? WHERE app_slug = ?')
            .run(sid, state.appSlug);
        } catch (_) {}
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
      setContainerBusy(state.appSlug, false);
      publish(sessionId, { type: 'status', status: 'idle', exitCode: code });
      settle();
    });

    runner.on('error', (err) => {
      state.runner = null;
      state.status = 'idle';
      updateDb(sessionId, { status: 'idle' });
      setContainerBusy(state.appSlug, false);
      publish(sessionId, { type: 'error', message: err.message });
      publish(sessionId, { type: 'status', status: 'idle' });
      settle();
    });

    runner.start();
  });
}

export function stopDispatch(sessionId) {
  const state = sessions.get(sessionId);
  if (!state?.runner) return;
  state.runner.stop();
  state.runner = null;
  state.status = 'idle';
  setContainerBusy(state.appSlug, false);
  updateDb(sessionId, { status: 'idle' });
  publish(sessionId, { type: 'status', status: 'idle' });
}

export function getInMemorySession(sessionId) {
  return sessions.get(sessionId) ?? null;
}

/**
 * Manual evict — tear down the shared app container and delete its workspace.
 * All in-memory sessions for this app get marked paused via the onEvict hook.
 */
export function evictApp(slug, reason = 'manual') {
  return evictAppContainer(slug, reason);
}
