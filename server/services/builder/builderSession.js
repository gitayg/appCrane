import { execFileSync } from 'child_process';
import { existsSync, readFileSync, readdirSync } from 'fs';
import { join, resolve } from 'path';
import { randomUUID } from 'crypto';
import { getDb } from '../../db.js';
import { ensureCodebaseContext } from '../appstudio/contextBuilder.js';
import { runAgentExec, agentCredentialKind, NO_CREDENTIAL_MESSAGE } from '../llm/runAgent.js';
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
import { defaultCoderModel, isAllowedCoderModel } from '../llm/coderModels.js';
import { explainTurnFailure, isAuthFailure } from './turnFailure.js';
import log from '../../utils/logger.js';

const STUDIO_IMAGE  = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';

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
  // One sentence, not a branch on the app's repo backend. createSession is the
  // only caller of this function, and its only caller is POST
  // /api/coder/:slug/session, which runs assertCraneHosted first — so every app
  // that ever reaches this line is Crane-hosted. The other half of the ternary
  // described shipping a branch to GitHub, which /api/agents did and which went
  // with it in v2.83.0; the release path below is the one that exists.
  lines.push('I read and edit the code in your Crane-hosted repo and run shell commands. You can ask me to add features, fix bugs, refactor, or explain how something works. When you are happy with a change, release it: you pick which changed files to commit, and AppCrane deploys them to sandbox.');
  lines.push('');

  lines.push('── Runtime ──');
  lines.push(`Model:      ${defaultCoderModel()} (default — pick another per message in the composer)`);
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

function appendMessage(sessionId, role, content, tokens, model) {
  const db = getDb();
  const row = db.prepare(
    'INSERT INTO coder_session_messages (session_id, role, content, tokens, model) VALUES (?, ?, ?, ?, ?) RETURNING id'
  ).get(sessionId, role, content, tokens ?? null, model ?? null);
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
  // The SECOND gate, and the one that made the per-user subscription unusable.
  //
  // v2.81.0 relaxed the route gates (coder.js, ask.js, appstudio.js) to "any
  // credential resolves", so a caller with their own Claude token got past
  // them -- and then hit this unconditional platform-key check inside the
  // service and was refused anyway. Measured on a real box with a real stored
  // token and no ANTHROPIC_API_KEY: POST /api/coder/<slug>/session answered
  // `{"error":{"code":"INTERNAL_ERROR","message":"ANTHROPIC_API_KEY not
  // configured"}}`. No test caught it because they all either set the env var
  // or stub at the runAgent layer, below this line.
  //
  // Same question as the route asks, so the two cannot disagree again.
  if (agentCredentialKind({ actingUserId: userId, appSlug: app.slug }) === 'none') {
    const err = new Error(NO_CREDENTIAL_MESSAGE);
    err.code = 'NOT_CONFIGURED';
    err.status = 503;
    throw err;
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

// The codebase summary is only sent on a thread's first turn, so a resumed
// thread skips building it. The first build can take minutes, and it used to
// happen with nothing on screen: say so after a moment, and say so again if it
// fails rather than continuing silently.
const CONTEXT_NOTE_AFTER_MS = 2000;

async function loadDispatchContext(appSlug, workspaceDir, { withCodebase = true, sessionId = null } = {}) {
  let contextDoc = '';
  if (withCodebase) {
    const slow = sessionId && setTimeout(() => publish(sessionId, {
      type: 'note',
      message: 'Reading the codebase before your first message, so the coder knows the app. This takes a minute or two on a fresh container.',
    }), CONTEXT_NOTE_AFTER_MS);
    try {
      const r = await ensureCodebaseContext(appSlug, workspaceDir);
      contextDoc = r?.contextDoc || '';
    } catch (err) {
      log.warn(`Builder: ensureCodebaseContext failed for ${appSlug}: ${err.message}`);
      if (sessionId) publish(sessionId, {
        type: 'note',
        message: `Could not prepare the codebase summary (${err.message}). Continuing without it.`,
      });
    } finally {
      if (slow) clearTimeout(slow);
    }
  }
  let agentContext = '';
  try {
    const notesPath = join(resolve(process.env.DATA_DIR || './data'), 'apps', appSlug, 'agent-context.md');
    if (existsSync(notesPath)) agentContext = readFileSync(notesPath, 'utf8');
  } catch (_) {}
  return { contextDoc, agentContext };
}

// ── typed-ahead follow-ups ────────────────────────────────────────────────
//
// TWO QUEUES, DELIBERATELY SEPARATE.
//
// appQueue (enqueueWork / aheadOf / PRIORITY) is per-APP and is about other
// work competing for the same container: an Improve job, another app-level
// turn. `ahead` in the chat means "N jobs are using this app's container
// before yours". BUILDER_OCCUPIED is a third thing again — a different USER
// already holds the one interactive session for this app.
//
// This queue is per-SESSION and holds only what THIS user typed while THIS
// session's turn was still running. It never touches appQueue: a follow-up
// enters appQueue exactly when it is dispatched, through the same
// enqueueWork() path any first message takes, and can then report its own
// `ahead`. So there is still at most one appQueue item per session at a time,
// which is the invariant the `aheadOf(...) - 1` arithmetic below depends on.
//
// It lives in SQLite rather than in the browser or in `state` because a typed-
// ahead message has to survive a page reload and be visible to anyone else
// watching the session — a client-side array loses both, and an in-memory one
// loses the reload.

function pendingFollowups(sessionId) {
  return getDb().prepare(
    "SELECT id, prompt, model, user_id, created_at FROM coder_session_followups "
    + "WHERE session_id = ? AND status = 'pending' ORDER BY id ASC"
  ).all(sessionId);
}

function publishFollowups(sessionId) {
  publish(sessionId, { type: 'followups', items: pendingFollowups(sessionId) });
}

/** Queue a message the user typed while a turn was in flight. */
function enqueueFollowup(sessionId, prompt, model, userId) {
  const row = getDb().prepare(
    'INSERT INTO coder_session_followups (session_id, prompt, model, user_id) '
    + 'VALUES (?, ?, ?, ?) RETURNING id, prompt, model, user_id, created_at'
  ).get(sessionId, prompt, model ?? null, userId ?? null);
  publishFollowups(sessionId);
  return row;
}

/** Cancel one pending follow-up. Returns false if it already ran or is gone. */
export function cancelFollowup(sessionId, followupId) {
  const info = getDb().prepare(
    "UPDATE coder_session_followups SET status = 'cancelled', resolved_at = datetime('now') "
    + "WHERE id = ? AND session_id = ? AND status = 'pending'"
  ).run(followupId, sessionId);
  if (!info.changes) return false;
  publishFollowups(sessionId);
  return true;
}

export function listFollowups(sessionId) {
  return pendingFollowups(sessionId);
}

/**
 * STOP CLEARS THE QUEUE.
 *
 * Stop means "stop what I asked for". The pending messages were written as
 * continuations of a turn the user has just abandoned — running them next
 * would apply instructions that assume work which was interrupted halfway, to
 * a workspace in a state nobody chose, and file edits are the one thing here
 * that is not cheap to undo. Cancelling is the recoverable direction, and the
 * cancelled text is published back into the transcript as a note so it can be
 * read and re-sent rather than silently lost.
 */
function cancelAllPending(sessionId, reason) {
  const rows = pendingFollowups(sessionId);
  if (!rows.length) return [];
  getDb().prepare(
    "UPDATE coder_session_followups SET status = 'cancelled', resolved_at = datetime('now') "
    + "WHERE session_id = ? AND status = 'pending'"
  ).run(sessionId);
  publishFollowups(sessionId);
  publish(sessionId, {
    type: 'note',
    message: `${rows.length} pending follow-up${rows.length === 1 ? '' : 's'} cancelled (${reason}): `
      + rows.map((r) => JSON.stringify(r.prompt.slice(0, 60))).join(', '),
  });
  return rows;
}

/**
 * Called once a turn is completely done. Takes the oldest pending follow-up
 * and dispatches it as an ordinary turn — same path, same appQueue entry, same
 * events — so order is preserved and nothing about a follow-up turn is special
 * once it starts running.
 */
async function drainNextFollowup(sessionId) {
  const state = sessions.get(sessionId);
  if (!state || state.runner || state.queued) return;
  const next = pendingFollowups(sessionId)[0];
  if (!next) return;
  const claimed = getDb().prepare(
    "UPDATE coder_session_followups SET status = 'dispatched', resolved_at = datetime('now') "
    + "WHERE id = ? AND status = 'pending'"
  ).run(next.id);
  if (!claimed.changes) return;   // cancelled between the read and the claim
  publishFollowups(sessionId);
  try {
    await dispatch(sessionId, next.prompt, { model: next.model, userId: next.user_id });
  } catch (err) {
    publish(sessionId, { type: 'error', message: `Queued follow-up could not start: ${err.message}` });
  }
}

/**
 * Start a turn, or queue it behind the one already running.
 *
 * Returns { started: true } or { queued: true, followup }. It no longer throws
 * "A dispatch is already running": typing the next instruction while the
 * current one works is the point of the feature.
 */
/**
 * One refusal for "this session has no running container": the row is marked
 * paused and the panel is told, so the UI can resume and retry instead of
 * sitting on "idle" next to an error it cannot act on.
 */
function sessionPaused(sessionId) {
  try { updateDb(sessionId, { status: 'paused' }); } catch (_) {}
  const live = sessions.get(sessionId);
  if (live) live.status = 'paused';
  publish(sessionId, { type: 'status', status: 'paused' });
  const err = new Error('This session is paused (its container was stopped). Resume it to continue.');
  err.code = 'SESSION_PAUSED';
  return err;
}

export async function dispatch(sessionId, prompt, { model, userId } = {}) {
  const state = sessions.get(sessionId);
  if (!state) throw sessionPaused(sessionId);

  // Never let an unvalidated string reach the shell-command builder. The route
  // validates first; this is the same allowlist, applied again at the last
  // point that still knows it is a model, because dispatch() is also reached
  // from drainNextFollowup() with a value that was persisted by an earlier
  // request.
  const chosen = model == null || model === '' ? defaultCoderModel() : String(model);
  if (!isAllowedCoderModel(chosen)) throw new Error(`Unsupported model '${chosen}'`);

  if (state.runner || state.queued) {
    return { queued: true, followup: enqueueFollowup(sessionId, prompt, chosen, userId) };
  }

  const c0 = getContainer(state.appSlug);
  if (!c0) throw sessionPaused(sessionId);

  touchActivity(sessionId);
  appendMessage(sessionId, 'user', prompt, null, chosen);

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
    run: () => runBuilderTurn(sessionId, state, prompt, chosen),
  }).finally(() => {
    state.queued = false;
    try { unsubQueue(); } catch (_) {}
    // The one moment at which the session is provably free: the appQueue item
    // is gone and no runner is attached. Draining here rather than from the
    // 'exit' handler avoids racing the queue's own bookkeeping.
    if (state.drainFollowups) void drainNextFollowup(sessionId);
  });

  return { started: true };
}

async function runBuilderTurn(sessionId, state, prompt, model) {
  state.drainFollowups = false;
  const c = getContainer(state.appSlug);
  if (!c) {
    publish(sessionId, { type: 'error', message: 'App container vanished while waiting in queue' });
    publish(sessionId, { type: 'status', status: 'paused' });
    return;
  }
  // Which model is answering, for the bubble the stream is about to fill.
  publish(sessionId, { type: 'turn', model });

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
      const { contextDoc, agentContext } = await loadDispatchContext(state.appSlug, c.workspaceDir, { withCodebase: !isResume, sessionId });
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
    // actingUserId is what lets this turn run on the session owner's own Claude
    // subscription: runAgentExec resolves user token -> app credentials -> platform
    // key and sends exactly one of them. Without it the stored token is never
    // reached and every turn falls back to the platform key.
    const ownerId = getDb().prepare('SELECT user_id FROM coder_sessions WHERE id = ?').get(sessionId)?.user_id ?? null;
    const credentialKind = agentCredentialKind({
      actingUserId: ownerId, hasAppCredentials: !!c.credsCleanup, apiKey: process.env.ANTHROPIC_API_KEY,
    });
    const runner = runAgentExec({
      containerId:  c.containerId,
      prompt:       augmentedPrompt,
      model,
      apiKey:       process.env.ANTHROPIC_API_KEY,
      resume:       c.claudeSessionId || undefined,
      hasAppCredentials: !!c.credsCleanup,
      actingUserId: ownerId,
    });
    state.runner = runner;

    let assistantBuf = '';
    let resultIsError = false;
    let settled = false;
    const settle = () => {
      if (settled) return;
      settled = true;
      state.settleTurn = null;
      resolveRun();
    };
    // Agent.stop() sets _stopped, which SUPPRESSES the 'exit' event — so a
    // stopped turn never reached settle() and its appQueue item stayed
    // `running` forever (the timeout that would have rescued it is cleared by
    // stop() too). Before v2.85.0 that wedged the session behind "A dispatch
    // is already running"; now it would wedge the follow-up queue, which must
    // drain. stopDispatch settles through this handle.
    state.settleTurn = settle;

    runner.on('system', (ev) => {
      // The CLI retries a rejected credential ten times over about three
      // minutes before giving up (measured: api_retry x10, error_status 401,
      // then is_error). A rejected key does not start working on attempt
      // seven, so end the turn at the first one and say what to fix.
      if (ev?.data?.subtype === 'api_retry') {
        const status = ev.data.error_status;
        if (status === 401 || status === 403) {
          resultIsError = true;
          if (!assistantBuf) assistantBuf = `API Error: ${status} (${ev.data.error || 'authentication failed'})`;
          runner.stop();
          finish(1);
          return;
        }
        if (ev.data.attempt === 1) {
          publish(sessionId, { type: 'note', message: `The Claude API returned ${status || 'an error'}; retrying (up to ${ev.data.max_retries || 'several'} attempts).` });
        }
      }
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
      if (ev.isError) resultIsError = true;
      const db = getDb();
      const newTokens = (db.prepare('SELECT cost_tokens FROM coder_sessions WHERE id = ?').get(sessionId)?.cost_tokens || 0)
        + ev.inputTokens + ev.outputTokens;
      const newCents = (db.prepare('SELECT cost_usd_cents FROM coder_sessions WHERE id = ?').get(sessionId)?.cost_usd_cents || 0)
        + ev.costUsdCents;
      updateDb(sessionId, { cost_tokens: newTokens, cost_usd_cents: newCents });
      publish(sessionId, { type: 'cost', inputTokens: ev.inputTokens, outputTokens: ev.outputTokens, costUsdCents: ev.costUsdCents });
    });

    let finished = false;
    const finish = (code) => {
      if (finished) return;
      finished = true;
      // A rejected credential arrives as ordinary assistant text. Record and
      // show what to fix instead, so it does not read like the coder's answer.
      const failure = explainTurnFailure({
        text: assistantBuf, isError: resultIsError, code, kind: credentialKind,
        stderrTail: runner.getStderrTail?.() || [],
      });
      if (failure) {
        appendMessage(sessionId, 'assistant', failure, null, model);
        publish(sessionId, { type: 'error', message: failure, turnFailed: true });
      } else if (assistantBuf) {
        appendMessage(sessionId, 'assistant', assistantBuf, null, model);
      }
      // The turn completed — a nonzero code is a bad ANSWER, not a broken
      // substrate, so the queued follow-up still gets its go. Except a
      // rejected credential: every follow-up would be rejected the same way.
      state.drainFollowups = !(failure && isAuthFailure(failure));
      state.runner = null;
      state.status = 'idle';
      updateDb(sessionId, { status: 'idle' });
      setContainerBusy(state.appSlug, false);
      publish(sessionId, { type: 'status', status: 'idle', exitCode: code });
      settle();
    };
    runner.on('exit', finish);

    runner.on('error', (err) => {
      // A timeout or a failed spawn says the substrate is wrong, not the
      // prompt. Feeding the queue into it would multiply one failure by
      // however many messages were typed ahead, so the follow-ups stay
      // pending and the user decides.
      state.drainFollowups = false;
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
  // Clear the queue even when nothing is running: a user who hits Stop has
  // said they do not want what is coming, and a Stop that left the typed-ahead
  // messages to fire anyway is the worst possible reading of the button.
  cancelAllPending(sessionId, 'turn stopped');
  if (!state?.runner) return;
  state.drainFollowups = false;
  state.runner.stop();
  state.runner = null;
  state.status = 'idle';
  setContainerBusy(state.appSlug, false);
  updateDb(sessionId, { status: 'idle' });
  publish(sessionId, { type: 'status', status: 'idle' });
  // Release the appQueue slot. Without this the stopped turn is still the
  // queue's `running` item and nothing for this app ever runs again.
  state.settleTurn?.();
}

/**
 * Manual evict — tear down the shared app container and delete its workspace.
 * All in-memory sessions for this app get marked paused via the onEvict hook.
 */
export function evictApp(slug, reason = 'manual') {
  return evictAppContainer(slug, reason);
}
