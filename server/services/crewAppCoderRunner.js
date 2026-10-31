/**
 * Crew: one coder turn for a task to an app coder.
 *
 * SECURITY FIX (review of v2.129.0): a Crew task never runs inside a person's
 * interactive coder session. It used to reuse the owner's idle session, which
 * resumed the app's shared Claude conversation, so the other agent saw — and
 * could steer — the owner's history with the coder. Now each Crew task gets
 * its own Claude conversation: the first turn starts one with no history, and
 * a follow-up on the SAME task resumes that task's conversation only
 * (crewAppCoder.js keeps its id in crew_tasks.coder_session_id). Nothing here
 * reads or writes coder_sessions or the app container's conversation id, so
 * the coder panel's thread is neither shown to the task nor continued by it.
 *
 * What stays the same as any coder turn: the app's container and workspace
 * (builder/appContainer.js), the app's work queue (builder/appQueue.js), the
 * owner's credential (actingUserId → user token, app credentials or platform
 * key), the default coder mode, and a read-only per-app coder MCP key issued
 * for the turn and revoked when it ends.
 *
 * Busy: refused while anyone's interactive coder session on the app is
 * mid-turn (the workspace would change under both), and the app's work queue
 * serialises the Crew turn with everything else on the container — an owner
 * who starts a turn while a Crew turn runs waits in that queue, as behind an
 * Improve job. The workspace itself is shared: what the Crew turn changes
 * appears in the owner's Changes tab, unreleased, which is how the owner
 * reviews it.
 *
 * Resolves { ok: true, text, claudeSessionId } or { ok: false, reason, busy?,
 * claudeSessionId? }; never throws for a failed turn.
 */
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { usesLocalRepo } from './managedRepo.js';

const SESSION_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

function interactiveTurnRunning(slug) {
  return !!getDb().prepare("SELECT 1 FROM coder_sessions WHERE app_slug = ? AND status IN ('active', 'queued')").get(slug);
}

async function realDeps() {
  const appContainer = await import('./builder/appContainer.js');
  const appQueue = await import('./builder/appQueue.js');
  const runAgent = await import('./llm/runAgent.js');
  const coderMcp = await import('./coderMcpKey.js');
  const { defaultCoderModel } = await import('./llm/coderModels.js');
  const { DEFAULT_CODER_MODE, permissionModeFor } = await import('./llm/coderModes.js');
  const { coderSystemPrompt } = await import('./builder/deliveryPrompt.js');
  const { explainTurnFailure } = await import('./builder/turnFailure.js');
  return {
    getOrCreateContainer: appContainer.getOrCreate,
    setContainerBusy: appContainer.setBusy,
    enqueue: (slug, item) => appQueue.enqueue(slug, { ...item, priority: appQueue.PRIORITY.BUILDER }),
    runAgentExec: runAgent.runAgentExec,
    agentCredentialKind: runAgent.agentCredentialKind,
    issueKey: coderMcp.issueCoderMcpKey,
    revokeKey: coderMcp.revokeCoderMcpKey,
    mcpConfig: coderMcp.coderMcpConfig,
    allowedTools: coderMcp.coderAllowedMcpTools,
    mcpPrompt: coderMcp.CODER_MCP_PROMPT,
    model: defaultCoderModel,
    permissionMode: () => permissionModeFor(DEFAULT_CODER_MODE),
    systemPrompt: coderSystemPrompt,
    explainTurnFailure,
    interactiveTurnRunning,
  };
}

export async function defaultCoderRunner({ app, userId, prompt, taskId, resume = null, signal }, deps = {}) {
  const d = { ...(await realDeps()), ...deps };

  if (!usesLocalRepo(app)) return { ok: false, reason: `${app.slug} is not Crane-hosted any more, so its coder cannot run.` };
  if (d.agentCredentialKind({ actingUserId: userId, appSlug: app.slug }) === 'none') {
    return { ok: false, reason: `${app.slug}'s owner has no Claude credential connected (and the app and platform have none), so the coder cannot run.` };
  }
  if (d.interactiveTurnRunning(app.slug)) {
    return { ok: false, busy: true, reason: `${app.slug}'s coder is in the middle of a turn in someone's coder session. Send the task again later.` };
  }

  let c;
  try {
    c = await d.getOrCreateContainer(app, (m) => log.info(`[crew-coder:${app.slug}] ${m}`), { userId });
  } catch (err) {
    return { ok: false, reason: `The coder could not start: ${err.message}` };
  }
  const resumeId = resume && SESSION_ID_RE.test(String(resume)) ? String(resume) : undefined;

  return d.enqueue(app.slug, {
    sourceType: 'crew',
    sourceId: taskId,
    label: 'Crew task',
    run: () => runTurn(d, { app, c, userId, prompt, taskId, resumeId, signal }),
  }).catch((err) => ({ ok: false, reason: `The coder turn failed: ${err.message}` }));
}

function runTurn(d, { app, c, userId, prompt, taskId, resumeId, signal }) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve({ ok: false, reason: 'The task was canceled before the coder started.' });
    const kind = d.agentCredentialKind({ actingUserId: userId, hasAppCredentials: !!c.credsCleanup, apiKey: process.env.ANTHROPIC_API_KEY });
    let key = null;
    try {
      key = d.issueKey({ userId, appId: app.id, sessionId: `crew-task:${taskId}` });
    } catch (err) {
      log.warn(`[crew-coder:${app.slug}] could not issue a coder MCP key: ${err.message}`);
    }
    let runner;
    try {
      runner = d.runAgentExec({
        containerId: c.containerId,
        prompt,
        model: d.model(),
        apiKey: process.env.ANTHROPIC_API_KEY,
        resume: resumeId,
        hasAppCredentials: !!c.credsCleanup,
        actingUserId: userId,
        permissionMode: d.permissionMode(),
        systemPrompt: d.systemPrompt(key ? d.mcpPrompt : null),
        ...(key ? { mcpConfig: d.mcpConfig(key.apiKey), allowedTools: d.allowedTools(), secrets: [key.apiKey] } : {}),
      });
    } catch (err) {
      if (key) { try { d.revokeKey(key.id); } catch (_) { /* expires anyway */ } }
      return resolve({ ok: false, reason: `The coder could not start: ${err.message}` });
    }

    let text = '';
    let isError = false;
    let sessionId = resumeId || null;
    let done = false;
    function finish(r) {
      if (done) return;
      done = true;
      if (key) { try { d.revokeKey(key.id); } catch (_) { /* expires anyway */ } }
      try { d.setContainerBusy(app.slug, false); } catch (_) { /* container gone */ }
      signal?.removeEventListener?.('abort', onAbort);
      resolve({ claudeSessionId: sessionId, ...r });
    }
    function onAbort() {
      try { runner.stop(); } catch (_) { /* already gone */ }
      finish({ ok: false, reason: 'The task was canceled; the coder turn was stopped.' });
    }
    signal?.addEventListener?.('abort', onAbort);

    runner.on('system', (ev) => {
      if (ev?.data?.subtype === 'api_retry' && (ev.data.error_status === 401 || ev.data.error_status === 403)) {
        // A rejected credential does not start working on a retry (builderSession does the same).
        try { runner.stop(); } catch (_) { /* gone */ }
        finish({ ok: false, reason: d.explainTurnFailure({ text: `API Error: ${ev.data.error_status}`, isError: true, code: 1, kind }) || 'The Claude credential was rejected.' });
        return;
      }
      // This task's own conversation id, for a follow-up on the same task.
      // Validated before it is kept: it goes back into a --resume argument.
      const sid = ev?.data?.session_id;
      if (sid && SESSION_ID_RE.test(String(sid))) sessionId = String(sid);
    });
    runner.on('data', (ev) => { if (ev?.type === 'text') text += ev.text; });
    runner.on('result', (ev) => { if (ev?.isError) isError = true; });
    runner.on('exit', (code) => {
      const failure = d.explainTurnFailure({ text, isError, code, kind, stderrTail: runner.getStderrTail?.() || [] });
      if (failure) finish({ ok: false, reason: failure });
      else if (text.trim()) finish({ ok: true, text });
      else finish({ ok: false, reason: 'The coder ended without an answer.' });
    });
    runner.on('error', (err) => finish({ ok: false, reason: `The coder turn failed: ${err.message}` }));

    try { d.setContainerBusy(app.slug, true); } catch (_) { /* container gone */ }
    runner.start();
  });
}
