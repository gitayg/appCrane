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
 * SECURITY FIX (review of v2.130.1): a Crew turn no longer runs inside the
 * app's container either. That container mounts the app's shared transcript
 * directory (every coder session's conversation) and its read-write
 * credentials file, and keeps whatever a turn leaves behind (hooks, processes,
 * files outside /workspace). Each turn now runs in its own throwaway container
 * (runAgentNew, --rm, read-only root) that mounts only the workspace, the
 * task's own Claude home (crewCoderHome.js), the app's skills read-only and
 * the one credential the turn uses. The owner's coder panel still runs in the
 * app's container.
 *
 * SECURITY FIX (review of v2.131.0): that credential is never the app's shared
 * Claude login. The login was mounted as a writable copy that is stored back
 * for the app when the turn ends (claudeCredentials.js), so a turn steered by
 * another person's agent could read out its refresh token or replace it with
 * a login of its choosing for the owner's later sessions. A Crew turn uses the
 * owner's own Claude token, else the platform ANTHROPIC_API_KEY, else it fails
 * (allowAppCredentials: false, checked at the gate and again in the turn).
 *
 * What stays the same as any coder turn: the app's workspace (the app
 * container is still created for it and marked busy for the turn, so it is not
 * evicted mid-turn), the app's work queue (builder/appQueue.js), the owner's
 * own credential (actingUserId → user token, else platform key), the
 * default coder mode, and a read-only per-app coder MCP key issued for the turn
 * and revoked when it ends.
 *
 * Busy: refused while another person holds the app's coder workspace
 * (occupiedByAnother), and while anyone's interactive coder session on the
 * app is mid-turn (the workspace would change under both); and the app's work queue
 * serialises the Crew turn with everything else on the container — an owner
 * who starts a turn while a Crew turn runs waits in that queue, as behind an
 * Improve job. The workspace itself is shared: what the Crew turn changes
 * appears in the owner's Changes tab, unreleased, which is how the owner
 * reviews it.
 *
 * Resolves { ok: true, text, claudeSessionId } or { ok: false, reason, busy?,
 * claudeSessionId? }; never throws for a failed turn.
 */
import crypto from 'crypto';
import { execFile } from 'child_process';
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { usesLocalRepo } from './managedRepo.js';
import { prepareCrewTaskHome, CREW_CODER_CONTAINER_TYPE } from './crewCoderHome.js';
import { getPlatformAnthropicKey } from './platformAnthropicKey.js';

const SESSION_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
export const NO_CREW_CREDENTIAL_REASON =
  "The app coder's owner has no Claude login of their own and no platform API key is set; Crew turns do not use the app's shared login.";
const STUDIO_IMAGE = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';
export const CREW_CODER_MEMORY_MB = 2048;

/**
 * The runAgentNew options of one Crew turn, minus the prompt-specific ones.
 * Exported so the isolation test runs exactly these mounts against Docker.
 */
export function crewTurnContainerOptions({ slug, taskId, workspaceDir, claudeHomeDir, containerName }) {
  return {
    image: STUDIO_IMAGE,
    pull: 'never',
    containerName,
    labels: { 'appcrane.container.type': CREW_CODER_CONTAINER_TYPE, 'app.slug': slug, 'crew.task': String(taskId) },
    workspaceDir,
    claudeHomeDir,
    appSlug: slug,
    allowAppCredentials: false,
    memory: '2g',
    memorySwap: '2g',
    cpus: '1',
    pidsLimit: 256,
    readOnlyRoot: true,
    tmpfs: [
      '/tmp:rw,exec,nosuid,nodev,size=512m',
      '/home/studio:rw,nosuid,nodev,size=64m,uid=100,gid=101,mode=0700',
    ],
    // The per-turn coder MCP endpoint (services/coderMcpKey.js), as the app container has it.
    addHosts: ['host.docker.internal:host-gateway'],
  };
}

export function crewContainerName(slug, taskId) {
  return `appcrane-crew-${slug}-t${taskId}-${crypto.randomBytes(3).toString('hex')}`;
}

function removeContainer(name) {
  execFile('docker', ['rm', '-f', name], { timeout: 15000 }, () => {});
}

function interactiveTurnRunning(slug) {
  return !!getDb().prepare("SELECT 1 FROM coder_sessions WHERE app_slug = ? AND status IN ('active', 'queued')").get(slug);
}

/**
 * SECURITY FIX (review of v2.129.1): another person holds the app's coder
 * workspace — the occupancy builderSession enforces between people
 * (activeOtherSessionForApp: a starting, idle or active session of someone
 * else). A Crew turn would edit their unreleased work in progress, so it is
 * refused; it never takes over.
 */
function occupiedByAnother(slug, ownerId) {
  return !!getDb().prepare("SELECT 1 FROM coder_sessions WHERE app_slug = ? AND user_id <> ? AND status IN ('starting', 'idle', 'active')").get(slug, ownerId);
}

async function realDeps() {
  const appContainer = await import('./builder/appContainer.js');
  const appQueue = await import('./builder/appQueue.js');
  const runAgent = await import('./llm/runAgent.js');
  const coderMcp = await import('./coderMcpKey.js');
  const admission = await import('./memoryAdmission.js');
  const { defaultCoderModel } = await import('./llm/coderModels.js');
  const { DEFAULT_CODER_MODE, permissionModeFor } = await import('./llm/coderModes.js');
  const { coderSystemPrompt } = await import('./builder/deliveryPrompt.js');
  const { explainTurnFailure } = await import('./builder/turnFailure.js');
  return {
    getOrCreateContainer: appContainer.getOrCreate,
    setContainerBusy: appContainer.setBusy,
    enqueue: (slug, item) => appQueue.enqueue(slug, { ...item, priority: appQueue.PRIORITY.BUILDER }),
    runAgentNew: runAgent.runAgentNew,
    prepareHome: prepareCrewTaskHome,
    admit: admission.admitContainer,
    reserveMemory: admission.reserveMemory,
    removeContainer,
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
    occupiedByAnother,
  };
}

export async function defaultCoderRunner({ app, userId, prompt, taskId, resume = null, signal }, deps = {}) {
  const d = { ...(await realDeps()), ...deps };

  if (!usesLocalRepo(app)) return { ok: false, reason: `${app.slug} is not Crane-hosted any more, so its coder cannot run.` };
  if (d.agentCredentialKind({ actingUserId: userId, appSlug: app.slug, allowAppCredentials: false }) === 'none') {
    return { ok: false, reason: NO_CREW_CREDENTIAL_REASON };
  }
  if (d.occupiedByAnother(app.slug, userId)) {
    return { ok: false, busy: true, reason: `${app.slug}'s coder workspace is in use by another person right now. Send the task again later.` };
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

async function runTurn(d, { app, c, userId, prompt, taskId, resumeId, signal }) {
  if (signal?.aborted) return { ok: false, reason: 'The task was canceled before the coder started.' };
  // Again here: the owner's token may have gone while the turn was queued, and
  // without it the app's login must not be the fallback.
  const kind = d.agentCredentialKind({ actingUserId: userId, appSlug: app.slug, apiKey: getPlatformAnthropicKey(), allowAppCredentials: false });
  if (kind === 'none') return { ok: false, reason: NO_CREW_CREDENTIAL_REASON };
  const name = crewContainerName(app.slug, taskId);
  try {
    await d.admit({
      name, memoryMb: CREW_CODER_MEMORY_MB, cpus: 1, kind: 'crew-coder', slug: app.slug, appId: app.id ?? null, userId,
      what: 'Crew coder turn', subject: `the Crew coder for ${app.slug}`,
    });
  } catch (err) {
    return { ok: false, reason: `The coder could not start: ${err.message}` };
  }
  if (signal?.aborted) return { ok: false, reason: 'The task was canceled before the coder started.' };
  let claudeHomeDir;
  try {
    claudeHomeDir = d.prepareHome(taskId, { slug: app.slug, resumeId });
  } catch (err) {
    return { ok: false, reason: `The coder could not start: ${err.message}` };
  }
  const release = d.reserveMemory(name, CREW_CODER_MEMORY_MB * 1024 * 1024);
  return new Promise((resolve) => {
    let key = null;
    try {
      key = d.issueKey({ userId, appId: app.id, sessionId: `crew-task:${taskId}` });
    } catch (err) {
      log.warn(`[crew-coder:${app.slug}] could not issue a coder MCP key: ${err.message}`);
    }
    let runner;
    try {
      runner = d.runAgentNew({
        ...crewTurnContainerOptions({ slug: app.slug, taskId, workspaceDir: c.workspaceDir, claudeHomeDir, containerName: name }),
        prompt,
        model: d.model(),
        apiKey: getPlatformAnthropicKey(),
        resume: resumeId,
        actingUserId: userId,
        permissionMode: d.permissionMode(),
        systemPrompt: d.systemPrompt(key ? d.mcpPrompt : null),
        ...(key ? { mcpConfig: d.mcpConfig(key.apiKey), allowedTools: d.allowedTools(), secrets: [key.apiKey] } : {}),
      });
    } catch (err) {
      if (key) { try { d.revokeKey(key.id); } catch (_) { /* expires anyway */ } }
      release();
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
      // Backstop: `docker run --rm` removes it on a normal exit; a stop or a
      // killed client can leave it running.
      try { d.removeContainer(name); } catch (_) { /* gone */ }
      release();
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
