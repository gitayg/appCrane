/**
 * Crew: one coder turn for a task to an app coder, on the real coder session.
 *
 * The same session machinery the coder panel uses (builder/builderSession.js),
 * started as the app coder's OWNER — the person who approved the task — so the
 * turn runs on that person's credential (user token → app credentials →
 * platform key, runAgent.js resolveAgentCredential) and in the app's own
 * container with the session's usual read-only coder MCP key. Nothing here
 * widens what a coder turn may do.
 *
 * One turn at a time per app: if the owner's session is mid-turn, or another
 * person holds the app's coder, the task is refused as busy (crewAppCoder.js
 * says why that is refused rather than queued). An idle session of the owner's
 * is reused, so the request and the answer appear in their coder panel.
 *
 * Resolves { ok: true, text, sessionId } or { ok: false, reason, busy?, sessionId? };
 * never throws for a failed turn.
 */
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { usesLocalRepo } from './managedRepo.js';

const TIMEOUT_MS = (parseInt(process.env.CODER_TIMEOUT_MS || '1800000', 10) || 1800000) + 10 * 60 * 1000;

export async function defaultCoderRunner({ app, userId, prompt, signal }, deps = {}) {
  // deps: the session API and credential probe, injected by tests in place of
  // a real container and a real Claude.
  const {
    createSession, dispatch, subscribe, stopDispatch, cancelFollowup,
  } = deps.session || await import('./builder/builderSession.js');
  const agentCredentialKind = deps.agentCredentialKind || (await import('./llm/runAgent.js')).agentCredentialKind;

  if (!usesLocalRepo(app)) return { ok: false, reason: `${app.slug} is not Crane-hosted any more, so its coder cannot run.` };
  if (agentCredentialKind({ actingUserId: userId, appSlug: app.slug }) === 'none') {
    return { ok: false, reason: `${app.slug}'s owner has no Claude credential connected (and the app and platform have none), so the coder cannot run.` };
  }

  let sessionId;
  try {
    sessionId = await createSession(app, userId, (m) => log.info(`[crew-coder:${app.slug}] ${m}`));
  } catch (err) {
    if (err.code === 'BUILDER_OCCUPIED') {
      return { ok: false, busy: true, reason: `${app.slug}'s coder is in use by another person right now. Send the task again later.` };
    }
    return { ok: false, reason: `The coder could not start: ${err.message}` };
  }

  const db = getDb();
  const status = db.prepare('SELECT status FROM coder_sessions WHERE id = ?').get(sessionId)?.status;
  if (status === 'active' || status === 'queued') {
    return { ok: false, busy: true, sessionId, reason: `${app.slug}'s coder is in the middle of a turn for its owner. Send the task again later.` };
  }
  const baseline = db.prepare('SELECT COALESCE(MAX(id), 0) AS id FROM coder_session_messages WHERE session_id = ?').get(sessionId).id;

  return new Promise((resolve) => {
    let started = false;
    let error = null;
    let done = false;
    let unsub = () => {};
    let timer = null;
    const onAbort = () => {
      try { stopDispatch(sessionId); } catch (_) { /* already idle */ }
      finish({ ok: false, reason: 'The task was canceled; the coder turn was stopped.' });
    };
    function finish(r) {
      if (done) return;
      done = true;
      try { unsub(); } catch (_) { /* gone */ }
      clearTimeout(timer);
      signal?.removeEventListener?.('abort', onAbort);
      resolve({ sessionId, ...r });
    }
    unsub = subscribe(sessionId, (ev) => {
      if (ev.type === 'turn' || (ev.type === 'status' && (ev.status === 'active' || ev.status === 'queued'))) started = true;
      if (ev.type === 'error') error = ev.message || 'the coder turn failed';
      if (ev.type === 'status' && ev.status === 'paused') {
        finish({ ok: false, reason: `The coder's container stopped before it finished${error ? `: ${error}` : '.'}` });
      } else if (ev.type === 'status' && ev.status === 'idle' && started) {
        if (error) return finish({ ok: false, reason: `The coder turn failed: ${error}` });
        const row = getDb().prepare(
          "SELECT content FROM coder_session_messages WHERE session_id = ? AND role = 'assistant' AND id > ? ORDER BY id DESC LIMIT 1",
        ).get(sessionId, baseline);
        if (row?.content?.trim()) finish({ ok: true, text: row.content });
        else finish({ ok: false, reason: 'The coder stopped without an answer (it was stopped or interrupted).' });
      }
    });
    timer = setTimeout(() => {
      try { stopDispatch(sessionId); } catch (_) { /* already idle */ }
      finish({ ok: false, reason: 'The coder did not finish in time; the turn was stopped.' });
    }, TIMEOUT_MS);
    timer.unref?.();
    if (signal?.aborted) return onAbort();
    signal?.addEventListener?.('abort', onAbort);

    dispatch(sessionId, prompt, { userId }).then((r) => {
      if (r?.queued) {
        // A turn slipped in between the status read and now: do not leave this
        // request queued behind it, where its answer would arrive unobserved.
        try { cancelFollowup(sessionId, r.followup?.id); } catch (_) { /* already ran */ }
        finish({ ok: false, busy: true, reason: `${app.slug}'s coder is in the middle of a turn for its owner. Send the task again later.` });
      }
    }).catch((err) => finish({ ok: false, reason: `The coder could not take the task: ${err.message}` }));
  });
}
