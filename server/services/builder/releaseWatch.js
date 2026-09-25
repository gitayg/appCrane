// Follow the sandbox deploy a coder release starts, and act on how it ends
// (v2.93.0).
//
// A release pushes a commit, and the app's deploy-on-push builds and deploys
// it in the background. Before this, the panel said "released" and nothing
// else: on Tiny Barons every sandbox deploy failed at `vite build` from July to
// September (Cannot find module @rollup/rollup-linux-x64-musl), each one
// silently, while the sandbox kept serving v0.5.1 and the coder's released
// changes never appeared.
//
// Now the session hears the outcome:
//   live        a line in the chat: which commit, which version, live on sandbox
//   failed      the failing lines of the build/deploy log are sent to the coder
//               as a message, asking it to reproduce and fix the failure, not to
//               release; the user reviews the fix and releases it. Once per
//               release commit, so a build the coder cannot fix never loops.
//   rolled_back reported, nothing sent: the deploy did not go live, but not
//               because the build broke.

import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { notifySession, dispatch, resumeSession, isSessionLive } from './builderSession.js';

const POLL_MS = 3000;
const MAX_WAIT_MS = 30 * 60 * 1000;
const autoFixed = new Set();   // release commit shas already handed to the coder

const stripAnsi = (s) => String(s || '').replace(/\u001b\[[0-9;]*m/g, '');

/**
 * The part of a deploy log worth a model's attention: every line that looks
 * like an error, then the last 30 lines, about 6 KB at most, so one runaway
 * log cannot become a runaway prompt.
 */
export function failureExcerpt(logText) {
  // Long lines are cut first, so one runaway line (a minified bundle, a base64
  // blob) cannot push the error out; errors then get their own budget ahead of
  // the tail.
  const lines = stripAnsi(logText).split('\n').map((l) => l.trimEnd()).filter(Boolean)
    .map((l) => (l.length > 300 ? `${l.slice(0, 300)}…` : l));
  const errors = lines.filter((l) => /error|ERR!|failed|Cannot find|not found|exited with|non-zero/i.test(l));
  const fit = (list, budget, fromEnd) => {
    const out = [];
    let used = 0;
    for (const l of fromEnd ? [...list].reverse() : list) {
      if (used + l.length + 1 > budget) break;
      out.push(l); used += l.length + 1;
    }
    return fromEnd ? out.reverse() : out;
  };
  const head = fit(errors, 3000, false);
  const tail = fit(lines.slice(-30).filter((l) => !head.includes(l)), 3000, true);
  return [...head, ...(head.length && tail.length ? ['…'] : []), ...tail].join('\n');
}

export function fixPrompt({ commit, deploymentId, excerpt }) {
  return [
    `[AppCrane] The sandbox deploy of your release (commit ${commit}, deploy #${deploymentId}) failed, so the change is not live.`,
    'Reproduce the failure in the workspace by running the same build the app\'s Dockerfile runs, fix the cause, and confirm the build passes.',
    'Do not release: the user reviews your fix and releases it, which deploys it again.',
    '',
    'Deploy log (the failing lines, then the end):',
    '```',
    excerpt,
    '```',
  ].join('\n');
}

async function sendFix({ sessionId, userId, prompt }) {
  if (!isSessionLive(sessionId)) await resumeSession(sessionId, () => {});
  return dispatch(sessionId, prompt, { userId });
}

/**
 * Watch one deployment row until it finishes. Never throws; returns the final
 * status (or 'timeout'). `deps` lets tests replace the dispatch and timing.
 */
export async function watchReleaseDeploy({
  sessionId, deploymentId, commit, userId,
  pollMs = POLL_MS, maxWaitMs = MAX_WAIT_MS, deps = {},
}) {
  const send = deps.sendFix || sendFix;
  const db = getDb();
  const started = Date.now();
  const short = String(commit || '').slice(0, 8);
  notifySession(sessionId, { type: 'note', message: `Deploying the release (commit ${short}) to sandbox, deploy #${deploymentId}…` });
  try {
    for (;;) {
      const row = db.prepare('SELECT status, version, log FROM deployments WHERE id = ?').get(deploymentId);
      const status = row?.status;
      if (status === 'live') {
        const msg = `The release (commit ${short}) is live on sandbox${row.version ? ` as v${row.version}` : ''}. Review it there, then promote it to production when you are happy.`;
        notifySession(sessionId, { type: 'deploy', status: 'live', deployment_id: deploymentId, version: row.version || null, message: msg }, { record: msg });
        return 'live';
      }
      if (status === 'rolled_back') {
        const msg = `Deploy #${deploymentId} of the release (commit ${short}) was rolled back and is not live.`;
        notifySession(sessionId, { type: 'deploy', status: 'rolled_back', deployment_id: deploymentId, message: msg }, { record: msg });
        return 'rolled_back';
      }
      if (status === 'failed' || !row) {
        const excerpt = failureExcerpt(row?.log);
        const already = autoFixed.has(commit);
        const msg = already
          ? `Deploy #${deploymentId} of the release (commit ${short}) failed again. It was already sent to the coder once for this commit, so it is not sent again automatically; the log is below.`
          : `Deploy #${deploymentId} of the release (commit ${short}) failed. The failing log lines were sent to the coder to fix; review its fix and release it.`;
        notifySession(sessionId, { type: 'deploy', status: 'failed', deployment_id: deploymentId, message: msg, log_excerpt: excerpt }, { record: `${msg}\n\n${excerpt}` });
        if (!already) {
          autoFixed.add(commit);
          try {
            await send({ sessionId, userId, prompt: fixPrompt({ commit: short, deploymentId, excerpt }) });
          } catch (e) {
            notifySession(sessionId, { type: 'error', message: `Could not hand the failed deploy to the coder (${e.message}). Ask it to fix the build using the log above.` });
          }
        }
        return 'failed';
      }
      if (Date.now() - started > maxWaitMs) {
        notifySession(sessionId, { type: 'note', message: `Deploy #${deploymentId} is still ${status || 'running'} after ${Math.round(maxWaitMs / 60000)} minutes; check the app's deploy log.` });
        return 'timeout';
      }
      await new Promise((r) => setTimeout(r, pollMs));
    }
  } catch (e) {
    log.warn(`[coder] release watch for deploy #${deploymentId} stopped: ${e.message}`);
    return 'error';
  }
}

/** For a failed deploy of a later commit: the guard is per release commit. */
export function _resetAutoFixed() { autoFixed.clear(); }
