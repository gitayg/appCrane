/**
 * Push coalescing for deploy-on-push (services/deployTrigger.js).
 *
 * A push that lands while a deploy of the same app+env is still in flight does
 * not start a second, overlapping deploy. It parks here as that env's ONE
 * follow-up; a later push replaces it (newest wins). When the in-flight deploy
 * reaches a terminal state — or stops counting as in flight because it went
 * stale or another deploy replaced it — the follow-up runs exactly once.
 *
 * Completion is detected by a light poll of the deployments table: one
 * unref'd interval, alive only while something is queued. The follow-up runs
 * through deployTrigger's own callback, so a deploy still in flight at that
 * moment simply queues it again.
 */

import { getDb } from '../db.js';
import log from '../utils/logger.js';

const DEFAULT_POLL_MS = 3000;

let pollMs = DEFAULT_POLL_MS;
let timer = null;
let ticking = null;
const queue = new Map(); // `${appId}:${env}` -> { appId, env, slug, behind, run }

const keyOf = (appId, env) => `${appId}:${env}`;

/**
 * Park `run` as the follow-up of app+env behind in-flight deployment `behind`,
 * replacing any follow-up already parked there. `run` is called with no
 * arguments once `behind` is no longer a fresh in-flight deploy.
 */
export function queueFollowUp({ appId, env, slug, behind, run }) {
  const key = keyOf(appId, env);
  const replaced = queue.has(key);
  queue.set(key, { appId, env, slug, behind, run });
  log.info(`[push-coalesce] ${slug}/${env}: push queued behind deployment ${behind}${replaced ? ' (replaces the earlier queued push)' : ''}`);
  ensureTimer();
}

function ensureTimer() {
  if (timer || queue.size === 0) return;
  timer = setInterval(() => { tickPushCoalescer().catch(() => {}); }, pollMs);
  timer.unref?.();
}

function stopTimerIfIdle() {
  if (queue.size === 0 && timer) {
    clearInterval(timer);
    timer = null;
  }
}

/** One poll: run every follow-up whose in-flight deploy is done. Never throws. */
export function tickPushCoalescer() {
  if (ticking) return ticking;
  ticking = (async () => {
    try {
      const { freshInflightDeploy } = await import('./deployer.js');
      const db = getDb();
      for (const [key, item] of [...queue]) {
        let inflight;
        try {
          inflight = freshInflightDeploy(db, item.appId, item.env);
        } catch (e) {
          log.warn(`[push-coalesce] ${item.slug}/${item.env}: could not read deploy state: ${e.message}`);
          continue;
        }
        if (inflight && inflight.id === item.behind) continue;
        if (queue.get(key) !== item) continue;
        queue.delete(key);
        log.info(`[push-coalesce] ${item.slug}/${item.env}: deployment ${item.behind} finished, deploying the queued push`);
        try {
          await item.run();
        } catch (e) {
          log.warn(`[push-coalesce] ${item.slug}/${item.env}: queued deploy could not start: ${e.message}`);
        }
      }
    } finally {
      ticking = null;
      stopTimerIfIdle();
    }
  })();
  return ticking;
}

/** The parked follow-ups, for tests and diagnostics. */
export function queuedFollowUps() {
  return [...queue.values()].map(({ appId, env, slug, behind }) => ({ appId, env, slug, behind }));
}

/** Test seam: drop every follow-up, stop the timer, optionally change the poll interval. */
export function resetPushCoalescer({ pollMs: ms = DEFAULT_POLL_MS } = {}) {
  queue.clear();
  if (timer) clearInterval(timer);
  timer = null;
  pollMs = ms;
}
