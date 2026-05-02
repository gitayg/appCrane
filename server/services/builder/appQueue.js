import { randomUUID } from 'crypto';
import log from '../../utils/logger.js';

// Priority levels — lower number drains first. FIFO within same priority.
export const PRIORITY = {
  IMPROVE: 1, // Web-filed enhancement requests (worker.js handleCode)
  BUILDER: 2, // Interactive Studio chat (builderSession.dispatch)
};

// slug -> { items: Item[], running: Item|null }
//   Item = { id, priority, sourceType, sourceId, label, run, resolve, reject, enqueuedAt }
const queues = new Map();

// slug -> Set<fn>  — listeners notified on every queue change
const subs = new Map();

function getQueue(slug) {
  let q = queues.get(slug);
  if (!q) { q = { items: [], running: null }; queues.set(slug, q); }
  return q;
}

function snapshot(slug) {
  const q = queues.get(slug);
  if (!q) return { depth: 0, running: null, items: [] };
  return {
    depth: q.items.length,
    running: q.running ? publicItem(q.running) : null,
    items: q.items.map(publicItem),
  };
}

function publicItem(it) {
  return {
    id: it.id,
    priority: it.priority,
    sourceType: it.sourceType,
    sourceId: it.sourceId,
    label: it.label,
    enqueuedAt: it.enqueuedAt,
  };
}

function notify(slug) {
  const set = subs.get(slug);
  if (!set) return;
  const snap = snapshot(slug);
  for (const fn of set) {
    try { fn(snap); } catch (err) { log.warn(`appQueue subscriber error: ${err.message}`); }
  }
}

export function subscribeQueue(slug, fn) {
  if (!subs.has(slug)) subs.set(slug, new Set());
  subs.get(slug).add(fn);
  // Fire current snapshot immediately so the new subscriber knows where things stand
  try { fn(snapshot(slug)); } catch (_) {}
  return () => subs.get(slug)?.delete(fn);
}

export function getQueueState(slug) {
  return snapshot(slug);
}

/**
 * What's ahead of a hypothetical NEW item with `priority` for `slug`?
 * Counts the running job (if any) plus all queued items with priority <=.
 * Useful for "Waiting in queue — N ahead" UI.
 */
export function aheadOf(slug, priority) {
  const q = queues.get(slug);
  if (!q) return 0;
  let n = 0;
  if (q.running) n++;
  for (const it of q.items) if (it.priority <= priority) n++;
  return n;
}

function pickNext(q) {
  if (!q.items.length) return null;
  // FIFO across all items, but lower priority number wins ties — so a
  // later-arrived IMPROVE jumps ahead of an earlier-queued BUILDER.
  let bestIdx = 0;
  for (let i = 1; i < q.items.length; i++) {
    const a = q.items[bestIdx], b = q.items[i];
    if (b.priority < a.priority) bestIdx = i;
    // else FIFO among equal priorities (already lowest by index)
  }
  return q.items.splice(bestIdx, 1)[0];
}

async function drain(slug) {
  const q = getQueue(slug);
  if (q.running) return;
  const next = pickNext(q);
  if (!next) return;
  q.running = next;
  notify(slug);
  log.info(`appQueue[${slug}]: running ${next.sourceType}#${next.sourceId} (${next.label})`);
  try {
    const result = await next.run();
    next.resolve(result);
  } catch (err) {
    next.reject(err);
  } finally {
    q.running = null;
    notify(slug);
    // Tail-call into next; small setImmediate so we don't blow the stack
    setImmediate(() => drain(slug));
  }
}

/**
 * Enqueue work for `slug`. Resolves with the value `run()` returns; rejects
 * with whatever `run()` throws.
 *
 *   await enqueue('snc', {
 *     priority: PRIORITY.IMPROVE,
 *     sourceType: 'improve',
 *     sourceId: '42',
 *     label: 'Add dark mode toggle',
 *     run: async () => doTheWork(),
 *   });
 */
export function enqueue(slug, { priority, sourceType, sourceId, label, run }) {
  if (typeof run !== 'function') {
    return Promise.reject(new Error('appQueue.enqueue: run must be a function'));
  }
  return new Promise((resolve, reject) => {
    const q = getQueue(slug);
    const item = {
      id: randomUUID(),
      priority: priority ?? PRIORITY.BUILDER,
      sourceType: sourceType || 'unknown',
      sourceId: sourceId != null ? String(sourceId) : '',
      label: label || '',
      run,
      resolve,
      reject,
      enqueuedAt: Date.now(),
    };
    q.items.push(item);
    notify(slug);
    setImmediate(() => drain(slug));
  });
}

/**
 * Cancel a queued (not-yet-running) item by id. Returns true if removed.
 * Does NOT cancel an in-flight `running` item — that needs caller-side abort.
 */
export function cancel(slug, id) {
  const q = queues.get(slug);
  if (!q) return false;
  const idx = q.items.findIndex(it => it.id === id);
  if (idx < 0) return false;
  const [item] = q.items.splice(idx, 1);
  item.reject(new Error('Cancelled'));
  notify(slug);
  return true;
}

export function clearForTests() {
  queues.clear();
  subs.clear();
}
