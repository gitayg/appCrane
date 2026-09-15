/**
 * Timestamped phase marks for a data export, recorded only while someone asked.
 *
 * test/backup-event-loop.test.js turns this on so that, when the event loop
 * stalls during an export, its report can say which step of the export was
 * running. Times are absolute milliseconds (performance.timeOrigin + now), so a
 * mark taken in a worker thread or another process lines up with the main
 * thread's. When nobody is tracing, a mark is a single null check.
 */

let sink = null;

export const nowAbs = () => performance.timeOrigin + performance.now();

export function traceBackup(name, extra) {
  if (sink) sink.push(extra ? { t: nowAbs(), name, ...extra } : { t: nowAbs(), name });
}

export function startBackupTrace() {
  sink = [];
  return sink;
}

export function stopBackupTrace() {
  const s = sink || [];
  sink = null;
  return s;
}
