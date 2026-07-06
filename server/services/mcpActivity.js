// Live, in-memory tracker of MCP request activity for THIS process.
//
// Used by the self-update endpoint to avoid restarting out from under an active
// MCP agent (a tool call in flight, or one that just ran and is likely mid-turn).
// In-memory is exactly right here: self-update restarts this process, so only
// this process's own in-flight MCP work matters. It also captures long-running
// calls (a large push/assemble) that the audit-log-based /recent-activity can't,
// because audit rows are written only after a call completes.
let inflight = 0;
let lastActivityAt = 0; // epoch ms of the most recent MCP request start or end

// Call at the start of handling an MCP request, and again when it finishes.
export function noteMcpStart() {
  inflight++;
  lastActivityAt = Date.now();
}
export function noteMcpEnd() {
  if (inflight > 0) inflight--;
  lastActivityAt = Date.now();
}

// Snapshot: how many MCP requests are executing right now, and how long since
// the last one started/ended. idleMs is Infinity if no MCP request has ever run.
export function getMcpActivity() {
  return {
    inflight,
    lastActivityAt: lastActivityAt || null,
    idleMs: lastActivityAt ? Date.now() - lastActivityAt : Infinity,
  };
}
