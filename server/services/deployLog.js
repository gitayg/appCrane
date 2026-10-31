import log from '../utils/logger.js';

// One deploy's log: every line goes to the deployments row (what the dashboard
// and appcrane_get_deploy_log show), and only the deploy's own steps go to the
// platform log. Indented lines are build output and container output, hundreds
// per deploy; echoing each one to the journal is how a busy box logged most of
// its disk away, and the row already keeps them.
//
// The stored text is bounded. Build output is limited to the first 500 lines,
// but the failure path appends the container's whole boot log (bootWatch reads
// up to 4 MB) and a 200-line `docker logs` tail with no limit on line length.
// The head says what was deployed and how the build went, the tail how it
// ended; the middle is what goes.

export const MAX_DEPLOY_LOG_CHARS = 1024 * 1024;
const HEAD_CHARS = 256 * 1024;

export function capDeployLog(text) {
  if (text.length <= MAX_DEPLOY_LOG_CHARS) return text;
  const marker = `\n... [${text.length - MAX_DEPLOY_LOG_CHARS} characters of deploy log omitted] ...\n`;
  const tail = MAX_DEPLOY_LOG_CHARS - HEAD_CHARS - marker.length;
  return text.slice(0, HEAD_CHARS) + marker + text.slice(-tail);
}

export function createDeployLog(deployId, db, logger = log) {
  const lines = [];
  let finished = false;
  const text = () => capDeployLog(lines.join('\n'));
  const append = (msg) => {
    lines.push(`[${new Date().toISOString().slice(11, 19)}] ${msg}`);
    if (!msg.startsWith('  ')) {
      const level = msg.startsWith('DEPLOY FAILED') ? 'error' : msg.startsWith('⚠') ? 'warn' : 'info';
      logger[level](`[deploy:${deployId}] ${msg}`);
    }
    // Don't overwrite status after the deploy is done.
    if (!finished) db.prepare("UPDATE deployments SET log = ?, status = 'building' WHERE id = ?").run(text(), deployId);
  };
  return { lines, append, text, finish: () => { finished = true; } };
}
