// Job Health: is the Node.js runtime AppCrane runs on missing a security fix?
// A warning on the row, never a failure: the platform keeps serving. The verdict
// comes from services/nodeSecurity.js; the boot log carries the same message.

import log from '../utils/logger.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';
import { nodeSecurityStatus } from './nodeSecurity.js';

export const JOB_ID = 'node-runtime';
const CHECK_MS = 6 * 60 * 60_000;
let timer = null;

export function runNodeSecurityCheck(version = process.versions.node) {
  const s = nodeSecurityStatus(version);
  const detail = {
    status: s.status, version: s.version, minimum: s.minimum, advisories: s.advisories,
    ...(s.status === 'ok' ? {} : { severity: 'warning' }),
    message: s.status === 'ok' ? s.message
      : `${s.message} Self-update installs it automatically on Linux hosts it manages; otherwise upgrade Node on this server and restart AppCrane.`,
  };
  setJobDetail(JOB_ID, detail);
  return detail;
}

/** The boot-log lines for this runtime: none when it is patched. */
export function bootSecurityWarnings(version = process.versions.node) {
  const s = nodeSecurityStatus(version);
  if (s.status === 'ok') return [];
  return [
    `  ⚠ SECURITY: ${s.message}`,
    '    Self-update moves a Linux host it manages to the fixed release; otherwise upgrade Node on this',
    '    server (nodesource apt, your package manager, or nvm) and restart AppCrane.',
    '',
  ];
}

export function startNodeSecurityCheck() {
  if (timer) return;
  jobStarted(JOB_ID, { cadenceMs: CHECK_MS });
  const tick = () => trackJob(JOB_ID, () => runNodeSecurityCheck()).catch((e) => log.warn(`[node-runtime] ${e.message}`));
  tick();
  timer = setInterval(tick, CHECK_MS);
  timer.unref?.();
}
