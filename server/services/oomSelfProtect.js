// AppCrane asks the kernel to kill app containers before it, at startup.
//
// The systemd unit install.sh writes carries OOMScoreAdjust=-500, but
// self-update never rewrites the unit, so an existing install keeps running
// with 0. Lowering the score needs CAP_SYS_RESOURCE, so this only acts when
// AppCrane runs as root on Linux; otherwise it reports what to do instead.
// Children AppCrane spawns (docker CLI, git) inherit the value; containers do
// not, because dockerd starts them, not AppCrane.

import { readFileSync, writeFileSync } from 'fs';

export const APPCRANE_OOM_SCORE_ADJ = -500;

export function protectFromOom({
  procFile = '/proc/self/oom_score_adj',
  target = APPCRANE_OOM_SCORE_ADJ,
  platform = process.platform,
  uid = typeof process.getuid === 'function' ? process.getuid() : null,
} = {}) {
  try {
    if (platform !== 'linux') return { status: 'unsupported', reason: `not Linux (${platform})` };
    const current = Number.parseInt(readFileSync(procFile, 'utf8').trim(), 10);
    if (Number.isInteger(current) && current <= target) return { status: 'already', value: current };
    if (uid !== 0) {
      return {
        status: 'not-permitted', value: Number.isInteger(current) ? current : null,
        reason: `not root; add OOMScoreAdjust=${target} to the appcrane unit (systemctl edit appcrane)`,
      };
    }
    writeFileSync(procFile, `${target}\n`);
    return { status: 'set', value: target, previous: Number.isInteger(current) ? current : null };
  } catch (e) {
    return { status: 'failed', reason: e.message };
  }
}
