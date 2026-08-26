// Bring a host's Node runtime up to AppCrane's floor during self-update.
//
// install.sh has always done this — it installs NODE_MAJOR.x when the host is
// missing Node or below the floor. The self-updater never did: it runs
// `git reset --hard`, `npm install --omit=dev`, rebuild, restart, and nothing
// else. So a box provisioned when the floor was 20 stayed on 20 through every
// update, forever, and the only signal was a warning in the boot log.
//
// That gap stopped being cosmetic when dependencies started declaring
// `engines.node >= 22`: `npm install --omit=dev` will happily install packages
// the runtime cannot run, and the failure surfaces later, at whatever code path
// first touches a Node-22-only feature, on a platform hosting dozens of apps.
//
// DECIDING, NOT DOING. This module only decides — it returns the action to take
// and why. The caller runs the commands. That keeps the policy (when is it safe
// to touch system packages on a live host?) testable without apt, which is the
// part worth getting right.

/** Every reason the upgrade is skipped, so a caller can log the specific one. */
export const SKIP = {
  AT_FLOOR:     'at_or_above_floor',
  DISABLED:     'disabled_by_env',
  NOT_LINUX:    'not_linux',
  NOT_ROOT:     'not_root',
  NO_APT:       'no_apt',
  NOT_SYSTEM:   'node_not_from_system_package_manager',
};

/**
 * What should self-update do about the runtime before installing dependencies?
 *
 * @param {object} env
 *   currentMajor {number}  process.versions.node major
 *   floor        {number}  NODE_FLOOR
 *   platform     {string}  process.platform
 *   isRoot       {boolean} euid === 0
 *   hasApt       {boolean} apt-get resolvable on PATH
 *   nodePath     {string}  the resolved `node` binary path
 *   skipEnv      {string=} APPCRANE_SKIP_NODE_UPGRADE
 * @returns {{ upgrade: boolean, blocking: boolean, reason: string, message: string, commands?: string[][] }}
 *   `blocking` means: do NOT continue the update. Installing dependencies that
 *   declare a newer engine onto this runtime is how a working platform becomes
 *   a broken one, and a host that stays on the previous AppCrane release is in
 *   better shape than one that half-updated.
 */
export function planNodeUpgrade({
  currentMajor, floor, platform, isRoot, hasApt, nodePath = '', skipEnv,
}) {
  if (currentMajor >= floor) {
    return { upgrade: false, blocking: false, reason: SKIP.AT_FLOOR,
      message: `Node ${currentMajor} is at or above the floor (${floor}).` };
  }

  // An explicit opt-out for operators who manage the runtime themselves — nvm,
  // asdf, a container image, a configuration-management tool. Their host is
  // still below the floor, so this stays BLOCKING: opting out of the automatic
  // upgrade is not the same as declaring the runtime supported.
  if (skipEnv === '1') {
    return { upgrade: false, blocking: true, reason: SKIP.DISABLED,
      message: `Node ${currentMajor} is below the floor (${floor}) and APPCRANE_SKIP_NODE_UPGRADE=1 ` +
        'is set, so the runtime was left alone. Upgrade it yourself, then update again.' };
  }

  if (platform !== 'linux') {
    return { upgrade: false, blocking: true, reason: SKIP.NOT_LINUX,
      message: `Node ${currentMajor} is below the floor (${floor}) and this host is ${platform}, ` +
        'where AppCrane does not manage system packages. Upgrade the runtime yourself.' };
  }
  if (!isRoot) {
    return { upgrade: false, blocking: true, reason: SKIP.NOT_ROOT,
      message: `Node ${currentMajor} is below the floor (${floor}) and this process is not root, ` +
        'so it cannot install packages. Upgrade the runtime, or run the updater as root.' };
  }
  if (!hasApt) {
    return { upgrade: false, blocking: true, reason: SKIP.NO_APT,
      message: `Node ${currentMajor} is below the floor (${floor}) and apt-get is unavailable, ` +
        'so AppCrane cannot upgrade it. Upgrade the runtime yourself.' };
  }

  // Node from nvm/asdf/a tarball lives outside the system prefixes, and
  // apt-get would install a SECOND node that PATH may never reach — the
  // upgrade would report success while this process kept running the old one.
  // Refuse rather than create two runtimes and a confusing outcome.
  if (nodePath && !/^\/usr\/(bin|local\/bin)\/node$/.test(nodePath)) {
    return { upgrade: false, blocking: true, reason: SKIP.NOT_SYSTEM,
      message: `Node ${currentMajor} is below the floor (${floor}) but its binary is at ${nodePath}, ` +
        'which is not a system package path (nvm, asdf or a manual install). apt-get would add a ' +
        'second Node that PATH may not prefer. Upgrade it through whatever installed it.' };
  }

  return {
    upgrade: true, blocking: false, reason: 'upgrading',
    message: `Node ${currentMajor} is below the floor (${floor}) — installing Node ${floor}.x before ` +
      'dependencies, because npm would otherwise install packages this runtime cannot run.',
    // Same source install.sh uses, so a self-updated host ends up identical to
    // a freshly provisioned one.
    // `set -o pipefail` is load-bearing, not decoration. Measured in a Debian
    // container: `curl -fsSL <404> | bash -` exits **0**, because a pipeline
    // reports the LAST command's status and bash exits 0 on empty stdin. Without
    // pipefail an unreachable nodesource looks like a successful setup, and the
    // apt-get that follows then installs whatever the base repos happen to
    // carry — a different Node than the one asked for, or none. verifyUpgrade()
    // still catches the outcome, but it should fail where it breaks.
    commands: [
      ['bash', ['-c', `set -o pipefail; curl -fsSL https://deb.nodesource.com/setup_${floor}.x | bash -`]],
      ['apt-get', ['install', '-y', 'nodejs']],
    ],
  };
}

/**
 * Did the upgrade actually take? Called with the major reported by the `node`
 * now on PATH — not by this process, which keeps running the binary it started
 * with and would report the old version no matter what.
 */
export function verifyUpgrade(installedMajor, floor) {
  if (Number.isFinite(installedMajor) && installedMajor >= floor) {
    return { ok: true, message: `Node ${installedMajor} is now installed; the restart will pick it up.` };
  }
  return {
    ok: false,
    message: `The Node upgrade reported success but the runtime on PATH is still ${installedMajor || 'unreadable'} ` +
      `(floor ${floor}). Not installing dependencies against it.`,
  };
}
