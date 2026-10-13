import { fileURLToPath } from 'url';

// Lines to put at the top of a test's `docker` shell shim, so the docker
// commands builder/workspaceRunner.js issues (exec into a coder container, run
// of a workspace helper) are played by workspace-docker-shim.mjs and every
// other subcommand still reaches the test's own cases.
const SHIM = fileURLToPath(new URL('./workspace-docker-shim.mjs', import.meta.url));
export const WORKSPACE_DOCKER_PRELUDE = [
  `case "$1" in exec) exec "${process.execPath}" "${SHIM}" "$@" ;; esac`,
  `case "$*" in *appcrane.container.type=workspace-helper*) exec "${process.execPath}" "${SHIM}" "$@" ;; esac`,
].join('\n');
