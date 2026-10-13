#!/usr/bin/env node
// Plays the two docker commands builder/workspaceRunner.js issues — `docker
// exec` into a coder container and `docker run` of a workspace helper — for
// tests whose docker is a shim. It runs the command on the host in the
// workspace the container WOULD have mounted at /workspace, so the git
// semantics under test (fileMode, rescue commits, the change list) are real.
// What it cannot show is the confinement itself; test/workspace-runner-live
// .test.js does that against real Docker.
//
//   exec ... appcrane-app-<slug> <argv>   -> $DATA_DIR/app-containers/<slug>/workspace
//   run ... -v <host>:/workspace ... --entrypoint <cmd> <image> <args>
import { spawnSync } from 'child_process';
import { join, resolve } from 'path';

const args = process.argv.slice(2);
const env = { ...process.env };
let cwd = null;
let argv = null;

function takeEnv(kv) {
  const eq = kv.indexOf('=');
  env[kv.slice(0, eq)] = kv.slice(eq + 1);
}

if (args[0] === 'exec') {
  let i = 1;
  for (; i < args.length; i++) {
    const a = args[i];
    if (a === '-i') continue;
    if (a === '-u' || a === '-w') { i++; continue; }
    if (a === '-e') { takeEnv(args[++i]); continue; }
    break;
  }
  const name = args[i];
  const m = /^appcrane-app-(.+)$/.exec(name || '');
  if (!m) { process.stderr.write(`Error response from daemon: No such container: ${name}\n`); process.exit(1); }
  cwd = join(resolve(process.env.DATA_DIR || './data'), 'app-containers', m[1], 'workspace');
  argv = args.slice(i + 1);
} else if (args[0] === 'run') {
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === '-e') { takeEnv(args[++i]); continue; }
    if (a === '-v') {
      const v = args[++i];
      const [host, target] = v.split(':');
      if (target === '/workspace') cwd = host;
      continue;
    }
    if (a === '--entrypoint') { argv = [args[i + 1], ...args.slice(i + 3)]; break; }
  }
} else {
  process.stderr.write(`workspace-docker-shim: unexpected ${args[0]}\n`);
  process.exit(125);
}

// The helper's HOME=/tmp is fine on the host; its PATH is not passed (no -e
// PATH), so the test's own PATH — and any git shim on it — applies.
const r = spawnSync(argv[0], argv.slice(1), { cwd, env, stdio: 'inherit' });
process.exit(r.status === null ? 1 : r.status);
