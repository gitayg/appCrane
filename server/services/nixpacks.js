/**
 * v2.21.10: Nixpacks integration. dockerfileGen only auto-builds Node apps;
 * this builds an image for an app that ships NO Dockerfile and ISN'T Node
 * (Python, Go, Ruby, Rust, static, PHP, …) by shelling out to `nixpacks build`.
 *
 * Requires the `nixpacks` binary on the deploy host. If it's absent, the
 * deployer surfaces a clear "install nixpacks or add a Dockerfile" error rather
 * than silently generating a broken Node Dockerfile.
 *
 * The image is tagged + labelled exactly like the docker-build path
 * (appcrane-<slug>-<env>:<commit>, labels slug=/env=/appcrane=true) so the
 * rest of the pipeline — start, health-check, prune — treats it identically.
 */
import { spawn, execFile } from 'child_process';
import { promisify } from 'util';
import { dockerBuildEnv } from './docker.js';
import { nixpacksResourceArgs } from './cpuPriority.js';

const execFileP = promisify(execFile);

// --cpu-quota and --memory arrived in nixpacks 1.x after 1.10 (absent from
// v1.10.0's CLI, present in v1.20.0's), and an older nixpacks rejects an
// unknown flag, which would fail the build. So ask the binary once.
let resourceFlagsProbe = null;
export async function nixpacksSupportsResourceFlags() {
  if (resourceFlagsProbe !== null) return resourceFlagsProbe;
  try {
    const { stdout } = await execFileP('nixpacks', ['build', '--help'], { timeout: 5000 });
    resourceFlagsProbe = /--cpu-quota\b/.test(stdout) && /--memory\b/.test(stdout);
  } catch {
    resourceFlagsProbe = false;
  }
  return resourceFlagsProbe;
}

export function resetNixpacksProbe() { resourceFlagsProbe = null; }

export function nixpacksArgs({ releaseDir, tag, slug, env, withResources }) {
  return [
    'build', releaseDir, '--name', tag,
    '--label', 'appcrane=true', '--label', `slug=${slug}`, '--label', `env=${env}`,
    ...(withResources ? nixpacksResourceArgs() : []),
  ];
}

export async function nixpacksAvailable() {
  try {
    await execFileP('nixpacks', ['--version'], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

export async function nixpacksBuild({ releaseDir, tag, slug, env, onLog }) {
  const withResources = await nixpacksSupportsResourceFlags();
  if (!withResources) onLog?.('nixpacks is too old for --cpu-quota/--memory; this build runs without a CPU or memory cap (upgrade nixpacks)');
  return new Promise((resolve, reject) => {
    const args = nixpacksArgs({ releaseDir, tag, slug, env, withResources });
    // nixpacks shells out to `docker build`, so it inherits the builder choice
    // from its own environment. Without this, the two build paths on one host
    // could use two different builders — see docker.js:dockerBuildEnv().
    const child = spawn('nixpacks', args, { stdio: 'pipe', env: dockerBuildEnv() });
    let buf = '';
    const emit = (chunk) => {
      buf += chunk;
      for (const line of chunk.toString().split('\n')) if (line.trim()) onLog?.(line);
    };
    child.stdout.on('data', emit);
    child.stderr.on('data', emit);
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      reject(new Error('nixpacks build timed out after 10 minutes'));
    }, 10 * 60 * 1000);
    child.on('error', (e) => { clearTimeout(timer); reject(new Error(`nixpacks not runnable: ${e.message}`)); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(tag);
      else reject(new Error(`nixpacks build failed (exit ${code}):\n${buf.slice(-3000)}`));
    });
  });
}
