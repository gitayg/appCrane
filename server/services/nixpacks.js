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

const execFileP = promisify(execFile);

export async function nixpacksAvailable() {
  try {
    await execFileP('nixpacks', ['--version'], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

export function nixpacksBuild({ releaseDir, tag, slug, env, onLog }) {
  return new Promise((resolve, reject) => {
    const args = [
      'build', releaseDir, '--name', tag,
      '--label', 'appcrane=true', '--label', `slug=${slug}`, '--label', `env=${env}`,
    ];
    const child = spawn('nixpacks', args, { stdio: 'pipe' });
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
