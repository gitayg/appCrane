import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const IMAGE_ID_RE = /^sha256:[a-f0-9]{64}$/;

/** { id, repoDigests } of a local image reference, or { error }. Never throws. */
export async function inspectImage(ref) {
  let stdout;
  try {
    ({ stdout } = await execFileAsync('docker', ['image', 'inspect', String(ref), '--format', '{{.Id}}|{{json .RepoDigests}}'], { timeout: 15000 }));
  } catch (err) {
    return { error: `image ${ref} is not on this host (${(err.stderr || err.message || '').trim().split('\n').pop()})` };
  }
  const [id, digests] = String(stdout).trim().split('|');
  if (!IMAGE_ID_RE.test(id)) return { error: `docker did not report an image id for ${ref}` };
  let repoDigests = [];
  try { repoDigests = JSON.parse(digests || '[]') || []; } catch { repoDigests = []; }
  return { id, repoDigests };
}

/** The image id a container was created from, or { error }. */
export async function containerImageId(name) {
  try {
    const { stdout } = await execFileAsync('docker', ['inspect', String(name), '--format', '{{.Image}}|{{.Config.Image}}'], { timeout: 15000 });
    const [id, ref] = String(stdout).trim().split('|');
    if (!IMAGE_ID_RE.test(id)) return { error: `docker did not report an image id for container ${name}` };
    return { id, ref };
  } catch (err) {
    return { error: `container ${name} could not be inspected (${(err.stderr || err.message || '').trim().split('\n').pop()})` };
  }
}
