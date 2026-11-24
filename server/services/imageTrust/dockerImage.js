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
    const { stdout } = await execFileAsync('docker', ['inspect', String(name), '--format', '{{.Image}}|{{index .Config.Labels "appcrane.image.ref"}}|{{.Config.Image}}'], { timeout: 15000 });
    const [id, label, configured] = String(stdout).trim().split('|');
    if (!IMAGE_ID_RE.test(id)) return { error: `docker did not report an image id for container ${name}` };
    return { id, ref: label || configured };
  } catch (err) {
    return { error: `container ${name} could not be inspected (${(err.stderr || err.message || '').trim().split('\n').pop()})` };
  }
}

/** Every local image tagged appcrane-<slug>-<env>:<tag> as { repository, tag, id }, or { error }. */
export async function listAppcraneImages() {
  let stdout;
  try {
    ({ stdout } = await execFileAsync('docker', ['images', '--no-trunc', '--filter', 'reference=appcrane-*', '--format', '{{.Repository}}|{{.Tag}}|{{.ID}}'], { timeout: 30000, maxBuffer: 16 * 1024 * 1024 }));
  } catch (err) {
    return { error: `docker images failed (${(err.stderr || err.message || '').trim().split('\n').pop()})` };
  }
  return {
    images: String(stdout).split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
      const [repository, tag, id] = l.split('|');
      return { repository, tag, id };
    }).filter((x) => IMAGE_ID_RE.test(x.id) && x.tag && x.tag !== '<none>'),
  };
}
