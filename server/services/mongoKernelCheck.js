// Job Health: can managed MongoDB run on the Docker host's kernel?
// A warning, not a failure: nothing is broken until an app asks for MongoDB,
// and provisioning then refuses with the same message (kernelCompat.js).

import log from '../utils/logger.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';
import { dockerHostMongoCompat, imageHasKernelCheck } from './kernelCompat.js';
import { MONGO_IMAGE } from './managedMongo.js';

export const JOB_ID = 'mongo-kernel';
const CHECK_MS = 6 * 60 * 60_000;
let timer = null;

export async function runMongoKernelCheck({ image = MONGO_IMAGE, fresh = true } = {}) {
  let detail;
  if (process.env.MANAGED_DB_MONGO_SKIP_KERNEL_CHECK === '1' || !imageHasKernelCheck(image)) {
    detail = { status: 'not-applicable', kernel: null, image, message: `The managed MongoDB image (${image}) is not checked against the kernel.` };
  } else {
    const c = await dockerHostMongoCompat({ fresh });
    detail = {
      status: c.status,
      kernel: c.kernel,
      image,
      ...(c.status === 'incompatible' ? { severity: 'warning' } : {}),
      message: c.status === 'incompatible' ? c.message
        : c.status === 'compatible' ? `Managed MongoDB can run on this server's kernel (${c.kernel}).`
        : `Could not read the Docker host's kernel version${c.error ? ` (${c.error})` : ''}; MongoDB is not blocked.`,
    };
  }
  setJobDetail(JOB_ID, detail);
  return detail;
}

export function startMongoKernelCheck() {
  if (timer) return;
  jobStarted(JOB_ID, { cadenceMs: CHECK_MS });
  const tick = () => trackJob(JOB_ID, () => runMongoKernelCheck()).catch((e) => log.warn(`[mongo-kernel] ${e.message}`));
  setTimeout(tick, 20_000).unref?.();
  timer = setInterval(tick, CHECK_MS);
  timer.unref?.();
}
