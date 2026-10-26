// Can managed MongoDB run on the kernel the Docker daemon runs on?
//
// MongoDB's 8.0 release notes: "running MongoDB with a Linux kernel version
// from 6.19 through 7.0.13 can cause MongoDB to crash. To prevent this crash,
// MongoDB detects these kernel versions and stops during startup. This
// incompatibility affects all MongoDB packages, including those obtained from
// the MongoDB website, a package manager, or Docker." Kernel 7.0.14 and later
// resolve it.
//
// The kernel is read from the daemon (`docker info`), not os.release(): with
// Docker Desktop or a remote daemon, containers run on a different kernel than
// the AppCrane process. mongod reads `uname -r` inside its container, which is
// that same daemon kernel, and parses its leading X.Y.Z — so an Ubuntu string
// like 7.0.0-1017-azure counts as 7.0.0 (MongoDB SERVER-136848).

import { execFile } from 'child_process';
import { promisify } from 'util';
import { AppError } from '../utils/errors.js';

const execFileAsync = promisify(execFile);

const FIRST_AFFECTED = [6, 19, 0];
const FIRST_FIXED = [7, 0, 14];
const CACHE_MS = 5 * 60_000;

export const MONGO_KERNEL_CODE = 'MONGO_KERNEL_INCOMPATIBLE';

export function parseKernelVersion(release) {
  const m = /^\s*(\d+)\.(\d+)(?:\.(\d+))?/.exec(String(release ?? ''));
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)];
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

/** 'incompatible' | 'compatible' | 'unknown' for a kernel release string. */
export function mongoKernelStatus(release) {
  const v = parseKernelVersion(release);
  if (!v) return 'unknown';
  return cmp(v, FIRST_AFFECTED) >= 0 && cmp(v, FIRST_FIXED) < 0 ? 'incompatible' : 'compatible';
}

export function mongoKernelMessage(kernel) {
  return `MongoDB 8.0 can't run on this server's kernel (${kernel}); upgrade to Linux 7.0.14 or later`;
}

export function mongoKernelError(kernel) {
  return new AppError(mongoKernelMessage(kernel), 409, MONGO_KERNEL_CODE);
}

// The startup refusal mongod writes before exiting (MongoDB SERVER-136848).
const MONGOD_REFUSAL = /linux kernel versions? 6\.19 and newer has a known incompatibility/i;

export function isMongodKernelRefusal(logText) {
  return MONGOD_REFUSAL.test(String(logText ?? ''));
}

/**
 * Only MongoDB 8.x and later carry the check. An image pinned to an older major
 * (MANAGED_DB_MONGO_IMAGE=mongo:7.0) is not refused here; a tag that does not
 * name a version (a digest, `latest`) is treated as 8.x, the default.
 */
export function imageHasKernelCheck(image) {
  const tag = /:([^/@]+)$/.exec(String(image ?? '').split('@')[0])?.[1];
  const major = tag ? /^(\d+)(?:\.|$|-)/.exec(tag)?.[1] : null;
  return major == null || Number(major) >= 8;
}

async function dockerKernel() {
  const { stdout } = await execFileAsync('docker', ['info', '--format', '{{.KernelVersion}}'], { timeout: 15000 });
  return stdout.trim();
}

let kernelSource = dockerKernel;
let cached = null;

/** Tests inject the kernel the daemon reports. Pass null to restore `docker info`. */
export function _setKernelSourceForTests(fn) {
  kernelSource = fn || dockerKernel;
  cached = null;
}

/** { kernel, status, message, error } for the Docker host. Never throws. */
export async function dockerHostMongoCompat({ fresh = false } = {}) {
  if (!fresh && cached && Date.now() - cached.at < CACHE_MS) return cached.value;
  let value;
  try {
    const kernel = await kernelSource();
    const status = mongoKernelStatus(kernel);
    value = { kernel: kernel || null, status, message: status === 'incompatible' ? mongoKernelMessage(kernel) : null, error: null };
  } catch (e) {
    value = { kernel: null, status: 'unknown', message: null, error: String(e?.stderr || e?.message || e).trim().slice(0, 300) };
  }
  cached = { at: Date.now(), value };
  return value;
}

/**
 * Refuse before any mongo container starts on an affected kernel. An unknown
 * kernel does not block: mongod still refuses by itself, and the exited-container
 * check in managedDb.js reports that within seconds.
 * MANAGED_DB_MONGO_SKIP_KERNEL_CHECK=1 turns this pre-check off (for a future
 * MongoDB build that runs on a kernel this table still lists).
 */
export async function assertMongoKernelCompatible(image) {
  if (process.env.MANAGED_DB_MONGO_SKIP_KERNEL_CHECK === '1') return;
  if (!imageHasKernelCheck(image)) return;
  const c = await dockerHostMongoCompat();
  if (c.status === 'incompatible') throw mongoKernelError(c.kernel);
}
