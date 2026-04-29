import { execFileSync } from 'child_process';
import { getDb } from '../db.js';

const DEFAULT_MAX = 5;

export function getMaxDevContainers() {
  try {
    const row = getDb().prepare("SELECT value FROM settings WHERE key = 'max_dev_containers'").get();
    const n = parseInt(row?.value, 10);
    return isNaN(n) || n < 1 ? DEFAULT_MAX : n;
  } catch (_) { return DEFAULT_MAX; }
}

export function countRunningDevContainers() {
  try {
    const out = execFileSync('docker', ['ps', '-q', '--filter', 'label=appcrane.container.type'], { stdio: 'pipe', timeout: 8000 });
    return out.toString().trim().split('\n').filter(Boolean).length;
  } catch (_) { return 0; }
}

export function assertCapacity() {
  const max = getMaxDevContainers();
  const current = countRunningDevContainers();
  if (current >= max) {
    const err = new Error(`System capacity is full (${current}/${max} dev containers running). Please try again later.`);
    err.code = 'CAPACITY_FULL';
    throw err;
  }
}
