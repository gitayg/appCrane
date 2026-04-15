import { platform, totalmem, freemem, cpus, hostname } from 'os';
import { execSync } from 'child_process';
import log from '../utils/logger.js';

export const isLinux = () => platform() === 'linux';
export const isDarwin = () => platform() === 'darwin';

export function getSystemInfo() {
  const totalMem = totalmem();
  const freeMem = freemem();
  const cpuCount = cpus().length;
  const cpuModel = cpus()[0]?.model || 'unknown';

  let diskTotal = 0, diskFree = 0;
  try {
    if (isLinux()) {
      const df = execSync("df -B1 / | tail -1").toString().trim().split(/\s+/);
      diskTotal = parseInt(df[1]) || 0;
      diskFree = parseInt(df[3]) || 0;
    } else {
      const df = execSync("df -k / | tail -1").toString().trim().split(/\s+/);
      diskTotal = (parseInt(df[1]) || 0) * 1024;
      diskFree = (parseInt(df[3]) || 0) * 1024;
    }
  } catch (e) {
    log.warn('Could not get disk info');
  }

  // CPU usage estimate (1s sample)
  let cpuPercent = 0;
  try {
    if (isLinux()) {
      const load = execSync("cat /proc/loadavg").toString().split(' ');
      cpuPercent = Math.round((parseFloat(load[0]) / cpuCount) * 100);
    } else {
      cpuPercent = Math.round(parseFloat(execSync("ps -A -o %cpu | awk '{s+=$1} END {print s}'").toString().trim()));
    }
  } catch (e) {
    cpuPercent = 0;
  }

  return {
    hostname: hostname(),
    platform: platform(),
    isLinux: isLinux(),
    cpu: { model: cpuModel, count: cpuCount, percent: Math.min(cpuPercent, 100) },
    memory: { total: totalMem, free: freeMem, used: totalMem - freeMem, percent: Math.round(((totalMem - freeMem) / totalMem) * 100) },
    disk: { total: diskTotal, free: diskFree, used: diskTotal - diskFree, percent: diskTotal ? Math.round(((diskTotal - diskFree) / diskTotal) * 100) : 0 },
  };
}

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
