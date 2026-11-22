import { execFile } from 'child_process';
import http from 'http';
import { HELPER_IMAGE } from '../volumeHelper.js';
import { OOM_APP_FLAG } from '../oomPriority.js';
import { CPU_APP_FLAG } from '../cpuPriority.js';

// Can an app container get the instance role's credentials? If it can, it can
// read the platform secret, whatever the app-level path rules say. AWS's own
// measure is the IMDSv2 token PUT from inside a container: at hop limit 1 the
// response dies at the docker bridge.

const HOST = '169.254.169.254';
export const IMDS_FIX = 'aws ec2 modify-instance-metadata-options --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled';

// A constant, no stored value can reach it.
const SCRIPT = `
req() { printf '%b' "$1" | nc -w 3 ${HOST} 80 | head -n 1; }
echo "TOKEN $(req 'PUT /latest/api/token HTTP/1.0\\r\\nHost: ${HOST}\\r\\nX-aws-ec2-metadata-token-ttl-seconds: 21600\\r\\n\\r\\n')"
echo "V1 $(req 'GET /latest/meta-data/ HTTP/1.0\\r\\nHost: ${HOST}\\r\\n\\r\\n')"
`;

export const PROBE_ARGS = ['run', '--rm', '--network', 'bridge', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '32m', OOM_APP_FLAG, CPU_APP_FLAG, HELPER_IMAGE, 'sh', '-c', SCRIPT];

function defaultRunDocker(args) {
  return new Promise((res) => {
    execFile('docker', args, { timeout: 90_000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      res({ status: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: String(stdout), stderr: String(stderr), error: err && typeof err.code !== 'number' ? String(err.message) : null });
    });
  });
}

// Does the instance answer on the host itself? Without this, "off EC2" and
// "on EC2 at hop limit 1" look the same from a container.
function defaultHostAnswers() {
  return new Promise((res) => {
    const req = http.request({ host: HOST, port: 80, path: '/latest/api/token', method: 'PUT', timeout: 2000, headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '60' } }, (r) => {
      r.resume();
      res(true);
    });
    req.on('timeout', () => { req.destroy(); res(false); });
    req.on('error', () => res(false));
    req.end();
  });
}

const statusOf = (line) => /HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(line || '')?.[1] || null;

/**
 * { status: 'exposed'|'blocked'|'not_measured', token, v1, detail, fix }.
 * 'blocked' only when the host itself gets an answer and the container does
 * not. Everything else that is not an answer is 'not_measured', never safe.
 */
export async function probeImds({ runDocker = defaultRunDocker, hostAnswers = defaultHostAnswers } = {}) {
  let run;
  try {
    run = await runDocker(PROBE_ARGS);
  } catch (e) {
    return { status: 'not_measured', token: null, v1: null, detail: `docker could not run: ${String(e.message).split('\n')[0]}`, fix: null };
  }
  if (!run || run.status !== 0) {
    const why = (run?.error || run?.stderr || 'no output').split('\n')[0].slice(0, 200);
    return { status: 'not_measured', token: null, v1: null, detail: `docker could not run the probe: ${why}`, fix: null };
  }
  const lines = run.stdout.split('\n');
  const token = statusOf(lines.find((l) => l.startsWith('TOKEN ')));
  const v1 = statusOf(lines.find((l) => l.startsWith('V1 ')));
  if (token || v1) {
    return { status: 'exposed', token, v1, detail: `from a bridge container: IMDSv2 token request ${token || 'no answer'}, IMDSv1 request ${v1 || 'no answer'}`, fix: IMDS_FIX };
  }
  if (await hostAnswers()) return { status: 'blocked', token: null, v1: null, detail: 'the host gets an answer from the instance metadata service and a bridge container does not', fix: null };
  return { status: 'not_measured', token: null, v1: null, detail: 'no instance metadata service answers on this host, so a container not reaching it proves nothing', fix: null };
}
