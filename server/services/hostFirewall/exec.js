import { execFile } from 'node:child_process';

// The one way this module runs anything: execFile with an argv array and,
// for iptables-restore, the rule text on stdin. Never a shell, so nothing in
// the database or in docker's output can become a command.

export function defaultRun(cmd, args, { input = null, timeout = 20_000 } = {}) {
  return new Promise((res) => {
    const child = execFile(cmd, args, { timeout, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      const code = err ? (typeof err.code === 'number' ? err.code : null) : 0;
      res({
        code,
        stdout: String(stdout ?? ''),
        stderr: String(stderr ?? ''),
        missing: err?.code === 'ENOENT',
        error: err && code === null ? String(err.message).split('\n')[0] : null,
      });
    });
    child.stdin?.on('error', () => {});
    if (input !== null) child.stdin?.end(input);
    else child.stdin?.end();
  });
}
