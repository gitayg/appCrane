// A smart-HTTP git server that REQUIRES an Authorization header, run as its
// own process. It has to be out-of-process: the code under test drives git
// with execFileSync, which blocks the test's event loop, so an in-process
// server could never answer and every clone would deadlock.
//
// argv: <projectRoot> <authLogFile>. Prints the listening port on stdout.
// Every request's Authorization header (or null) is appended to authLogFile as
// one JSON line, so the test can prove what git actually sent.
import http from 'http';
import { spawn, execFileSync } from 'child_process';
import { appendFileSync } from 'fs';
import { join } from 'path';

const [projectRoot, authLog] = process.argv.slice(2);
const backend = join(execFileSync('git', ['--exec-path']).toString().trim(), 'git-http-backend');

const server = http.createServer((req, res) => {
  const auth = req.headers.authorization || null;
  appendFileSync(authLog, `${JSON.stringify({ url: req.url, auth })}\n`);
  if (!auth) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="git"' });
    return res.end('auth required');
  }
  const [path, query = ''] = req.url.split('?');
  const cgi = spawn(backend, [], {
    env: {
      PATH: process.env.PATH,
      GIT_PROJECT_ROOT: projectRoot,
      GIT_HTTP_EXPORT_ALL: '1',
      PATH_INFO: path,
      QUERY_STRING: query,
      REQUEST_METHOD: req.method,
      CONTENT_TYPE: req.headers['content-type'] || '',
      CONTENT_LENGTH: req.headers['content-length'] || '',
      REMOTE_USER: 'installation',
      REMOTE_ADDR: '127.0.0.1',
    },
  });
  req.pipe(cgi.stdin);
  const chunks = [];
  cgi.stdout.on('data', (c) => chunks.push(c));
  cgi.on('close', () => {
    const buf = Buffer.concat(chunks);
    const split = buf.indexOf('\r\n\r\n');
    const headers = {};
    let status = 200;
    for (const line of buf.slice(0, split).toString().split('\r\n')) {
      const i = line.indexOf(':');
      if (i < 0) continue;
      const k = line.slice(0, i).trim();
      const v = line.slice(i + 1).trim();
      if (k.toLowerCase() === 'status') status = parseInt(v, 10);
      else headers[k] = v;
    }
    res.writeHead(status, headers);
    res.end(buf.slice(split + 4));
  });
});
server.listen(0, '127.0.0.1', () => { process.stdout.write(`${server.address().port}\n`); });
process.on('SIGTERM', () => server.close(() => process.exit(0)));
