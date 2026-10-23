'use strict';
// The only way out of the auto-patch npm helper. The helper runs on a Docker
// network created with --internal (no default route); this proxy is the one
// container on that network that also sits on a routable bridge, and it relays
// exactly one thing: an HTTP CONNECT tunnel to registry.npmjs.org:443, the
// registry the bump already pins. TLS stays end to end (no interception).
// Refused with 403: any other host or port, an IP literal, a plain-HTTP
// request (GET http://...), anything that is not host:port.
//
// Runs as a file in the pinned node image (egress.js mounts it read-only) and
// is required by the tests, so the code under test is the code that runs.

const net = require('net');
const http = require('http');

const DEFAULT_ALLOW = 'registry.npmjs.org:443';

function allowList(raw) {
  return new Set(String(raw || DEFAULT_ALLOW).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
}

/** { host, port } when the CONNECT target is allowed, else null. */
function decide(target, allow = allowList(process.env.APPCRANE_EGRESS_ALLOW)) {
  if (typeof target !== 'string') return null;
  const m = /^([a-z0-9-]+(?:\.[a-z0-9-]+)+):([0-9]{1,5})$/i.exec(target);
  if (!m) return null;
  const host = m[1].toLowerCase();
  const port = Number(m[2]);
  if (net.isIP(host) || /^[0-9.]+$/.test(host)) return null;
  if (!allow.has(`${host}:${port}`)) return null;
  return { host, port };
}

function createProxy({ allow = allowList(process.env.APPCRANE_EGRESS_ALLOW), log = () => {}, connect = net.connect } = {}) {
  const server = http.createServer((req, res) => {
    log(`refused ${req.method} ${String(req.url).slice(0, 200)}`);
    res.writeHead(403, { 'content-type': 'text/plain', connection: 'close' });
    res.end('appcrane auto-patch egress: only CONNECT to the npm registry is allowed\n');
  });
  server.on('connect', (req, client, head) => {
    const t = decide(req.url, allow);
    if (!t) {
      log(`refused CONNECT ${String(req.url).slice(0, 200)}`);
      client.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
      return;
    }
    const up = connect(t.port, t.host, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) up.write(head);
      up.pipe(client);
      client.pipe(up);
    });
    up.setTimeout(120000, () => up.destroy());
    up.on('error', () => client.destroy());
    client.on('error', () => up.destroy());
  });
  return server;
}

module.exports = { decide, createProxy, allowList, DEFAULT_ALLOW };

if (require.main === module) {
  const port = Number(process.env.PORT || 3128);
  createProxy({ log: (m) => console.log(m) }).listen(port, '0.0.0.0', () => console.log(`appcrane-auto-patch-proxy listening on ${port}`));
}
