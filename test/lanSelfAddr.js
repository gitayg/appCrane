// A non-loopback IPv4 address this host can reach itself on, for tests that
// need a direct client whose socket address is not 127.0.0.1.
//
// Having an interface is not enough: a VPN or endpoint agent can reset or
// swallow a connection to the host's own address, and the test then fails on
// "other side closed" with nothing wrong in the code under test.
import { createServer } from 'node:http';
import { connect } from 'node:net';
import { networkInterfaces } from 'node:os';

// A raw socket rather than fetch: an aborted fetch leaves its connect attempt
// pending, and that handle keeps the test process from exiting.
function selfReachable(address) {
  return new Promise((resolve) => {
    const srv = createServer((req, res) => res.end('ok'));
    srv.once('error', () => resolve(false));
    srv.listen(0, address, () => {
      const sock = connect({ host: address, port: srv.address().port });
      let reply = '';
      const done = (ok) => {
        clearTimeout(timer);
        sock.destroy();
        srv.closeAllConnections();
        srv.close();
        resolve(ok);
      };
      const timer = setTimeout(() => done(false), 2000);
      sock.on('connect', () => sock.write(`GET / HTTP/1.1\r\nHost: ${address}\r\nConnection: close\r\n\r\n`));
      sock.on('data', (d) => { reply += d; });
      sock.on('end', () => done(/\r\n\r\nok$/.test(reply)));
      sock.on('error', () => done(false));
    });
  });
}

export async function findLanSelfAddr() {
  const candidates = Object.values(networkInterfaces()).flat()
    .filter((i) => i && i.family === 'IPv4' && !i.internal)
    .map((i) => i.address);
  if (!candidates.length) return { addr: null, skip: 'no non-loopback IPv4 interface to bind' };
  for (const addr of candidates) if (await selfReachable(addr)) return { addr, skip: false };
  return { addr: null, skip: `no non-loopback IPv4 address accepts a connection from this host (${candidates.join(', ')}); a VPN or firewall is resetting it` };
}
