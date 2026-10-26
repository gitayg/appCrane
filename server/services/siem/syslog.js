import tls from 'tls';
import dgram from 'dgram';
import { isIP } from 'net';
import { toSyslog, octetFrame } from './mapping.js';
import { guardFor } from './netGuard.js';

// Syslog transports. tcp-tls: RFC 5425 (TLS) with RFC 6587 octet-counting
// framing, one connection per batch, certificate verified against the system
// roots or the sink's custom CA. udp: RFC 5426, one message per datagram, no
// TLS and no delivery confirmation (legacy collectors only).

const CONNECT_TIMEOUT_MS = 15_000;
export const UDP_MAX_BYTES = 8192;

export function buildSyslogMessages(docs, sink) {
  return docs.map(d => toSyslog(d, { format: sink.format, facility: sink.config.facility ?? 13 }));
}

function sendTls(messages, sink, allowlist) {
  const { host, port } = sink.config;
  const { lookup } = guardFor(host, allowlist);
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) { socket.destroy(); reject(err); } else resolve();
    };
    const socket = tls.connect({
      host, port: Number(port), lookup,
      servername: isIP(host) ? undefined : host,
      ca: sink.ca_pem ? [sink.ca_pem] : undefined,
      rejectUnauthorized: !sink.tls_skip_verify,
      minVersion: 'TLSv1.2',
    });
    const timer = setTimeout(() => done(new Error(`syslog connection to ${host}:${port} timed out`)), CONNECT_TIMEOUT_MS);
    socket.on('error', done);
    socket.once('secureConnect', () => {
      socket.end(Buffer.concat(messages.map(octetFrame)), () => {
        done();
        setTimeout(() => socket.destroy(), 2000).unref();
      });
    });
    socket.on('data', () => {});
  });
}

function resolveGuarded(host, lookup) {
  if (isIP(host)) return Promise.resolve({ address: host, family: isIP(host) });
  return new Promise((resolve, reject) => {
    lookup(host, {}, (err, address, family) => (err ? reject(err) : resolve({ address, family })));
  });
}

async function sendUdp(messages, sink, allowlist) {
  const { host, port } = sink.config;
  const { lookup } = guardFor(host, allowlist);
  const { address, family } = await resolveGuarded(host, lookup);
  const socket = dgram.createSocket(family === 6 ? 'udp6' : 'udp4');
  try {
    for (const m of messages) {
      let buf = Buffer.from(m, 'utf8');
      if (buf.length > UDP_MAX_BYTES) buf = buf.subarray(0, UDP_MAX_BYTES);
      await new Promise((resolve, reject) => socket.send(buf, Number(port), address, e => (e ? reject(e) : resolve())));
    }
  } finally {
    socket.close();
  }
}

export async function sendSyslog(docs, sink, _secrets, allowlist) {
  if (!docs.length) return;
  const messages = buildSyslogMessages(docs, sink);
  if (sink.config.transport === 'udp') return sendUdp(messages, sink, allowlist);
  return sendTls(messages, sink, allowlist);
}
