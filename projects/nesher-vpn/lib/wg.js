// WireGuard key material and client-config rendering. Pure functions — no I/O.
import { generateKeyPairSync, randomBytes } from 'crypto';

const b64 = (b64url) => Buffer.from(b64url, 'base64url').toString('base64');

/** A fresh Curve25519 keypair in WireGuard's base64 encoding. */
export function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  return {
    privateKey: b64(privateKey.export({ format: 'jwk' }).d),
    publicKey: b64(publicKey.export({ format: 'jwk' }).x),
  };
}

/** 32 random bytes, the same as `wg genpsk`. Adds a symmetric layer on top of the DH handshake. */
export const generatePresharedKey = () => randomBytes(32).toString('base64');

/** A WireGuard key is 32 bytes, base64-encoded (44 chars ending in '='). */
export const isWgKey = (k) => typeof k === 'string' && /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(k);

/**
 * The client-side .conf — the same text the WireGuard app imports by QR or file.
 * AllowedIPs covers ::/0 too so the phone's IPv6 can't bypass the tunnel (the
 * tunnel carries no v6, so v6 traffic is simply dropped rather than leaked).
 */
export function renderClientConfig({ privateKey, address, dns, serverPublicKey, presharedKey, endpoint, name }) {
  return [
    `# Nesher VPN — ${String(name).replace(/[\r\n]/g, ' ')}`,
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${address}/32`,
    `DNS = ${dns}`,
    '',
    '[Peer]',
    `PublicKey = ${serverPublicKey}`,
    `PresharedKey = ${presharedKey}`,
    `Endpoint = ${endpoint}`,
    'AllowedIPs = 0.0.0.0/0, ::/0',
    'PersistentKeepalive = 25',
    '',
  ].join('\n');
}
