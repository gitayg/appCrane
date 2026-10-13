/**
 * AppCrane's private certificate authority for the managed databases.
 *
 * PURE: generates keys and builds X.509 certificates, and nothing else. No
 * SQLite, no files, no docker. services/dbCerts.js owns storage (keys
 * encrypted with services/encryption.js) and services/managedDb.js owns what
 * the engines do with the result.
 *
 * =========================================================================
 * WHY A HAND-BUILT DER ENCODER, AND NOT `openssl` OR A DEPENDENCY
 * =========================================================================
 * Node can generate keys and sign bytes (crypto.generateKeyPairSync,
 * crypto.sign) and can PARSE a certificate (crypto.X509Certificate), but it
 * has no API that ISSUES one. Measured on Node 22.22.0: there is no
 * createCertificate / X509Certificate constructor that takes a subject, and
 * crypto.X509Certificate is read-only.
 *
 * The usual answer is to shell out to `openssl`. That puts a host binary on
 * the critical path of every provision, and the host is the one machine whose
 * contents AppCrane does not choose — the engine images ship openssl, the box
 * running AppCrane may not, and a missing binary would surface as "provisioning
 * failed" mid-deploy. A dependency (node-forge, @peculiar/x509) would be the
 * only cryptography in package.json, for ~150 lines of ASN.1.
 *
 * A certificate is a fixed DER structure around a signature node can already
 * produce, so it is built here. The parts that are actually cryptographic —
 * key generation and the ECDSA signature — are node:crypto's; this file only
 * arranges bytes. test/managed-db-pki.test.js checks every certificate back
 * through crypto.X509Certificate (subject, SANs, validity, issuer, and
 * verify() against the CA's public key), and the real engines accept them,
 * which is the check that a hand encoder cannot fake.
 *
 * EC P-256 / ecdsa-with-SHA256. Every engine AppCrane runs (postgres:16,
 * mariadb:11.4, mongo:8.0, redis:8.10) links OpenSSL 3, and every driver the
 * docs name (node-postgres, mysql2, mongodb, ioredis) goes through Node's TLS,
 * which is OpenSSL too; P-256 is the curve all of them support by default.
 */

import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Validity
// ---------------------------------------------------------------------------

/** The CA lives ten years; nothing rotates it automatically (see dbCerts.js). */
export const CA_VALIDITY_DAYS = 3650;

/** Server and client certificates live two years and are renewed early. */
export const LEAF_VALIDITY_DAYS = 730;

/**
 * Renew a leaf once it has fewer than this many days left. Renewal writes the
 * new files BEFORE the old certificate expires, and the next deploy or restart
 * (client) or the next ensureServer (server) picks them up — a month is enough
 * slack that a platform nobody deploys for weeks still never crosses an expiry.
 */
export const RENEW_BEFORE_DAYS = 30;

/** The CA's subject. MariaDB's REQUIRE ISSUER compares against this string. */
export const CA_COMMON_NAME = 'AppCrane Managed DB CA';

const DAY_MS = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------

function len(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, body) {
  const b = Buffer.isBuffer(body) ? body : Buffer.concat(body);
  return Buffer.concat([Buffer.from([tag]), len(b.length), b]);
}

const seq = (...items) => tlv(0x30, items);
const set = (...items) => tlv(0x31, items);
const octets = (b) => tlv(0x04, b);
const bitString = (b, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), b]));
const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
const utf8 = (s) => tlv(0x0c, Buffer.from(String(s), 'utf8'));
const explicit = (n, body) => tlv(0xa0 | n, body);

function integer(buf) {
  let b = Buffer.from(buf);
  while (b.length > 1 && b[0] === 0x00 && !(b[1] & 0x80)) b = b.subarray(1);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
  return tlv(0x02, b);
}

function oid(dotted) {
  const parts = dotted.split('.').map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (const p of parts.slice(2)) {
    const stack = [p & 0x7f];
    for (let v = Math.floor(p / 128); v > 0; v = Math.floor(v / 128)) stack.unshift(0x80 | (v & 0x7f));
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}

/** UTCTime through 2049, GeneralizedTime after — RFC 5280 4.1.2.5. */
function time(d) {
  const iso = d.toISOString().replace(/[-:T]/g, '').slice(0, 14); // YYYYMMDDHHMMSS
  if (d.getUTCFullYear() < 2050) return tlv(0x17, Buffer.from(`${iso.slice(2)}Z`, 'ascii'));
  return tlv(0x18, Buffer.from(`${iso}Z`, 'ascii'));
}

const OID = {
  commonName: '2.5.4.3',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  subjectAltName: '2.5.29.17',
  subjectKeyId: '2.5.29.14',
  authorityKeyId: '2.5.29.35',
  serverAuth: '1.3.6.1.5.5.7.3.1',
  clientAuth: '1.3.6.1.5.5.7.3.2',
};

function name(cn) {
  return seq(set(seq(oid(OID.commonName), utf8(cn))));
}

function ext(id, critical, valueDer) {
  return critical ? seq(oid(id), bool(true), octets(valueDer)) : seq(oid(id), octets(valueDer));
}

function ipBytes(ip) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return Buffer.from(ip.split('.').map(Number));
  throw new Error(`dbPki: only IPv4 SAN addresses are supported, got ${JSON.stringify(ip)}`);
}

function keyId(publicKey) {
  // RFC 5280 4.2.1.2 method 1: SHA-1 of the subjectPublicKey BIT STRING
  // contents. Here: of the whole SPKI, which is equally unique and is what
  // matters — the AKI of a leaf has to equal the SKI of its CA, and both are
  // computed by this one function.
  return crypto.createHash('sha1').update(publicKey.export({ type: 'spki', format: 'der' })).digest();
}

// Common names are login names and fixed labels this platform generates. The
// check is the injection boundary for MariaDB's REQUIRE SUBJECT literal and for
// the x509 user Mongo derives from the subject, so it is strict on purpose.
const SAFE_CN = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$/;

function buildCert({ subjectCn, issuerCn, subjectPublicKey, issuerPublicKey, signingKey, days, isCa, usage, bothUsages = false, dnsNames = [], ips = [], now = new Date() }) {
  if (!SAFE_CN.test(subjectCn)) throw new Error(`dbPki: refusing an unsafe common name ${JSON.stringify(subjectCn)}`);
  // Back-dated a minute: a container whose clock is a few seconds behind the
  // host would otherwise reject a certificate issued "in the future".
  const notBefore = new Date(now.getTime() - 60 * 1000);
  const notAfter = new Date(now.getTime() + days * DAY_MS);
  const serial = crypto.randomBytes(16);
  serial[0] &= 0x7f; // positive, as RFC 5280 requires

  const exts = [];
  if (isCa) {
    exts.push(ext(OID.basicConstraints, true, seq(bool(true))));
    // keyCertSign (bit 5) + cRLSign (bit 6): 0b00000110, 1 unused bit.
    exts.push(ext(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)));
  } else {
    exts.push(ext(OID.basicConstraints, true, seq()));
    // digitalSignature (bit 0) — all an ECDSA key does in TLS 1.2/1.3.
    exts.push(ext(OID.keyUsage, true, bitString(Buffer.from([0x80]), 7)));
    // A server certificate is serverAuth only, so it cannot double as a client
    // credential — except where the engine needs exactly that (`bothUsages`):
    // mongod presents its certificate as a CLIENT on its own intra-set
    // connections, and refuses one without clientAuth.
    const eku = usage === 'server'
      ? (bothUsages ? [OID.serverAuth, OID.clientAuth] : [OID.serverAuth])
      : [OID.clientAuth];
    exts.push(ext(OID.extKeyUsage, false, seq(...eku.map(oid))));
    const sans = [
      ...dnsNames.map(d => tlv(0x82, Buffer.from(String(d), 'ascii'))),
      ...ips.map(ip => tlv(0x87, ipBytes(ip))),
    ];
    if (sans.length) exts.push(ext(OID.subjectAltName, false, seq(...sans)));
  }
  exts.push(ext(OID.subjectKeyId, false, octets(keyId(subjectPublicKey))));
  exts.push(ext(OID.authorityKeyId, false, seq(tlv(0x80, keyId(issuerPublicKey)))));

  const sigAlg = seq(oid(OID.ecdsaSha256));
  const tbs = seq(
    explicit(0, integer(Buffer.from([2]))), // v3
    integer(serial),
    sigAlg,
    name(issuerCn),
    seq(time(notBefore), time(notAfter)),
    name(subjectCn),
    subjectPublicKey.export({ type: 'spki', format: 'der' }),
    explicit(3, seq(...exts)),
  );
  // DER-encoded ECDSA-Sig-Value, which is exactly what X.509 carries.
  const signature = crypto.sign('sha256', tbs, signingKey);
  const der = seq(tbs, sigAlg, bitString(signature));
  const b64 = der.toString('base64').match(/.{1,64}/g).join('\n');
  return {
    certPem: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`,
    notAfter: notAfter.toISOString(),
    serial: serial.toString('hex'),
  };
}

function newKeyPair() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * A fresh self-signed CA. `keyPem` is PKCS#8 and must be stored encrypted.
 *
 * `commonName` defaults to the platform CA's. The other caller is the
 * per-instance Redis client CA (dbCerts.ensureRedisCa): a CA whose ONLY job is
 * to be the one trust anchor a single Redis instance accepts client
 * certificates from, so that a certificate issued for a different app cannot
 * complete that instance's handshake.
 */
export function generateCa({ now, commonName = CA_COMMON_NAME } = {}) {
  const { publicKey, privateKey } = newKeyPair();
  const cert = buildCert({
    subjectCn: commonName,
    issuerCn: commonName,
    subjectPublicKey: publicKey,
    issuerPublicKey: publicKey,
    signingKey: privateKey,
    days: CA_VALIDITY_DAYS,
    isCa: true,
    now,
  });
  return { ...cert, commonName, keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}

/**
 * The CN of a certificate's subject. A leaf's issuer name has to be its CA's
 * subject byte for byte — OpenSSL finds the issuer by NAME before it checks the
 * signature — so issueCert() reads it off the CA rather than assuming the
 * platform CA's.
 */
function subjectCnOf(certPem) {
  const m = /^CN=(.*)$/m.exec(new crypto.X509Certificate(certPem).subject);
  if (!m) throw new Error('dbPki: CA certificate has no CN');
  return m[1];
}

/**
 * Issue a leaf signed by `ca` ({ certPem, keyPem }).
 *
 *   usage 'server'  serverAuth EKU, SANs for the names clients dial
 *   usage 'client'  clientAuth EKU, CN = the database login it authenticates
 */
export function issueCert({ ca, commonName, usage, dnsNames = [], ips = [], days = LEAF_VALIDITY_DAYS, bothUsages = false, now }) {
  if (usage !== 'server' && usage !== 'client') throw new Error(`dbPki: usage must be 'server' or 'client', got ${JSON.stringify(usage)}`);
  const caKey = crypto.createPrivateKey(ca.keyPem);
  const caPub = crypto.createPublicKey(caKey);
  const { publicKey, privateKey } = newKeyPair();
  const cert = buildCert({
    subjectCn: commonName,
    issuerCn: ca.commonName || subjectCnOf(ca.certPem),
    subjectPublicKey: publicKey,
    issuerPublicKey: caPub,
    signingKey: caKey,
    days,
    isCa: false,
    usage,
    bothUsages,
    dnsNames,
    ips,
    now,
  });
  return { ...cert, keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}

/** Parsed facts about a certificate. Never touches a key. */
export function certInfo(certPem) {
  const x = new crypto.X509Certificate(certPem);
  return {
    subject: x.subject,
    issuer: x.issuer,
    notAfter: new Date(x.validTo).toISOString(),
    subjectAltName: x.subjectAltName || '',
    serial: x.serialNumber,
  };
}

/** True when the certificate expires within RENEW_BEFORE_DAYS (or already has). */
export function needsRenewal(certPem, { now = new Date(), days = RENEW_BEFORE_DAYS } = {}) {
  const notAfter = new Date(new crypto.X509Certificate(certPem).validTo).getTime();
  return notAfter - now.getTime() < days * DAY_MS;
}
