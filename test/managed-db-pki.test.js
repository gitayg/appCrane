import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { mkdtempSync, rmSync, statSync, readFileSync, readdirSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// AppCrane's private CA for the managed databases (services/dbPki.js) and its
// storage (services/dbCerts.js).
//
// dbPki.js hand-builds X.509 DER around node:crypto's signature, so nothing
// here trusts its own encoder: every certificate is read back through
// crypto.X509Certificate, which is OpenSSL's parser, and verified against the
// CA's public key. The real engines accepting these certificates is proven
// separately (see the real-engine verification in the release notes); this
// file pins the fields those engines depend on.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-pki-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const pki = await import('../server/services/dbPki.js');
const { initDb, getDb } = await import('../server/db.js');
const certs = await import('../server/services/dbCerts.js');
const { decrypt } = await import('../server/services/encryption.js');

before(() => initDb(process.env.DATA_DIR));
after(() => { try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {} });

const DAY = 86400e3;

test('the CA is a real, self-signed CA certificate with a ten-year life', () => {
  const ca = pki.generateCa();
  const x = new crypto.X509Certificate(ca.certPem);
  assert.equal(x.subject, `CN=${pki.CA_COMMON_NAME}`);
  assert.equal(x.issuer, x.subject);
  assert.equal(x.ca, true, 'basicConstraints CA:TRUE');
  assert.ok(x.verify(x.publicKey), 'self-signature verifies');
  const life = (new Date(x.validTo) - new Date(x.validFrom)) / DAY;
  assert.ok(life > 3649 && life < 3651, `CA validity ~10y, got ${life} days`);
  assert.match(ca.keyPem, /^-----BEGIN PRIVATE KEY-----/);
  assert.equal(crypto.createPrivateKey(ca.keyPem).asymmetricKeyDetails.namedCurve, 'prime256v1');
});

test('a server certificate carries the SANs apps dial, serverAuth only, signed by the CA', () => {
  const ca = pki.generateCa();
  const s = pki.issueCert({ ca, commonName: 'appcrane-db-postgres', usage: 'server', dnsNames: ['host.docker.internal', 'localhost'], ips: ['127.0.0.1', '172.17.0.1'] });
  const x = new crypto.X509Certificate(s.certPem);
  const caX = new crypto.X509Certificate(ca.certPem);
  assert.equal(x.subject, 'CN=appcrane-db-postgres');
  assert.equal(x.issuer, `CN=${pki.CA_COMMON_NAME}`);
  assert.equal(x.ca, false);
  assert.ok(x.verify(caX.publicKey), 'signature verifies against the CA key');
  assert.ok(x.checkIssued(caX), 'issuer/AKI chain to the CA');
  for (const san of ['DNS:host.docker.internal', 'DNS:localhost', 'IP Address:127.0.0.1', 'IP Address:172.17.0.1']) {
    assert.ok(x.subjectAltName.includes(san), `missing SAN ${san}: ${x.subjectAltName}`);
  }
  assert.ok(x.checkHost('host.docker.internal'), 'hostname verification for the name apps use');
  assert.ok(x.checkIP('172.17.0.1'));
  assert.deepEqual(x.keyUsage, ['1.3.6.1.5.5.7.3.1'], 'serverAuth only — it must not double as a client credential');
  const life = (new Date(x.validTo) - new Date(x.validFrom)) / DAY;
  assert.ok(life > 729 && life < 731, `leaf validity ~2y, got ${life}`);
});

test('a client certificate is CN = the login, clientAuth only, no SANs', () => {
  const ca = pki.generateCa();
  const c = pki.issueCert({ ca, commonName: 'crane_a14_u', usage: 'client' });
  const x = new crypto.X509Certificate(c.certPem);
  assert.equal(x.subject, 'CN=crane_a14_u');
  assert.deepEqual(x.keyUsage, ['1.3.6.1.5.5.7.3.2']);
  assert.equal(x.subjectAltName, undefined);
  assert.ok(x.verify(new crypto.X509Certificate(ca.certPem).publicKey));
});

test('a certificate from a different CA does not verify against ours', () => {
  const ours = pki.generateCa();
  const theirs = pki.generateCa();
  const c = pki.issueCert({ ca: theirs, commonName: 'crane_a1_u', usage: 'client' });
  assert.equal(new crypto.X509Certificate(c.certPem).verify(new crypto.X509Certificate(ours.certPem).publicKey), false);
});

test('unsafe common names are refused before they can reach REQUIRE SUBJECT or an x509 user', () => {
  const ca = pki.generateCa();
  for (const cn of ["x'; DROP USER root; --", 'a/CN=root', '', 'a\nb', '-lead']) {
    assert.throws(() => pki.issueCert({ ca, commonName: cn, usage: 'client' }), /unsafe common name/, JSON.stringify(cn));
  }
});

test('needsRenewal: inside 30 days yes, otherwise no', () => {
  const ca = pki.generateCa();
  const fresh = pki.issueCert({ ca, commonName: 'x', usage: 'client' });
  const aged = pki.issueCert({ ca, commonName: 'x', usage: 'client', now: new Date(Date.now() - 710 * DAY) });
  assert.equal(pki.needsRenewal(fresh.certPem), false);
  assert.equal(pki.needsRenewal(aged.certPem), true);
});

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

test('the CA key is stored only encrypted — never as plaintext PEM in SQLite', () => {
  const ca = certs.ensureCa();
  const row = getDb().prepare("SELECT * FROM managed_db_certs WHERE name = 'ca'").get();
  assert.ok(row, 'CA row exists');
  assert.ok(!row.key_enc.includes('PRIVATE KEY'), 'key_enc must not be plaintext');
  assert.equal(decrypt(row.key_enc), ca.keyPem, 'and it round-trips through encryption.js');
  assert.deepEqual(certs.ensureCa().certPem, ca.certPem, 'the CA is generated once, then reused');

  // Scan the database FILES too, so a plaintext copy in some other column or
  // table would be caught, not just the one this test knows about.
  getDb().pragma('wal_checkpoint(TRUNCATE)');
  const files = readdirSync(process.env.DATA_DIR).filter((n) => /\.(db|sqlite)(-wal)?$/.test(n));
  assert.ok(files.length > 0, 'found no database file to scan — the scan would prove nothing');
  for (const f of files) {
    assert.ok(!readFileSync(join(process.env.DATA_DIR, f)).includes('BEGIN PRIVATE KEY'), `${f} contains a plaintext private key`);
  }
});

test('server certificate: reused while SANs match, reissued when they change or it ages', () => {
  const a = certs.ensureServerCert('postgres', { dnsNames: ['host.docker.internal'], ips: ['127.0.0.1'] });
  assert.equal(a.renewed, true);
  const b = certs.ensureServerCert('postgres', { dnsNames: ['host.docker.internal'], ips: ['127.0.0.1'] });
  assert.equal(b.renewed, false);
  assert.equal(b.certPem, a.certPem);
  const c = certs.ensureServerCert('postgres', { dnsNames: ['host.docker.internal'], ips: ['127.0.0.1', '172.18.0.1'] });
  assert.equal(c.renewed, true, 'a new bridge gateway address must reissue the certificate');
  assert.ok(new crypto.X509Certificate(c.certPem).checkIP('172.18.0.1'));
});

test('client certificate: renewed inside the window, and the old one stays valid until it expires', async () => {
  const { encrypt } = await import('../server/services/encryption.js');
  const ca = certs.ensureCa();
  const aged = pki.issueCert({ ca, commonName: 'crane_a9_u', usage: 'client', now: new Date(Date.now() - 710 * DAY) });
  getDb().prepare("INSERT INTO managed_db_certs (name, cert_pem, key_enc, not_after) VALUES ('client:crane_a9_u', ?, ?, ?)")
    .run(aged.certPem, encrypt(aged.keyPem), aged.notAfter);
  const next = certs.ensureClientCert('crane_a9_u');
  assert.equal(next.renewed, true);
  assert.notEqual(next.certPem, aged.certPem);
  assert.ok(new Date(next.notAfter) - Date.now() > 700 * DAY);
  // Rotation must not break a running app: the certificate it holds is still
  // inside its validity and still chains to the same CA.
  const held = new crypto.X509Certificate(aged.certPem);
  assert.ok(new Date(held.validTo) > new Date(), 'held cert not yet expired');
  assert.ok(held.verify(new crypto.X509Certificate(ca.certPem).publicKey));
  assert.equal(certs.ensureClientCert('crane_a9_u').renewed, false, 'renewed once, then reused');
});

test('server files: 0700 directory outside every engine volume, key 0600', () => {
  const cert = certs.ensureServerCert('mariadb', { dnsNames: ['host.docker.internal'], ips: ['127.0.0.1'] });
  const dir = certs.writeServerFiles('mariadb', cert, { 'pg_hba.conf': 'x' });
  const root = join(process.env.DATA_DIR, 'managed-db');
  assert.equal(dir, join(root, '_tls', 'server', 'mariadb'));
  // Not under managed-db/<engine>, which IS that engine's data volume.
  for (const engine of ['postgres', 'mariadb', 'mongo', 'redis']) assert.ok(!dir.startsWith(join(root, engine) + '/'));
  assert.equal(statSync(join(root, '_tls')).mode & 0o777, 0o700);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(join(dir, 'server.key')).mode & 0o777, 0o600);
  assert.equal(statSync(join(dir, 'server.pem')).mode & 0o777, 0o600);
});

test('client files: parents 0700; key 0400 and chowned when AppCrane is root, 0444 otherwise', () => {
  const cert = certs.ensureClientCert('crane_a5_u');
  const owner = { uid: process.getuid(), gid: process.getgid() };

  // Not root (this test run): cannot chown, so the key must be readable by
  // whatever uid the container runs as, and the 0700 parents are the boundary.
  const plain = certs.writeClientFiles('crane_a5_u', cert, owner);
  assert.equal(plain.chowned, false);
  assert.equal(statSync(join(plain.hostDir, 'client.key')).mode & 0o777, 0o444);
  assert.equal(statSync(join(process.env.DATA_DIR, 'managed-db', '_tls', 'client')).mode & 0o777, 0o700);
  assert.equal(statSync(join(process.env.DATA_DIR, 'managed-db', '_tls')).mode & 0o777, 0o700);

  // Root (the production install): key 0400, owned by the image's uid. The
  // chown target here is our own uid, which an unprivileged chown permits.
  const realGetuid = process.getuid;
  process.getuid = () => 0;
  try {
    const rooted = certs.writeClientFiles('crane_a5_u', cert, owner);
    assert.equal(rooted.chowned, true);
    const st = statSync(join(rooted.hostDir, 'client.key'));
    assert.equal(st.mode & 0o777, 0o400);
    assert.equal(st.uid, owner.uid);
  } finally {
    process.getuid = realGetuid;
  }
  assert.equal(readFileSync(join(plain.hostDir, 'client.crt'), 'utf8'), cert.certPem);
  assert.deepEqual(plain.files, {
    ca: '/run/appcrane/db/ca.crt', cert: '/run/appcrane/db/client.crt',
    key: '/run/appcrane/db/client.key', pem: '/run/appcrane/db/client.pem',
  });
});

test('dropClientCert removes the row and the files', () => {
  certs.writeClientFiles('crane_a6_u', certs.ensureClientCert('crane_a6_u'), null);
  const dir = certs.clientTlsDir('crane_a6_u');
  assert.ok(existsSync(dir));
  certs.dropClientCert('crane_a6_u');
  assert.ok(!existsSync(dir));
  assert.equal(certs.clientCertInfo('crane_a6_u'), null);
});

test('resolveImageOwner parses `id`, and a missing `id` falls back to null (0444 path)', async () => {
  const ok = await certs.resolveImageOwner('img', { exec: async () => ({ stdout: 'uid=1000(node) gid=1000(node) groups=1000(node)\n' }) });
  assert.deepEqual(ok, { uid: 1000, gid: 1000 });
  const none = await certs.resolveImageOwner('img', { exec: async () => { throw new Error('exec: "id": executable file not found'); } });
  assert.equal(none, null);
  let argv;
  await certs.resolveImageOwner('img:1', { exec: async (_c, a) => { argv = a; return { stdout: '' }; } });
  assert.deepEqual(argv, ['run', '--rm', '--network', 'none', '--entrypoint', 'id', 'img:1'], 'argv only, no shell, no network');
});
