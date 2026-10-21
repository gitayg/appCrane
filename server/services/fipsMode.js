/**
 * FIPS 140-3 mode: what this Node's OpenSSL is doing, what APPCRANE_FIPS asks
 * for, and what is still on a non-approved algorithm. docs/FIPS.md is the
 * deployer's side.
 *
 *   APPCRANE_FIPS=off      (default) nothing is checked.
 *   APPCRANE_FIPS=prefer   start either way; warn when the FIPS provider is not
 *                          active or the self-check fails.
 *   APPCRANE_FIPS=require  refuse to start unless crypto.getFips() is 1 AND the
 *                          self-check passes (MD5 refused, the approved
 *                          algorithms AppCrane uses answer their known vectors).
 *
 * Node has no API that names the loaded OpenSSL providers; getFips() is the
 * only signal, so `provider` below is inferred from it.
 */
import crypto from 'crypto';
import { parsePasswordHash, PBKDF2_SCHEME, scryptAvailable } from './encryption.js';
import { keyFileUsesLegacyKdf, keyFileKdf } from './managedDbEncryption.js';

export const FIPS_MODES = Object.freeze(['off', 'prefer', 'require']);

export function fipsSetting(env = process.env) {
  const v = String(env.APPCRANE_FIPS ?? 'off').trim().toLowerCase() || 'off';
  if (!FIPS_MODES.includes(v)) throw new Error(`APPCRANE_FIPS must be one of ${FIPS_MODES.join(', ')}, not ${JSON.stringify(v)}`);
  return v;
}

// Published vectors: FIPS 180-2 "abc"; RFC 4231 test case 2; RFC 7914 section
// 11 (PBKDF2-HMAC-SHA256, c=1); GCM spec test case 14 (AES-256, zero key/IV).
const KAT = {
  sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  hmac: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  pbkdf2: '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783',
  gcmCt: 'cea7403d4d606b6e074ec5d3baf39d18',
  gcmTag: 'd0d1c8a799996bf0265b98b5d48ab919',
};

function attempt(name, fn) {
  try {
    const ok = fn() === true;
    return { name, ok, detail: ok ? 'ok' : 'wrong output' };
  } catch (e) {
    return { name, ok: false, detail: String(e?.code || e?.message || e).slice(0, 160) };
  }
}

/**
 * { ok, md5Available, checks }. `ok` means every approved algorithm worked;
 * whether MD5 being available is a failure is the caller's (require mode's)
 * decision. `c` is injectable for tests.
 */
export function selfCheck(c = crypto) {
  const checks = [
    attempt('sha256', () => c.createHash('sha256').update('abc').digest('hex') === KAT.sha256),
    attempt('hmac-sha256', () => c.createHmac('sha256', 'Jefe').update('what do ya want for nothing?').digest('hex') === KAT.hmac),
    attempt('pbkdf2-hmac-sha256', () => c.pbkdf2Sync('passwd', 'salt', 1, 64, 'sha256').toString('hex') === KAT.pbkdf2),
    attempt('aes-256-gcm', () => {
      const e = c.createCipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(12));
      const ct = Buffer.concat([e.update(Buffer.alloc(16)), e.final()]);
      const tag = e.getAuthTag();
      if (ct.toString('hex') !== KAT.gcmCt || tag.toString('hex') !== KAT.gcmTag) return false;
      const d = c.createDecipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(12), { authTagLength: 16 });
      const bad = Buffer.from(tag);
      bad[0] ^= 1;
      d.setAuthTag(bad);
      d.update(ct);
      try { d.final(); return false; } catch { return true; }
    }),
    attempt('csprng', () => c.randomBytes(32).length === 32),
  ];
  let md5Available;
  try {
    c.createHash('md5').update('x').digest();
    md5Available = true;
  } catch {
    md5Available = false;
  }
  return { ok: checks.every((x) => x.ok), md5Available, checks };
}

/**
 * Call once at startup, before anything else touches crypto. Throws in
 * `require` mode when the process is not in FIPS mode; returns the result
 * otherwise. `getFips` and `check` are injectable for tests.
 */
export function enforceFipsAtStartup({ env = process.env, getFips = () => crypto.getFips(), check = () => selfCheck(), log = console } = {}) {
  const mode = fipsSetting(env);
  if (mode === 'off') return { mode, fipsActive: getFips() === 1, checked: false };
  const fipsActive = getFips() === 1;
  const sc = check();
  const problems = [];
  if (!fipsActive) problems.push(`crypto.getFips() is ${getFips()}, not 1 (Node is not running with a FIPS provider: start it with --enable-fips or --force-fips, or set it in the OpenSSL config)`);
  if (sc.md5Available) problems.push('MD5 is available, so the FIPS provider is not the one answering');
  for (const x of sc.checks) if (!x.ok) problems.push(`self-check ${x.name} failed: ${x.detail}`);
  if (problems.length && mode === 'require') {
    throw Object.assign(new Error(`APPCRANE_FIPS=require: refusing to start. ${problems.join('; ')}`), { code: 'FIPS_REQUIRED' });
  }
  for (const p of problems) log.warn(`[fips] APPCRANE_FIPS=prefer: ${p}`);
  return { mode, fipsActive, checked: true, problems, selfCheck: sc };
}

/** Users whose stored password is not PBKDF2 (scrypt, or not parseable). */
export function legacyPasswordCount(db) {
  const rows = db.prepare('SELECT password_hash FROM users WHERE password_hash IS NOT NULL').all();
  let scrypt = 0;
  let unreadable = 0;
  for (const r of rows) {
    const p = parsePasswordHash(r.password_hash);
    if (!p) unreadable++;
    else if (p.scheme !== PBKDF2_SCHEME) scrypt++;
  }
  return { scrypt, unreadable };
}

/** Everything the Settings "Cryptography" card and Job Health show. Never a key, hash or secret. */
export function cryptoStatus(db, { env = process.env, getFips = () => crypto.getFips(), check = () => selfCheck() } = {}) {
  let mode;
  let modeError = null;
  try { mode = fipsSetting(env); } catch (e) { mode = 'invalid'; modeError = e.message; }
  const fipsActive = getFips() === 1;
  const sc = check();
  const pw = legacyPasswordCount(db);
  const scryptOk = scryptAvailable();
  let mariadbLegacy = null;
  let kdf = null;
  try {
    mariadbLegacy = keyFileUsesLegacyKdf(db) ? 1 : 0;
    kdf = keyFileKdf(env).name;
  } catch (e) {
    kdf = `invalid (${e.message})`;
  }
  const legacy = [];
  if (pw.scrypt) {
    legacy.push({
      id: 'password-scrypt',
      count: pw.scrypt,
      detail: scryptOk
        ? `${pw.scrypt} user password(s) still scrypt; each is re-hashed to PBKDF2-HMAC-SHA256 at that user's next password sign-in.`
        : `${pw.scrypt} user password(s) are scrypt and this process cannot compute scrypt; those users must have their password reset.`,
    });
  }
  if (pw.unreadable) legacy.push({ id: 'password-unreadable', count: pw.unreadable, detail: `${pw.unreadable} stored password(s) are in no known format; those users cannot sign in with a password.` });
  if (mariadbLegacy) {
    legacy.push({
      id: 'mariadb-keyfile-sha1',
      count: 1,
      detail: 'The managed MariaDB key file is wrapped with EVP_BytesToKey/SHA-1 (the only derivation MariaDB before 12.0 accepts). Set APPCRANE_TDE_KDF=pbkdf2-sha256 with a MariaDB 12.x image.',
    });
  }
  return {
    mode,
    modeError,
    fipsActive,
    provider: fipsActive ? 'fips (crypto.getFips() = 1)' : 'default (crypto.getFips() = 0)',
    openssl: process.versions.openssl,
    node: process.version,
    sharedOpenssl: Boolean(process.config?.variables?.node_shared_openssl),
    selfCheck: sc,
    scryptAvailable: scryptOk,
    mariadbKeyFileKdf: kdf,
    legacy,
    documentedExceptions: [
      { id: 'pki-sha1-key-id', detail: 'dbPki.js: SHA-1 of the public key as the X.509 subject/authority key identifier (RFC 5280 4.2.1.2 method 1). An identifier, not a security function.' },
    ],
    claimable: fipsActive && sc.ok && !sc.md5Available && legacy.length === 0,
  };
}
