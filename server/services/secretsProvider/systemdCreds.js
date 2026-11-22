import { spawn } from 'child_process';
import { readdirSync, readFileSync, lstatSync } from 'fs';
import { join } from 'path';
import { assertAllowedKey } from './keyPolicy.js';

// systemd encrypted credentials: no AWS, no network. `crane secrets migrate
// --provider systemd-creds` seals each key with `systemd-creds encrypt` into
// /etc/credstore.encrypted/appcrane.<KEY> (root only), and a drop-in for the
// unit names them in LoadCredentialEncrypted=. systemd decrypts them when the
// service starts and hands the plaintext to it in $CREDENTIALS_DIRECTORY, a
// per-service ramfs only the service user can read.
//
// Credential name: appcrane.<KEY>, the allowlisted environment name as it is.
// systemd-creds embeds the name in the ciphertext and refuses to decrypt under
// another one, so a credential cannot be loaded as a different key.

export const PROVIDER_SYSTEMD = 'systemd-creds';
export const CRED_PREFIX = 'appcrane.';
export const DEFAULT_CREDSTORE = '/etc/credstore.encrypted';
export const DEFAULT_UNIT = 'appcrane';
export const DROPIN_NAME = 'credentials.conf';
const MAX_CRED_BYTES = 65536;
const UNIT_RE = /^[A-Za-z0-9@._-]{1,200}$/;

export const credentialName = (key) => `${CRED_PREFIX}${key}`;

/** Where things are, from the environment (.env settings applied). */
export function systemdPaths(env = process.env) {
  const unit = env.APPCRANE_SECRETS_UNIT || DEFAULT_UNIT;
  if (!UNIT_RE.test(unit)) throw new Error('APPCRANE_SECRETS_UNIT is not a valid unit name');
  const credstore = env.APPCRANE_SECRETS_CREDSTORE || DEFAULT_CREDSTORE;
  const dropinDir = env.APPCRANE_SECRETS_DROPIN_DIR || `/etc/systemd/system/${unit}.service.d`;
  return { unit, credstore, dropinDir, dropin: join(dropinDir, DROPIN_NAME) };
}

/** The keys a boot requires as credentials: APPCRANE_SECRETS_KEYS (comma list), default ENCRYPTION_KEY. */
export function expectedKeys(env = process.env) {
  const raw = env.APPCRANE_SECRETS_KEYS;
  const keys = raw ? raw.split(',').map((k) => k.trim()).filter(Boolean) : ['ENCRYPTION_KEY'];
  for (const k of keys) assertAllowedKey(k);
  return [...new Set(keys)];
}

const fixHint = (paths) => `Run sudo crane secrets migrate --provider systemd-creds, or check ${paths.dropin} and run systemctl daemon-reload && systemctl restart ${paths.unit}`;

/**
 * { KEY: value } from the appcrane.* files of $CREDENTIALS_DIRECTORY. Files
 * without the prefix are not AppCrane's (a unit can be given other
 * credentials) and are left alone. An appcrane.* name off the allowlist stops
 * the boot, as a non-allowlisted key in the AWS platform secret does.
 */
export function readCredentialsDirectory(dir) {
  let names;
  try {
    names = readdirSync(dir);
  } catch (e) {
    throw new Error(`CREDENTIALS_DIRECTORY ${dir} cannot be read (${e.code || 'error'})`);
  }
  const out = {};
  const others = [];
  for (const name of names) {
    if (!name.startsWith(CRED_PREFIX)) { others.push(name); continue; }
    const key = name.slice(CRED_PREFIX.length);
    try {
      assertAllowedKey(key);
    } catch (e) {
      throw new Error(`credential ${JSON.stringify(name.slice(0, 80))}: ${e.message}`);
    }
    const file = join(dir, name);
    const st = lstatSync(file);
    if (!st.isFile()) throw new Error(`credential ${name} is not a regular file`);
    if (st.size > MAX_CRED_BYTES) throw new Error(`credential ${name} is larger than ${MAX_CRED_BYTES} bytes`);
    out[key] = readFileSync(file, 'utf8').trim();
  }
  return { values: out, others };
}

/** The credentials systemd delivered, checked against what this host expects. Throws naming keys, never values. */
export function systemdCredentialValues(env = process.env) {
  const paths = systemdPaths(env);
  const required = expectedKeys(env);
  const dir = env.CREDENTIALS_DIRECTORY;
  if (!dir) {
    throw new Error(`APPCRANE_SECRETS_PROVIDER=systemd-creds but CREDENTIALS_DIRECTORY is not set: this process was not started by the ${paths.unit} systemd unit with its credentials `
      + `(required: ${required.map(credentialName).join(', ')}). ${fixHint(paths)}.`);
  }
  const { values, others } = readCredentialsDirectory(dir);
  const missing = required.filter((k) => !Object.prototype.hasOwnProperty.call(values, k));
  if (missing.length) {
    const unprefixed = missing.filter((k) => others.includes(k));
    throw new Error(`credential ${missing.map(credentialName).join(', ')} is missing from CREDENTIALS_DIRECTORY. `
      + `${paths.dropin} needs LoadCredentialEncrypted=${credentialName(missing[0])}:${join(paths.credstore, credentialName(missing[0]))}. ${fixHint(paths)}.`
      + (unprefixed.length ? ` (A credential named ${unprefixed.join(', ')} was delivered: AppCrane reads only names starting with ${CRED_PREFIX}.)` : ''));
  }
  return values;
}

// ── the systemd-creds and systemctl binaries (found on PATH) ───────────────

/** { status, stdout, stderr }. `input` goes to stdin: a value never goes in argv. Rejects only when it cannot run. */
export function runTool(bin, args, { input = null, timeout = 60_000 } = {}) {
  return new Promise((res, rej) => {
    const child = spawn(bin, args, { stdio: ['pipe', 'pipe', 'pipe'], timeout });
    const out = [];
    const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => rej(Object.assign(new Error(`${bin} could not be run (${e.code || e.message})`), { code: e.code })));
    child.on('close', (status, signal) => res({ status: status ?? (signal ? 128 : 1), stdout: Buffer.concat(out), stderr: Buffer.concat(err).toString('utf8') }));
    child.stdin.on('error', () => { /* a tool that exits early closes stdin */ });
    child.stdin.end(input ?? undefined);
  });
}

function toolError(what, r, scrub = []) {
  let detail = r.stderr.split('\n').filter(Boolean)[0] || `exit ${r.status}`;
  for (const v of scrub) if (v) detail = detail.split(v).join('[redacted]');
  return new Error(`${what} failed: ${detail.slice(0, 300)}`);
}

/** Seals `value` into `outPath` under credential `name`. */
export async function encryptCredential(name, value, outPath) {
  const r = await runTool('systemd-creds', ['encrypt', `--name=${name}`, '-', outPath], { input: value });
  if (r.status !== 0) throw toolError(`systemd-creds encrypt of ${name}`, r, [value]);
}

/** The plaintext of the credential file, trimmed as a boot reads it. Needs root with the host key. */
export async function decryptCredential(name, path) {
  const r = await runTool('systemd-creds', ['decrypt', `--name=${name}`, path, '-']);
  if (r.status !== 0) throw toolError(`systemd-creds decrypt of ${path}`, r);
  return r.stdout.toString('utf8').trim();
}

export async function systemctl(args) {
  return runTool('systemctl', args);
}

// ── the drop-in ─────────────────────────────────────────────────────────────

const LINE_RE = /^LoadCredentialEncrypted=appcrane\.([A-Za-z0-9_]+):(\S+)$/;

/** { keys: { KEY: path }, foreign: [lines that are not ours] } */
export function parseDropin(text) {
  const keys = {};
  const foreign = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line === '[Service]') continue;
    const m = LINE_RE.exec(line);
    if (m) keys[m[1]] = m[2];
    else foreign.push(line);
  }
  return { keys, foreign };
}

export function dropinText(keys, credstore) {
  return '# Written by crane secrets migrate --provider systemd-creds. AppCrane\'s own keys,\n'
    + '# sealed with this host\'s credential key; systemd decrypts them into\n'
    + '# $CREDENTIALS_DIRECTORY when the service starts. Remove this file only with\n'
    + '# the keys back in .env (see the rollback steps the migration printed).\n'
    + '[Service]\n'
    + keys.map((k) => `LoadCredentialEncrypted=${credentialName(k)}:${join(credstore, credentialName(k))}\n`).join('');
}
