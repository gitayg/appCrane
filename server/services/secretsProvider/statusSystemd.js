import { existsSync, readFileSync, statSync } from 'fs';
import { PLATFORM_SECRET_NAMES } from './keyPolicy.js';
import { credentialName, systemdPaths, expectedKeys, parseDropin, decryptCredential, systemctl } from './systemdCreds.js';
import { join } from 'path';

// true, false, or null when this user cannot look (the store is root's, 0700).
function present(file) {
  try { return statSync(file).isFile(); } catch (e) { return e.code === 'ENOENT' ? false : null; }
}

/**
 * crane secrets status for systemd-creds. Key names and paths only. As root
 * each credential is decrypted to check it would load (the value is dropped);
 * otherwise that column says it was not checked.
 */
export async function systemdStatus({ parsed, env = process.env }) {
  const paths = systemdPaths(env);
  const keys = expectedKeys(env);
  const root = process.geteuid?.() === 0;
  const out = {
    provider: 'systemd-creds',
    unit: paths.unit,
    dropin: paths.dropin,
    dropin_present: existsSync(paths.dropin),
    dropin_keys: [],
    credstore: paths.credstore,
    expected_keys: keys,
    credentials: [],
    loadable_keys: [],
    problems: [],
    checked_as_root: root,
    unit_sees_dropin: null,
    imds: null,
  };
  if (out.dropin_present) out.dropin_keys = Object.keys(parseDropin(readFileSync(paths.dropin, 'utf8')).keys);
  else out.problems.push(`no drop-in at ${paths.dropin}: systemd hands the service no credentials`);
  for (const k of keys) {
    if (out.dropin_present && !out.dropin_keys.includes(k)) out.problems.push(`${paths.dropin} does not load ${credentialName(k)}`);
  }
  for (const k of [...new Set([...keys, ...out.dropin_keys])]) {
    const file = join(paths.credstore, credentialName(k));
    const c = { key: k, file, present: present(file), decrypts: null };
    if (c.present === false) out.problems.push(`${file} is missing`);
    else if (c.present && root) {
      try {
        await decryptCredential(credentialName(k), file);
        c.decrypts = true;
        out.loadable_keys.push(k);
      } catch (e) {
        c.decrypts = false;
        c.error = e.message;
        out.problems.push(`${file} does not decrypt`);
      }
    }
    out.credentials.push(c);
  }
  try {
    const r = await systemctl(['show', `${paths.unit}.service`, '-p', 'DropInPaths', '--value']);
    if (r.status === 0) out.unit_sees_dropin = r.stdout.toString('utf8').split(/\s+/).includes(paths.dropin);
  } catch (_) { /* no systemctl: stays null */ }
  if (out.unit_sees_dropin === false && out.dropin_present) out.problems.push(`systemd does not list ${paths.dropin} for ${paths.unit}.service: run sudo systemctl daemon-reload`);
  out.still_in_env_file = [...new Set([...PLATFORM_SECRET_NAMES, ...keys])].filter((k) => parsed[k]);
  for (const k of out.still_in_env_file) if (keys.includes(k)) out.problems.push(`${k} is in .env as well as a credential: a different value stops the boot`);
  return out;
}
