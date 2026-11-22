import { existsSync, readFileSync, statSync, mkdirSync, chmodSync, openSync, writeSync, fsyncSync, closeSync, renameSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { MigrateRefused, oldKeyCopies } from './migrate.js';
import { ALLOWED_PLATFORM_KEYS, PLATFORM_SECRET_NAMES, assertAllowedKey, validatedPlatformKeys } from './keyPolicy.js';
import { parseEnvText, withKeys, withoutKeys } from './envText.js';
import {
  PROVIDER_SYSTEMD, DEFAULT_CREDSTORE, DEFAULT_UNIT, credentialName, systemdPaths, expectedKeys,
  encryptCredential, decryptCredential, systemctl, runTool, parseDropin, dropinText,
} from './systemdCreds.js';
import { readEnvKey, stageEnv } from '../keyRotation/envFile.js';
import { serverAnswers } from '../keyRotation/preflight.js';

export const DEFAULT_BACKUP_DIR = '/var/backups/appcrane';

const isRoot = () => process.geteuid?.() === 0;
const ordered = (keys) => ALLOWED_PLATFORM_KEYS.filter((k) => keys.includes(k));

async function unitState(unit) {
  let show;
  try {
    show = await systemctl(['show', `${unit}.service`, '-p', 'LoadState', '--value']);
  } catch (e) {
    throw new MigrateRefused(`systemctl could not be run (${e.code || e.message}): the systemd-creds provider needs systemd`);
  }
  const loadState = show.stdout.toString('utf8').trim();
  if (loadState !== 'loaded') throw new MigrateRefused(`systemd has no unit ${unit}.service (LoadState=${loadState || 'unknown'}). Pass --unit with the name AppCrane runs as`);
  const active = await systemctl(['is-active', '--quiet', `${unit}.service`]);
  return { active: active.status === 0 };
}

function writeBackup(dir, text, now) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const file = join(dir, `env.pre-systemd-creds-${now.toISOString().replace(/[:.]/g, '-')}`);
  const fd = openSync(file, 'wx', 0o600);
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(file, 0o600);
  return file;
}

function writeAtomic(path, text, mode) {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, text, { mode, flag: 'w' });
  chmodSync(tmp, mode);
  renameSync(tmp, path);
}

export function rollbackSteps({ envPath, envStat, backupFile, dropin, unit, credentialFiles }) {
  return [
    `sudo systemctl stop ${unit}`,
    `sudo install -m ${(envStat.mode & 0o777).toString(8).padStart(4, '0')} -o ${envStat.uid} -g ${envStat.gid} ${backupFile} ${envPath}`,
    `sudo rm ${dropin}`,
    'sudo systemctl daemon-reload',
    `sudo systemctl start ${unit}`,
    `# once it runs from .env again: sudo rm ${credentialFiles.join(' ')}`,
  ];
}

/**
 * crane secrets migrate --provider systemd-creds. Run as root: systemd-creds
 * needs the host key, the credential store and the drop-in are root's.
 *
 * The order keeps every crash bootable: backup -> seal each key and decrypt it
 * back -> drop-in -> daemon-reload -> trial load -> .env renamed into place
 * last. Until that rename .env holds the keys and names no provider, so the
 * host boots from .env (the drop-in alone only hands the service files it
 * ignores); after it the host boots from the credentials.
 *
 * onStep(name) runs after each step: 'backup', 'credentials-written',
 * 'dropin-written', 'daemon-reloaded', 'env-committed'.
 */
export async function migrateToSystemdCreds({
  envPath, dataDir, port = 5001, dryRun = false, keys = null,
  credstore = null, dropinDir = null, unit = null, backupDir = DEFAULT_BACKUP_DIR,
  requireRoot = true, now = new Date(), onStep = () => {}, listArchive,
}) {
  if (!existsSync(envPath)) throw new MigrateRefused(`no .env at ${envPath}`);
  const envText = readFileSync(envPath, 'utf8');
  const envStat = statSync(envPath);
  const parsed = parseEnvText(envText);
  const current = process.env.APPCRANE_SECRETS_PROVIDER || parsed.APPCRANE_SECRETS_PROVIDER;
  if (current && current !== PROVIDER_SYSTEMD) throw new MigrateRefused(`this AppCrane already uses APPCRANE_SECRETS_PROVIDER=${current}; one provider at a time`);
  const already = current === PROVIDER_SYSTEMD;

  let paths;
  try {
    paths = systemdPaths({
      APPCRANE_SECRETS_UNIT: unit || parsed.APPCRANE_SECRETS_UNIT,
      APPCRANE_SECRETS_CREDSTORE: credstore || parsed.APPCRANE_SECRETS_CREDSTORE,
      APPCRANE_SECRETS_DROPIN_DIR: dropinDir || parsed.APPCRANE_SECRETS_DROPIN_DIR,
    });
  } catch (e) {
    throw new MigrateRefused(e.message);
  }

  // ENCRYPTION_KEY by default (PLATFORM_SECRET_NAMES); --keys can move any allowlisted name.
  let candidates = PLATFORM_SECRET_NAMES;
  if (keys) {
    try { for (const k of keys) assertAllowedKey(k); } catch (e) { throw new MigrateRefused(e.message); }
    const absent = keys.filter((k) => !parsed[k]);
    if (absent.length) throw new MigrateRefused(`${absent.join(', ')} not in ${envPath}`);
    candidates = keys;
  }
  const moving = ordered(candidates.filter((k) => parsed[k]));
  if (!moving.length) throw new MigrateRefused(`nothing to move: ${envPath} holds none of ${candidates.join(', ')}`);
  if (parsed.ENCRYPTION_KEY && !readEnvKey(envText)) throw new MigrateRefused(`${envPath} has no ENCRYPTION_KEY of 64 hex characters`);
  const values = Object.fromEntries(moving.map((k) => [k, parsed[k]]));
  try { validatedPlatformKeys(values, envPath); } catch (e) { throw new MigrateRefused(e.message); }
  for (const k of moving) {
    if (process.env[k] && process.env[k] !== parsed[k]) {
      throw new MigrateRefused(`${k} is set in this shell and differs from the one in .env. The server prefers the environment over .env. Unset it (and remove it from the service definition) first`);
    }
  }
  if (!dryRun && requireRoot && !isRoot()) throw new MigrateRefused('run as root (sudo crane secrets migrate --provider systemd-creds): systemd-creds needs the host key, and the credential store and drop-in belong to root');

  if (await serverAnswers(port)) throw new MigrateRefused(`something answers on port ${port}: AppCrane appears to be running. Stop it first (sudo systemctl stop ${paths.unit})`);
  const state = await unitState(paths.unit);
  if (state.active) throw new MigrateRefused(`${paths.unit}.service is active. Stop it first: sudo systemctl stop ${paths.unit}`);
  let version;
  try {
    const v = await runTool('systemd-creds', ['--version']);
    if (v.status !== 0) throw new Error(`exit ${v.status}`);
    version = v.stdout.toString('utf8').split('\n')[0].trim();
  } catch (e) {
    throw new MigrateRefused(`systemd-creds is not available (${e.code || e.message})`);
  }

  // What is there already: a drop-in of ours, credentials from an earlier run.
  let dropKeys = {};
  if (existsSync(paths.dropin)) {
    const d = parseDropin(readFileSync(paths.dropin, 'utf8'));
    if (d.foreign.length) throw new MigrateRefused(`${paths.dropin} holds lines this command did not write (${d.foreign[0]}); move them to another drop-in first`);
    dropKeys = d.keys;
  }
  const earlier = already ? (() => { try { return expectedKeys(parsed); } catch (e) { throw new MigrateRefused(e.message); } })() : [];
  const allKeys = ordered([...new Set([...earlier, ...Object.keys(dropKeys), ...moving])]);
  if (!allKeys.includes('ENCRYPTION_KEY') && !parsed.ENCRYPTION_KEY) throw new MigrateRefused(`${envPath} has no ENCRYPTION_KEY`);

  const file = (k) => join(paths.credstore, credentialName(k));
  const canDecrypt = isRoot() || !requireRoot;
  const credentials = [];
  for (const k of allKeys) {
    const exists = existsSync(file(k));
    const entry = { key: k, credential: credentialName(k), file: file(k), exists, action: null };
    if (!moving.includes(k)) {
      if (!exists) throw new MigrateRefused(`${paths.dropin} or APPCRANE_SECRETS_KEYS names ${credentialName(k)}, and ${file(k)} does not exist: the unit would not start. Put ${k} back in .env and run this again`);
      entry.action = 'keep';
    } else if (!exists) {
      entry.action = 'write';
    } else if (!canDecrypt) {
      entry.action = 'compare (needs root)';
    } else {
      let back;
      try { back = await decryptCredential(credentialName(k), file(k)); } catch (e) { throw new MigrateRefused(`${file(k)} exists and could not be decrypted: ${e.message}`); }
      if (back !== parsed[k]) throw new MigrateRefused(`${file(k)} already holds a different ${k}. Overwriting could lose the only copy of a key; nothing was changed`);
      entry.action = 'reuse (same value)';
    }
    credentials.push(entry);
  }

  const settings = {
    APPCRANE_SECRETS_PROVIDER: PROVIDER_SYSTEMD,
    APPCRANE_SECRETS_KEYS: allKeys.join(','),
    ...(paths.credstore !== DEFAULT_CREDSTORE ? { APPCRANE_SECRETS_CREDSTORE: paths.credstore } : {}),
    ...(paths.unit !== DEFAULT_UNIT ? { APPCRANE_SECRETS_UNIT: paths.unit } : {}),
    ...(paths.dropinDir !== `/etc/systemd/system/${paths.unit}.service.d` ? { APPCRANE_SECRETS_DROPIN_DIR: paths.dropinDir } : {}),
  };
  const newText = withKeys(withoutKeys(envText, moving), settings);
  const newDropin = dropinText(allKeys, paths.credstore);
  const summary = {
    provider: PROVIDER_SYSTEMD, systemd_creds: version, unit: paths.unit, moved: moving, keys: allKeys,
    credentials: credentials.map(({ key, credential, file: f, action }) => ({ key, credential, file: f, action })),
    dropin: paths.dropin, dropin_text: newDropin, env_settings: settings,
    left_in_env: ALLOWED_PLATFORM_KEYS.filter((k) => parsed[k] && !moving.includes(k)),
  };
  if (dryRun) {
    const backupFile = join(backupDir, 'env.pre-systemd-creds-<time>');
    return {
      dry_run: true, ...summary, root: isRoot(), backup: backupFile,
      rollback: rollbackSteps({ envPath, envStat, backupFile, dropin: paths.dropin, unit: paths.unit, credentialFiles: allKeys.map(file) }),
      copies: await oldKeyCopies(dataDir, listArchive ? { list: listArchive } : {}),
    };
  }

  const backupFile = writeBackup(backupDir, envText, now);
  onStep('backup');
  const rollback = rollbackSteps({ envPath, envStat, backupFile, dropin: paths.dropin, unit: paths.unit, credentialFiles: allKeys.map(file) });
  const fail = (e) => { e.backup = backupFile; e.rollback = rollback; return e; };

  try {
    if (!existsSync(paths.credstore)) {
      mkdirSync(paths.credstore, { recursive: true, mode: 0o700 });
      chmodSync(paths.credstore, 0o700);
    }
    for (const c of credentials.filter((x) => x.action === 'write')) {
      const tmp = join(paths.credstore, `.${c.credential}.tmp-${process.pid}`);
      rmSync(tmp, { force: true });
      try {
        await encryptCredential(c.credential, parsed[c.key], tmp);
        chmodSync(tmp, 0o600);
        const back = await decryptCredential(c.credential, tmp);
        if (back !== parsed[c.key]) throw new MigrateRefused(`${c.credential} did not decrypt back to the value in .env. .env was not changed`);
        renameSync(tmp, c.file);
      } finally {
        rmSync(tmp, { force: true });
      }
    }
    onStep('credentials-written');

    mkdirSync(paths.dropinDir, { recursive: true, mode: 0o755 });
    writeAtomic(paths.dropin, newDropin, 0o644);
    onStep('dropin-written');

    const reload = await systemctl(['daemon-reload']);
    if (reload.status !== 0) throw new Error(`systemctl daemon-reload failed (${reload.stderr.split('\n')[0] || `exit ${reload.status}`}). .env was not changed`);
    const seen = (await systemctl(['show', `${paths.unit}.service`, '-p', 'DropInPaths', '--value'])).stdout.toString('utf8').split(/\s+/);
    if (!seen.includes(paths.dropin)) throw new Error(`after daemon-reload systemd does not list ${paths.dropin} as a drop-in of ${paths.unit}.service. .env was not changed`);
    onStep('daemon-reloaded');

    // The boot this host will do next: every credential the drop-in names
    // decrypts to a value the policy accepts, and .env no longer competes.
    const booted = {};
    for (const k of allKeys) booted[k] = await decryptCredential(credentialName(k), file(k));
    validatedPlatformKeys(booted, 'systemd credentials');
    for (const k of moving) if (booted[k] !== parsed[k]) throw new MigrateRefused(`${credentialName(k)} does not hold the value in .env. .env was not changed`);
    const next = parseEnvText(newText);
    const clash = allKeys.filter((k) => next[k]);
    if (clash.length) throw new Error(`the new .env would still set ${clash.join(', ')}. .env was not changed`);

    const staged = stageEnv(envPath, newText, { like: envStat });
    try {
      staged.commit();
    } catch (e) {
      staged.discard();
      throw e;
    }
    onStep('env-committed');
  } catch (e) {
    throw fail(e);
  }

  return {
    dry_run: false, ...summary, backup: backupFile, rollback, boot_check_keys: allKeys,
    copies: await oldKeyCopies(dataDir, listArchive ? { list: listArchive } : {}),
  };
}
