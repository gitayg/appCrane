import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { execFile } from 'child_process';
import { getValue, putValue, createSecret, isNotFound } from './awsOps.js';
import { loadPlatformSecrets } from './index.js';
import { PLACEHOLDER_KEY, PLATFORM_SECRET_NAMES, parseSecretObject, validatedPlatformKeys, assertSecretSize } from './keyPolicy.js';
import { applyAwsSettings, parseEnvText, withKeys, withoutKeys } from './envText.js';
import { probeImds, IMDS_FIX } from './imdsProbe.js';
import { readEnvKey, stageEnv } from '../keyRotation/envFile.js';
import { openExclusive, serverAnswers } from '../keyRotation/preflight.js';

const SECRET_ID_RE = /^[A-Za-z0-9/_+=.@:-]{1,2048}$/;
const REGION_RE = /^[a-z0-9-]{1,32}$/;

export class MigrateRefused extends Error {}

function listTar(file) {
  return new Promise((res, rej) => {
    execFile('tar', ['-tzf', file], { timeout: 300_000, maxBuffer: 256 * 1024 * 1024 }, (err, stdout) => (err ? rej(err) : res(String(stdout).split('\n'))));
  });
}

const subdirs = (dir) => { try { return readdirSync(dir).filter((n) => statSync(join(dir, n)).isDirectory()); } catch { return []; } };
const filesIn = (dir) => { try { return readdirSync(dir).map((n) => join(dir, n)); } catch { return []; } };

/**
 * Files that still hold an ENCRYPTION_KEY after a migration, by name. Moving
 * the key out of .env does not reach these, so the old key stays exposed until
 * crane rotate-key makes it worthless.
 */
export async function oldKeyCopies(dataDir, { list = listTar } = {}) {
  const files = [];
  const candidates = [
    ...subdirs(join(dataDir, 'update-snapshots')).map((d) => join(dataDir, 'update-snapshots', d, 'env.backup')),
    ...subdirs(join(dataDir, 'backups')).filter((d) => d.startsWith('key-rotation-')).map((d) => join(dataDir, 'backups', d, 'env.backup')),
    ...subdirs(dataDir).filter((d) => d.startsWith('pre-import-')).map((d) => join(dataDir, d, '.env')),
  ];
  for (const f of candidates) {
    if (existsSync(f) && parseEnvText(readFileSync(f, 'utf8')).ENCRYPTION_KEY) files.push(f);
  }
  const archives = [];
  const uninspected = [];
  for (const f of [...filesIn(join(dataDir, 'backups')), ...filesIn(join(dataDir, 'backups', 'local'))]) {
    if (/\.zip$/.test(f)) { uninspected.push(f); continue; }
    if (!/\.tar\.gz$/.test(f)) continue;
    try {
      if ((await list(f)).some((m) => m === '.env' || m === './.env')) archives.push(f);
    } catch {
      uninspected.push(f);
    }
  }
  return { files, archives, uninspected };
}

async function readExisting(cfg, secretId) {
  try {
    const { text } = await getValue(cfg, secretId);
    const label = `secret ${secretId}`;
    const values = parseSecretObject(text, label);
    validatedPlatformKeys(values, label);
    const { [PLACEHOLDER_KEY]: placeholder, ...real } = values;
    return { exists: true, values: real, hadPlaceholder: placeholder !== undefined };
  } catch (e) {
    if (isNotFound(e)) return { exists: false, values: {}, hadPlaceholder: false };
    throw e;
  }
}

/**
 * crane secrets migrate. The order is what keeps a crash bootable: until the
 * rename of .env the host still boots from .env, and the secret is verified to
 * hold the same values before that rename happens. After it the host boots
 * from the secret. There is no step at which neither works.
 *
 * onStep(name) runs after each step: 'secret-written', 'read-back',
 * 'env-staged', 'env-committed'.
 */
export async function migrateToSecretsManager({
  secretId, region = null, envPath, dataDir, port = 5001, dryRun = false, acceptImdsExposure = false,
  probe = probeImds, onStep = () => {}, listArchive = listTar, readBackDelayMs = 1000,
}) {
  if (!secretId || !SECRET_ID_RE.test(secretId)) throw new MigrateRefused('--secret-id is not a valid secret name or ARN');
  if (region && !REGION_RE.test(region)) throw new MigrateRefused('--region is not a valid region name');
  if (!existsSync(envPath)) throw new MigrateRefused(`no .env at ${envPath}`);
  const envText = readFileSync(envPath, 'utf8');
  const parsed = parseEnvText(envText);

  const moving = PLATFORM_SECRET_NAMES.filter((k) => parsed[k]);
  if (parsed.APPCRANE_SECRETS_ID && parsed.APPCRANE_SECRETS_ID !== secretId) throw new MigrateRefused(`.env already points at another platform secret (${parsed.APPCRANE_SECRETS_ID})`);
  if (!moving.length) throw new MigrateRefused(`nothing to move: ${envPath} holds none of ${PLATFORM_SECRET_NAMES.join(', ')}`);
  if (parsed.ENCRYPTION_KEY && !readEnvKey(envText)) throw new MigrateRefused(`${envPath} has no ENCRYPTION_KEY of 64 hex characters`);
  if (!parsed.ENCRYPTION_KEY && !parsed.APPCRANE_SECRETS_ID) throw new MigrateRefused(`${envPath} has no ENCRYPTION_KEY`);
  for (const k of moving) {
    if (process.env[k] && process.env[k] !== parsed[k]) {
      throw new MigrateRefused(`${k} is set in this shell and differs from the one in .env. The server prefers the environment over .env. Unset it (and remove it from the service definition) first`);
    }
  }

  if (await serverAnswers(port)) throw new MigrateRefused(`something answers on port ${port}: AppCrane appears to be running. Stop it first`);
  const dbPath = join(dataDir, 'deployhub.db');
  let db = null;
  if (existsSync(dbPath)) {
    try {
      db = openExclusive(dbPath);
    } catch (e) {
      throw e.code === 'IN_USE' ? new MigrateRefused(e.message) : e;
    }
  }
  try {
    const imds = await probe();
    if (imds.status === 'exposed' && !acceptImdsExposure) {
      throw Object.assign(new MigrateRefused(`an app container can reach the instance metadata service (${imds.detail}), so it could get the instance role's credentials and read this secret. `
        + `Fix: ${IMDS_FIX}. Or pass --accept-imds-exposure to migrate anyway.`), { imds });
    }

    applyAwsSettings(envText);
    const cfg = { region: region || process.env.AWS_REGION || null };
    const existing = await readExisting(cfg, secretId);
    const different = moving.filter((k) => existing.values[k] && existing.values[k] !== parsed[k]);
    if (different.length) throw new MigrateRefused(`secret ${secretId} already holds a different ${different.join(', ')}. Overwriting could lose the only copy of a key; nothing was changed`);

    const merged = { ...existing.values, ...Object.fromEntries(moving.map((k) => [k, parsed[k]])) };
    const label = `secret ${secretId}`;
    validatedPlatformKeys(merged, label);
    const text = JSON.stringify(merged);
    assertSecretSize(text, label);
    // A re-run after a crash finds the values there already: no second version.
    const unchanged = existing.exists && !existing.hadPlaceholder && moving.every((k) => existing.values[k] === parsed[k]);

    const settings = { APPCRANE_SECRETS_PROVIDER: 'aws-secrets-manager', APPCRANE_SECRETS_ID: secretId, ...(region ? { APPCRANE_SECRETS_REGION: region } : {}) };
    const summary = { secret_id: secretId, region, moved: moving, secret_exists: existing.exists, imds };
    if (dryRun) return { dry_run: true, ...summary, would_write_secret: !unchanged, copies: await oldKeyCopies(dataDir, { list: listArchive }) };

    if (!unchanged) {
      const scrub = Object.values(merged);
      if (existing.exists) await putValue(cfg, secretId, text, { scrub });
      else await createSecret(cfg, secretId, text, { scrub });
    }
    onStep('secret-written');

    // A write may take a moment to be visible; a mismatch after that is a refusal.
    let back = null;
    for (let i = 0; i < 4; i++) {
      if (i) await new Promise((r) => setTimeout(r, readBackDelayMs));
      try {
        back = parseSecretObject((await getValue(cfg, secretId)).text, label);
      } catch (e) {
        if (i === 3) throw e;
        continue;
      }
      if (moving.every((k) => back[k] === merged[k])) break;
      back = null;
    }
    if (!back) throw new MigrateRefused(`secret ${secretId} did not read back with the values written. .env was not changed`);
    onStep('read-back');

    const newText = withKeys(withoutKeys(envText, moving), settings);
    const staged = stageEnv(envPath, newText);
    try {
      onStep('env-staged');
      staged.commit();
    } catch (e) {
      staged.discard();
      throw e;
    }
    onStep('env-committed');

    // The boot this host will do next, on a copy of the environment it will have.
    let booted;
    try {
      booted = await loadPlatformSecrets({ env: { ...parseEnvText(newText), ...(process.env.AWS_REGION ? { AWS_REGION: process.env.AWS_REGION } : {}) }, log: { warn() {} } });
    } catch (e) {
      throw new Error(`.env now points at ${secretId} and the secret read back correctly, but a trial boot failed: ${e.message}`);
    }
    return { dry_run: false, ...summary, secret_written: !unchanged, boot_check_keys: booted.keys, copies: await oldKeyCopies(dataDir, { list: listArchive }) };
  } finally {
    if (db) db.close();
  }
}
