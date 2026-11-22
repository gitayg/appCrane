import { getValue, describeVersions, versionWithStage, putValue, createSecret, moveStage, isNotFound } from './awsOps.js';
import { assertAllowedKey, assertSecretSize, parseSecretObject, validatedPlatformKeys, MAX_SECRET_BYTES } from './keyPolicy.js';
import { PROVIDER_SYSTEMD, systemdCredentialValues, systemdPaths, credentialName } from './systemdCreds.js';

const PROVIDER = 'aws-secrets-manager';
const DEFAULT_APP_PREFIX = 'appcrane/apps';
const NAMESPACE_RE = /^[a-f0-9]{32}$/;
const ENVS = ['sandbox', 'production'];
const SECRET_NAME_RE = /^[A-Za-z0-9_-]{1,256}$/;
const PREFIX_RE = /^[A-Za-z0-9_+=.@-]+(\/[A-Za-z0-9_+=.@-]+)*$/;

// What this process loaded at boot: key names and the version, never a value.
let loaded = null;

/**
 * null when no provider is configured; else { provider, secretId, region }:
 * 'aws-secrets-manager' with its secret and region, or 'systemd-creds' with
 * both null (it has no platform secret in AWS and no app secrets).
 */
export function providerConfig(env = process.env) {
  const provider = env.APPCRANE_SECRETS_PROVIDER;
  if (!provider) return null;
  if (provider === PROVIDER_SYSTEMD) return { provider, secretId: null, region: null };
  if (provider !== PROVIDER) throw new Error(`APPCRANE_SECRETS_PROVIDER=${provider} is not supported (expected ${PROVIDER} or ${PROVIDER_SYSTEMD})`);
  return { provider, secretId: env.APPCRANE_SECRETS_ID || null, region: env.APPCRANE_SECRETS_REGION || env.AWS_REGION || null };
}

/** True when secretsmanager:<NAME> app references can work here: AWS Secrets Manager only. */
export function appSecretsAvailable(env = process.env) {
  return providerConfig(env)?.provider === PROVIDER;
}

function requirePlatform(env = process.env) {
  const cfg = providerConfig(env);
  if (!cfg) throw new Error('no secrets provider is configured (APPCRANE_SECRETS_PROVIDER)');
  if (!cfg.secretId) throw new Error('no platform secret is configured (APPCRANE_SECRETS_ID)');
  return cfg;
}

/**
 * Loads the platform keys and sets them on `env`: the AWS platform secret, or
 * the systemd credentials in $CREDENTIALS_DIRECTORY. No provider: no-op,
 * returns { active: false }. Throws on any failure: never fall back to .env.
 */
export async function loadPlatformSecrets({ env = process.env, log = console } = {}) {
  const cfg = providerConfig(env);
  if (cfg?.provider === PROVIDER_SYSTEMD) {
    const label = 'systemd credentials';
    return applyPlatformKeys(validatedPlatformKeys(systemdCredentialValues(env), label), { env, log, label, cfg, versionId: null });
  }
  if (!cfg?.secretId) return { active: false };
  const label = `platform secret ${cfg.secretId}`;
  const { text, versionId } = await getValue(cfg, cfg.secretId);
  return applyPlatformKeys(validatedPlatformKeys(parseSecretObject(text, label), label), { env, log, label, cfg, versionId });
}

function applyPlatformKeys(values, { env, log, label, cfg, versionId }) {
  const names = Object.keys(values);
  const conflicts = names.filter((k) => env[k] && env[k] !== values[k]);
  if (conflicts.length) {
    throw new Error(`${conflicts.join(', ')} differ between ${label} and .env (or the environment). `
      + 'Two keys is how data gets encrypted under the wrong one: remove the .env line that is not the real one.');
  }
  if (!values.ENCRYPTION_KEY && !env.ENCRYPTION_KEY) {
    if (cfg.provider === PROVIDER_SYSTEMD) throw new Error(`the ${label} hold no ENCRYPTION_KEY and .env has none either. Run sudo crane secrets migrate --provider systemd-creds.`);
    throw new Error(`${label} has no ENCRYPTION_KEY and .env has none either. Run crane secrets migrate, or add the key to the secret.`);
  }
  const duplicates = names.filter((k) => env[k]);
  for (const k of names) env[k] = values[k];
  if (duplicates.length) log.warn(`${duplicates.join(', ')} also set in .env or the environment with the same value as ${label}: remove the .env line`);
  loaded = { provider: cfg.provider, secretId: cfg.secretId, versionId, keys: new Set(names) };
  return { active: true, provider: cfg.provider, secretId: cfg.secretId, keys: names, versionId, duplicates };
}

/** True when this process loaded `name` from the platform secret (or wrote it there). */
export function platformKeyLoaded(name) {
  return !!loaded?.keys.has(name);
}

/** The platform secret's JSON as an object (AWSCURRENT, or `stage`). */
export async function readPlatformSecret({ stage = null } = {}) {
  const cfg = requirePlatform();
  const { text } = await getValue(cfg, cfg.secretId, { stage });
  return parseSecretObject(text, `platform secret ${cfg.secretId}`);
}

function platformText(values, label) {
  validatedPlatformKeys(values, label);
  const text = JSON.stringify(values);
  assertSecretSize(text, label);
  return text;
}

/** New version holding `values`, labelled AWSPENDING only. Returns { versionId }. */
export async function stagePlatformSecret(values) {
  const cfg = requirePlatform();
  const text = platformText(values, `platform secret ${cfg.secretId}`);
  return { versionId: await putValue(cfg, cfg.secretId, text, { stages: ['AWSPENDING'], scrub: Object.values(values) }) };
}

/** Moves AWSCURRENT to versionId; AWSPREVIOUS follows the old version. */
export async function promotePlatformSecret(versionId) {
  const cfg = requirePlatform();
  const versions = await describeVersions(cfg, cfg.secretId);
  const current = versionWithStage(versions, 'AWSCURRENT');
  if (current !== versionId) await moveStage(cfg, cfg.secretId, 'AWSCURRENT', { to: versionId, from: current });
  await discardPlatformStage(versionId);
  if (loaded) loaded.versionId = versionId;
}

/** Best effort: AWSPENDING no longer labels versionId. A leftover label changes nothing that is read. */
export async function discardPlatformStage(versionId) {
  const cfg = requirePlatform();
  try { await moveStage(cfg, cfg.secretId, 'AWSPENDING', { from: versionId }); } catch { /* see above */ }
}

/** { current, pending } version ids of the platform secret. */
export async function platformVersions() {
  const cfg = requirePlatform();
  const versions = await describeVersions(cfg, cfg.secretId);
  return { current: versionWithStage(versions, 'AWSCURRENT'), pending: versionWithStage(versions, 'AWSPENDING') };
}

/** Read-merge-write of one key in the platform secret; used by the Anthropic key setting. */
export async function setPlatformSecretKey(name, value) {
  assertAllowedKey(name);
  if (providerConfig()?.provider === PROVIDER_SYSTEMD) {
    throw new Error(`${name} is a systemd credential, which only root can write and AppCrane does not run as root. Change it on the host: sudo crane secrets migrate --provider systemd-creds with the new value in .env`);
  }
  const cfg = requirePlatform();
  const label = `platform secret ${cfg.secretId}`;
  const { text } = await getValue(cfg, cfg.secretId);
  const merged = { ...parseSecretObject(text, label), [name]: value };
  const versionId = await putValue(cfg, cfg.secretId, platformText(merged, label), { scrub: [value] });
  if (loaded) { loaded.keys.add(name); loaded.versionId = versionId; } else loaded = { secretId: cfg.secretId, versionId, keys: new Set([name]) };
}

/**
 * What a backup or snapshot records about keys it does not hold, or null with
 * no provider. The version is what this process loaded: rotate-key needs
 * AppCrane stopped, so it cannot change under a running server.
 */
export function backupSecretsNote(env = process.env) {
  const cfg = providerConfig(env);
  if (!cfg) return null;
  const keys = loaded ? [...loaded.keys].sort() : [];
  const held = keys.includes('ENCRYPTION_KEY');
  if (cfg.provider === PROVIDER_SYSTEMD) {
    const paths = systemdPaths(env);
    return {
      provider: cfg.provider,
      secret_id: null,
      region: null,
      version_id: null,
      credentials: keys.map((k) => `${paths.credstore}/${credentialName(k)}`),
      keys_in_provider: keys,
      encryption_key_in_provider: held,
      restorable_from_this_copy_alone: !held,
      note: held
        ? `ENCRYPTION_KEY lives in a systemd encrypted credential (${paths.credstore}/${credentialName('ENCRYPTION_KEY')}), sealed with this host's /var/lib/systemd/credential.secret, not in this copy. `
          + 'This copy alone cannot restore the encrypted values: on this host root can decrypt the credential; on any other host only an offline copy of the key works.'
        : 'A secrets provider is configured; ENCRYPTION_KEY is not in it.',
    };
  }
  return {
    provider: cfg.provider,
    secret_id: cfg.secretId,
    region: cfg.region,
    version_id: loaded?.versionId ?? null,
    keys_in_provider: keys,
    encryption_key_in_provider: held,
    restorable_from_this_copy_alone: !held,
    note: held
      ? 'ENCRYPTION_KEY lives in AWS Secrets Manager, not in this copy. This copy alone cannot restore the encrypted values: the host needs read access to the secret, at the version above if the key has been rotated since.'
      : 'A secrets provider is configured; ENCRYPTION_KEY is not in it.',
  };
}

/** The app prefix as paths are really built, trailing slashes and safety check included. Throws on an unsafe one. */
export function appSecretPrefix() {
  const prefix = (process.env.APPCRANE_SECRETS_APP_PREFIX || DEFAULT_APP_PREFIX).replace(/\/+$/, '');
  if (!PREFIX_RE.test(prefix) || prefix.split('/').some((part) => part === '.' || part === '..')) throw new Error('APPCRANE_SECRETS_APP_PREFIX is not a safe path');
  return prefix;
}

/** Where everything of one app lives: appcrane/apps/<namespace>, or under APPCRANE_SECRETS_APP_PREFIX. Throws on an unsafe part. */
export function appSecretRoot(namespace) {
  if (typeof namespace !== 'string' || !NAMESPACE_RE.test(namespace)) throw new Error('invalid app secrets namespace for a secret name');
  return `${appSecretPrefix()}/${namespace}`;
}

/**
 * <root>/<env>/<name>, where namespace is apps.secrets_namespace (migration 167):
 * not the slug, which the next app can hold, and not the id, which a restore
 * hands out again. Throws on an unsafe part.
 */
export function appSecretName(namespace, env, name) {
  const root = appSecretRoot(namespace);
  if (!ENVS.includes(env)) throw new Error('invalid environment for a secret name');
  if (typeof name !== 'string' || !SECRET_NAME_RE.test(name)) throw new Error('invalid secret name: letters, digits, _ and - only');
  return `${root}/${env}/${name}`;
}

function appSecretTarget(namespace, env, name) {
  const cfg = providerConfig();
  if (!cfg) throw new Error('no secrets provider is configured (APPCRANE_SECRETS_PROVIDER)');
  if (cfg.provider !== PROVIDER) {
    throw Object.assign(new Error(`app secret references (secretsmanager:<NAME>) need APPCRANE_SECRETS_PROVIDER=${PROVIDER}; this AppCrane uses ${cfg.provider}, which holds only AppCrane's own keys`), { code: 'APP_SECRETS_UNSUPPORTED' });
  }
  const id = appSecretName(namespace, env, name);
  // A prefix configured over the platform secret must not hand it to an app.
  if (cfg.secretId && (cfg.secretId === id || cfg.secretId.includes(`:secret:${id}`))) throw new Error(`the app secret path ${id} is the platform secret`);
  return { cfg, id };
}

/** Plaintext of the app secret, or one `field` of its JSON. Throws when missing. */
export async function getAppSecret(namespace, env, name, field = null) {
  const { cfg, id } = appSecretTarget(namespace, env, name);
  const { text } = await getValue(cfg, id);
  if (field == null) return text;
  const obj = parseSecretObject(text, `secret ${id}`);
  if (!Object.prototype.hasOwnProperty.call(obj, field)) throw new Error(`secret ${id} has no field ${field}`);
  const v = obj[field];
  return typeof v === 'string' ? v : JSON.stringify(v);
}

/** Creates or updates the app secret. Returns { name } and never the value. */
export async function putAppSecret(namespace, env, name, value) {
  const { cfg, id } = appSecretTarget(namespace, env, name);
  if (typeof value !== 'string' || !value) throw new Error('a secret value must be a non-empty string');
  if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES) throw new Error(`the value is larger than Secrets Manager's ${MAX_SECRET_BYTES} byte limit`);
  try {
    await putValue(cfg, id, value);
  } catch (e) {
    if (!isNotFound(e)) throw e;
    await createSecret(cfg, id, value);
  }
  return { name: id };
}

export { isNotFound };
