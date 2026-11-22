// App env vars that point at AWS Secrets Manager instead of holding a value.
//
// env_vars keeps the reference text, encrypted like any value, so key rotation,
// backups and config export see an ordinary encrypted cell. The value exists only
// in the environment of the container started from it.
//
// A reference is a NAME and nothing else. The path is always built here from the
// app's own secrets_namespace and env (secretsProvider.appSecretName), so no ARN,
// slash or `..` can point at another app or at the platform secret, which holds
// ENCRYPTION_KEY. The namespace is random and stays with the app row (migration
// 167): the secrets outlive the app in AWS, and a slug or id can come back. Errors carry key names and a fixed reason, never a provider
// error's text: a JSON parse failure quotes the bytes it choked on.
import { getDb } from '../db.js';
import { decrypt } from './encryption.js';
import { appSecretName, appSecretRoot, getAppSecret, providerConfig, putAppSecret } from './secretsProvider/index.js';
import { MALFORMED_EXTERNAL, PROVIDERS, externalSource, isExternalRef, parseExternalRef, providerOfRef } from './externalSecrets/refs.js';
import { checkExternalRef, resolveExternalRef } from './externalSecrets/resolve.js';
import { logAudit } from '../middleware/audit.js';

export const REF_PREFIX = 'secretsmanager:';
export const REF_SOURCE = 'secrets_manager';

const NAME_RE = /^[A-Za-z0-9_-]{1,256}$/;
const FIELD_RE = /^[A-Za-z0-9_.-]{1,256}$/;
const UNSAFE_FIELDS = new Set(['__proto__', 'prototype', 'constructor']);
const ENVS = ['production', 'sandbox'];
// PutSecretValue: SecretString max 65536 bytes.
const MAX_SECRET_BYTES = 65536;

export class SecretRefError extends Error {
  constructor(message, { code = 'SECRET_REF', keys = [] } = {}) {
    super(message);
    this.name = 'SecretRefError';
    this.code = code;
    this.keys = keys;
  }
}

/**
 * True when a decrypted env var value is a reference: secretsmanager:<NAME>[#field].
 * True for a malformed one as well, so that it is refused and never injected as
 * text. Only the start of the value counts.
 */
export function isSecretRef(plain) {
  return typeof plain === 'string' && (plain.startsWith(REF_PREFIX) || isExternalRef(plain));
}

/** The `source` an API reports for a reference: secrets_manager, or the outside store's (vault, infisical, onepassword, aws_ssm). */
export function refSource(plain) {
  return isExternalRef(plain) ? externalSource(plain) : REF_SOURCE;
}

function refLabel(plain) {
  return isExternalRef(plain) ? (PROVIDERS[providerOfRef(plain)]?.label ?? 'an outside secret store') : 'AWS Secrets Manager';
}

/** { name, field } or null. Refuses ARNs, slashes and anything that could leave the app's own path. */
export function parseSecretRef(plain) {
  if (typeof plain !== 'string' || !plain.startsWith(REF_PREFIX)) return null;
  const rest = plain.slice(REF_PREFIX.length);
  const hash = rest.indexOf('#');
  const name = hash < 0 ? rest : rest.slice(0, hash);
  const field = hash < 0 ? null : rest.slice(hash + 1);
  if (!NAME_RE.test(name)) return null;
  if (field !== null && (!FIELD_RE.test(field) || UNSAFE_FIELDS.has(field))) return null;
  return { name, field };
}

export function formatSecretRef(name, field = null) {
  const text = `${REF_PREFIX}${name}${field === null || field === undefined ? '' : `#${field}`}`;
  if (!parseSecretRef(text)) throw new SecretRefError('Invalid secret reference name or field', { code: 'SECRET_REF_MALFORMED' });
  return text;
}

const MALFORMED = 'malformed reference: use secretsmanager:<NAME> or secretsmanager:<NAME>#<field>, where NAME holds only letters, digits, _ and - (no ARN, no path)';

// App secret references live in AWS only: systemd-creds holds platform keys.
const AWS_PROVIDER = 'aws-secrets-manager';
const awsOnly = (cfg) => cfg?.provider === AWS_PROVIDER;
const SYSTEMD_ONLY = 'this AppCrane keeps its keys in systemd-creds, which holds no app secrets; secretsmanager: references need APPCRANE_SECRETS_PROVIDER=aws-secrets-manager';

// The provider puts the SDK's error name in .code.
function fetchFailure(e, namespace, env, name) {
  const kind = e?.code || e?.name;
  if (kind === 'ResourceNotFoundException') return notFoundAt(namespace, env, name);
  if (kind === 'AccessDeniedException') return 'access denied by AWS';
  if (kind === 'APP_SECRETS_UNSUPPORTED') return SYSTEMD_ONLY;
  return 'could not be read from Secrets Manager';
}

function writeFailure(e) {
  if ((e?.code || e?.name) === 'AccessDeniedException') return 'access denied by AWS';
  if ((e?.code || e?.name) === 'APP_SECRETS_UNSUPPORTED') return SYSTEMD_ONLY;
  return 'could not be written to Secrets Manager';
}

function providerActive() {
  return awsOnly(providerConfig());
}

// The app's own namespace, from the row when the caller holds a partial one. No
// fallback to anything else: without it a reference reaches nothing.
function appNamespace(app) {
  const namespace = app?.secrets_namespace
    ?? (app?.id == null ? null : getDb().prepare('SELECT secrets_namespace FROM apps WHERE id = ?').get(app.id)?.secrets_namespace);
  if (!namespace) throw new SecretRefError('This app has no secrets namespace', { code: 'SECRET_REF_NO_NAMESPACE' });
  return namespace;
}

// Where a missing secret is expected: the only place a caller learns the path.
function notFoundAt(namespace, env, name) {
  try { return `secret not found at ${appSecretName(namespace, env, name)}`; } catch (_) { return 'secret not found'; }
}

/** rows: [{ key, plain }]. Returns { KEY: value } with references resolved for this app+env. Throws SecretRefError naming the keys (never values) when any fails. */
export async function resolveEnvValues(app, env, rows, { getSecret } = {}) {
  const refs = rows.filter((r) => isSecretRef(r.plain) && !isExternalRef(r.plain));
  const noProvider = refs.length > 0 && !getSecret && !providerActive();
  const read = getSecret || getAppSecret;
  const entries = [];
  const failures = [];
  const external = [];
  const sessions = new Map();
  for (const { key, plain } of rows) {
    if (!isSecretRef(plain)) { entries.push([key, plain]); continue; }
    if (isExternalRef(plain)) {
      try {
        const got = await resolveExternalRef(app, plain, sessions);
        entries.push([key, got.value]);
        external.push({ key, reference: plain, provider: got.provider, connection: got.connection, ok: true });
      } catch (e) {
        failures.push([key, `${plain}: ${e.message}`]);
        external.push({ key, reference: plain, provider: providerOfRef(plain), ...(e.connection && { connection: e.connection }), ok: false });
      }
      continue;
    }
    const ref = parseSecretRef(plain);
    if (!ref) { failures.push([key, MALFORMED]); continue; }
    if (noProvider) { failures.push([key, 'no secrets provider is configured on this AppCrane (APPCRANE_SECRETS_PROVIDER)']); continue; }
    if (!ENVS.includes(env)) { failures.push([key, 'invalid environment']); continue; }
    let namespace;
    try { namespace = appNamespace(app); } catch (e) { failures.push([key, e.message]); continue; }
    try {
      const value = await read(namespace, env, ref.name, ref.field);
      if (typeof value !== 'string') { failures.push([key, 'the secret has no text value']); continue; }
      entries.push([key, value]);
    } catch (e) {
      failures.push([key, fetchFailure(e, namespace, env, ref.name)]);
    }
  }
  if (external.length && app?.id) {
    try { logAudit(null, app.id, 'secret-ref-resolve', { env, refs: external }); } catch (_) { /* auditing must not decide a deploy */ }
  }
  if (failures.length) {
    const detail = failures.map(([k, why]) => `${k} (${why})`).join('; ');
    throw new SecretRefError(`Could not resolve secret reference(s) for ${app.slug}/${env}: ${detail}`, {
      code: 'SECRET_REF_UNRESOLVED', keys: failures.map(([k]) => k),
    });
  }
  return Object.fromEntries(entries);
}

/**
 * env_vars rows ({ key, value_encrypted }) to what a container gets. A value that
 * fails to decrypt is omitted and reported, as it always was; an unresolved
 * reference throws, because a container started without it is a wrong container.
 */
export async function resolveStoredEnv(app, env, rows, opts = {}) {
  const plain = [];
  const decryptFailures = [];
  for (const r of rows) {
    try { plain.push({ key: r.key, plain: decrypt(r.value_encrypted) }); }
    catch (_) { decryptFailures.push(r.key); }
  }
  const values = await resolveEnvValues(app, env, plain, opts);
  const refRows = plain.filter((r) => isSecretRef(r.plain));
  return {
    values, decryptFailures, refKeys: refRows.map((r) => r.key),
    refSources: Object.fromEntries(refRows.map((r) => [r.key, refLabel(r.plain)])),
  };
}

/** Refuses a value that starts with the prefix and cannot work. Any other value passes untouched. */
export function assertStorableValue(plain, { config = providerConfig, app = null } = {}) {
  if (!isSecretRef(plain)) return;
  if (isExternalRef(plain)) {
    if (!parseExternalRef(plain)) throw new SecretRefError(MALFORMED_EXTERNAL, { code: 'SECRET_REF_MALFORMED' });
    if (!app) throw new SecretRefError('An outside secret store reference needs the app it belongs to', { code: 'SECRET_REF_MALFORMED' });
    try { checkExternalRef(app, plain); } catch (e) { throw new SecretRefError(e.message, { code: e.code === 'SECRET_REF_MALFORMED' ? e.code : 'SECRET_REF_UNUSABLE' }); }
    return;
  }
  if (!parseSecretRef(plain)) throw new SecretRefError(MALFORMED, { code: 'SECRET_REF_MALFORMED' });
  const cfg = config();
  if (cfg === null) {
    throw new SecretRefError('This value is a Secrets Manager reference, and no secrets provider is configured on this AppCrane (APPCRANE_SECRETS_PROVIDER).', { code: 'SECRETS_PROVIDER_NOT_CONFIGURED' });
  }
  if (!awsOnly(cfg)) throw new SecretRefError(`This value is a Secrets Manager reference, and ${SYSTEMD_ONLY}.`, { code: 'SECRETS_PROVIDER_NOT_CONFIGURED' });
}

/** Everything that can refuse a store request without calling AWS. `vars`: { KEY: value }. */
export function assertStoreRequest(env, vars, { config = providerConfig } = {}) {
  if (!ENVS.includes(env)) throw new SecretRefError('env must be production or sandbox', { code: 'VALIDATION' });
  const cfg = config();
  if (cfg === null) {
    throw new SecretRefError('store "secrets_manager" needs a secrets provider, and none is configured on this AppCrane (APPCRANE_SECRETS_PROVIDER).', { code: 'SECRETS_PROVIDER_NOT_CONFIGURED' });
  }
  if (!awsOnly(cfg)) throw new SecretRefError(`store "secrets_manager": ${SYSTEMD_ONLY}.`, { code: 'SECRETS_PROVIDER_NOT_CONFIGURED' });
  for (const [key, value] of Object.entries(vars)) {
    const text = String(value);
    if (text.length === 0) throw new SecretRefError(`${key}: Secrets Manager cannot store an empty value`, { code: 'VALIDATION', keys: [key] });
    if (Buffer.byteLength(text, 'utf8') > MAX_SECRET_BYTES) throw new SecretRefError(`${key}: larger than the ${MAX_SECRET_BYTES} bytes Secrets Manager stores`, { code: 'VALIDATION', keys: [key] });
    if (isSecretRef(text)) throw new SecretRefError(`${key}: the value is already a reference; set it without store "secrets_manager"`, { code: 'VALIDATION', keys: [key] });
  }
}

/**
 * Writes each value to this app+env's path. Returns what landed plus the first
 * failure, so the caller records the references for the secrets that do exist.
 * Stops at the first failure. Call assertStoreRequest first.
 */
export async function storeAppSecrets(app, env, vars, { putSecret = putAppSecret } = {}) {
  const stored = [];
  for (const [key, value] of Object.entries(vars)) {
    try {
      const { name } = await putSecret(appNamespace(app), env, key, String(value));
      stored.push({ key, reference: formatSecretRef(key), name });
    } catch (e) {
      return { stored, failed: { key, reason: writeFailure(e) } };
    }
  }
  return { stored, failed: null };
}

/** The AWS secret a stored reference points at, or null. For telling a caller what stays behind on a delete. */
export function retainedSecretName(app, env, plain) {
  const ref = parseSecretRef(plain);
  if (!ref) return null;
  try { return appSecretName(appNamespace(app), env, ref.name); } catch (_) { return null; }
}

/**
 * What stays in AWS when an app goes, or null when there is nothing to say.
 * `rows`: its env_vars ({ env, value_encrypted }). The prefix is reported whenever
 * a provider is on, because a secret whose env var was removed earlier has no row
 * here, and once the app's row is gone nothing in AppCrane can name its namespace.
 */
export function retainedAppSecrets(app, rows) {
  const names = [];
  let undecryptable = 0;
  for (const r of rows) {
    let plain;
    try { plain = decrypt(r.value_encrypted); } catch (_) { undecryptable++; continue; }
    const name = isSecretRef(plain) ? retainedSecretName(app, r.env, plain) : null;
    if (name) names.push(name);
  }
  let active = false;
  try { active = providerActive(); } catch (_) { /* a bad setting must not stop a delete */ }
  if (!active && !names.length) return null;
  try {
    return { path_prefix: `${appSecretRoot(appNamespace(app))}/`, referenced: [...new Set(names)].sort(), undecryptable_env_vars: undecryptable };
  } catch (_) {
    return null;
  }
}
