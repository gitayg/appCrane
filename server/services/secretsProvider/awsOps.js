import { randomUUID } from 'crypto';

// The only file that loads the AWS SDK, and only when a call is made: an
// install without the feature never loads it.

const clients = new Map();

async function client(cfg) {
  const key = `${cfg.region || ''}|${process.env.AWS_ENDPOINT_URL_SECRETS_MANAGER || ''}`;
  if (clients.has(key)) return clients.get(key);
  const sdk = await import('@aws-sdk/client-secrets-manager');
  const entry = {
    sdk,
    sm: new sdk.SecretsManagerClient({
      ...(cfg.region ? { region: cfg.region } : {}),
      // Boot waits on this call: a black-holed network must end in a clear exit.
      // Without throwOnRequestTimeout, requestTimeout only logs a warning and waits forever (measured).
      requestHandler: { connectionTimeout: 5000, requestTimeout: 15000, throwOnRequestTimeout: true },
    }),
  };
  clients.set(key, entry);
  return entry;
}

/**
 * An SDK failure as an error that cannot carry a value: a new Error with no
 * cause, the SDK's name and first line, and `scrub` (the values just sent)
 * removed in case a service or proxy echoed them. A JSON parse failure quotes
 * its input, so its message is dropped.
 */
function safeError(op, target, e, scrub = []) {
  const name = e?.name || 'Error';
  let detail = name === 'SyntaxError' ? 'the response could not be parsed' : String(e?.message || '').split('\n')[0].slice(0, 300);
  for (const v of scrub) if (v) detail = detail.split(v).join('[redacted]');
  const err = new Error(`Secrets Manager ${op} on ${target} failed: ${name}: ${detail}`);
  err.code = name;
  return err;
}

async function send(cfg, commandName, input, op, target, scrub) {
  const { sdk, sm } = await client(cfg).catch((e) => { throw safeError(op, target, e, scrub); });
  try {
    return await sm.send(new sdk[commandName](input));
  } catch (e) {
    throw safeError(op, target, e, scrub);
  }
}

/** { text, versionId, stages } of one version (AWSCURRENT unless `stage`). Throws when it holds no string. */
export async function getValue(cfg, secretId, { stage = null } = {}) {
  const res = await send(cfg, 'GetSecretValueCommand', { SecretId: secretId, ...(stage ? { VersionStage: stage } : {}) }, 'GetSecretValue', secretId);
  if (typeof res.SecretString !== 'string') throw new Error(`Secrets Manager secret ${secretId} holds no string value`);
  return { text: res.SecretString, versionId: res.VersionId, stages: res.VersionStages || [] };
}

/** { [versionId]: [stages] } */
export async function describeVersions(cfg, secretId) {
  const res = await send(cfg, 'DescribeSecretCommand', { SecretId: secretId }, 'DescribeSecret', secretId);
  return res.VersionIdsToStages || {};
}

export const versionWithStage = (versions, stage) => Object.keys(versions).find((id) => versions[id].includes(stage)) || null;

/** New version. Without `stages` Secrets Manager moves AWSCURRENT to it. Returns its version id. */
export async function putValue(cfg, secretId, text, { stages = null, scrub = [] } = {}) {
  const res = await send(cfg, 'PutSecretValueCommand', {
    SecretId: secretId, SecretString: text, ClientRequestToken: randomUUID(), ...(stages ? { VersionStages: stages } : {}),
  }, 'PutSecretValue', secretId, [text, ...scrub]);
  return res.VersionId;
}

export async function createSecret(cfg, name, text, { scrub = [] } = {}) {
  const res = await send(cfg, 'CreateSecretCommand', {
    Name: name, SecretString: text, ClientRequestToken: randomUUID(), Description: 'Managed by AppCrane',
  }, 'CreateSecret', name, [text, ...scrub]);
  return res.VersionId;
}

export async function moveStage(cfg, secretId, stage, { to = null, from = null }) {
  await send(cfg, 'UpdateSecretVersionStageCommand', {
    SecretId: secretId, VersionStage: stage,
    ...(to ? { MoveToVersionId: to } : {}), ...(from ? { RemoveFromVersionId: from } : {}),
  }, 'UpdateSecretVersionStage', secretId);
}

export const isNotFound = (e) => e?.code === 'ResourceNotFoundException';
