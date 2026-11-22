// AWS SSM Parameter Store: GetParameter (WithDecryption) over the JSON 1.1 API,
// signed with SigV4 here. There is no @aws-sdk/client-ssm in the dependencies;
// the credentials come from the AWS SDK default chain (env, profile, instance
// role) through the Secrets Manager client that already is one.
import { createHash, createHmac } from 'node:crypto';
import { StoreError, requestJson } from '../http.js';

const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const hmac = (k, s) => createHmac('sha256', k).update(s, 'utf8').digest();

async function defaultCredentials(region) {
  const sdk = await import('@aws-sdk/client-secrets-manager');
  const client = new sdk.SecretsManagerClient(region ? { region } : {});
  try {
    const [creds, resolvedRegion] = await Promise.all([client.config.credentials(), client.config.region()]);
    return { creds, region: region || resolvedRegion };
  } catch (_) {
    throw new StoreError('no AWS credentials or region could be loaded from the default credential chain');
  } finally {
    client.destroy?.();
  }
}

/** Headers for a SigV4-signed POST of `body` to `url`. Exported for the test's cross-check. */
export function signRequest({ url, body, target, region, creds, now = new Date() }) {
  const u = new URL(url);
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const date = amzDate.slice(0, 8);
  const headers = {
    'content-type': 'application/x-amz-json-1.1',
    host: u.host,
    'x-amz-date': amzDate,
    'x-amz-target': target,
    ...(creds.sessionToken && { 'x-amz-security-token': creds.sessionToken }),
  };
  const names = Object.keys(headers).sort();
  const canonical = [
    'POST', u.pathname || '/', '',
    ...names.map((n) => `${n}:${String(headers[n]).trim()}`), '',
    names.join(';'), sha256(body),
  ].join('\n');
  const scope = `${date}/${region}/ssm/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonical)].join('\n');
  const key = hmac(hmac(hmac(hmac(`AWS4${creds.secretAccessKey}`, date), region), 'ssm'), 'aws4_request');
  const signature = createHmac('sha256', key).update(toSign, 'utf8').digest('hex');
  return {
    ...headers,
    authorization: `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}`,
  };
}

export async function read(conn, ref, { session }) {
  session.aws ??= await defaultCredentials(conn.settings.region || process.env.AWS_REGION || null);
  const { creds, region } = session.aws;
  if (!region) throw new StoreError('no AWS region is set for this connection');
  const url = conn.settings.endpoint || process.env.AWS_ENDPOINT_URL_SSM || `https://ssm.${region}.amazonaws.com/`;
  const body = JSON.stringify({ Name: ref.name, WithDecryption: true });
  const headers = signRequest({ url, body, target: 'AmazonSSM.GetParameter', region, creds });
  const { json } = await requestJson(url, { method: 'POST', headers, body }).catch((e) => {
    throw new StoreError(e.status === 400 ? 'parameter not found or not readable (HTTP 400)' : e.message, e.status);
  });
  const value = json?.Parameter?.Value;
  if (typeof value !== 'string') throw new StoreError('the parameter has no value');
  if (ref.key === null) return value;
  let parsed;
  try { parsed = JSON.parse(value); } catch (_) { throw new StoreError('the parameter is not JSON, so it has no key'); }
  if (!parsed || typeof parsed !== 'object' || !Object.prototype.hasOwnProperty.call(parsed, ref.key)) throw new StoreError(`key ${ref.key} not found`);
  return parsed[ref.key];
}
