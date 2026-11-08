// Which keys the platform secret may set on the server's environment.

const KEY_RE = /^[A-Z][A-Z0-9_]*$/;
const DENIED = [/^NODE_OPTIONS$/, /^PATH$/, /^LD_/, /^DYLD_/, /^DATA_DIR$/, /^APPCRANE_SECRETS_/];
const ENCRYPTION_KEY_RE = /^[0-9a-fA-F]{64}$/;

// The CloudFormation template creates the secret with this one generated key,
// so the template never holds a value. It is not configuration: never loaded.
export const PLACEHOLDER_KEY = 'PLACEHOLDER';

// What `crane secrets migrate` moves out of .env.
export const PLATFORM_SECRET_NAMES = ['ENCRYPTION_KEY', 'ANTHROPIC_API_KEY'];

export const MAX_SECRET_BYTES = 65536;

export function assertAllowedKey(name) {
  if (typeof name !== 'string' || !KEY_RE.test(name) || DENIED.some((re) => re.test(name))) {
    throw new Error(`the key name ${JSON.stringify(String(name).slice(0, 64))} is not allowed in the platform secret`);
  }
}

/** A secret string as a plain object. JSON.parse's own message quotes the input, so it never leaves here. */
export function parseSecretObject(text, label) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${label} is not a JSON object`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${label} is not a JSON object`);
  return parsed;
}

/** The keys to load from the platform secret. Throws naming keys, never values. */
export function validatedPlatformKeys(values, label) {
  const out = {};
  for (const [name, value] of Object.entries(values)) {
    if (name === PLACEHOLDER_KEY) continue;
    assertAllowedKey(name);
    if (typeof value !== 'string' || !value) throw new Error(`${label}: ${name} must be a non-empty string`);
    if (name === 'ENCRYPTION_KEY' && !ENCRYPTION_KEY_RE.test(value)) throw new Error(`${label}: ENCRYPTION_KEY must be 64 hex characters`);
    out[name] = value;
  }
  return out;
}

export function assertSecretSize(text, label) {
  if (Buffer.byteLength(text, 'utf8') > MAX_SECRET_BYTES) throw new Error(`${label} is larger than Secrets Manager's ${MAX_SECRET_BYTES} byte limit`);
}
