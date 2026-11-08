import { existsSync, readFileSync } from 'fs';
import { providerConfig, platformVersions, readPlatformSecret } from './index.js';
import { PLACEHOLDER_KEY, PLATFORM_SECRET_NAMES } from './keyPolicy.js';
import { applyProviderSettings, parseEnvText } from './envText.js';
import { probeImds } from './imdsProbe.js';

/** crane secrets status. Key names only, never a value. */
export async function secretsStatus({ envPath, probe = probeImds }) {
  const text = existsSync(envPath) ? readFileSync(envPath, 'utf8') : '';
  applyProviderSettings(text);
  const parsed = parseEnvText(text);
  const cfg = providerConfig();
  const out = {
    provider: cfg?.provider ?? null,
    secret_id: cfg?.secretId ?? null,
    region: cfg?.region ?? null,
    current_readable: null,
    read_error: null,
    keys: [],
    pending_version: null,
  };
  if (cfg?.secretId) {
    try {
      const values = await readPlatformSecret();
      out.current_readable = true;
      out.keys = Object.keys(values).filter((k) => k !== PLACEHOLDER_KEY).sort();
      out.pending_version = (await platformVersions()).pending;
    } catch (e) {
      out.current_readable = false;
      out.read_error = e.message;
    }
  }
  out.still_in_env_file = [...new Set([...PLATFORM_SECRET_NAMES, ...out.keys])].filter((k) => parsed[k]);
  out.imds = await probe();
  return out;
}
