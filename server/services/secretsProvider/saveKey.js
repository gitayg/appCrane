import { existsSync, readFileSync } from 'fs';
import { setPlatformSecretKey } from './index.js';
import { parseEnvText, withoutKeys } from './envText.js';
import { stageEnv } from '../keyRotation/envFile.js';

/**
 * Store one platform key in the secret. A leftover .env line of that name goes
 * with it, because the old value next to the new one would refuse the next
 * boot. The new .env is written first and renamed after the secret took the
 * value, so a failed write changes neither.
 */
export async function saveKeyToProvider(name, value, { envPath }) {
  let staged = null;
  if (existsSync(envPath)) {
    const text = readFileSync(envPath, 'utf8');
    if (Object.prototype.hasOwnProperty.call(parseEnvText(text), name)) staged = stageEnv(envPath, withoutKeys(text, [name]));
  }
  try {
    await setPlatformSecretKey(name, value);
  } catch (e) {
    if (staged) staged.discard();
    throw e;
  }
  if (staged) staged.commit();
}
