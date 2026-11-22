import { parseEnvText, withKeys, withoutKeys } from './envText.js';
import { providerConfig, platformKeyLoaded } from './index.js';
import { ALLOWED_PLATFORM_KEYS } from './keyPolicy.js';

const SETTINGS = [
  'APPCRANE_SECRETS_PROVIDER', 'APPCRANE_SECRETS_ID', 'APPCRANE_SECRETS_REGION', 'APPCRANE_SECRETS_APP_PREFIX',
  'APPCRANE_SECRETS_KEYS', 'APPCRANE_SECRETS_CREDSTORE', 'APPCRANE_SECRETS_UNIT', 'APPCRANE_SECRETS_DROPIN_DIR',
];

/**
 * What to do with an archive's .env when restoring over this host:
 * { action: 'copy' }, { action: 'merge', text, dropped }, or
 * { action: 'refuse', message }.
 *
 * The one case that needs care is a host whose keys live in the platform
 * secret receiving an .env from before the migration. Copied as it is, the
 * provider settings go and keys return to a file. Merged carelessly, the next
 * boot sees two values for one key and refuses.
 */
export function planRestoredEnv(archiveText, { env = process.env, keyLoaded = platformKeyLoaded } = {}) {
  const cfg = providerConfig(env);
  const systemd = cfg?.provider === 'systemd-creds';
  if (!cfg || (!systemd && !cfg.secretId)) return { action: 'copy' };
  const archive = parseEnvText(archiveText);
  // An archive from a migrated host names its own secret; its database goes with that key.
  if (archive.APPCRANE_SECRETS_PROVIDER) return { action: 'copy' };
  const held = ALLOWED_PLATFORM_KEYS.filter((k) => keyLoaded(k));
  if (!held.length) return { action: 'copy' };
  if (held.includes('ENCRYPTION_KEY') && archive.ENCRYPTION_KEY && archive.ENCRYPTION_KEY !== env.ENCRYPTION_KEY) {
    return {
      action: 'refuse',
      message: systemd
        ? 'This backup carries a different ENCRYPTION_KEY from the one in this host\'s systemd credential, and its database decrypts only with its own. '
          + 'Restoring would leave two keys, and AppCrane refuses to boot with two. Nothing was changed. Seal the backup\'s key into the credential '
          + '(put it in .env and run sudo crane secrets migrate --provider systemd-creds after moving the old credential aside), or restore on a host without the secrets provider, then rotate.'
        : 'This backup carries a different ENCRYPTION_KEY from the one in Secrets Manager, and its database decrypts only with its own. '
          + 'Restoring would leave two keys, and AppCrane refuses to boot with two. Nothing was changed. Put the backup\'s key in the secret '
          + '(a new version), or restore on a host without the secrets provider, then rotate.',
    };
  }
  const dropped = held.filter((k) => archive[k]);
  const settings = Object.fromEntries(SETTINGS.filter((k) => env[k]).map((k) => [k, env[k]]));
  return { action: 'merge', text: withKeys(withoutKeys(archiveText, dropped), settings), dropped };
}
