import { existsSync, readFileSync, writeFileSync, renameSync, statSync, realpathSync, unlinkSync } from 'fs';
import { randomBytes } from 'crypto';
import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import { platformKeyLoaded, providerConfig } from './secretsProvider/index.js';
import { PROVIDER_SYSTEMD } from './secretsProvider/systemdCreds.js';
import {
  ENV_NAME, getPlatformAnthropicKey, hasStoredPlatformAnthropicKey, setPlatformAnthropicKey, sealEnvironment,
} from './platformAnthropicKey.js';
import defaultLog from '../utils/logger.js';

/**
 * One-time move of ANTHROPIC_API_KEY from .env / the environment into the
 * database (platformAnthropicKey.js). Runs on every boot after initDb() and is
 * idempotent: with a key already stored it only drops the matching .env line
 * and the environment variable.
 *
 * A key loaded from the platform secret (AWS Secrets Manager) is copied, never
 * removed from the secret: the secret is shared with ENCRYPTION_KEY and is
 * edited with `crane secrets`, not from a boot path.
 */

// Same parse as the .env loader at the top of server/index.js.
function envLineKey(line) {
  const t = line.trim();
  if (!t || t.startsWith('#')) return null;
  const eq = t.indexOf('=');
  if (eq === -1) return null;
  return { key: t.slice(0, eq).trim(), value: t.slice(eq + 1).trim() };
}

/** Remove the ANTHROPIC_API_KEY lines whose value is `value`; every other byte is kept. Returns { removed, kept }. */
export function removeEnvFileKey(envPath, value) {
  if (!envPath || !existsSync(envPath)) return { removed: 0, kept: 0 };
  const target = realpathSync(envPath);
  const content = readFileSync(target, 'utf8');
  const lines = content.split('\n');
  let removed = 0;
  let kept = 0;
  const out = lines.filter((line) => {
    const p = envLineKey(line);
    if (!p || p.key !== ENV_NAME) return true;
    if (p.value === value) { removed++; return false; }
    kept++;
    return true;
  });
  if (!removed) return { removed, kept };
  const tmp = `${target}.${randomBytes(6).toString('hex')}.tmp`;
  try {
    writeFileSync(tmp, out.join('\n'), { mode: statSync(target).mode & 0o777, flag: 'wx' });
    renameSync(tmp, target);
  } catch (e) {
    try { unlinkSync(tmp); } catch (_) {}
    throw e;
  }
  return { removed, kept };
}

export function migratePlatformAnthropicKey({
  envPath,
  db = getDb(),
  env = process.env,
  fromProvider = platformKeyLoaded(ENV_NAME),
  log = defaultLog,
} = {}) {
  const value = (env[ENV_NAME] || '').trim();
  const result = { migrated: false, envLinesRemoved: 0, fromProvider: !!(value && fromProvider) };
  let unsaved = null;
  try {
    if (value && !hasStoredPlatformAnthropicKey(db)) {
      setPlatformAnthropicKey(value, null, db);
      result.migrated = true;
      const from = fromProvider ? 'secrets-manager' : 'env';
      log.info(`Platform Anthropic key moved from ${from === 'env' ? '.env / the environment' : 'the platform secret'} into the database (encrypted)`);
      try {
        logAudit(null, null, 'platform.anthropic-key-migrated', { from, suffix: value.slice(-4) });
      } catch (e) {
        log.warn(`Platform Anthropic key migration not audited: ${e.message}`);
      }
    }
    const storedKey = getPlatformAnthropicKey(db);
    if (value && storedKey && value !== storedKey) {
      log.warn(`${ENV_NAME} in .env or the environment differs from the key stored in the database and is ignored; set the key in Settings`);
    }
    if (storedKey) {
      const { removed, kept } = removeEnvFileKey(envPath, storedKey);
      result.envLinesRemoved = removed;
      if (removed) log.info(`${ENV_NAME} line removed from .env`);
      if (kept) log.warn(`.env still has ${kept} ${ENV_NAME} line(s) that differ from the stored key; they are ignored`);
    }
    if (value && fromProvider) {
      log.info(providerConfig(env)?.provider === PROVIDER_SYSTEMD
        ? `${ENV_NAME} is also a systemd encrypted credential; AppCrane no longer reads it there, so its file in the credential store and its LoadCredentialEncrypted line can be removed`
        : `${ENV_NAME} is also in the platform secret in AWS Secrets Manager; AppCrane no longer reads it there, so it can be removed from that secret`);
    }
  } catch (e) {
    // The key stays usable for this process (in memory only) and the boot goes
    // on; the next boot tries again.
    log.error(`Platform Anthropic key not moved into the database: ${e.message}`);
    unsaved = value || null;
  } finally {
    sealEnvironment({ keepInMemory: unsaved });
  }
  return result;
}
