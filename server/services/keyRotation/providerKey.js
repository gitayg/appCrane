import { writeFileSync } from 'fs';
import { join } from 'path';
import { providerConfig, readPlatformSecret, stagePlatformSecret, promotePlatformSecret, discardPlatformStage, platformVersions } from '../secretsProvider/index.js';
import { applyProviderSettings } from '../secretsProvider/envText.js';
import { rotateDatabase, selfCheck } from './rotate.js';
import { systemdKeyHeld } from './systemdKey.js';

const KEY_RE = /^[0-9a-f]{64}$/i;

/**
 * The platform secret when it holds ENCRYPTION_KEY, or null when rotation is
 * the plain .env case. A provider that cannot be read throws: it is not a
 * reason to go and rotate whatever .env happens to hold.
 */
export async function keyHeldByProvider(envText) {
  applyProviderSettings(envText);
  const cfg = providerConfig();
  if (cfg?.provider === 'systemd-creds') return systemdKeyHeld();
  if (!cfg?.secretId) return null;
  const values = await readPlatformSecret();
  if (!values.ENCRYPTION_KEY) return null;
  if (!KEY_RE.test(values.ENCRYPTION_KEY)) throw new Error(`platform secret ${cfg.secretId}: ENCRYPTION_KEY must be 64 hex characters`);
  return { values, oldKey: values.ENCRYPTION_KEY.toLowerCase(), secretId: cfg.secretId, region: cfg.region };
}

export function recoveryCommand(held, newVersion, oldVersion) {
  const region = held.region ? ` --region ${held.region}` : '';
  return `aws secretsmanager update-secret-version-stage --secret-id ${held.secretId}${region} --version-stage AWSCURRENT --move-to-version-id ${newVersion} --remove-from-version-id ${oldVersion}`;
}

/**
 * The provider half of crane rotate-key. better-sqlite3 transactions are
 * synchronous and the stage is a network call, so it happens before the
 * transaction opens, after a dry run has shown the transaction will not refuse:
 * stage (AWSPENDING) -> read it back -> commit the database -> promote -> verify.
 * Anything before the commit leaves AWSCURRENT as it was.
 */
export async function rotateWithProvider(db, { held, newKey, backupDir }) {
  const { oldKey } = held;
  const before = await platformVersions();
  try {
    rotateDatabase(db, { oldKey, newKey, dryRun: true });
  } catch (e) {
    if (before.pending) e.message += `. Version ${before.pending} of the secret is still labelled AWSPENDING: if an earlier rotation stopped after its database commit, the database uses that version's key. Finish it with: ${recoveryCommand(held, before.pending, before.current)}`;
    throw e;
  }
  const { versionId } = await stagePlatformSecret({ ...held.values, ENCRYPTION_KEY: newKey });

  let report;
  try {
    // Version ids are not secrets. Should this process die after the commit, this names the way back.
    writeFileSync(join(backupDir, 'secret-rotation.json'), JSON.stringify({
      secret_id: held.secretId, region: held.region, previous_version_id: before.current, new_version_id: versionId,
      if_interrupted: recoveryCommand(held, versionId, before.current),
    }, null, 2), { mode: 0o600 });
    const pending = await readPlatformSecret({ stage: 'AWSPENDING' });
    if (pending.ENCRYPTION_KEY !== newKey) throw new Error('the staged version of the secret did not read back with the new key; the database was not changed');
    report = rotateDatabase(db, { oldKey, newKey });
  } catch (e) {
    await discardPlatformStage(versionId);
    throw e;
  }

  try {
    await promotePlatformSecret(versionId);
  } catch (e) {
    e.dbCommitted = true;
    e.message = `the database now uses the new key but the secret could not be promoted (${e.message}). AppCrane will not read its data until this is done. Run: `
      + `${recoveryCommand(held, versionId, before.current)} (or restore ${backupDir}/deployhub.db)`;
    throw e;
  }

  let failures;
  try {
    const current = await readPlatformSecret();
    failures = current.ENCRYPTION_KEY === newKey ? selfCheck(db, newKey) : ['AWSCURRENT does not hold the new key'];
  } catch (e) {
    failures = [e.message];
  }
  report.post_check = failures.length ? { ok: false, failures } : { ok: true };
  return { report, provider: { secret_id: held.secretId, version_id: versionId, previous_version_id: before.current, undo: recoveryCommand(held, before.current, versionId) } };
}
