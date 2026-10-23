import { readFileSync, existsSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// The server loads .env into its environment (without overriding what is
// already set), so DATA_DIR and PORT may live there; this CLI does not load it.
function envValue(envPath, name) {
  if (process.env[name]) return process.env[name];
  if (!existsSync(envPath)) return null;
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const t = line.trim();
    if (t.startsWith(`${name}=`)) return t.slice(name.length + 1).trim() || null;
  }
  return null;
}

function newKeyFrom(opts) {
  if (opts.newKeyFile) return readFileSync(resolve(opts.newKeyFile), 'utf8').trim();
  if (process.env.NEW_ENCRYPTION_KEY) return process.env.NEW_ENCRYPTION_KEY.trim();
  return null;
}

function printReport(out, report, notes) {
  out.header(report.dry_run ? 'Dry run: nothing was changed' : 'Re-encrypted');
  const rows = Object.entries(report.counts).filter(([, n]) => n > 0).map(([k, n]) => [k, n]);
  if (rows.length) out.table(['where', 'values'], rows);
  else out.dim('  no encrypted values stored');
  console.log('');
  out.info(`${report.values} value(s) ${report.dry_run ? 'would be' : 'were'} re-encrypted`);
  out.info(`${report.audit_checkpoints_resigned} audit checkpoint(s) ${report.dry_run ? 'would be' : 'were'} re-signed`
    + (report.audit_checkpoints_invalid_left ? `; ${report.audit_checkpoints_invalid_left} already failing their signature are left as they are` : ''));
  if (report.recovery_codes.unused) {
    out.info(`${report.recovery_codes.unused} unused MFA recovery code(s) of ${report.recovery_codes.users} user(s) keep working (the previous key's recovery-code secret is kept, encrypted)`);
  }
  for (const f of report.failures) out.err(`does not decrypt: ${f}`);
  for (const u of report.uncovered) out.err(`encrypted value rotate-key does not cover: ${u}`);
  for (const i of report.inert_left_as_is) out.warn(`left as is (log row, nothing reads it back): ${i}`);
  for (const b of report.blockers || []) out.err(b);
  if (notes.evidence_packs) out.warn(`${notes.evidence_packs} evidence pack(s) were signed with the previous key; they verify only with it (kept in the backup folder)`);
  if (notes.offsite_backups_configured) {
    out.warn('Off-site backup sets made before the rotation are signed (and, if encrypted, encrypted) under the previous key. On this host they show as not verified '
      + 'and are never pruned automatically; restore one on a host whose .env holds the previous key. Run a fresh off-site backup after AppCrane starts.');
  }
}

export function registerRotateKey(program, out) {
  program
    .command('rotate-key')
    .description('Re-encrypt every stored secret under a new ENCRYPTION_KEY (AppCrane must be stopped; backs up first)')
    .option('--dry-run', 'Report what would be re-encrypted and anything that blocks it; change nothing')
    .option('--new-key-file <path>', 'Read the new 64-hex key from this file (or set NEW_ENCRYPTION_KEY); default: generate one')
    .option('--data-dir <dir>', 'AppCrane data directory (default: DATA_DIR from the environment or .env, else ./data)')
    .option('--env-file <path>', 'The .env holding ENCRYPTION_KEY (default: ./.env in the AppCrane directory)')
    .option('--port <port>', 'AppCrane HTTP port, probed to make sure it is stopped (default: $PORT, PORT in .env, or 5001)')
    .option('--json', 'Print the report as JSON')
    .action(async (opts) => {
      const envPath = resolve(opts.envFile || join(ROOT, '.env'));
      const dataDir = resolve(opts.dataDir || envValue(envPath, 'DATA_DIR') || join(ROOT, 'data'));
      const { rotateKey, RefusedError } = await import('../server/services/keyRotation/index.js');
      try {
        const res = await rotateKey({ dataDir, envPath, newKey: newKeyFrom(opts), dryRun: !!opts.dryRun, port: Number(opts.port || envValue(envPath, 'PORT') || 5001) });
        if (opts.json) out.json({ ...res.report, backup_dir: res.backupDir, notes: res.notes });
        else printReport(out, res.report, res.notes);
        if (res.report.dry_run) {
          if (res.report.blockers.length) process.exit(1);
          return;
        }
        if (!res.report.post_check.ok) {
          out.err(`post-rotation check failed: ${res.report.post_check.failures.join(', ')}`);
          out.err(`Restore ${res.backupDir}/deployhub.db and ${res.backupDir}/env.backup before starting AppCrane.`);
          process.exit(1);
        }
        console.log('');
        out.ok('ENCRYPTION_KEY rotated. .env now holds the new key; every value was checked against it.');
        out.info(`Backup (the old key is ONLY here now): ${res.backupDir}`);
        out.dim('Start AppCrane, check it, then store a copy of the new key away from this host. Delete the backup folder once you no longer need the old key.');
      } catch (e) {
        if (e.report && !opts.json) printReport(out, e.report, {});
        if (opts.json && e.report) out.json({ ...e.report, error: e.message, backup_dir: e.backupDir || null });
        out.err(e instanceof RefusedError ? `Refused: ${e.message}` : `Rotation failed: ${e.message}`);
        if (e.backupDir && !e.dbCommitted) out.dim(`Nothing was changed (the transaction rolled back; .env untouched). Backup taken first: ${e.backupDir}`);
        process.exit(1);
      }
    });
}
