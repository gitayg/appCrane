import { dirname, join, resolve } from 'path';
import { existsSync, readFileSync } from 'fs';
import { fileURLToPath } from 'url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function envValue(envPath, name) {
  if (process.env[name]) return process.env[name];
  if (!existsSync(envPath)) return null;
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const t = line.trim();
    if (t.startsWith(`${name}=`)) return t.slice(name.length + 1).trim() || null;
  }
  return null;
}

const IMDS_LABEL = {
  exposed: 'EXPOSED: an app container can reach the instance metadata service',
  blocked: 'blocked: a bridge container gets no answer and the host does',
  not_measured: 'not measured',
};

function printImds(out, imds) {
  const line = `Instance metadata from a container: ${IMDS_LABEL[imds.status]} (${imds.detail})`;
  if (imds.status === 'exposed') {
    out.err(line);
    out.info(`Fix: ${imds.fix}`);
  } else if (imds.status === 'blocked') {
    out.ok(line);
  } else {
    out.warn(line);
  }
}

function printCopies(out, copies) {
  const all = [...copies.files, ...copies.archives];
  if (all.length) {
    out.warn('These still hold the old key (a file, or a .env inside an archive):');
    for (const f of all) console.log(`  ${f}`);
  } else {
    out.info('No local file was found still holding the old key.');
  }
  for (const f of copies.uninspected) out.warn(`Could not look inside ${f}; assume it holds the old key.`);
  out.warn('Off-site (S3) backup sets are not listed here and hold the old key too.');
  out.info('Moving the key does not reach those copies. Run crane rotate-key, so the copy they hold stops opening anything.');
}

const dataDirOf = (opts, envPath) => resolve(opts.dataDir || envValue(envPath, 'DATA_DIR') || join(ROOT, 'data'));

function printSystemdStatus(out, s, opts) {
  if (opts.json) out.json(s);
  else {
    out.header('Secrets provider');
    out.keyValue({
      Provider: 'systemd-creds (systemd encrypted credentials)',
      Unit: `${s.unit}.service`,
      'Drop-in': `${s.dropin} (${s.dropin_present ? 'present' : 'MISSING'})`,
      'systemd sees the drop-in': s.unit_sees_dropin === null ? 'not checked' : (s.unit_sees_dropin ? 'yes' : 'NO'),
      'Keys expected': s.expected_keys.join(', ') || '(none)',
      'Keys a boot would load': s.checked_as_root ? (s.loadable_keys.join(', ') || '(none)') : 'not checked (run with sudo to decrypt)',
      'Secret names still in .env': s.still_in_env_file.join(', ') || '(none)',
    });
    for (const c of s.credentials) {
      const state = c.present === null ? 'not visible (run with sudo)' : (c.present ? 'present' : 'MISSING');
      const dec = c.decrypts === null ? '' : (c.decrypts ? ', decrypts' : ', DOES NOT DECRYPT');
      console.log(`  ${c.file}: ${state}${dec}`);
    }
    for (const p of s.problems) out.err(p);
  }
  if (s.problems.length) process.exit(1);
}

async function migrateSystemd(out, opts, envPath) {
  const { migrateToSystemdCreds } = await import('../server/services/secretsProvider/migrateSystemd.js');
  const { MigrateRefused } = await import('../server/services/secretsProvider/migrate.js');
  try {
    const res = await migrateToSystemdCreds({
      envPath,
      dataDir: dataDirOf(opts, envPath),
      port: Number(opts.port || envValue(envPath, 'PORT') || 5001),
      dryRun: !!opts.dryRun,
      keys: opts.keys ? opts.keys.split(',').map((k) => k.trim()).filter(Boolean) : null,
      unit: opts.unit || null,
      credstore: opts.credstoreDir ? resolve(opts.credstoreDir) : null,
      dropinDir: opts.dropinDir ? resolve(opts.dropinDir) : null,
      ...(opts.backupDir ? { backupDir: resolve(opts.backupDir) } : {}),
    });
    if (opts.json) return out.json(res);
    if (res.dry_run) {
      out.header('Dry run: nothing was changed');
      if (!res.root) out.warn('Not running as root: the real run needs sudo, and existing credentials were not compared.');
      out.info(`${res.systemd_creds}; unit ${res.unit}.service`);
      out.info(`Would back up .env to ${res.backup} (0600, root)`);
      for (const c of res.credentials) out.info(`${c.file}: ${c.action}`);
      out.info(`Would write ${res.dropin}:`);
      console.log(res.dropin_text.replace(/^/gm, '    '));
      out.info(`Would run systemctl daemon-reload, remove ${res.moved.join(', ')} from .env and set ${Object.entries(res.env_settings).map(([k, v]) => `${k}=${v}`).join(' ')}`);
    } else {
      out.ok(`Sealed ${res.moved.join(', ')} into systemd credentials and decrypted them back. .env no longer holds them.`);
      out.info(`A boot of ${res.unit}.service loads: ${res.boot_check_keys.join(', ')}. Start it: sudo systemctl start ${res.unit}`);
      out.warn(`${res.backup} holds the old .env with the plaintext keys (root only).`);
      out.warn('The credentials decrypt only on this host (its /var/lib/systemd/credential.secret). Keep an offline copy of ENCRYPTION_KEY: '
        + 'without it, losing this host or that file loses every encrypted value. Then remove the backup: sudo shred -u ' + res.backup);
    }
    for (const k of res.left_in_env) out.info(`${k} stays in .env${k === 'ANTHROPIC_API_KEY' ? ': AppCrane moves it into its database at the next boot' : ''} (pass --keys to seal it too)`);
    out.info('To roll back:');
    for (const step of res.rollback) console.log(`  ${step}`);
    printCopies(out, res.copies);
  } catch (e) {
    out.err(e instanceof MigrateRefused ? `Refused: ${e.message}` : `Migration failed: ${e.message}`);
    if (e.backup) out.info(`.env backup taken first: ${e.backup}`);
    if (e.rollback) { out.info('To undo what was done:'); for (const step of e.rollback) console.log(`  ${step}`); }
    process.exit(1);
  }
}

export function registerSecrets(program, out) {
  const secrets = program.command('secrets').description('Where AppCrane\'s own keys live: AWS Secrets Manager or systemd encrypted credentials');

  secrets
    .command('status')
    .description('Provider, secret, the key names it holds, what is still in .env, and whether a container can reach instance metadata. Never values')
    .option('--env-file <path>', 'The .env (default: ./.env in the AppCrane directory)')
    .option('--json', 'Print as JSON')
    .action(async (opts) => {
      const envPath = resolve(opts.envFile || join(ROOT, '.env'));
      const { secretsStatus } = await import('../server/services/secretsProvider/status.js');
      let s;
      try {
        s = await secretsStatus({ envPath });
      } catch (e) {
        out.err(e.message);
        process.exit(1);
      }
      if (s.provider === 'systemd-creds') return printSystemdStatus(out, s, opts);
      if (opts.json) {
        out.json(s);
      } else {
        out.header('Secrets provider');
        out.keyValue({
          Provider: s.provider || 'not configured',
          'Platform secret': s.secret_id || '(none)',
          Region: s.region || '(SDK default)',
          'AWSCURRENT readable': s.current_readable === null ? 'n/a' : (s.current_readable ? 'yes' : 'NO'),
          'Keys in the secret': s.keys.join(', ') || '(none)',
          'Secret names still in .env': s.still_in_env_file.join(', ') || '(none)',
        });
        if (s.read_error) out.err(s.read_error);
        if (s.pending_version) out.warn(`Version ${s.pending_version} is labelled AWSPENDING: a crane rotate-key may have stopped midway. Its backup folder holds secret-rotation.json with the way to finish.`);
        printImds(out, s.imds);
      }
      if (s.current_readable === false) process.exit(1);
    });

  secrets
    .command('migrate')
    .description('Move ENCRYPTION_KEY from .env to a Secrets Manager secret or to systemd encrypted credentials (AppCrane must be stopped)')
    .option('--provider <name>', 'aws-secrets-manager (default) or systemd-creds (run with sudo)', 'aws-secrets-manager')
    .option('--secret-id <id>', 'aws-secrets-manager: secret name or ARN; created if the name does not exist')
    .option('--keys <list>', 'systemd-creds: comma list of allowlisted keys to move (default: ENCRYPTION_KEY)')
    .option('--unit <name>', 'systemd-creds: the systemd unit AppCrane runs as (default: appcrane)')
    .option('--credstore-dir <dir>', 'systemd-creds: where the encrypted credentials go (default: /etc/credstore.encrypted)')
    .option('--dropin-dir <dir>', 'systemd-creds: the unit\'s drop-in directory (default: /etc/systemd/system/<unit>.service.d)')
    .option('--backup-dir <dir>', 'systemd-creds: where the .env backup goes, root only (default: /var/backups/appcrane)')
    .option('--region <region>', 'AWS region (default: AWS_REGION or the SDK default)')
    .option('--dry-run', 'Report what would happen; change nothing')
    .option('--accept-imds-exposure', 'Migrate even though an app container can reach instance metadata')
    .option('--data-dir <dir>', 'AppCrane data directory (default: DATA_DIR from the environment or .env, else ./data)')
    .option('--env-file <path>', 'The .env (default: ./.env in the AppCrane directory)')
    .option('--port <port>', 'AppCrane HTTP port, probed to make sure it is stopped (default: $PORT, PORT in .env, or 5001)')
    .option('--json', 'Print as JSON')
    .action(async (opts) => {
      const envPath = resolve(opts.envFile || join(ROOT, '.env'));
      if (opts.provider === 'systemd-creds') return migrateSystemd(out, opts, envPath);
      const { migrateToSecretsManager, MigrateRefused } = await import('../server/services/secretsProvider/migrate.js');
      if (opts.provider !== 'aws-secrets-manager') {
        out.err(`Refused: --provider must be aws-secrets-manager or systemd-creds`);
        process.exit(1);
      }
      if (!opts.secretId) {
        out.err('Refused: --secret-id is required with --provider aws-secrets-manager');
        process.exit(1);
      }
      try {
        const res = await migrateToSecretsManager({
          secretId: opts.secretId,
          region: opts.region || envValue(envPath, 'APPCRANE_SECRETS_REGION'),
          envPath,
          dataDir: dataDirOf(opts, envPath),
          port: Number(opts.port || envValue(envPath, 'PORT') || 5001),
          dryRun: !!opts.dryRun,
          acceptImdsExposure: !!opts.acceptImdsExposure,
        });
        if (opts.json) return out.json(res);
        printImds(out, res.imds);
        if (res.dry_run) {
          out.header('Dry run: nothing was changed');
          out.info(`Would move ${res.moved.join(', ')} to ${res.secret_id} (${res.secret_exists ? 'new version' : 'new secret'}), then remove them from .env.`);
        } else {
          out.ok(`Moved ${res.moved.join(', ')} to ${res.secret_id} and read it back. .env no longer holds them.`);
          out.info(`A boot from this configuration loads: ${res.boot_check_keys.join(', ')}`);
        }
        printCopies(out, res.copies);
      } catch (e) {
        out.err(e instanceof MigrateRefused ? `Refused: ${e.message}` : `Migration failed: ${e.message}`);
        process.exit(1);
      }
    });
}
