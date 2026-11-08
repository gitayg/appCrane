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

export function registerSecrets(program, out) {
  const secrets = program.command('secrets').description('AWS Secrets Manager: where AppCrane\'s own keys live');

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
    .description('Move ENCRYPTION_KEY and ANTHROPIC_API_KEY from .env to a Secrets Manager secret (AppCrane must be stopped)')
    .requiredOption('--secret-id <id>', 'Secret name or ARN; created if the name does not exist')
    .option('--region <region>', 'AWS region (default: AWS_REGION or the SDK default)')
    .option('--dry-run', 'Report what would happen; change nothing')
    .option('--accept-imds-exposure', 'Migrate even though an app container can reach instance metadata')
    .option('--data-dir <dir>', 'AppCrane data directory (default: DATA_DIR from the environment or .env, else ./data)')
    .option('--env-file <path>', 'The .env (default: ./.env in the AppCrane directory)')
    .option('--port <port>', 'AppCrane HTTP port, probed to make sure it is stopped (default: $PORT, PORT in .env, or 5001)')
    .option('--json', 'Print as JSON')
    .action(async (opts) => {
      const envPath = resolve(opts.envFile || join(ROOT, '.env'));
      const { migrateToSecretsManager, MigrateRefused } = await import('../server/services/secretsProvider/migrate.js');
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
