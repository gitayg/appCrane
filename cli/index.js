import { Command } from 'commander';
import { getApiUrl, getApiKey, saveConfig, getConfig } from './config.js';
import * as out from './output.js';

const program = new Command();

// HTTP helper
async function api(method, path, body) {
  const url = `${getApiUrl()}${path}`;
  const headers = { 'Content-Type': 'application/json' };
  const key = getApiKey();
  if (key) headers['X-API-Key'] = key;

  const opts = { method, headers };
  if (body && method !== 'GET') opts.body = JSON.stringify(body);

  try {
    const res = await fetch(url, opts);
    const data = await res.json();
    if (!res.ok) {
      out.err(data.error?.message || `HTTP ${res.status}`);
      process.exit(1);
    }
    return data;
  } catch (e) {
    out.err(`Connection failed: ${e.message}`);
    out.dim(`API URL: ${url}`);
    out.dim('Is the AppCrane server running? Start with: node server/index.js');
    process.exit(1);
  }
}

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
const __clidir = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__clidir, '..', 'package.json'), 'utf8'));

program
  .name('crane')
  .description('AppCrane - Self-hosted deployment manager')
  .version(pkg.version);

// ── Config ──────────────────────────────
program
  .command('config')
  .description('Configure CLI connection')
  .option('--url <url>', 'API server URL')
  .option('--key <key>', 'API key')
  .option('--show', 'Show current config')
  .action((opts) => {
    if (opts.show) {
      const config = getConfig();
      out.header('AppCrane Config');
      out.keyValue({
        'API URL': config.api_url,
        'API Key': config.api_key ? config.api_key.slice(0, 12) + '...' : '(not set)',
      });
      return;
    }
    const config = getConfig();
    if (opts.url) config.api_url = opts.url;
    if (opts.key) config.api_key = opts.key;
    saveConfig(config);
    out.ok('Config saved');
  });

// ── Init (direct DB access, no server needed) ──────────────────────────────
program
  .command('init')
  .description('Initialize AppCrane (first run - creates admin directly in DB)')
  .option('--name <name>', 'Admin name', 'admin')
  .option('--email <email>', 'Admin email')
  .action(async (opts) => {
    try {
      // Import DB and encryption directly - no API call needed
      const { dirname, join } = await import('path');
      const { fileURLToPath } = await import('url');
      const __dirname = dirname(fileURLToPath(import.meta.url));
      const { initDb, getDb } = await import(join(__dirname, '..', 'server', 'db.js'));
      const { generateApiKey, hashApiKey } = await import(join(__dirname, '..', 'server', 'services', 'encryption.js'));

      initDb();
      const db = getDb();

      // Check if admin already exists
      const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
      if (userCount > 0) {
        out.err('AppCrane is already initialized. Admin user exists.');
        process.exit(1);
      }

      const adminName = opts.name || 'admin';
      const adminEmail = opts.email || 'admin@localhost';
      const apiKey = generateApiKey('dhk_admin');
      const keyHash = hashApiKey(apiKey);

      db.prepare(
        'INSERT INTO users (name, email, role, api_key_hash) VALUES (?, ?, ?, ?)'
      ).run(adminName, adminEmail, 'admin', keyHash);

      // Generate and save ENCRYPTION_KEY to .env if not present
      const crypto = await import('crypto');
      const { readFileSync, writeFileSync, existsSync } = await import('fs');
      const envPath = join(__dirname, '..', '.env');
      let envContent = '';
      if (existsSync(envPath)) {
        envContent = readFileSync(envPath, 'utf8');
      }
      if (!envContent.includes('ENCRYPTION_KEY=')) {
        const encKey = crypto.randomBytes(32).toString('hex');
        envContent += `\nENCRYPTION_KEY=${encKey}\n`;
        writeFileSync(envPath, envContent);
        process.env.ENCRYPTION_KEY = encKey;
        out.ok('ENCRYPTION_KEY generated and saved to .env');
      }

      out.ok('AppCrane initialized!');
      out.header('Admin User');
      out.keyValue({ Name: adminName, Email: adminEmail, Role: 'admin' });
      console.log('');
      out.warn(`API Key: ${apiKey}`);
      out.warn('Save this key! It will not be shown again.');

      // Auto-save key
      const config = getConfig();
      config.api_key = apiKey;
      saveConfig(config);
      console.log('');
      out.ok('API key auto-saved to ~/.appcrane/config.json');
    } catch (e) {
      out.err(`Init failed: ${e.message}`);
      out.dim('Make sure you run this from the appCrane directory.');
      process.exit(1);
    }
  });

// ── Regenerate Admin Key (direct DB, server-only) ──────────────────────────────
program
  .command('regenerate-key')
  .description('Regenerate admin API key (must run on server)')
  .action(async () => {
    try {
      const { dirname, join } = await import('path');
      const { fileURLToPath } = await import('url');
      const __dirname = dirname(fileURLToPath(import.meta.url));
      const { initDb, getDb } = await import(join(__dirname, '..', 'server', 'db.js'));
      const { generateApiKey, hashApiKey } = await import(join(__dirname, '..', 'server', 'services', 'encryption.js'));

      initDb();
      const db = getDb();

      const admin = db.prepare("SELECT * FROM users WHERE role = 'admin' LIMIT 1").get();
      if (!admin) {
        out.err('No admin user found. Run: crane init');
        process.exit(1);
      }

      const apiKey = generateApiKey('dhk_admin');
      const keyHash = hashApiKey(apiKey);
      db.prepare('UPDATE users SET api_key_hash = ? WHERE id = ?').run(keyHash, admin.id);

      out.ok(`Admin key regenerated for ${admin.name}`);
      out.warn(`New API Key: ${apiKey}`);
      out.warn('Save this key! The old key no longer works.');

      // Auto-save
      const config = getConfig();
      config.api_key = apiKey;
      saveConfig(config);
      out.ok('API key auto-saved to ~/.appcrane/config.json');
    } catch (e) {
      out.err(`Failed: ${e.message}`);
      out.dim('Make sure you run this from the appCrane directory.');
      process.exit(1);
    }
  });

// ── Update (git pull + systemctl restart) ──────────────────────────────
program
  .command('update')
  .description('Pull latest code from GitHub and restart AppCrane')
  .action(async () => {
    try {
      const { execSync, execFileSync } = await import('child_process');
      const { dirname, join } = await import('path');
      const { fileURLToPath } = await import('url');
      const { readFileSync } = await import('fs');
      const __dirname = dirname(fileURLToPath(import.meta.url));
      const projectDir = join(__dirname, '..');
      const pkgPath = join(projectDir, 'package.json');
      const readVersion = () => {
        try { return JSON.parse(readFileSync(pkgPath, 'utf8')).version; }
        catch (_) { return 'unknown'; }
      };

      const fromVersion = readVersion();
      out.info(`Current version: v${fromVersion}`);

      out.info('Pulling latest from GitHub...');
      const pullOutput = execSync('git fetch origin && git reset --hard origin/main', { cwd: projectDir, stdio: 'pipe' }).toString().trim();
      console.log(pullOutput);

      const toVersion = readVersion();
      if (toVersion === fromVersion) {
        out.dim(`Already on latest (v${toVersion}) — no version change.`);
      } else {
        out.ok(`Updated v${fromVersion} → v${toVersion}`);
      }

      out.info('Installing dependencies...');
      try {
        execSync('npm install --omit=dev --prefer-offline', { cwd: projectDir, stdio: 'pipe', timeout: 120000 });
        out.ok('Dependencies installed');
      } catch (e) {
        out.warn('npm install failed: ' + e.message);
      }

      out.info('Restarting AppCrane...');
      try {
        execFileSync('systemctl', ['restart', 'appcrane'], { stdio: 'pipe' });
        out.ok(`AppCrane v${toVersion} restarted!`);
      } catch (e) {
        out.warn('systemctl restart failed: ' + e.message);
        out.dim('Try manually: systemctl restart appcrane');
      }
    } catch (e) {
      out.err(`Update failed: ${e.message}`);
      process.exit(1);
    }
  });

// ── Caddy ──────────────────────────────
program
  .command('caddy')
  .description('Show or reload Caddy reverse proxy config')
  .option('--reload', 'Regenerate and reload Caddy config')
  .option('--show', 'Show current generated Caddyfile')
  .action(async (opts) => {
    if (opts.reload) {
      out.info('Regenerating Caddy config and reloading...');
      const data = await api('POST', '/api/caddy/reload');
      if (data.success) {
        out.ok('Caddy reloaded');
      } else {
        out.err(`Caddy reload failed: ${data.error || 'unknown'}`);
      }
      if (data.caddyfile) {
        console.log('');
        console.log(data.caddyfile);
      }
    } else {
      // Show generated config (plain text)
      const url = `${getApiUrl()}/api/caddy/config`;
      const key = getApiKey();
      const res = await fetch(url, { headers: { 'X-API-Key': key } });
      if (!res.ok) { out.err('Failed to get config'); process.exit(1); }
      console.log(await res.text());
    }
  });

// ── Setup HTTPS ──────────────────────────────
program
  .command('setup-https')
  .description('Install Caddy, configure HTTPS, set up firewall')
  .requiredOption('--domain <domain>', 'Domain for AppCrane (e.g., crane.example.com)')
  .action(async (opts) => {
    const { execSync } = await import('child_process');
    const { existsSync, readFileSync, writeFileSync } = await import('fs');
    const domain = opts.domain;

    // Check if running as root
    try {
      execSync('whoami', { stdio: 'pipe' });
    } catch (e) {}
    const isRoot = process.getuid?.() === 0;
    if (!isRoot) {
      out.err('setup-https must be run as root (use sudo)');
      process.exit(1);
    }

    // Step 1: Install Caddy
    out.header('Step 1: Installing Caddy');
    try {
      execSync('which caddy', { stdio: 'pipe' });
      out.ok('Caddy already installed');
    } catch (e) {
      out.info('Installing Caddy...');
      try {
        execSync('apt install -y debian-keyring debian-archive-keyring apt-transport-https curl', { stdio: 'inherit' });
        execSync("curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg", { stdio: 'inherit' });
        execSync("curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list", { stdio: 'inherit' });
        execSync('apt update', { stdio: 'inherit' });
        execSync('apt install -y caddy', { stdio: 'inherit' });
        out.ok('Caddy installed');
      } catch (e2) {
        out.err(`Caddy install failed: ${e2.message}`);
        out.dim('Install manually: https://caddyserver.com/docs/install');
        process.exit(1);
      }
    }

    // Step 2: Create Caddyfile (replaces default)
    out.header('Step 2: Configuring Caddy');
    const caddyfilePath = '/etc/caddy/Caddyfile';

    // Extract root domain (e.g., crane.example.com -> example.com)
    const parts = domain.split('.');
    const rootDomain = parts.length > 2 ? parts.slice(-2).join('.') : null;

    let caddyfile = `# Managed by AppCrane\n\n`;
    caddyfile += `${domain} {\n    reverse_proxy localhost:5001\n}\n`;

    if (rootDomain && rootDomain !== domain) {
      caddyfile += `\n${rootDomain} {\n    redir https://${domain}{uri} permanent\n}\n`;
      out.ok(`${domain} → AppCrane`);
      out.ok(`${rootDomain} → redirects to ${domain}`);
    } else {
      out.ok(`${domain} → AppCrane`);
    }

    writeFileSync(caddyfilePath, caddyfile);
    out.ok('Caddyfile written');

    // Step 3: Restart Caddy
    out.header('Step 3: Starting Caddy');
    try {
      execSync('systemctl restart caddy', { stdio: 'inherit' });
      execSync('systemctl enable caddy', { stdio: 'pipe' });
      out.ok('Caddy started (auto-HTTPS enabled)');
    } catch (e) {
      out.err(`Caddy start failed: ${e.message}`);
      out.dim('Check: systemctl status caddy');
      process.exit(1);
    }

    // Step 4: Configure firewall
    out.header('Step 4: Configuring firewall');
    try {
      // Check if ufw is available
      execSync('which ufw', { stdio: 'pipe' });
      execSync('ufw allow 22/tcp', { stdio: 'pipe' });
      execSync('ufw allow 80/tcp', { stdio: 'pipe' });
      execSync('ufw allow 443/tcp', { stdio: 'pipe' });
      execSync('ufw deny 5001', { stdio: 'pipe' });
      try {
        execSync('echo "y" | ufw enable', { stdio: 'pipe' });
      } catch (e) {
        // ufw may already be enabled
      }
      out.ok('Firewall configured (80, 443 open | 5001 blocked externally)');
    } catch (e) {
      out.warn('ufw not available. Configure firewall manually:');
      out.dim('  Allow ports 22, 80, 443. Deny port 5001.');
    }

    // Step 5: Update CLI config + .env
    out.header('Step 5: Updating config');
    const config = getConfig();
    config.api_url = `https://${domain}`;
    saveConfig(config);
    out.ok(`CLI URL set to https://${domain}`);

    // Save CRANE_DOMAIN to .env so Caddy config includes AppCrane's route
    const { dirname: dn, join: jn } = await import('path');
    const { fileURLToPath: fu } = await import('url');
    const projDir = jn(dn(fu(import.meta.url)), '..');
    const envPath = jn(projDir, '.env');
    let envContent = '';
    try { envContent = readFileSync(envPath, 'utf8'); } catch (e) {}

    if (envContent.includes('CRANE_DOMAIN=')) {
      envContent = envContent.replace(/CRANE_DOMAIN=.*/g, `CRANE_DOMAIN=${domain}`);
    } else {
      envContent += `\nCRANE_DOMAIN=${domain}\n`;
    }

    // Also set BASE_DOMAIN from the domain (e.g., myapp.example.com -> example.com)
    const baseDomain = parts.slice(-2).join('.');
    if (envContent.includes('BASE_DOMAIN=')) {
      envContent = envContent.replace(/BASE_DOMAIN=.*/g, `BASE_DOMAIN=${baseDomain}`);
    } else {
      envContent += `BASE_DOMAIN=${baseDomain}\n`;
    }

    writeFileSync(envPath, envContent);
    out.ok(`CRANE_DOMAIN=${domain} saved to .env`);
    out.ok(`BASE_DOMAIN=${baseDomain} saved to .env`);

    // Step 6: Verify
    out.header('Step 6: Verifying');
    out.info(`Testing https://${domain}/api/info ...`);
    // Wait a moment for Caddy to provision cert
    await new Promise(r => setTimeout(r, 3000));
    try {
      const res = await fetch(`https://${domain}/api/info`);
      const data = await res.json();
      if (data.name === 'AppCrane') {
        out.ok(`HTTPS is working! https://${domain}`);
      } else {
        out.warn('Got a response but it may not be AppCrane');
      }
    } catch (e) {
      out.warn(`Could not verify yet: ${e.message}`);
      out.dim('DNS may need a few minutes to propagate. Try:');
      out.dim(`  curl -s https://${domain}/api/info`);
    }

    console.log('');
    out.header('Done!');
    out.keyValue({
      'Dashboard': `https://${domain}`,
      'API': `https://${domain}/api/info`,
      'Docs': `https://${domain}/docs`,
      'Agent guide': `https://${domain}/agent-guide`,
    });
    console.log('');
    out.dim('Make sure DNS A records point to this server:');
    try {
      const ip = execSync('curl -s ifconfig.me', { stdio: 'pipe', timeout: 5000 }).toString().trim();
      out.dim(`  ${domain}  →  ${ip}`);
      if (rootDomain && rootDomain !== domain) {
        out.dim(`  ${rootDomain}  →  ${ip}  (redirects to ${domain})`);
      }
      out.dim(`  *.${parts.slice(-2).join('.')}  →  ${ip}  (for app subdomains)`);
    } catch (e) {
      out.dim(`  ${domain}  →  YOUR_SERVER_IP`);
    }
  });

// ── Me ──────────────────────────────
program
  .command('me')
  .description('Show current user info')
  .action(async () => {
    const data = await api('GET', '/api/auth/me');
    out.header('Current User');
    out.keyValue({
      Name: data.user.name,
      Email: data.user.email || '-',
      Role: data.user.role,
      Apps: data.apps.map(a => a.slug).join(', ') || 'none',
    });
  });

// ── Server ──────────────────────────
program
  .command('status')
  .description('Show server health and all apps')
  .action(async () => {
    const data = await api('GET', '/api/server/health');
    const s = data.system;

    out.header('AppCrane Server');
    out.keyValue({
      Host: s.hostname,
      Platform: s.platform,
      CPU: `${s.cpu.percent}% (${s.cpu.count} cores)`,
      Memory: `${s.memory_formatted.used} / ${s.memory_formatted.total} (${s.memory.percent}%)`,
      Disk: `${s.disk_formatted.used} / ${s.disk_formatted.total} (${s.disk.percent}%)`,
    });

    console.log('');
    out.header('Apps');
    out.keyValue({
      Total: data.apps.total,
      Environments: data.apps.environments,
      Healthy: data.apps.healthy,
      Down: data.apps.down,
    });

    if (data.recent_deploys?.length) {
      console.log('');
      out.header('Recent Deploys');
      out.table(
        ['App', 'Env', 'Version', 'Status', 'When'],
        data.recent_deploys.slice(0, 5).map(d => [
          d.slug, d.env, d.version || '-', d.status, d.finished_at || d.started_at
        ])
      );
    }
  });

// ── Reconcile ──────────────────────────────────────────────────────────────
program
  .command('reconcile')
  .description('Register orphaned filesystem apps into AppCrane DB and reload Caddy')
  .option('--dry-run', 'Preview what would be registered without making changes')
  .action(async (opts) => {
    try {
      const { dirname, join } = await import('path');
      const { fileURLToPath } = await import('url');
      const __dirname = dirname(fileURLToPath(import.meta.url));

      const { initDb } = await import(join(__dirname, '..', 'server', 'db.js'));
      initDb();

      const { reconcileOrphanedApps } = await import(join(__dirname, '..', 'server', 'services', 'reconcile.js'));

      if (opts.dryRun) {
        out.info('Dry run — no changes will be made.');
      }

      out.info('Scanning data/apps/ directory...');
      const result = await reconcileOrphanedApps({ dryRun: opts.dryRun });

      if (result.orphaned === 0) {
        out.ok('No orphaned apps found. Everything is in sync.');
        return;
      }

      if (result.registered.length > 0) {
        out.header(opts.dryRun ? `Would register ${result.registered.length} app(s)` : `Registered ${result.registered.length} app(s)`);
        for (const app of result.registered) {
          out.keyValue({
            'App': `${app.name} (${app.slug})`,
            'Slot': app.slot,
            'Prod port': app.ports.prod_be,
            'Sandbox port': app.ports.sand_be,
          });
          console.log('');
        }
      }

      if (result.skipped.length > 0) {
        out.warn(`Skipped ${result.skipped.length} app(s) due to errors:`);
        for (const s of result.skipped) {
          out.err(`  ${s.slug}: ${s.error}`);
        }
      }

      if (!opts.dryRun) {
        if (result.caddy?.success) {
          out.ok('Caddy reloaded — app routes are now active.');
        } else if (result.caddy) {
          out.warn('Caddy reload failed: ' + (result.caddy.error || 'unknown'));
          out.dim('Run: crane caddy --reload');
        }

        const hasNeedsRestart = result.registered.some(a => a.needs_restart);
        if (hasNeedsRestart) {
          out.warn('Some apps have no running container. Redeploy them from the dashboard.');
        }
      }
    } catch (e) {
      out.err(`Reconcile failed: ${e.message}`);
      process.exit(1);
    }
  });

program.parse();
