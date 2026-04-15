#!/usr/bin/env node
/**
 * Standalone bulk redeployer — calls the in-process deployer directly.
 *
 * No HTTP, no API key, no jq, no ~/.appcrane/config.json dependency.
 * Runs the same deploy pipeline the REST API would, but reads apps straight
 * from the SQLite DB using the repo's own modules.
 *
 * Usage (run as the AppCrane user, from the repo root):
 *   node scripts/bulk-redeploy.js              # deploy all apps, env=production
 *   node scripts/bulk-redeploy.js sandbox      # deploy all apps, env=sandbox
 *   node scripts/bulk-redeploy.js production myapp,other   # only listed slugs
 */
import { readFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '..');

const envPath = join(repoRoot, '.env');
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const eq = t.indexOf('=');
    if (eq === -1) continue;
    const k = t.slice(0, eq).trim();
    const v = t.slice(eq + 1).trim();
    if (!process.env[k]) process.env[k] = v;
  }
}

const { initDb, getDb } = await import(join(repoRoot, 'server/db.js'));
const { deployApp } = await import(join(repoRoot, 'server/services/deployer.js'));
const { getPortsForSlot } = await import(join(repoRoot, 'server/services/portAllocator.js'));

initDb();
const db = getDb();

const targetEnv = (process.argv[2] || 'production').trim();
if (!['production', 'sandbox'].includes(targetEnv)) {
  console.error(`env must be 'production' or 'sandbox', got: ${targetEnv}`);
  process.exit(1);
}

const slugFilter = process.argv[3] ? new Set(process.argv[3].split(',').map(s => s.trim()).filter(Boolean)) : null;

const allApps = db.prepare('SELECT * FROM apps').all();
const apps = slugFilter ? allApps.filter(a => slugFilter.has(a.slug)) : allApps;

if (apps.length === 0) {
  console.log('No matching apps in DB.');
  process.exit(0);
}

console.log(`Queueing ${apps.length} deploy(s) [env=${targetEnv}]...`);

for (const app of apps) {
  const ports = getPortsForSlot(app.slot);
  const deployResult = db.prepare(`
    INSERT INTO deployments (app_id, env, status, log)
    VALUES (?, ?, 'pending', 'bulk-redeploy from scripts/bulk-redeploy.js')
  `).run(app.id, targetEnv);
  const deployId = deployResult.lastInsertRowid;
  console.log(`  → ${app.slug} (deploy id ${deployId})`);
  deployApp(deployId, app, targetEnv, ports).catch(err => {
    console.error(`     ✗ ${app.slug} failed: ${err.message}`);
  });
}

console.log(`\nAll deploys queued. Monitor with:`);
console.log(`  docker ps --filter label=appcrane=true --format 'table {{.Names}}\\t{{.Status}}'`);
console.log(`  journalctl -u appcrane -f`);
console.log(`\nExiting in 3s (deploys continue in background).`);
setTimeout(() => process.exit(0), 3000);
