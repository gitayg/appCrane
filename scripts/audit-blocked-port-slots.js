#!/usr/bin/env node
/**
 * scripts/audit-blocked-port-slots.js (v2.6.10)
 *
 * Find apps whose current slot maps to a WHATWG-blocked port. Without
 * the v2.6.10 fix in getNextSlot, AppCrane could hand out slot 23
 * (→ prod_be 4045 = NFS lockd, blocked by undici's fetch) or any of
 * ~80 other booby-trapped ports. The deploy + container start
 * successfully but the health probe silently fails with no signal.
 *
 * Run on the AppCrane host:
 *   node scripts/audit-blocked-port-slots.js
 *
 * Output: one line per affected app with current slot + which port is
 * blocked + a suggested safe replacement slot. Does NOT mutate
 * anything — slot reassignment changes the container's host port and
 * needs a Caddy reload, so the operator should drive that explicitly:
 *
 *   sqlite3 data/deployhub.db "UPDATE apps SET slot = <NEW_SLOT> WHERE slug = '<SLUG>';"
 *   sudo systemctl restart appcrane  # picks up new ports + reloads Caddy
 *
 * App data lives under <DATA_DIR>/apps/<slug>/... keyed by slug, NOT
 * slot — reassignment is safe across the data dir.
 */

import { initDb, getDb } from '../server/db.js';
import { getPortsForSlot, getNextSlot } from '../server/services/portAllocator.js';
import { describeBlockedPorts, arePortsSafe } from '../server/services/blockedPorts.js';

initDb();
const db = getDb();

const apps = db.prepare('SELECT id, slug, name, slot FROM apps ORDER BY slot').all();
const affected = [];
for (const app of apps) {
  const ports = getPortsForSlot(app.slot);
  const blocked = describeBlockedPorts(ports);
  if (blocked.length > 0) {
    affected.push({ ...app, ports, blocked });
  }
}

if (affected.length === 0) {
  console.log('✓ No apps are on blocked-port slots.');
  process.exit(0);
}

console.log(`Found ${affected.length} app(s) on blocked-port slot(s):\n`);
for (const a of affected) {
  console.log(`  • ${a.slug} (id=${a.id}) — slot ${a.slot}`);
  for (const b of a.blocked) {
    console.log(`      ${b.key} = ${b.port} → ${b.reason}`);
  }
}

// Suggest the next safe slot (the same one getNextSlot would hand to a
// brand-new app). Reassigning multiple apps in one go means picking
// successive safe slots, which the operator can do via the SQL above.
try {
  const suggested = getNextSlot(db);
  console.log(`\nSuggested next safe slot: ${suggested}`);
  console.log(`  Ports: ${JSON.stringify(getPortsForSlot(suggested))}`);
  console.log(`  Verify: ${arePortsSafe(getPortsForSlot(suggested)) ? 'all four ports clean ✓' : 'NOT SAFE — bug in allocator'}`);
} catch (e) {
  console.error(`\nCould not compute next safe slot: ${e.message}`);
}

console.log(`\nTo reassign:\n  sqlite3 data/deployhub.db "UPDATE apps SET slot = <NEW_SLOT> WHERE slug = '<SLUG>';"\n  sudo systemctl restart appcrane`);
