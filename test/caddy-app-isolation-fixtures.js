// Shared fixture for the per-app origin isolation Caddyfile tests: one fresh
// database holding every app shape generateCaddyfile() branches on.
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

export async function setupFixture() {
  process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-isolation-'));
  process.env.ENCRYPTION_KEY = 'e'.repeat(64);
  process.env.CRANE_DOMAIN = 'crane.example.test';
  process.env.PORT = '5001';

  const { initDb, getDb } = await import('../server/db.js');
  initDb();
  const db = getDb();

  const mkApp = (slug, slot, extra = {}, live = ['production', 'sandbox']) => {
    const id = db.prepare(
      `INSERT INTO apps (name, slug, slot, source_type, auth_mode, auth_bypass_paths, domain, slug_aliases, frame_ancestors)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).run(slug, slug, slot, 'managed', extra.auth_mode ?? 'authenticated',
          extra.auth_bypass_paths ?? null, extra.domain ?? null,
          extra.slug_aliases ?? '[]', extra.frame_ancestors ?? null).lastInsertRowid;
    for (const env of live) {
      db.prepare('INSERT INTO deployments (app_id, env, status) VALUES (?,?,?)').run(id, env, 'live');
    }
    return id;
  };

  const ids = {};
  ids.hub = mkApp('hub', 1, { slug_aliases: JSON.stringify(['oldhub']), frame_ancestors: 'https://portal.example.com' });
  ids.open = mkApp('open', 2, { auth_mode: 'headless' });
  ids.runner = mkApp('runner', 3, { auth_bypass_paths: JSON.stringify(['/ws/runner', '/hooks/']) });
  ids.shop = mkApp('shop', 4, { domain: 'shop.example.com', frame_ancestors: "'none'" }, ['production']);
  ids.idle = mkApp('idle', 5, {}, []);
  ids.boxed = mkApp('boxed', 6, { domain: 'boxed.example.com' });
  db.prepare('INSERT INTO app_domain_aliases (app_id, domain) VALUES (?, ?)').run(ids.shop, 'old-shop.example.com');
  return { db, ids };
}

export function setSetting(db, key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, value);
}
