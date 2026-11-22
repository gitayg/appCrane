import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createApp } from './app.js';
import { createPool } from './db.js';
import { migrate } from './migrate.js';

const here = dirname(fileURLToPath(import.meta.url));
const { version } = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));

const db = createPool();
if (db) {
  const applied = await migrate(db, join(here, 'migrations'));
  console.log(applied.length ? `migrations applied: ${applied.join(', ')}` : 'migrations: up to date');
} else {
  console.log('DATABASE_URL is not set: running without a database');
}
if (!process.env.APPCRANE_IDENTITY_SECRET) {
  console.warn('APPCRANE_IDENTITY_SECRET is not set: every request except /api/health will be refused');
}

const app = createApp({ version, db, clientDir: join(here, '..', 'client', 'dist') });
const port = Number(process.env.PORT) || 3000;
app.listen(port, '0.0.0.0', () => console.log(`__APP_SLUG__ v${version} listening on ${port}`));
