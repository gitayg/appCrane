import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHandler } from './app.js';

const here = dirname(fileURLToPath(import.meta.url));
const { version } = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));

if (!process.env.APPCRANE_IDENTITY_SECRET) {
  console.warn('APPCRANE_IDENTITY_SECRET is not set: every request except /api/health will be refused');
}

const port = Number(process.env.PORT) || 3000;
createServer(createHandler({ version, publicDir: join(here, '..', 'public') }))
  .listen(port, '0.0.0.0', () => console.log(`__APP_SLUG__ v${version} listening on ${port}`));
