#!/usr/bin/env node

import { createRequire } from 'module';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

// Load CLI
const __dirname = dirname(fileURLToPath(import.meta.url));
import('../cli/index.js').catch(e => {
  console.error('Failed to start AppCrane CLI:', e.message);
  process.exit(1);
});
