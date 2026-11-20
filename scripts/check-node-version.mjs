// npm "pretest": fail fast, in one line, when the tests would run on the wrong
// Node instead of dying later on a native-module error from better-sqlite3.
import { readFileSync } from 'fs';
import { createRequire } from 'module';
import { nodeProblem } from './lib/node-check.mjs';

const root = new URL('../', import.meta.url);
const required = readFileSync(new URL('.nvmrc', root), 'utf8').trim().replace(/^v/, '');

let problem = nodeProblem({ required, version: process.versions.node });
if (!problem) {
  let loadError;
  try {
    const Database = createRequire(new URL('package.json', root))('better-sqlite3');
    new Database(':memory:').close();
  } catch (err) {
    loadError = String(err?.message || err);
  }
  problem = nodeProblem({ required, version: process.versions.node, loadError });
}

if (problem) {
  console.error(problem);
  process.exit(1);
}
