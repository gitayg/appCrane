#!/usr/bin/env node
// Regenerates plugins/releases.json: for each plugin in this repo's marketplace,
// the version it ships and a hash of every file in it.
//
// Why: plugin.json sets an explicit `version`, and Claude Code uses that version
// to decide whether an update exists. Change a plugin's files without bumping it
// and nobody who already installed the plugin ever receives the change —
// `claude plugin update` reports it is already at the latest version, and
// nothing goes red. test/plugin-releases.test.js fails the moment the files and
// the recorded hash disagree; this script refuses to re-record a changed plugin
// whose version was not bumped, so regenerating cannot paper over it.
//
//   npm run gen:plugin-releases   # after changing a plugin and bumping its version
import { readFileSync, writeFileSync, readdirSync, lstatSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const RELEASES = join(ROOT, 'plugins', 'releases.json');

function files(dir, out = []) {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name), st = lstatSync(p);
    if (st.isDirectory()) files(p, out);
    else out.push(p);
  }
  return out;
}

/** Hash of a plugin's files: paths and contents, line endings normalised. */
export function pluginHash(dir) {
  const h = createHash('sha256');
  for (const f of files(dir)) {
    const st = lstatSync(f);
    const body = st.isSymbolicLink() ? 'symlink' : readFileSync(f).toString('latin1').replace(/\r\n/g, '\n');
    h.update(relative(dir, f).replace(/\\/g, '/') + '\0' + body + '\0');
  }
  return h.digest('hex');
}

/** The marketplace's local plugins as { name: { version, hash } }. */
export function currentReleases() {
  const mkt = JSON.parse(readFileSync(join(ROOT, '.claude-plugin', 'marketplace.json'), 'utf8'));
  const out = {};
  for (const p of mkt.plugins) {
    if (typeof p.source !== 'string' || !p.source.startsWith('./')) continue;
    const dir = join(ROOT, p.source);
    const { version } = JSON.parse(readFileSync(join(dir, '.claude-plugin', 'plugin.json'), 'utf8'));
    out[p.name] = { version, hash: pluginHash(dir) };
  }
  return out;
}

/** Plugins whose files changed while their version stayed the same. */
export function unbumped(recorded, current) {
  return Object.entries(current).filter(([n, c]) => recorded[n] && recorded[n].hash !== c.hash && recorded[n].version === c.version).map(([n]) => n);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const recorded = existsSync(RELEASES) ? JSON.parse(readFileSync(RELEASES, 'utf8')) : {};
  const current = currentReleases();
  const stuck = unbumped(recorded, current);
  if (stuck.length) {
    console.error(`refusing: ${stuck.join(', ')} changed but kept version ${stuck.map(n => current[n].version).join(', ')}. Bump "version" in its .claude-plugin/plugin.json first, or installed copies never receive the change.`);
    process.exit(1);
  }
  writeFileSync(RELEASES, JSON.stringify(current, null, 2) + '\n');
  console.log(`wrote ${Object.keys(current).length} plugin(s) to ${relative(ROOT, RELEASES)}`);
}
