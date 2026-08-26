// The manifest-to-ecosystem table: which files AppCrane knows how to read, and
// how to turn each one into packages OSV can be asked about.
//
// This exists so that "AppCrane scans npm apps" becomes "AppCrane scans the
// ecosystems in this table". Adding Composer or Maven is a row plus a parser;
// no caller changes, because the row carries the OSV ecosystem name and the
// ecosystem travels with every package (see scanShapes.js).
//
// Two rules run through every parser here, and they are the same two rules the
// scanner has:
//
//   * A parser that cannot understand its file THROWS. The caller records
//     'error'. Returning [] would read as "this app has no dependencies",
//     which is a clean bill of health for a file nothing successfully read —
//     the exact failure the feature exists to stop.
//   * A name or version derived wrongly is worse than no answer at all,
//     because OSV replies "no vulnerabilities" for a package that does not
//     exist and the app is recorded green. Every transformation below that
//     looks fussy is there because the un-fussy version produced a false clean
//     against the live API.
//
// requirements.txt is DELIBERATELY ABSENT. Its specifiers are constraints, not
// installed versions: `django>=4.2`, `requests~=2.31`, or a bare `boto3` name
// pin nothing, and the file has no record of what pip actually resolved.
// Picking the lower bound, the upper bound, or the latest release all produce a
// confident answer about a version that may not be installed — a wrong CLEAN as
// easily as a wrong finding. A pip app therefore has no readable manifest and
// is recorded 'skipped', which says "never looked at" out loud. If it is ever
// added it must stay 'skipped' with a reason, never a guess.

import { readFileSync } from 'fs';
import { basename } from 'path';
import { assertPackage } from './scanShapes.js';

/**
 * Ordered: the first entry whose file exists in a release wins, so the most
 * specific and most common manifest comes first.
 *
 * `ecosystem` is spelled as OSV spells it — 'crates.io' and 'RubyGems' are
 * case- and punctuation-sensitive in the API, and a near miss returns an empty
 * result set rather than an error.
 */
export const MANIFESTS = [
  { file: 'package-lock.json', ecosystem: 'npm',        parse: parseNpmLock },
  { file: 'go.sum',            ecosystem: 'Go',         parse: parseGoSum },
  { file: 'Cargo.lock',        ecosystem: 'crates.io',  parse: parseCargoLock },
  { file: 'Gemfile.lock',      ecosystem: 'RubyGems',   parse: parseGemfileLock },
  { file: 'poetry.lock',       ecosystem: 'PyPI',       parse: parsePoetryLock },
  { file: 'Pipfile.lock',      ecosystem: 'PyPI',       parse: parsePipfileLock },
];

/**
 * Read one manifest into the packages to query.
 *
 * @param {string} absPath absolute path to the manifest
 * @param {object} [entry] the MANIFESTS row; resolved from the filename if omitted
 * @returns {Array<{name: string, version: string, ecosystem: string}>}
 * @throws if the file is unreadable, or is not the file it claims to be
 */
export function parseManifest(absPath, entry) {
  const row = entry || MANIFESTS.find(m => m.file === basename(absPath));
  if (!row) throw new Error(`no parser for ${basename(absPath)}`);

  const text = readFileSync(absPath, 'utf8');

  let packages;
  try {
    packages = row.parse(text, row.ecosystem);
  } catch (e) {
    // The filename is what a reader of the recorded error has to work with —
    // "unexpected token" on its own does not say which of an app's manifests
    // could not be read.
    throw new Error(`${row.file}: ${e.message}`);
  }

  // Producers assert what they emit. A parser that drifts out of shape fails
  // here, in the scan that produced it, rather than three surfaces later in an
  // email that renders "undefined".
  packages.forEach((p, i) => assertPackage(p, `${row.file}[${i}]`));
  return packages;
}

/** Collapse duplicates; OSV is billed by query slot, not by distinct package. */
function dedupe(packages) {
  const seen = new Set();
  return packages.filter((p) => {
    const id = `${p.name}@${p.version}`;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

// --- npm --------------------------------------------------------------------

function parseNpmLock(text, ecosystem) {
  const lock = JSON.parse(text);

  // lockfileVersion 2 and 3 both carry the real dependency set under
  // `packages`. A v1 lockfile has only the legacy `dependencies` tree and is
  // not read: npm has written v2+ since npm 7 (2020) and this platform's Node
  // floor is 22, so a v1 file on the box is an anomaly worth surfacing as an
  // error rather than parsing on a best-effort basis.
  if (!lock.packages) {
    throw new Error(
      `no "packages" (lockfileVersion ${lock.lockfileVersion ?? 'unknown'}) — ` +
      `only npm lockfile v2/v3 are read`
    );
  }

  const packages = [];
  for (const [key, entry] of Object.entries(lock.packages)) {
    // A workspace link entry carries only { resolved, link: true } and no
    // version. Its contents appear separately under the source path.
    if (!entry?.version) continue;

    // Only entries under node_modules/ are registry packages. Two kinds are
    // not, and both carry a real version so the check above misses them: the ""
    // root entry, which is the application itself, and workspace members, which
    // npm keys by source path ("packages/ui"). Neither is published anywhere.
    const cut = key.lastIndexOf('node_modules/');
    if (cut === -1) continue;

    // Nested dependencies key as node_modules/a/node_modules/b — the name is
    // what follows the LAST node_modules/, not the first.
    //
    // ALIASES: the key is the INSTALL PATH, which for an aliased dependency is
    // the alias rather than the package. npm writes
    // `"node_modules/mylodash": { name: "lodash", version: "4.17.15" }` for
    // `npm i mylodash@npm:lodash@4.17.15`, and ships aliases itself —
    // string-width-cjs, strip-ansi-cjs and ansi-styles-cjs reach ordinary
    // lockfiles through cliui/wrap-ansi. Asking OSV about "mylodash" returns
    // nothing and records a vulnerable lodash as clean, so entry.name is
    // authoritative when present and the path is only the fallback.
    const name = entry.name || key.slice(cut + 'node_modules/'.length);
    if (!name) continue;

    packages.push({ name, version: entry.version, ecosystem });
  }
  return dedupe(packages);
}

// --- Go ---------------------------------------------------------------------

function parseGoSum(text, ecosystem) {
  const packages = [];
  let lineNo = 0;

  for (const raw of text.split('\n')) {
    lineNo++;
    const line = raw.trim();
    if (!line) continue;

    const fields = line.split(/\s+/);
    if (fields.length !== 3) {
      throw new Error(`line ${lineNo}: expected "module version hash", got ${fields.length} fields`);
    }
    const [name, version] = fields;

    // Every module gets TWO lines: one for the module zip and one for its
    // go.mod, written as `<version>/go.mod`. The second is a hash of the
    // manifest, not a separate release — treating it as one asks OSV about
    // version "v1.9.1/go.mod", which matches no range and answers clean, and
    // doubles the query count while doing it.
    if (version.endsWith('/go.mod')) continue;

    if (!version.startsWith('v')) {
      throw new Error(`line ${lineNo}: ${JSON.stringify(version)} is not a Go module version`);
    }

    // Versions are passed through verbatim, including the +incompatible suffix
    // and pseudo-versions like v0.0.0-20210101000000-abcdef123456. Measured
    // against the live API rather than assumed: github.com/docker/docker at
    // v20.10.0+incompatible, 20.10.0+incompatible, v20.10.0 and 20.10.0 all
    // return the same 35 advisories, so OSV normalises the Go form itself and
    // the least transformation here is also the safest.
    packages.push({ name, version, ecosystem });
  }

  // go.sum records the whole module graph, not just the build list, so this
  // over-reports modules a build never links. That direction is the acceptable
  // one: a finding on an unused module costs a reader a minute, a missed
  // finding on a used one costs them the incident.
  return dedupe(packages);
}

// --- TOML block reader, shared by Cargo.lock and poetry.lock ----------------

/**
 * Split a TOML file into its `[[<name>]]` array-of-table blocks.
 *
 * Only the keys asked for are captured, and nested tables are namespaced by
 * their header. Both files put arrays of inline tables inside a block —
 * poetry's `files = [{file = "...", hash = "..."}]` — whose lines contain `=`
 * and would otherwise be read as block-level keys.
 *
 * @returns {Array<{ lineNo: number, keys: Map<string, string> }>}
 */
function tomlBlocks(text, arrayHeader, wanted) {
  const blocks = [];
  let current = null;
  let table = null;
  let lineNo = 0;

  for (const raw of text.split('\n')) {
    lineNo++;
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    if (line === arrayHeader) {
      current = { lineNo, keys: new Map() };
      table = null;
      blocks.push(current);
      continue;
    }
    if (line.startsWith('[')) {
      // A nested table — [package.dependencies], [package.source], [metadata].
      // It ends the block-level key run without ending the block.
      table = line.slice(1, line.lastIndexOf(']'));
      continue;
    }
    if (!current) continue;

    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    const path = table ? `${table}.${key}` : key;
    if (!wanted.has(path)) continue;
    current.keys.set(path, unquote(line.slice(eq + 1).trim()));
  }
  return blocks;
}

function unquote(value) {
  const q = value[0];
  if ((q === '"' || q === "'") && value.endsWith(q) && value.length >= 2) {
    return value.slice(1, -1);
  }
  return value;
}

// --- Rust -------------------------------------------------------------------

function parseCargoLock(text, ecosystem) {
  const blocks = tomlBlocks(text, '[[package]]', new Set(['name', 'version', 'source']));
  const packages = [];

  for (const block of blocks) {
    const name = block.keys.get('name');
    const version = block.keys.get('version');
    if (!name || !version) {
      throw new Error(`[[package]] at line ${block.lineNo} has no ${name ? 'version' : 'name'}`);
    }

    // A block with no `source` is a local crate — the root binary or a
    // workspace member. Cargo omits the key for anything it did not fetch.
    // These are not published, so a query either matches nothing or matches an
    // unrelated crate that happens to share the name.
    if (!block.keys.has('source')) continue;

    packages.push({ name, version, ecosystem });
  }
  return dedupe(packages);
}

// --- Ruby -------------------------------------------------------------------

function parseGemfileLock(text, ecosystem) {
  const packages = [];
  let section = null;
  let inSpecs = false;
  let lineNo = 0;

  for (const raw of text.split('\n')) {
    lineNo++;
    if (!raw.trim()) continue;

    // Section headers sit flush left: GEM, GIT, PATH, PLATFORMS, DEPENDENCIES,
    // CHECKSUMS, BUNDLED WITH. Everything below one belongs to it.
    if (!/^\s/.test(raw)) {
      section = raw.trim();
      inSpecs = false;
      continue;
    }

    const indent = raw.length - raw.trimStart().length;

    // Only the GEM section is rubygems.org. GIT and PATH sections list gems
    // resolved from a repository or a local directory; their `specs:` blocks
    // look identical, and their versions are whatever the checkout declares,
    // which need not correspond to any published release.
    if (section !== 'GEM') continue;

    if (indent === 2) {
      inSpecs = raw.trim() === 'specs:';
      continue;
    }
    if (!inSpecs) continue;

    // The block is indentation-sensitive and that is the whole trap: 4 spaces
    // is an installed gem, 6 is one of its dependency CONSTRAINTS. A parser
    // that takes both reports `actionpack (= 7.0.4)` as a gem at version
    // "= 7.0.4" and floods the batch with constraint noise.
    if (indent !== 4) continue;

    const m = /^([^\s(]+) \(([^)]+)\)$/.exec(raw.trim());
    if (!m) throw new Error(`line ${lineNo}: cannot read ${JSON.stringify(raw.trim())} as a gem`);

    // Platform-specific gems are written `nokogiri (1.13.8-x86_64-linux)`. The
    // suffix is the platform, not part of the version, and leaving it on
    // changes the answer: Ruby reads the hyphen as a prerelease separator, so
    // the string sorts BELOW the plain version. Measured against the live API —
    // activerecord 7.0.0 returns 4 advisories, activerecord
    // 7.0.0-x86_64-linux returns 1, and the 3 that vanish are the ones whose
    // range opens at `introduced: 7.0.0`. That is three silent false cleans
    // from one suffix. Ruby prereleases themselves use dots (1.0.0.beta1), so
    // splitting at the first hyphen only ever removes a platform.
    const version = m[2].split('-')[0];
    packages.push({ name: m[1], version, ecosystem });
  }
  return dedupe(packages);
}

// --- Python -----------------------------------------------------------------

function parsePoetryLock(text, ecosystem) {
  const blocks = tomlBlocks(text, '[[package]]', new Set(['name', 'version', 'package.source.type']));
  const packages = [];

  for (const block of blocks) {
    const name = block.keys.get('name');
    const version = block.keys.get('version');
    if (!name || !version) {
      throw new Error(`[[package]] at line ${block.lineNo} has no ${name ? 'version' : 'name'}`);
    }

    // `[package.source]` with type directory or file is a path dependency —
    // the app's own code or a sibling package, not something on PyPI. A git
    // source keeps its upstream name and is left in.
    const sourceType = block.keys.get('package.source.type');
    if (sourceType === 'directory' || sourceType === 'file') continue;

    packages.push({ name, version, ecosystem });
  }
  return dedupe(packages);
}

function parsePipfileLock(text, ecosystem) {
  const lock = JSON.parse(text);

  // default and develop are the two installed sets; _meta is the hash of the
  // Pipfile and the source list. A file with neither section is not a
  // Pipfile.lock, whatever it is called.
  if (!lock.default && !lock.develop) {
    throw new Error('no "default" or "develop" section');
  }

  const packages = [];
  for (const section of ['default', 'develop']) {
    for (const [name, entry] of Object.entries(lock[section] || {})) {
      if (!entry?.version) {
        // A VCS, file or editable requirement pins a ref rather than a
        // release. There is no version to query, and inventing one is the
        // requirements.txt mistake this table exists to avoid.
        if (entry && (entry.git || entry.file || entry.path || entry.editable)) continue;
        throw new Error(`"${name}" in ${section} has no version and no source`);
      }

      // pipenv pins exactly, always: "version": "==2.28.1". Anything else is a
      // range, and a range has no single installed version — the same reason
      // requirements.txt is not in the table. An 'error' here is visible and
      // gets fixed; quietly dropping the package would not be.
      if (!entry.version.startsWith('==')) {
        throw new Error(`"${name}" in ${section} is not pinned: ${JSON.stringify(entry.version)}`);
      }
      packages.push({ name, version: entry.version.slice(2), ecosystem });
    }
  }
  return dedupe(packages);
}
