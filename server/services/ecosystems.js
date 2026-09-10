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
 * Grouped by language, most common first. Order is presentation only: the
 * scanner reads EVERY manifest it finds, so a repo holding both a
 * package-lock.json and a yarn.lock is read twice and deduped by OSV's own
 * answer rather than one file shadowing the other.
 *
 * `ecosystem` is spelled as OSV spells it — 'crates.io', 'RubyGems' and
 * 'Packagist' are case- and punctuation-sensitive in the API, and a near miss
 * returns an empty result set rather than an error. Measured, not assumed:
 * symfony/http-kernel 5.4.10 under 'Packagist' returns GHSA-h7vf-5wrv-9fhv,
 * and under 'packagist' returns nothing at all.
 */
export const MANIFESTS = [
  { file: 'package-lock.json', ecosystem: 'npm',        parse: parseNpmLock },
  { file: 'yarn.lock',         ecosystem: 'npm',        parse: parseYarnLock },
  { file: 'pnpm-lock.yaml',    ecosystem: 'npm',        parse: parsePnpmLock },
  { file: 'composer.lock',     ecosystem: 'Packagist',  parse: parseComposerLock },
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

// --- PHP -------------------------------------------------------------------

/**
 * Composer writes the git TAG into `version`, and more than half of Packagist
 * tags carry a leading v — 64 of BookStack's 113 runtime packages do. OSV does
 * not: its Packagist advisories spell every boundary and every enumerated
 * version bare (guzzlehttp/guzzle's version list runs "6.5.7", "6.5.8", and
 * GHSA-cwxw-98qj-8qjx opens at fixed "7.12.1"), because Packagist itself
 * normalises the tag away. So the v is a tag prefix, not part of the version.
 *
 * Measured against the live API before deciding, because the reasoning cuts the
 * other way for Go: guzzlehttp/guzzle answers 11 advisories for both "6.5.7"
 * and "v6.5.7", and 9 for both "6.5.8" and "v6.5.8", so the query endpoint
 * normalises it today and neither spelling is currently wrong. The strip is
 * chosen anyway because it matches the spelling OSV's own DATA uses, and the
 * data is what the endpoint's normalisation is a convenience over. This is the
 * exact mirror of the Go rule above: +incompatible is KEPT because it appears
 * inside OSV's Go ranges, and the v is DROPPED because it appears nowhere in
 * OSV's Packagist ranges.
 *
 * Only ever removed in front of a digit. A Composer release version is numeric;
 * the non-numeric forms are branch pins, and those never reach here.
 */
function stripComposerTagPrefix(version) {
  return /^v\d/.test(version) ? version.slice(1) : version;
}

function parseComposerLock(text, ecosystem) {
  const lock = JSON.parse(text);

  // `packages` is runtime, `packages-dev` is require-dev. A file with neither
  // is not a composer.lock, whatever it is called. `platform` and
  // `platform-dev` are separate top-level keys holding php and ext-* entries,
  // which are interpreter and extension constraints rather than Packagist
  // packages; they are not read, and must not be.
  if (!Array.isArray(lock.packages) && !Array.isArray(lock['packages-dev'])) {
    throw new Error('no "packages" or "packages-dev" array');
  }

  const packages = [];
  for (const section of ['packages', 'packages-dev']) {
    if (lock[section] === undefined) continue;
    if (!Array.isArray(lock[section])) {
      throw new Error(`"${section}" is not an array`);
    }

    for (const entry of lock[section]) {
      const name = entry?.name;
      if (typeof name !== 'string' || !name) {
        throw new Error(`an entry in ${section} has no name`);
      }
      const version = entry?.version;
      if (typeof version !== 'string' || !version) {
        throw new Error(`"${name}" in ${section} has no version`);
      }

      // dev-main, dev-master, 1.0.x-dev: Composer's spelling for "whatever that
      // branch points at today". There is no release to ask about — OSV returns
      // nothing for "dev-main" — and picking the branch alias instead would be
      // the requirements.txt mistake. Skipped for the same reason a Pipfile git
      // requirement is.
      if (version.startsWith('dev-') || version.endsWith('-dev')) continue;

      packages.push({ name, version: stripComposerTagPrefix(version), ecosystem });
    }
  }
  return dedupe(packages);
}

// --- yarn -------------------------------------------------------------------

/**
 * A range that names a protocol is not a registry range.
 *
 * file:, link:, portal:, workspace:, git+ssh:, https:, github: — all resolve to
 * something whose version is whatever the checkout declares, which need not
 * correspond to any published release. A semver range never contains a colon
 * or a slash, so this cannot swallow one; `^7.0.0`, `>=1 <2`, `1.x`, `*` and
 * `latest` all pass through.
 */
const NON_REGISTRY_RANGE = /^[a-z][a-z0-9+.-]*:|\//;

function parseYarnLock(text, ecosystem) {
  // TWO INCOMPATIBLE FORMATS UNDER ONE FILENAME. Classic (yarn 1) is a bespoke
  // text format writing `version "1.2.3"`; Berry (yarn 2+) is YAML writing
  // `version: 1.2.3` alongside an authoritative `resolution:`. Reading one with
  // the other's rules finds no versions at all, which is a clean scan for a
  // file nothing understood — so the format is identified from its own marker
  // and an unmarked file is refused rather than guessed at.
  if (/^__metadata:/m.test(text)) return parseYarnBerry(text, ecosystem);
  if (/^#\s*yarn lockfile v1\s*$/m.test(text)) return parseYarnClassic(text, ecosystem);
  throw new Error(
    'no "# yarn lockfile v1" header and no "__metadata:" block — cannot tell yarn ' +
    'classic from yarn berry, and the two spell every version differently'
  );
}

/**
 * The package a yarn-classic `resolved` URL names, or null if the URL is not a
 * registry tarball.
 *
 * This is the authority, and the entry's own descriptors are only the fallback,
 * because classic has no `name` field and its key is what the DEPENDENT called
 * the package. Measured across 11 real lockfiles / 10221 entries: `resolved` is
 * present on every single one, and disagrees with the descriptor once —
 * `ansi-html@0.0.7, ansi-html@^0.0.7, "ansi-html@https://registry.yarnpkg.com/
 * ansi-html-community/-/ansi-html-community-0.0.8.tgz"`, a `resolutions`
 * override that swaps in a different package under the old name. Read from the
 * descriptor that entry reports ansi-html 0.0.8, a version ansi-html has never
 * published; read from the URL it reports the ansi-html-community 0.0.8 that is
 * actually installed.
 *
 * A registry tarball is `<registry>/<name>/-/<file>.tgz`, and the name is taken
 * from the segments immediately before `/-/` rather than immediately after the
 * host — an Artifactory or Nexus mirror serves the same layout under a path
 * prefix (`/api/npm/npm-remote/lodash/-/lodash-4.17.21.tgz`), where counting
 * from the host yields "api".
 */
function yarnClassicResolvedName(url) {
  const cut = url.indexOf('/-/');
  if (cut === -1) return null;
  const segments = url.slice(0, cut).split('/');
  const last = segments[segments.length - 1];
  const scope = segments[segments.length - 2];
  if (!last) return null;
  return scope && scope.startsWith('@') ? `${scope}/${last}` : last;
}

/**
 * The package a yarn-classic descriptor names, or null when it names something
 * that is not on the registry. Used when `resolved` is absent or is not a
 * registry tarball — an offline mirror rewrites it to a bare filename.
 *
 * The separator is the FIRST @ after position 0, not the last. Both ends of
 * that matter: a scoped name opens with an @ that is not a separator, and a git
 * range closes with one (`foo@git+ssh://git@github.com/x/y.git`) that is not
 * either. Taking the last @ reads that descriptor as a package called
 * "foo@git+ssh://git" — a name no registry has, so OSV answers clean.
 */
function yarnClassicName(descriptor) {
  const d = unquote(descriptor.trim());
  const at = d.indexOf('@', d.startsWith('@') ? 1 : 0);
  if (at <= 0) throw new Error(`cannot read ${JSON.stringify(d)} as a yarn descriptor`);

  const range = d.slice(at + 1);

  // ALIASES: `yarn add mylodash@npm:lodash@4.17.15` keys the entry by the
  // ALIAS. Asking OSV about "mylodash" records a lodash with known advisories
  // as clean.
  if (range.startsWith('npm:')) {
    const inner = range.slice('npm:'.length);
    const iat = inner.indexOf('@', inner.startsWith('@') ? 1 : 0);
    return iat > 0 ? inner.slice(0, iat) : inner;
  }

  if (NON_REGISTRY_RANGE.test(range)) return null;
  return d.slice(0, at);
}

function parseYarnClassic(text, ecosystem) {
  const packages = [];
  let descriptors = null;
  let version = null;
  let resolved = null;
  let headerLine = 0;
  let lineNo = 0;

  const flush = () => {
    if (!descriptors) return;
    if (!version) {
      throw new Error(`the entry at line ${headerLine} has no version`);
    }

    const fromUrl = resolved && yarnClassicResolvedName(resolved);
    if (fromUrl) {
      packages.push({ name: fromUrl, version, ecosystem });
    } else {
      // Several descriptors can share one entry when they resolved to the same
      // release; they name the same package, so at most one survives dedupe.
      for (const d of descriptors) {
        const name = yarnClassicName(d);
        if (name) packages.push({ name, version, ecosystem });
      }
    }

    descriptors = null;
    version = null;
    resolved = null;
  };

  for (const raw of text.split('\n')) {
    lineNo++;
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;

    // An entry header sits flush left and may carry several comma-separated
    // descriptors that resolved to the same release.
    if (!/^\s/.test(raw)) {
      flush();
      const head = raw.trim();
      if (!head.endsWith(':')) {
        throw new Error(`line ${lineNo}: expected an entry header ending in ":", got ${JSON.stringify(head)}`);
      }
      headerLine = lineNo;
      descriptors = head.slice(0, -1).split(/,\s+/);
      continue;
    }

    let m = /^\s+version\s+"([^"]+)"\s*$/.exec(raw);
    if (m) { version = m[1]; continue; }
    m = /^\s+resolved\s+"([^"]+)"\s*$/.exec(raw);
    if (m) resolved = m[1];
  }
  flush();

  return dedupe(packages);
}

/**
 * The package a Berry `resolution:` names, or null when it is not a registry
 * package.
 *
 * A resolution is `<ident>@<protocol>:<selector>`, and the ident is what the
 * package IS rather than what the dependent called it — which is why Berry is
 * read from `resolution` and not from the entry key. `esbuild@npm:esbuild-wasm@
 * ^0.23.0` is keyed under esbuild and resolves to esbuild-wasm; docusaurus
 * ships `react-loadable@npm:@docusaurus/react-loadable@6.0.0`, an unscoped
 * alias of a scoped package. Both are real lines from yarn's own lockfile.
 *
 * The protocol is found from the FIRST @ after position 0 for the same reason
 * the classic reader uses the first: a patch resolution embeds a second, whole
 * descriptor after its own protocol
 * (`fsevents@patch:fsevents@npm%3A2.3.2#optional!builtin`), so the last @ lands
 * in the middle of it.
 */
function yarnBerryName(resolution) {
  const m = /^(.+?)@([a-z][a-z0-9+.-]*):/.exec(resolution);
  if (!m) throw new Error(`cannot read ${JSON.stringify(resolution)} as a yarn resolution`);
  const [, ident, protocol] = m;

  // patch: is a local diff applied over a registry release. The ident and the
  // `version:` field are both the upstream ones, and so are the advisories —
  // dropping it would hide a finding on a package that is genuinely installed.
  if (protocol === 'npm' || protocol === 'patch') return ident;

  // workspace:, portal:, link:, file:, exec:, https:, git*: — published
  // nowhere, or published at a version the checkout invented.
  return null;
}

function parseYarnBerry(text, ecosystem) {
  const packages = [];
  let open = false;
  let version = null;
  let resolution = null;
  let entryLine = 0;
  let lineNo = 0;

  const flush = () => {
    if (!open) return;
    if (!version) throw new Error(`the entry at line ${entryLine} has no "version:"`);
    if (!resolution) throw new Error(`the entry at line ${entryLine} has no "resolution:"`);
    const name = yarnBerryName(resolution);
    if (name) packages.push({ name, version, ecosystem });
    open = false;
    version = null;
    resolution = null;
  };

  for (const raw of text.split('\n')) {
    lineNo++;
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;

    if (!/^\s/.test(raw)) {
      flush();
      const head = raw.trim();
      if (!head.endsWith(':')) {
        throw new Error(`line ${lineNo}: expected an entry header ending in ":", got ${JSON.stringify(head)}`);
      }
      entryLine = lineNo;
      // __metadata carries the lockfile version and cache key, not a package.
      // Its `version: 10` would otherwise be read as a release of a package
      // called __metadata.
      open = unquote(head.slice(0, -1)) !== '__metadata';
      continue;
    }
    if (!open) continue;

    // Anchored at EXACTLY two spaces. Berry nests `dependencies:` and
    // `peerDependencies:` maps one level deeper, and a dependency whose name is
    // literally `version` or `resolution` is a legal npm package.
    let m = /^ {2}version:\s*(.+?)\s*$/.exec(raw);
    if (m) { version = unquote(m[1]); continue; }
    m = /^ {2}resolution:\s*(.+?)\s*$/.exec(raw);
    if (m) resolution = unquote(m[1]);
  }
  flush();

  return dedupe(packages);
}

// --- pnpm -------------------------------------------------------------------

// pnpm has rewritten its key format twice, and each spelling parses cleanly as
// the others' garbage rather than failing:
//
//   5.x   /typescript/4.7.4              /react-dom/17.0.2_react@17.0.2
//   6.x   /typescript@4.7.4              /react-dom@17.0.2(react@17.0.2)
//   9.x   typescript@4.7.4               react-dom@17.0.2
//
// Read as 9.x, a 5.x key yields the package "/typescript/4" at version "7.4" —
// a name no registry has, and therefore a clean answer. Only 9.x is read, and
// the rest are refused BY VERSION and by name. That is a deliberate trade: an
// 'error' with a fix in it is visible, and the 5.x and 6.x peer-dependency
// suffixes have never been measured against a real file here.
//
// Written by pnpm 9 (March 2024) and pnpm 10, which still writes '9.0'.
const PNPM_SUPPORTED_LOCKFILE = /^9(\.|$)/;

/**
 * A 9.x `packages:` key is `name@version`. The separator is taken as the LAST @
 * because that is the rule the format states, but measured across 4165 real
 * keys in three lockfiles, the last @ and the first-after-the-scope are the
 * SAME @ every time — the paren cut below is what keeps it that way, and
 * without it neither spelling is right. So this line is not where a scoped name
 * is won or lost; the cut is.
 */
function pnpmPackage(key, ecosystem) {
  // Peer-dependency variants live in `snapshots:` rather than here — measured
  // at 0 of 745 and 0 of 1719 keys across two real 9.0 lockfiles — but a key is
  // cut at its first paren anyway, because a name cannot contain one and a
  // suffix left on would be read as part of the version.
  const paren = key.indexOf('(');
  const bare = paren === -1 ? key : key.slice(0, paren);

  const at = bare.lastIndexOf('@');
  if (at <= 0) throw new Error(`cannot read ${JSON.stringify(key)} as "name@version"`);

  const version = bare.slice(at + 1);

  // A tarball, git or file dependency is keyed by its URL where the version
  // goes. There is no registry release behind it to ask about, and the URL is
  // not one.
  if (!/^\d/.test(version)) return null;

  return { name: bare.slice(0, at), version, ecosystem };
}

function parsePnpmLock(text, ecosystem) {
  const declared = /^lockfileVersion:\s*(.+?)\s*$/m.exec(text);
  if (!declared) throw new Error('no lockfileVersion — this is not a pnpm-lock.yaml');

  const lockfileVersion = unquote(declared[1]);
  if (!PNPM_SUPPORTED_LOCKFILE.test(lockfileVersion)) {
    throw new Error(
      `lockfileVersion ${JSON.stringify(lockfileVersion)} is not read — only 9.x is. ` +
      '5.x keys packages as "/name/version" and 6.x as "/name@version", each with its ' +
      'own peer-dependency suffix; regenerate the lockfile with pnpm 9 or later'
    );
  }

  // Only the keys of `packages:` are needed, and they are one flat run of
  // exactly-two-space lines under a flush-left header — so this reads that run
  // rather than the file. No YAML library is a dependency of this platform and
  // none is added for a shape this narrow, the same call the TOML block reader
  // above already makes for Cargo.lock and poetry.lock.
  const packages = [];
  let inPackages = false;
  let sawPackages = false;
  let lineNo = 0;

  for (const raw of text.split('\n')) {
    lineNo++;
    if (!raw.trim()) continue;

    if (!/^\s/.test(raw)) {
      inPackages = raw.trimEnd() === 'packages:';
      if (inPackages) sawPackages = true;
      continue;
    }
    if (!inPackages) continue;

    // Four-space lines are the entry's own fields — resolution, engines, cpu,
    // os, deprecated, hasBin. Only the two-space keys are packages.
    if (!/^ {2}\S/.test(raw)) continue;

    const head = raw.trim();
    if (!head.endsWith(':')) {
      throw new Error(`line ${lineNo}: expected a "name@version:" key, got ${JSON.stringify(head)}`);
    }
    const pkg = pnpmPackage(unquote(head.slice(0, -1)), ecosystem);
    if (pkg) packages.push(pkg);
  }

  // snapshots: without packages: is a truncated file, and an importers-only
  // lockfile describes a workspace with nothing installed. Either way nothing
  // was read, and nothing-read must not be recorded as nothing-vulnerable.
  if (!sawPackages) throw new Error('no "packages:" section');

  return dedupe(packages);
}
