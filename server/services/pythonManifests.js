// Python manifests that are not lockfiles: requirements.txt and pyproject.toml.
//
// requirements.txt is read for its exact pins only. `name==1.2.3` (or `===`)
// is what pip installs, so it is asked about; every other line is a constraint
// (`django>=4.2`, `requests~=2.31`, a bare `boto3`) that names no installed
// version, and guessing one is a wrong clean as easily as a wrong finding. Those
// lines are never queried: they come back as notes, which the release check
// shows as a warning, and a file that pins nothing is recorded 'skipped' with
// that reason rather than scanned clean.
//
// pyproject.toml lists ranges, never what was resolved, so a project with only
// a pyproject.toml has nothing to scan. noManifestReason() says so by name.

import { existsSync, readFileSync } from 'fs';
import { basename, join } from 'path';

const NAME_RE = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$/;
const PIN_RE = /^===?\s*([^\s,;*]+)$/;
const SHOWN = 8;

/** PEP 503 name: lowercase, runs of - _ . collapsed to one hyphen. */
export function canonicalPyName(name) {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

function logicalLines(text) {
  const out = [];
  let buf = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)#.*$/, '');
    if (/\\\s*$/.test(line)) { buf += line.replace(/\\\s*$/, ' '); continue; }
    out.push((buf + line).trim());
    buf = '';
  }
  if (buf.trim()) out.push(buf.trim());
  return out.filter(Boolean);
}

/**
 * Sort every line of a requirements.txt into what can be asked about and what
 * cannot.
 * @returns {{ pinned: Array<{name: string, version: string}>, unpinned: string[], includes: string[], other: string[] }}
 */
export function readRequirements(text) {
  const out = { pinned: [], unpinned: [], includes: [], other: [] };
  for (const line of logicalLines(text)) {
    if (/^(-r|-c|--requirement|--constraint)(\s|=|$)/.test(line)) { out.includes.push(line); continue; }
    const editable = /^(-e|--editable)(\s+|=)(.*)$/.exec(line);
    if (!editable && line.startsWith('-')) continue;
    const spec = (editable ? editable[3] : line).replace(/\s+--[a-z][\w-]*(?:=\S*)?/gi, '').split(';')[0].trim();
    // A local path (the app itself, `-e .`, or a sibling package) is not on
    // PyPI and not a dependency to scan, as with poetry's directory sources.
    if (/^(?:[./~]|file:)/i.test(spec)) continue;
    if (editable || /^[a-z][a-z0-9+.-]*:\/\//i.test(spec) || spec.includes('@')) { out.other.push(spec); continue; }
    const m = NAME_RE.exec(spec);
    if (!m) { out.other.push(spec); continue; }
    const pin = PIN_RE.exec(m[2].trim());
    if (pin) out.pinned.push({ name: canonicalPyName(m[1]), version: pin[1] });
    else out.unpinned.push(spec);
  }
  return out;
}

/** The parser the manifest table calls: exact pins only, never a guess. */
export function parseRequirementsTxt(text, ecosystem) {
  const seen = new Set();
  const packages = [];
  for (const p of readRequirements(text).pinned) {
    const id = `${p.name}@${p.version}`;
    if (seen.has(id)) continue;
    seen.add(id);
    packages.push({ ...p, ecosystem });
  }
  return packages;
}

const list = (items) => items.slice(0, SHOWN).join(', ') + (items.length > SHOWN ? `, and ${items.length - SHOWN} more` : '');

/**
 * What a scan of these manifests did not cover, one sentence per gap.
 * @param {Array<{ path: string, entry?: { file: string } }>} manifests
 * @param {string} [root] stripped from the paths shown
 */
export function manifestNotes(manifests, root = '') {
  const notes = [];
  for (const m of manifests) {
    if (basename(m.path) !== 'requirements.txt') continue;
    let r;
    try { r = readRequirements(readFileSync(m.path, 'utf8')); } catch { continue; }
    const where = root && m.path.startsWith(root) ? m.path.slice(root.length).replace(/^\/+/, '') : basename(m.path);
    if (r.unpinned.length) notes.push(`${where}: ${r.unpinned.length} requirement(s) not pinned with == were not scanned (${list(r.unpinned)}); pin them, or commit a lockfile (uv.lock, poetry.lock, Pipfile.lock)`);
    if (r.includes.length) notes.push(`${where}: ${r.includes.length} -r/-c include line(s) were not followed (${list(r.includes)})`);
    if (r.other.length) notes.push(`${where}: ${r.other.length} VCS or URL requirement(s) name no PyPI release and were not scanned (${list(r.other)})`);
  }
  if (manifests.length && root && existsSync(join(root, 'pyproject.toml')) && !manifests.some((m) => m.ecosystem === 'PyPI')) {
    notes.push('pyproject.toml: no uv.lock, poetry.lock, Pipfile.lock or requirements.txt records its installed versions, so its Python dependencies were not scanned');
  }
  return notes;
}

/** Why a release with no readable manifest has nothing to scan. */
export function noManifestReason(releaseDir, fallback) {
  if (releaseDir && existsSync(join(releaseDir, 'pyproject.toml'))) {
    return 'pyproject.toml lists version ranges, not what is installed, and there is no uv.lock, poetry.lock, Pipfile.lock or ==-pinned requirements.txt, so there is nothing to scan';
  }
  return fallback;
}
