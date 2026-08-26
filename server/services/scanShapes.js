// The payload shapes every scanning surface agrees on.
//
// v2.52.0 was built by parallel agents against frozen FUNCTION SIGNATURES, and
// that was not enough. The scanner stored findings as { name, version, ids[] }
// while the brief for the digest described { package, id, fixed_version }. The
// email only rendered because its author happened to code defensively
// (`f.name ?? f.package`). Nothing enforced the agreement — it held by luck.
//
// So the shapes are executable now, not described. Producers assert what they
// emit and consumers assert what they receive; a mismatch fails a test instead
// of rendering "undefined" in someone's inbox.

/** A dependency to ask OSV about. `ecosystem` is OSV's name, e.g. npm, PyPI, Go. */
export function assertPackage(p, where = 'package') {
  const bad = (m) => { throw new Error(`${where}: ${m} — got ${JSON.stringify(p)}`); };
  if (!p || typeof p !== 'object') bad('not an object');
  if (typeof p.name !== 'string' || !p.name) bad('name must be a non-empty string');
  if (typeof p.version !== 'string' || !p.version) bad('version must be a non-empty string');
  if (typeof p.ecosystem !== 'string' || !p.ecosystem) {
    bad('ecosystem must be a non-empty string — it travels WITH the package so one scan can ' +
        'mix npm and PyPI in a single OSV batch, rather than being hardcoded at query time');
  }
  return p;
}

/**
 * One vulnerable dependency.
 *
 * `ids` is a LIST: a single package version routinely carries several
 * advisories (lodash 4.17.15 returned six from the live API), and collapsing to
 * the first under-reports.
 *
 * `fixed` is the version that resolves them, or null when OSV published no
 * fixed event. Nullable on purpose — but a null must mean "OSV did not say",
 * never "we did not look". Discarding it was the single most actionable field
 * missing from the digest: an email that names a problem without naming the
 * upgrade costs the reader a separate investigation.
 */
export function assertFinding(f, where = 'finding') {
  const bad = (m) => { throw new Error(`${where}: ${m} — got ${JSON.stringify(f)}`); };
  if (!f || typeof f !== 'object') bad('not an object');
  if (typeof f.name !== 'string' || !f.name) bad('name must be a non-empty string');
  if (typeof f.version !== 'string' || !f.version) bad('version must be a non-empty string');
  if (typeof f.ecosystem !== 'string' || !f.ecosystem) bad('ecosystem must be a non-empty string');
  if (!Array.isArray(f.ids) || f.ids.length === 0) bad('ids must be a non-empty array of advisory ids');
  if (f.ids.some((i) => typeof i !== 'string' || !i)) bad('every id must be a non-empty string');
  if (!(f.fixed === null || (typeof f.fixed === 'string' && f.fixed))) {
    bad('fixed must be a non-empty string or null (null = OSV published no fixed version)');
  }
  return f;
}

/** Convenience for tests and producers. */
export function assertFindings(list, where = 'findings') {
  if (!Array.isArray(list)) throw new Error(`${where}: not an array`);
  list.forEach((f, i) => assertFinding(f, `${where}[${i}]`));
  return list;
}
