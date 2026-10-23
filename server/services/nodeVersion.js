// Node majors the generated build uses, newest first. Every line here still
// gets security fixes and has an official node:<major>-alpine image.
export const NODE_MAJORS = ['26', '24', '22'];

// Built only when the app asks for them by version. Both are end of life, so
// they get no fix for CVE-2026-111497 (Node2Shell) or anything after it.
export const LEGACY_NODE_MAJORS = ['20', '18'];

export const DEFAULT_NODE_MAJOR = '22';
export const PREVIOUS_DEFAULT_NODE_MAJOR = '20';

const BUILDABLE = [...NODE_MAJORS, ...LEGACY_NODE_MAJORS];
const SUPPORTED_TEXT = `${NODE_MAJORS.slice().reverse().join(', ')} (and ${LEGACY_NODE_MAJORS.join(' or ')} when asked for)`;

export function nodeImage(major) {
  return `node:${major}-alpine`;
}

export function legacyNodeWarning(major) {
  return `Node ${major} gets no security fixes (CVE-2026-111497); move to 22, 24 or 26`;
}

// npm range syntax (docs.npmjs.com/cli/configuring-npm/package-json#engines,
// node-semver): `||` = OR, space = AND, `a - b` hyphen ranges, ^ ~ > >= < <= =,
// x-ranges (20, 20.x, 20.*, *). Pre-release tags are dropped.

function parseVersion(raw) {
  const s = String(raw).trim().replace(/^[v=]+/i, '').replace(/[-+].*$/, '');
  const m = /^(\d+|[*xX])(?:\.(\d+|[*xX]))?(?:\.(\d+|[*xX]))?$/.exec(s);
  if (!m) throw new Error(`cannot parse version "${raw}"`);
  const parts = [];
  for (const p of m.slice(1, 4)) {
    if (p === undefined || /^[*xX]$/.test(p)) break;
    parts.push(Number(p));
  }
  return parts;
}

const pad = (parts) => [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];

function bump(parts, index) {
  const out = pad(parts).slice(0, index + 1);
  out[index] += 1;
  return pad(out);
}

function parseComparator(term) {
  const m = /^(\^|~>?|>=|<=|>|<|=)?(.+)$/.exec(term);
  const op = m[1] || '';
  const parts = parseVersion(m[2]);
  const last = parts.length - 1;

  if (parts.length === 0) return op === '<' || op === '>' ? [{ op: '<', v: [0, 0, 0] }] : [];
  if (op === '^') {
    const lead = parts.findIndex((n) => n !== 0);
    const idx = lead === -1 ? last : lead;
    return [{ op: '>=', v: pad(parts) }, { op: '<', v: bump(parts, idx) }];
  }
  if (op === '~' || op === '~>') {
    return [{ op: '>=', v: pad(parts) }, { op: '<', v: bump(parts, Math.min(last, 1)) }];
  }
  if (op === '' || op === '=') {
    if (parts.length === 3) return [{ op: '>=', v: parts }, { op: '<=', v: parts }];
    return [{ op: '>=', v: pad(parts) }, { op: '<', v: bump(parts, last) }];
  }
  if (op === '>') return parts.length === 3 ? [{ op: '>', v: parts }] : [{ op: '>=', v: bump(parts, last) }];
  if (op === '<=') return parts.length === 3 ? [{ op: '<=', v: parts }] : [{ op: '<', v: bump(parts, last) }];
  return [{ op, v: pad(parts) }];
}

export function parseNodeRange(input) {
  const text = String(input ?? '').trim();
  if (!text) throw new Error('empty range');
  return text.split(/\s*\|\|\s*/).map((alt) => {
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(alt.trim());
    if (hyphen) {
      const lo = parseVersion(hyphen[1]);
      const hi = parseVersion(hyphen[2]);
      const upper = hi.length === 3
        ? { op: '<=', v: hi }
        : hi.length === 0 ? null : { op: '<', v: bump(hi, hi.length - 1) };
      return [{ op: '>=', v: pad(lo) }, ...(upper ? [upper] : [])];
    }
    const terms = alt.replace(/(\^|~>?|>=|<=|>|<|=)\s+/g, '$1').split(/\s+/).filter(Boolean);
    if (!terms.length) return [];
    return terms.flatMap(parseComparator);
  });
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

// A major satisfies the range when SOME release in it does: the official image
// floats to the newest patch of the line, so the major is what gets chosen.
// Each AND-set is an interval; intersect it with [major.0.0, major+1.0.0).
export function majorSatisfies(alternatives, major) {
  const m = Number(major);
  return alternatives.some((ands) => {
    let lo = { v: [m, 0, 0], incl: true };
    let hi = { v: [m + 1, 0, 0], incl: false };
    for (const { op, v } of ands) {
      if (op === '>=' || op === '>') {
        const c = cmp(v, lo.v);
        if (c > 0 || (c === 0 && op === '>')) lo = { v, incl: op === '>=' };
      } else {
        const c = cmp(v, hi.v);
        if (c < 0 || (c === 0 && op === '<')) hi = { v, incl: op === '<=' };
      }
    }
    const c = cmp(lo.v, hi.v);
    return c < 0 || (c === 0 && lo.incl && hi.incl);
  });
}

function stated(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'string' && value.trim()) return value.trim();
  return null;
}

function readStatedNode({ manifest, packageJsons = [] }) {
  const fromManifest = stated(manifest?.node_version);
  if (fromManifest) return { range: fromManifest, source: 'deployhub.json node_version', strict: true };
  const fromManifestEngines = stated(manifest?.engines?.node);
  if (fromManifestEngines) return { range: fromManifestEngines, source: 'deployhub.json engines.node', strict: true };
  for (const { pkg, label } of packageJsons) {
    const fromPkg = stated(pkg?.engines?.node);
    if (fromPkg) return { range: fromPkg, source: `${label} engines.node`, strict: false };
  }
  return null;
}

function result(major, reason, warnings = []) {
  return { version: major, image: nodeImage(major), reason, warnings };
}

// Returns { version, image, reason, warnings }. A stated range that allows the
// default line gets the default (no surprise jump to a newer major); otherwise
// the newest buildable line that satisfies it. Precedence: deployhub.json
// (node_version, then engines.node) > package.json engines.node > default.
//
// deployhub.json is an instruction to AppCrane, so a value no buildable line
// satisfies throws. package.json engines is advisory (npm itself only warns
// unless engine-strict is set) and was not read before, so a value nothing
// satisfies falls back to the default with a warning instead of failing a
// deploy that worked yesterday.
export function pickNodeVersion({ manifest, packageJsons } = {}) {
  const s = readStatedNode({ manifest, packageJsons });

  if (!s) {
    return result(
      DEFAULT_NODE_MAJOR,
      `default (no Node version in deployhub.json or package.json engines); AppCrane's default changed from Node ${PREVIOUS_DEFAULT_NODE_MAJOR} to ${DEFAULT_NODE_MAJOR}`,
    );
  }

  let alternatives = null;
  let parseError = null;
  try { alternatives = parseNodeRange(s.range); } catch (err) { parseError = err.message; }

  const defaultFits = alternatives && majorSatisfies(alternatives, DEFAULT_NODE_MAJOR);
  const major = defaultFits ? DEFAULT_NODE_MAJOR : alternatives && BUILDABLE.find((v) => majorSatisfies(alternatives, v));
  if (major) {
    const how = defaultFits
      ? `${s.source} "${s.range}" allows the default Node ${DEFAULT_NODE_MAJOR}`
      : NODE_MAJORS.includes(major)
      ? `newest supported Node line satisfying ${s.source} "${s.range}"`
      : `${s.source} "${s.range}" allows only end-of-life Node lines; using the newest of them`;
    return result(major, how, LEGACY_NODE_MAJORS.includes(major) ? [legacyNodeWarning(major)] : []);
  }

  const why = parseError
    ? `which AppCrane could not parse (${parseError})`
    : 'and no Node line AppCrane builds satisfies it';
  if (s.strict) {
    throw new Error(
      `NODE_VERSION_UNSUPPORTED: ${s.source} is "${s.range}", ${why}. AppCrane builds Node ${SUPPORTED_TEXT}. ` +
      'Set node_version to one of those, or commit your own Dockerfile.',
    );
  }
  return result(
    DEFAULT_NODE_MAJOR,
    `default; ${s.source} "${s.range}" was ignored`,
    [`${s.source} is "${s.range}", ${why}; building on the default Node ${DEFAULT_NODE_MAJOR}. AppCrane builds Node ${SUPPORTED_TEXT}.`],
  );
}

export function describeNodeBuild(node) {
  return `Generated Dockerfile (${node.image}, non-root) - Node ${node.version}: ${node.reason}`;
}
