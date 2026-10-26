// PHP minors AppCrane's generated build can use, newest first. Only lines that
// still get security fixes AND have an official php:<v>-apache image belong
// here. Dates from php.net/supported-versions.php.
export const PHP_VERSIONS = [
  { version: '8.5', activeUntil: '2027-12-31', securityUntil: '2029-12-31' },
  { version: '8.4', activeUntil: '2026-12-31', securityUntil: '2028-12-31' },
  { version: '8.3', activeUntil: '2025-12-31', securityUntil: '2027-12-31' },
];

// Used by an app whose composer.json states no php requirement and that has
// never been deployed with the generated PHP build before.
export const DEFAULT_PHP_VERSION = '8.5';

const SUPPORTED = PHP_VERSIONS.map((v) => v.version);

export function phpImage(version) {
  return `php:${version}-apache`;
}

export function isSupportedPhpVersion(version) {
  return SUPPORTED.includes(version);
}

// Composer constraint syntax, per getcomposer.org/doc/articles/versions.md:
//   space or comma = AND (binds tighter), `||` or legacy `|` = OR,
//   ^1.2.3 = >=1.2.3 <2.0.0, ^0.3 = >=0.3.0 <0.4.0,
//   ~1.2 = >=1.2 <2.0.0 (NOT npm's <1.3), ~1.2.3 = >=1.2.3 <1.3.0, ~1 = ~1.0,
//   1.0.* = >=1.0 <1.1, `1.0 - 2.0` = >=1.0.0 <2.1, `*` = anything.
// Stability flags (@dev, -beta…) are dropped: a php image is always stable.

function parseVersion(raw) {
  const s = String(raw).trim().replace(/^v/i, '').replace(/@\w+$/, '').replace(/-.*$/, '');
  const m = /^(\d+|[*xX])(?:\.(\d+|[*xX]))?(?:\.(\d+|[*xX]))?(?:\.(\d+|[*xX]))?$/.exec(s);
  if (!m) throw new Error(`cannot parse version "${raw}"`);
  const parts = [];
  for (const p of m.slice(1, 4)) {
    if (p === undefined || /^[*xX]$/.test(p)) break;
    parts.push(Number(p));
  }
  return { parts, wildcard: /[*xX]/.test(s) };
}

const pad = (parts) => [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];

function bump(parts, index) {
  const out = pad(parts).slice(0, index + 1);
  out[index] += 1;
  return pad(out);
}

function wildcardRange(parts) {
  if (parts.length === 0) return [];
  return [{ op: '>=', v: pad(parts) }, { op: '<', v: bump(parts, parts.length - 1) }];
}

function parseTerm(term) {
  if (term === '*' || /^[xX]$/.test(term)) return [];
  const m = /^(\^|~|>=|<=|<>|!=|==|=|>|<)?(.+)$/.exec(term);
  const op = m[1] || '';
  const { parts, wildcard } = parseVersion(m[2]);

  if (op === '^') {
    const lead = parts.findIndex((n) => n !== 0);
    const idx = lead === -1 ? Math.max(parts.length - 1, 0) : lead;
    return [{ op: '>=', v: pad(parts) }, { op: '<', v: bump(parts, idx) }];
  }
  if (op === '~') {
    const idx = parts.length <= 2 ? 0 : parts.length - 2;
    return [{ op: '>=', v: pad(parts) }, { op: '<', v: bump(parts, idx) }];
  }
  if (!op || op === '=' || op === '==') {
    if (wildcard) return wildcardRange(parts);
    return [{ op: '==', v: pad(parts) }];
  }
  if (op === '<>') return [{ op: '!=', v: pad(parts) }];
  return [{ op, v: pad(parts) }];
}

export function parseComposerConstraint(input) {
  const text = String(input ?? '').trim();
  if (!text) throw new Error('empty constraint');
  return text.split(/\s*\|\|?\s*/).map((alt) => {
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(alt.trim());
    if (hyphen) {
      const lo = parseVersion(hyphen[1]);
      const hi = parseVersion(hyphen[2]);
      const upper = hi.parts.length >= 3
        ? { op: '<=', v: pad(hi.parts) }
        : { op: '<', v: bump(hi.parts, hi.parts.length - 1) };
      return [{ op: '>=', v: pad(lo.parts) }, upper];
    }
    const terms = alt
      .replace(/(>=|<=|<>|!=|==|=|>|<|\^|~)\s+/g, '$1')
      .split(/[\s,]+/)
      .filter(Boolean);
    if (!terms.length) throw new Error('empty alternative');
    return terms.flatMap(parseTerm);
  });
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function holds({ op, v }, x) {
  const c = cmp(x, v);
  switch (op) {
    case '>=': return c >= 0;
    case '>': return c > 0;
    case '<=': return c <= 0;
    case '<': return c < 0;
    case '==': return c === 0;
    case '!=': return c !== 0;
    default: return false;
  }
}

// A minor satisfies the constraint when SOME patch release of it does — the
// official image floats to the latest patch, so the minor is what is chosen.
// Any satisfying patch range inside a minor starts at 0 or next to a patch
// number the constraint names, so testing those candidates is exact.
export function minorSatisfies(alternatives, minor) {
  const [maj, min] = minor.split('.').map(Number);
  return alternatives.some((ands) => {
    const patches = new Set([0, 99999]);
    for (const { v } of ands) {
      if (v[0] === maj && v[1] === min) {
        patches.add(v[2]);
        patches.add(v[2] + 1);
        if (v[2] > 0) patches.add(v[2] - 1);
      }
    }
    return [...patches].some((p) => ands.every((t) => holds(t, [maj, min, p])));
  });
}

export function readPhpConstraint(composerJson) {
  const platform = composerJson?.config?.platform?.php;
  if (typeof platform === 'string' && platform.trim()) {
    return { constraint: platform.trim(), source: 'composer.json config.platform.php' };
  }
  const required = composerJson?.require?.php;
  if (typeof required === 'string' && required.trim()) {
    return { constraint: required.trim(), source: 'composer.json require.php' };
  }
  return null;
}

// Returns { version, image, reason }. A constraint always wins; without one a
// version pinned by the app's previous generated-PHP deploy is kept; otherwise
// DEFAULT_PHP_VERSION. Throws when a stated constraint matches nothing.
export function choosePhpVersion({ composerJson, pinnedPhpVersion } = {}) {
  const stated = readPhpConstraint(composerJson);
  const supportedText = SUPPORTED.join(', ');

  if (stated) {
    let alternatives;
    try {
      alternatives = parseComposerConstraint(stated.constraint);
    } catch (err) {
      throw new Error(
        `PHP_VERSION_UNSUPPORTED: ${stated.source} is "${stated.constraint}", which AppCrane could not ` +
        `parse (${err.message}). Supported PHP versions: ${supportedText}.`,
      );
    }
    const version = SUPPORTED.find((v) => minorSatisfies(alternatives, v));
    if (!version) {
      throw new Error(
        `PHP_VERSION_UNSUPPORTED: ${stated.source} is "${stated.constraint}", and no PHP version AppCrane ` +
        `builds satisfies it. Supported PHP versions: ${supportedText}. Widen the constraint, or commit ` +
        'your own Dockerfile.',
      );
    }
    return {
      version,
      image: phpImage(version),
      reason: `newest supported version satisfying ${stated.source} "${stated.constraint}"`,
    };
  }

  if (pinnedPhpVersion && isSupportedPhpVersion(pinnedPhpVersion)) {
    return {
      version: pinnedPhpVersion,
      image: phpImage(pinnedPhpVersion),
      reason: 'pinned from the previous deploy (no php requirement in composer.json)',
    };
  }

  const fallback = pinnedPhpVersion
    ? `default; the previous deploy used PHP ${pinnedPhpVersion}, which AppCrane no longer builds`
    : 'default (no php requirement in composer.json)';
  return { version: DEFAULT_PHP_VERSION, image: phpImage(DEFAULT_PHP_VERSION), reason: fallback };
}

// The PHP minor recorded on the app's most recent deployment that went live
// (rolled_back rows went live before being replaced). Same env first; an env's
// first deploy follows the other env so production does not jump ahead of the
// sandbox it was tested in.
export function pinnedPhpVersionFor(db, appId, env) {
  const sql =
    "SELECT php_version FROM deployments WHERE app_id = ? AND php_version IS NOT NULL " +
    "AND status IN ('live', 'rolled_back')";
  const order = ' ORDER BY id DESC LIMIT 1';
  const same = db.prepare(`${sql} AND env = ?${order}`).get(appId, env);
  if (same) return same.php_version;
  return db.prepare(`${sql}${order}`).get(appId)?.php_version ?? null;
}

export function describePhpBuild(php) {
  return `Generated Dockerfile (${php.image}, non-root) - PHP ${php.version}: ${php.reason}`;
}
