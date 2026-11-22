// Where `ARG APP_BASE_PATH` goes in an app-provided Dockerfile.
//
// The value differs between sandbox (/<slug>-sandbox/) and production
// (/<slug>/), and an ENV with a new value misses the build cache for every
// instruction after it. Declared right after FROM, it made a promote re-run the
// whole dependency install. It only has to be in place before the first
// instruction that can build the frontend, and nothing can build it before the
// source is in the image: the instructions ahead of the first COPY/ADD of
// anything other than dependency manifests only ever see package.json and
// lockfiles. So it goes immediately before that COPY/ADD.
//
// It stays in the FIRST stage, as before (an ARG is per-stage and an ENV is
// inherited only by stages built FROM this one). Moving it to other stages
// would put APP_BASE_PATH into the runtime environment of images that never had
// it there. A first stage with no such COPY (a deps-only stage) gets it at its
// end, which a `FROM <that stage>` build stage still inherits.

const MANIFEST_NAMES = [
  /^package[^/]*\.json$/,
  /^npm-shrinkwrap\.json$/,
  /^yarn\.lock$/,
  /^\.yarnrc(\.yml)?$/,
  /^\.yarn$/,
  /^pnpm-(lock|workspace)\.yaml$/,
  /^bun\.lockb?$/,
  /^\.npmrc$/,
  /^\.nvmrc$/,
  /^\.node-version$/,
  /^requirements[^/]*\.txt$/,
  /^Pipfile(\.lock)?$/,
  /^poetry\.lock$/,
  /^pyproject\.toml$/,
  /^go\.(mod|sum)$/,
  /^Gemfile(\.lock)?$/,
  /^composer\.(json|lock)$/,
  /^Cargo\.(toml|lock)$/,
];

/** Logical instructions: { keyword, text, start, end } with line indexes, continuations and heredocs joined. */
export function parseInstructions(lines) {
  let escape = '\\';
  for (const l of lines) {
    const m = /^\s*#\s*escape\s*=\s*(\S)\s*$/i.exec(l);
    if (m) { escape = m[1]; break; }
    if (!/^\s*#/.test(l) && l.trim()) break;
  }
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim() || /^\s*#/.test(line)) { i++; continue; }
    const start = i;
    let text = line;
    while (text.trimEnd().endsWith(escape) && i + 1 < lines.length) {
      i++;
      if (/^\s*#/.test(lines[i])) continue;
      text = text.trimEnd().slice(0, -1) + ' ' + lines[i];
    }
    const heredocs = [...text.matchAll(/<<(-?)["']?([A-Za-z_][A-Za-z0-9_]*)["']?/g)];
    for (const [, dash, word] of heredocs) {
      while (i + 1 < lines.length) {
        i++;
        if ((dash ? lines[i].trim() : lines[i]) === word) break;
      }
    }
    const keyword = (/^\s*(\w+)/.exec(text)?.[1] || '').toUpperCase();
    out.push({ keyword, text, start, end: i });
    i++;
  }
  return out;
}

function copySources(text) {
  const body = text.replace(/^\s*\w+\s+/, '');
  if (body.trimStart().startsWith('[')) {
    try {
      const arr = JSON.parse(body.trim());
      return Array.isArray(arr) ? arr.slice(0, -1).map(String) : null;
    } catch (_) {
      return null;
    }
  }
  const tokens = body.trim().split(/\s+/).filter((t) => !t.startsWith('--'));
  return tokens.slice(0, -1);
}

function isManifestOnlyCopy(text) {
  if (/\s--from[=\s]/i.test(text)) return false;
  const sources = copySources(text);
  if (!sources || !sources.length) return false;
  return sources.every((s) => {
    if (s.includes('$') || /^[a-z]+:\/\//i.test(s)) return false;
    const base = s.replace(/\/+$/, '').split('/').pop();
    return MANIFEST_NAMES.some((re) => re.test(base));
  });
}

function needsBasePath(ins) {
  if (/\bAPP_BASE_PATH\b/.test(ins.text)) return true;
  if (ins.keyword === 'COPY' || ins.keyword === 'ADD') return !isManifestOnlyCopy(ins.text);
  if (ins.keyword === 'RUN') return /--mount=[^\s]*type=bind/.test(ins.text);
  return false;
}

/**
 * The Dockerfile with `ARG APP_BASE_PATH=/` + `ENV APP_BASE_PATH=$APP_BASE_PATH`
 * placed in the first stage, or null when it already declares the ARG or has no FROM.
 */
export function placeAppBasePathArg(content) {
  if (/^\s*ARG\s+APP_BASE_PATH\b/im.test(content)) return null;
  const lines = content.split('\n');
  const instructions = parseInstructions(lines);
  const fromAt = instructions.findIndex((ins) => ins.keyword === 'FROM');
  if (fromAt === -1) return null;

  const decl = ['ARG APP_BASE_PATH=/', 'ENV APP_BASE_PATH=$APP_BASE_PATH'];
  let insertAt = null;
  let lastInStage = instructions[fromAt];
  for (let k = fromAt + 1; k < instructions.length; k++) {
    const ins = instructions[k];
    if (ins.keyword === 'FROM') break;
    if (needsBasePath(ins)) { insertAt = ins.start; break; }
    lastInStage = ins;
  }
  if (insertAt !== null) {
    lines.splice(insertAt, 0, ...decl);
  } else {
    lines.splice(lastInStage.end + 1, 0, ...decl, '');
  }
  return lines.join('\n');
}
