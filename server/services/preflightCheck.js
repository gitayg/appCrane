// v2.6.16: pre-flight entry-exists check.
// Verify that deployhub.json's declared be.entry actually resolves in
// the just-built image, before we stop the old container or hand off
// to the 30s health probe. Catches the class of failure where a
// monorepo build puts the entry at /app/packages/server/dist/server.js
// but the manifest says "node server.js" — converts a 30s mystery
// timeout (whose docker logs only show wrapper info) into a 1s deploy
// failure with the missing path + suggested candidates spelled out.

import { execFileSync } from 'node:child_process';

const COMMON_ENTRY_NAMES = [
  'server.js', 'server.mjs',
  'index.js', 'index.mjs',
  'app.js', 'app.mjs',
  'main.js', 'main.mjs',
];

export async function preflightEntryCheck({ image, entry }) {
  const trimmed = (entry || '').trim();
  if (!trimmed) return { ok: true, skipped: 'empty entry' };

  // entryToCmd routes shell-metacharacter entries through `sh -c`. Skip
  // pre-flight for those — too varied to validate generically.
  if (/[;&|<>$`]/.test(trimmed)) {
    return { ok: true, skipped: 'shell-piped entry' };
  }

  const parts = trimmed.split(/\s+/);
  const exe = parts[0];

  if (exe === 'node' && parts.length >= 2 && !parts[1].startsWith('-')) {
    const relPath = parts[1].replace(/^\.?\/+/, '');
    if (imageFileExists(image, `/app/${relPath}`)) {
      return { ok: true };
    }
    const candidates = findCandidates(image);
    return {
      ok: false,
      shortReason: `declared entry "${entry}" — /app/${relPath} not found in built image`,
      message: buildNodeEntryNotFoundMessage(entry, relPath, candidates),
    };
  }

  if (exe === 'npm' && (parts[1] === 'start' || parts[1] === 'run')) {
    const startScript = readNpmStartScript(image);
    if (startScript) return { ok: true };
    const candidates = findCandidates(image);
    return {
      ok: false,
      shortReason: `declared entry "${entry}" — /app/package.json has no scripts.start`,
      message: buildNpmStartMissingMessage(entry, candidates),
    };
  }

  return { ok: true, skipped: `unrecognized entry pattern: ${exe}` };
}

function imageFileExists(image, absPath) {
  try {
    execFileSync(
      'docker',
      ['run', '--rm', '--entrypoint', 'sh', image, '-c', `test -e "${absPath}"`],
      { stdio: 'pipe', timeout: 15000 },
    );
    return true;
  } catch {
    return false;
  }
}

function readNpmStartScript(image) {
  try {
    const out = execFileSync(
      'docker',
      ['run', '--rm', '--entrypoint', 'sh', image, '-c', 'cat /app/package.json 2>/dev/null || true'],
      { stdio: 'pipe', timeout: 15000 },
    ).toString();
    if (!out.trim()) return null;
    const pkg = JSON.parse(out);
    return pkg?.scripts?.start || null;
  } catch {
    return null;
  }
}

function findCandidates(image) {
  // Find common entry-file names anywhere under /app (skipping node_modules),
  // capped at 30 raw hits, then ranked + trimmed to 5.
  const namePredicates = COMMON_ENTRY_NAMES
    .map((n) => `-name '${n}'`)
    .join(' -o ');
  const cmd =
    `find /app -maxdepth 6 -type f \\( ${namePredicates} \\) ` +
    `! -path '*/node_modules/*' 2>/dev/null | head -30`;
  try {
    const out = execFileSync(
      'docker',
      ['run', '--rm', '--entrypoint', 'sh', image, '-c', cmd],
      { stdio: 'pipe', timeout: 15000 },
    ).toString().trim();
    if (!out) return [];
    return rankCandidates(out.split('\n').filter(Boolean));
  } catch {
    return [];
  }
}

function rankCandidates(paths) {
  const score = (p) => {
    let s = 0;
    if (/\b(dist|build|out|lib)\b/.test(p)) s += 10;
    if (/\bserver\b/.test(p)) s += 5;
    if (/\b(test|tests|spec|specs|example|examples|fixture|fixtures|__tests__)\b/.test(p)) s -= 20;
    s -= p.split('/').length;
    return s;
  };
  return paths.sort((a, b) => score(b) - score(a)).slice(0, 5);
}

function buildNodeEntryNotFoundMessage(entry, relPath, candidates) {
  const out = [
    `Pre-flight check failed: deployhub.json declares be.entry: "${entry}", ` +
    `but /app/${relPath} does not exist in the built image.`,
  ];

  if (candidates.length === 0) {
    out.push(
      '',
      `No common entry-file names (${COMMON_ENTRY_NAMES.join(', ')}) ` +
      'were found under /app outside node_modules.',
      '',
      'Likely causes:',
      '  • The Dockerfile build stage failed silently and the entry was never produced.',
      '  • The entry file uses a non-standard name AppCrane could not auto-detect.',
      '',
      'Open the Dockerfile and verify it copies (or builds) your entry file into /app/.',
    );
    return out.join('\n');
  }

  const best = candidates[0];
  const bestRel = best.replace(/^\/app\//, '');

  out.push(
    '',
    'Candidate entry files found in the built image:',
    ...candidates.map((c) => `  • ${c}`),
    '',
    'Recommended fix — layout-agnostic (survives future build-path changes):',
    '  1. Add to your root package.json:',
    `       "scripts": { "start": "node ${bestRel}" }`,
    '  2. Update deployhub.json:',
    '       "be": { "entry": "npm start", "health": "<your health path>" }',
    '',
    'Or, minimal one-line change in deployhub.json:',
    `       "be": { "entry": "node ${bestRel}", "health": "<your health path>" }`,
    '',
    'Commit + push to your repo, then redeploy.',
  );
  return out.join('\n');
}

function buildNpmStartMissingMessage(entry, candidates) {
  const out = [
    `Pre-flight check failed: deployhub.json declares be.entry: "${entry}", ` +
    'but /app/package.json has no "scripts.start" field in the built image.',
  ];

  if (candidates.length > 0) {
    const best = candidates[0];
    const bestRel = best.replace(/^\/app\//, '');
    out.push(
      '',
      'Candidate entry files found in the built image:',
      ...candidates.map((c) => `  • ${c}`),
      '',
      'Recommended fix — add a start script to your root package.json:',
      `  "scripts": { "start": "node ${bestRel}" }`,
      '',
      'Commit + push, then redeploy.',
    );
  } else {
    out.push(
      '',
      'Add a start script to your root package.json, e.g.:',
      '  "scripts": { "start": "node <path/to/your/entry.js>" }',
      '',
      'Commit + push, then redeploy.',
    );
  }
  return out.join('\n');
}
