// A Node runtime AppCrane downloads for itself, for a host where it cannot
// install one through the system package manager.
//
// Self-update used to refuse outright on such a host: below the Node floor,
// not root, so `apt-get install nodejs` was impossible, so no update at all
// until someone with sudo upgraded the box by hand. This installs the official
// build from nodejs.org into the AppCrane directory instead, with no root:
//
//   <appcrane>/.runtime/node-v22.x.y-linux-x64/   the unpacked release
//   <appcrane>/.runtime/current -> node-v22...   what safe-boot.sh puts on PATH
//
// Under the AppCrane directory rather than DATA_DIR because the two readers
// must agree on it, and safe-boot.sh does not see a DATA_DIR that an operator
// set in .env (the server reads .env itself; systemd does not pass it on).
// `git reset --hard` leaves it alone: it is untracked and gitignored.
//
// Integrity: the tarball's SHA-256 must match the line for it in the release's
// SHASUMS256.txt, both fetched from nodejs.org over TLS. The unpacked binary
// must then run and report the requested major; that also catches a host whose
// glibc is too old for the official build, before anything depends on it.
//
// Also runnable as a script, which is how safe-boot.sh reaches it on a host
// that is already stuck below the floor:
//   node server/services/bundledNode.js 22     -> prints the bin directory

import { execFileSync } from 'child_process';
import { createHash, randomBytes } from 'crypto';
import { mkdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

export const NODE_DIST = 'https://nodejs.org/dist';

const DIST_ARCH = { x64: 'x64', arm64: 'arm64' };

/** The official build's name for this CPU, or null when there is none we use. */
export function nodeDistArch(arch) {
  return DIST_ARCH[arch] || null;
}

export function runtimeRoot(appcraneDir) {
  return join(appcraneDir, '.runtime');
}

export function bundledBinDir(appcraneDir) {
  return join(runtimeRoot(appcraneDir), 'current', 'bin');
}

async function fetchOk(fetchImpl, url, as) {
  const r = await fetchImpl(url);
  if (!r.ok) throw new Error(`GET ${url} answered HTTP ${r.status}`);
  if (as === 'json') return r.json();
  if (as === 'text') return r.text();
  return Buffer.from(await r.arrayBuffer());
}

/**
 * Download, verify and activate the newest Node `major` for this host.
 * Returns { version, binDir }. Throws, leaving `current` untouched, on any
 * failure: a half-installed runtime must never become the one that boots.
 */
export async function installBundledNode({
  major,
  appcraneDir,
  platform = process.platform,
  arch = process.arch,
  baseUrl = NODE_DIST,
  fetchImpl = globalThis.fetch,
  log = () => {},
}) {
  if (platform !== 'linux') throw new Error(`a bundled Node is only installed on Linux (this host is ${platform})`);
  const distArch = nodeDistArch(arch);
  if (!distArch) throw new Error(`no official Node build is used for CPU architecture '${arch}'`);
  if (!Number.isInteger(major) || major < 1) throw new Error(`invalid Node major '${major}'`);

  const index = await fetchOk(fetchImpl, `${baseUrl}/index.json`, 'json');
  // index.json is newest first; take the newest release of the wanted major
  // that ships a tarball for this CPU.
  const release = index.find((r) => r.version?.startsWith(`v${major}.`)
    && Array.isArray(r.files) && r.files.includes(`linux-${distArch}`));
  if (!release) throw new Error(`nodejs.org lists no Node ${major} release for linux-${distArch}`);
  const version = release.version;
  if (!/^v\d+\.\d+\.\d+$/.test(version)) throw new Error(`unexpected version string '${version}'`);

  const root = runtimeRoot(appcraneDir);
  const dest = join(root, `node-${version}-linux-${distArch}`);
  // Already unpacked and working (a retried update): just point `current` at it.
  let existing = '';
  try { existing = execFileSync(join(dest, 'bin', 'node'), ['-v'], { stdio: 'pipe', timeout: 15000 }).toString().trim(); } catch (_) {}
  if (existing === version) {
    activate(root, dest);
    log(`Node ${version} already present at ${dest}`);
    return { version, binDir: bundledBinDir(appcraneDir) };
  }

  const file = `node-${version}-linux-${distArch}.tar.gz`;
  const sums = await fetchOk(fetchImpl, `${baseUrl}/${version}/SHASUMS256.txt`, 'text');
  const line = sums.split('\n').find((l) => l.trim().endsWith(`  ${file}`));
  const expected = line?.trim().split(/\s+/)[0];
  if (!expected || !/^[0-9a-f]{64}$/.test(expected)) throw new Error(`SHASUMS256.txt has no checksum for ${file}`);

  log(`downloading ${file}`);
  const tarball = await fetchOk(fetchImpl, `${baseUrl}/${version}/${file}`, 'buffer');
  const actual = createHash('sha256').update(tarball).digest('hex');
  if (actual !== expected) {
    throw new Error(`checksum mismatch for ${file}: expected ${expected}, got ${actual}. Not installing it.`);
  }

  mkdirSync(root, { recursive: true });
  const nonce = randomBytes(6).toString('hex');
  const staging = join(root, `.staging-${nonce}`);
  const tarPath = join(root, `.download-${nonce}.tar.gz`);
  try {
    writeFileSync(tarPath, tarball);
    mkdirSync(staging);
    execFileSync('tar', ['-xzf', tarPath, '-C', staging, '--strip-components=1'], { stdio: 'pipe', timeout: 120000 });

    // Runs, and is the major that was asked for. An official build on a host
    // whose glibc is too old fails right here, not at the next boot.
    let reported;
    try {
      reported = execFileSync(join(staging, 'bin', 'node'), ['-v'], { stdio: 'pipe', timeout: 15000 }).toString().trim();
    } catch (err) {
      throw new Error(`the downloaded Node does not run on this host (${(err.stderr || err.message).toString().trim()})`);
    }
    if (!reported.startsWith(`v${major}.`)) throw new Error(`the downloaded Node reports ${reported}, not v${major}.x`);

    rmSync(dest, { recursive: true, force: true });
    renameSync(staging, dest);
    activate(root, dest);
    log(`Node ${version} installed at ${dest}`);
    return { version, binDir: bundledBinDir(appcraneDir) };
  } finally {
    rmSync(tarPath, { force: true });
    rmSync(staging, { recursive: true, force: true });
  }
}

// Swap `current` in one rename, so a boot never sees it missing.
function activate(root, dest) {
  const tmpLink = join(root, `.current-${randomBytes(6).toString('hex')}`);
  symlinkSync(dest, tmpLink);
  renameSync(tmpLink, join(root, 'current'));
}

// Script mode, for safe-boot.sh: `node bundledNode.js <major>`.
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const major = Number(process.argv[2]);
  const appcraneDir = process.env.APPCRANE_DIR || resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  installBundledNode({ major, appcraneDir, log: (m) => process.stderr.write(`[bundled-node] ${m}\n`) })
    .then(({ binDir }) => { process.stdout.write(`${binDir}\n`); })
    .catch((err) => { process.stderr.write(`[bundled-node] ${err.message}\n`); process.exit(1); });
}

