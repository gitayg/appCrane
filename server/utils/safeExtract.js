// Safe archive extraction — used by deploy.js and upload.js for app
// release uploads. Both used to call `unzip -o` / `tar -xzf` directly,
// which honored entries containing `..` or absolute paths in older
// distros' tools, allowing zip-slip / path-traversal write into any
// directory the AppCrane process could touch (including /etc and
// /root/.claude on the production host that runs as root).
//
// This helper:
//   1. Pre-scans every entry name and rejects '..', leading '/', and
//      paths whose resolved real path leaves the destination dir.
//   2. Uses adm-zip (already a dependency) for zips so we never shell
//      out to the system unzip.
//   3. For tar, passes --no-overwrite-dir / --no-same-owner /
//      --no-same-permissions and post-walks the destination to verify
//      every entry sits inside it.
//
// See feedback memory: "Always validate archive entries against
// path-traversal before extraction; never trust system unzip/tar."

import { execFileSync } from 'child_process';
import { existsSync, readdirSync, statSync, realpathSync } from 'fs';
import { join, resolve, sep } from 'path';

const UNSAFE_ENTRY_RE = /(?:^|[/\\])\.\.(?:[/\\]|$)/;

/** Extract a `.zip` into destDir. Throws on any unsafe entry. */
export async function safeExtractZip(zipPath, destDir) {
  const dest = resolve(destDir);
  const AdmZip = (await import('adm-zip')).default;
  const zip = new AdmZip(zipPath);
  const entries = zip.getEntries();
  for (const e of entries) {
    const name = e.entryName;
    if (!name || name.startsWith('/') || UNSAFE_ENTRY_RE.test(name)) {
      throw new Error(`zip-slip: refusing entry "${name}"`);
    }
    const target = resolve(join(dest, name));
    if (!target.startsWith(dest + sep) && target !== dest) {
      throw new Error(`zip-slip: entry "${name}" resolves outside ${dest}`);
    }
  }
  // adm-zip's extractAllTo writes entries by resolved name. Pre-validation
  // above caught traversal attempts; this is the actual write phase.
  zip.extractAllTo(dest, /* overwrite */ true);
}

/**
 * Extract a `.tar.gz` / `.tgz` into destDir using system tar with safety
 * flags, then walk the destination and assert every file resolves under
 * it. Throws on traversal violation; the caller is responsible for
 * cleaning up the partial extraction.
 */
export function safeExtractTarGz(tarPath, destDir) {
  const dest = resolve(destDir);
  // GNU tar 1.32+ refuses '..' members by default. Pass extra flags as
  // belt-and-suspenders for older distros / BusyBox tar.
  execFileSync('tar', [
    '-xzf', tarPath,
    '-C', dest,
    '--no-overwrite-dir',
    '--no-same-owner',
    '--no-same-permissions',
  ], { timeout: 60000, stdio: 'pipe' });

  // Post-walk: every file's real path must be inside dest. This catches
  // symlink shenanigans where the tar entry itself looked safe but
  // pointed at a previously-extracted symlink.
  walkAndAssertContained(dest, dest);
}

function walkAndAssertContained(current, root) {
  if (!existsSync(current)) return;
  const entries = readdirSync(current, { withFileTypes: true });
  for (const e of entries) {
    const full = join(current, e.name);
    let real;
    try { real = realpathSync(full); } catch (_) { continue; }
    if (!real.startsWith(root + sep) && real !== root) {
      throw new Error(`tar-slip: extracted entry resolves outside ${root}: ${full} -> ${real}`);
    }
    if (e.isDirectory()) walkAndAssertContained(full, root);
  }
}

/**
 * Convenience: dispatch by file extension. `.zip` → safeExtractZip,
 * `.tar.gz` / `.tgz` → safeExtractTarGz, anything else → throw.
 */
export async function safeExtract(archivePath, destDir, originalName) {
  const lower = (originalName || archivePath).toLowerCase();
  if (lower.endsWith('.zip')) return safeExtractZip(archivePath, destDir);
  if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) return safeExtractTarGz(archivePath, destDir);
  throw new Error(`Unsupported archive type: ${originalName || archivePath}`);
}
