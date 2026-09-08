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
  // CVE-2026-76845 / GHSA-vwc7-r8mq-g2x9 (CWE-59), v2.65.5. There is nothing to
  // upgrade to: the advisory's first_patched_version is null and 0.6.0 IS the
  // latest published adm-zip.
  //
  // adm-zip's Utils.writeFileTo opens the computed destination with
  // fs.openSync(path, 'w') — no O_NOFOLLOW, no lstat — so a symlink ALREADY
  // SITTING at the destination is followed and the entry is written through it,
  // outside the extraction root. The entry-name scan above cannot see that, and
  // neither could a stricter version of it: the archive entry is named
  // `config.js` and is entirely legitimate. The advisory is explicit that the
  // write happens "without any traversal sequence appearing in the archive".
  //
  // A malicious archive cannot plant the symlink itself — adm-zip never calls
  // symlinkSync, so a symlink ENTRY is written out as a regular file holding the
  // link text. The attacker needs separate write access to the destination
  // before extraction. So the defence is to refuse a destination that already
  // contains one, which also costs nothing on the normal path: callers extract
  // into a directory they created moments earlier and which is therefore empty.
  assertNoSymlinks(dest);

  // adm-zip's extractAllTo writes entries by resolved name. Pre-validation
  // above caught traversal attempts; this is the actual write phase.
  zip.extractAllTo(dest, /* overwrite */ true);

  // The same realpath sweep the tar path has always run. The zip path never had
  // one, and that asymmetry is why this class of bug had no coverage here.
  //
  // What it adds over the pre-check is the TOCTOU window: assertNoSymlinks looks
  // at the destination, and extractAllTo writes to it a moment later. An
  // attacker who can write to that directory can plant the link in between. The
  // sweep does not prevent that write, but it fails the deploy loudly instead of
  // letting it report success. test/adm-zip-symlink-destination.test.js does NOT
  // cover this line — the race is not deterministically reproducible — so it is
  // deliberate defence-in-depth, not something the suite is proving.
  assertTreeContained(dest);
}

/**
 * Refuse a destination that contains a symlink at any depth.
 *
 * Dirent.isSymbolicLink() reflects lstat, so this does not follow the link it is
 * looking for. Empty or missing directory: nothing to reject.
 */
function assertNoSymlinks(dir) {
  if (!existsSync(dir)) return;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isSymbolicLink()) {
      throw new Error(`unsafe extraction destination: "${full}" is a symlink`);
    }
    if (e.isDirectory()) assertNoSymlinks(full);
  }
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
  assertTreeContained(dest);
}

/**
 * Containment must be judged in REAL-PATH space on BOTH sides.
 *
 * walkAndAssertContained realpaths each entry but was handed the raw dest as
 * its root, so wherever the destination itself sits under a symlinked path the
 * two strings can never match and every legitimate extraction is rejected. On
 * macOS that is any temp dir — /var is a symlink to /private/var — which is why
 * the tar branch's post-walk had never been exercised: it is Linux-only in
 * practice and DATA_DIR there happens to be a real path. Resolving the root
 * once here fixes the zip caller and the tar caller together.
 */
function assertTreeContained(dir) {
  const root = existsSync(dir) ? realpathSync(dir) : resolve(dir);
  walkAndAssertContained(dir, root);
}

function walkAndAssertContained(current, root) {
  if (!existsSync(current)) return;
  const entries = readdirSync(current, { withFileTypes: true });
  for (const e of entries) {
    const full = join(current, e.name);
    let real;
    try { real = realpathSync(full); } catch (_) { continue; }
    if (!real.startsWith(root + sep) && real !== root) {
      throw new Error(`archive-slip: extracted entry resolves outside ${root}: ${full} -> ${real}`);
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
