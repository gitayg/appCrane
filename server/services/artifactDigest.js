import { createHash } from 'crypto';
import { createReadStream, existsSync, readFileSync, statSync } from 'fs';

// The identity of an uploaded release.
//
// An app deployed from git is identified by its commit SHA, and supply-chain
// verify compares that SHA against what GitHub reports. An uploaded bundle had
// no equivalent: routes/deploy.js recorded `req.body.commit_sha || 'unknown'`,
// a value supplied BY THE UPLOADER and checked against nothing. So the one
// question worth asking of a release — is what is running what was reviewed? —
// had no answer for upload apps, and verification logged "the deploying commit
// was NOT verified" and passed.
//
// That is why 'upload' was deprecated in v2.3.1: it had no provenance. This
// gives it one rather than reversing the decision. The digest is computed HERE,
// over the bytes actually received, before extraction — never taken from the
// request, which is the mistake commit_sha made.

/** SHA-256 of a file, streamed so a 200 MB bundle does not land in memory. */
export function digestFile(path) {
  return new Promise((resolve, reject) => {
    if (!existsSync(path)) return reject(new Error(`artifact not found: ${path}`));
    const hash = createHash('sha256');
    const stream = createReadStream(path);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * What gets recorded for an uploaded release.
 *
 * `sha256` is over the received bytes. `declared` is whatever the uploader
 * claimed in commit_sha — kept because it is often a genuine git SHA from the
 * machine that built the bundle and is useful context, but it is REPORTED, not
 * TRUSTED, and never stands in for the digest.
 */
export async function describeArtifact(path, { declared = null, filename = null } = {}) {
  const sha256 = await digestFile(path);
  return {
    sha256,
    bytes: statSync(path).size,
    filename: filename || null,
    declared_commit_sha: declared || null,
    // The value that goes in deployments.commit_hash. Prefixed so nothing can
    // mistake a content digest for a git commit: they are both 40+ hex chars
    // and confusing them would make an upload look like a verified git deploy.
    commit_hash: `sha256:${sha256}`,
  };
}

/** Does a recorded identity belong to an uploaded artifact rather than a git commit? */
export function isArtifactHash(commitHash) {
  return typeof commitHash === 'string' && commitHash.startsWith('sha256:');
}

// ---------------------------------------------------------------------------
// Tree digest — what stays checkable AFTER the bundle is gone
// ---------------------------------------------------------------------------
//
// The uploaded file is unlinked as soon as it is extracted, so at rollback time
// there is no bundle left to re-hash. What remains on disk is the release
// directory, and a digest over that IS re-computable later. Recording it at
// deploy and comparing it at rollback answers the one question rollback
// actually raises: is this release directory still the thing that was deployed?
//
// Deliberately REPORT-ONLY, unlike the git-commit verifier which fails closed.
// A release directory is a live working directory: an app that writes a log,
// an SQLite file, or a cache under its own release path mutates the tree by
// running normally. Failing a rollback on that would block the recovery path
// during exactly the incident it exists for. So drift is stated loudly in the
// deploy log and left as the operator's call.

import { readdirSync } from 'fs';
import { join as joinPath, relative, sep } from 'path';

const TREE_SKIP = new Set(['node_modules', '.git']);

function walk(root, dir, out) {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (TREE_SKIP.has(entry.name)) continue;
    const full = joinPath(dir, entry.name);
    if (entry.isDirectory()) walk(root, full, out);
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

/**
 * Deterministic digest over a release directory.
 *
 * Paths are POSIX-normalised and sorted so the value does not depend on
 * readdir order or platform separator, and each file contributes its path and
 * size as well as its bytes — otherwise renaming two files past each other
 * leaves the digest unchanged.
 *
 * node_modules and .git are excluded: they are reinstalled or absent rather
 * than shipped, and hashing a 200 MB dependency tree on every deploy costs more
 * than the drift signal is worth.
 */
export function digestTree(dir) {
  const hash = createHash('sha256');
  let files = 0;
  for (const file of walk(dir, dir, [])) {
    const rel = relative(dir, file).split(sep).join('/');
    hash.update(rel);
    hash.update('\0');
    hash.update(String(statSync(file).size));
    hash.update('\0');
    hash.update(readFileSync(file));
    hash.update('\0');
    files += 1;
  }
  return { sha256: hash.digest('hex'), files };
}
