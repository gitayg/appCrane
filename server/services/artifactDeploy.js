import { mkdirSync, unlinkSync } from 'fs';
import { resolve, join } from 'path';
import { getDb } from '../db.js';
import { getPortsForSlot } from './portAllocator.js';
import { describeArtifact } from './artifactDigest.js';
import log from '../utils/logger.js';

// Deploying a release from a bundle of bytes, wherever the bytes came from.
//
// This was inline in routes/deploy.js and reachable only through a multipart
// POST. That mattered more than it looks: a personal MCP key (dhk_mcp_*) is
// allow-listed to /api/mcp and /api/files/staged and nothing else
// (middleware/auth.js), and dhk_app_* keys were removed in v2.2.12 — so an
// agent holding the only credential it can hold could not deploy a bundle at
// all. With the managed-repo path also gated on a working service-account PAT,
// an owner whose PAT had expired had no route left: the repo write failed and
// the upload fallback was refused by key scope.
//
// Extracting it gives the same code two front doors, the HTTP route and an MCP
// tool over a staged file, without either reimplementing extraction,
// provenance, or the deploy handoff.

const ALLOWED_EXT = ['.tar.gz', '.tgz', '.zip'];

export function isAllowedArtifactName(name) {
  const lower = String(name || '').toLowerCase();
  return ALLOWED_EXT.some((ext) => lower.endsWith(ext));
}

/**
 * Extract a bundle into a fresh release directory and start a deploy.
 *
 * Consumes `filePath`: the file is unlinked on every path out of here,
 * success or failure. Callers that must keep their copy (the staged-file
 * store owns its bytes and sweeps them on its own schedule) pass
 * `keepSource: true`.
 *
 * Returns { deployId, artifact, releaseDir }. Throws on a bad env, a
 * disallowed extension, a path that escapes DATA_DIR, or a failed extract —
 * the deploy itself runs detached and reports through the deployment row.
 */
export async function deployArtifact({
  app, env, filePath, filename, declaredSha = null, commitMessage = null,
  userId, keepSource = false,
}) {
  const drop = () => { if (!keepSource) { try { unlinkSync(filePath); } catch (_) {} } };

  if (!['production', 'sandbox'].includes(env)) {
    drop();
    throw new Error('env must be production or sandbox');
  }
  if (!isAllowedArtifactName(filename)) {
    drop();
    throw new Error(`Only ${ALLOWED_EXT.join(', ')} files allowed — got '${filename}'`);
  }

  // Identity first, over the bytes as received, before anything unpacks or
  // rewrites them. The uploader's own commit_sha claim is recorded beside it
  // and never in place of it.
  let artifact;
  try {
    artifact = await describeArtifact(filePath, { declared: declaredSha, filename });
  } catch (e) {
    drop();
    throw new Error(`Could not read the uploaded artifact: ${e.message}`);
  }

  const dataDir = resolve(process.env.DATA_DIR || './data');
  const releaseDir = resolve(join(dataDir, 'apps', app.slug, env, 'releases', `${Date.now()}-upload`));
  if (!releaseDir.startsWith(dataDir)) {
    drop();
    throw new Error('Security: release path escapes the data directory');
  }
  mkdirSync(releaseDir, { recursive: true });

  try {
    // SECURITY: see server/utils/safeExtract.js — validates every archive
    // entry against zip-slip / tar-slip before writing.
    const { safeExtract } = await import('../utils/safeExtract.js');
    await safeExtract(filePath, releaseDir, filename);
  } catch (e) {
    drop();
    throw new Error(`Extract failed: ${e.message}`);
  }
  drop();

  const db = getDb();
  const result = db.prepare(`
    INSERT INTO deployments (app_id, env, status, commit_hash, commit_message, deployed_by, log)
    VALUES (?, ?, 'pending', ?, ?, ?, 'Triggered by artifact upload')
  `).run(app.id, env, artifact.commit_hash, commitMessage, userId);
  const deployId = result.lastInsertRowid;

  db.prepare(`
    UPDATE deployments
       SET artifact_sha256 = ?, artifact_bytes = ?, artifact_filename = ?, declared_commit_sha = ?
     WHERE id = ?
  `).run(artifact.sha256, artifact.bytes, artifact.filename, artifact.declared_commit_sha, deployId);

  // The provenance line is written by the deployer, not here. deployApp's
  // appendLog rebuilds deployments.log from its own buffer on every call, so
  // anything written to that column before the deploy starts is discarded.
  try {
    const { deployApp } = await import('./deployer.js');
    const ports = getPortsForSlot(app.slot);
    deployApp(deployId, app, env, ports, {
      preExtractedDir: releaseDir,
      commitHash: artifact.commit_hash,
    }).catch((err) => log.error(`Upload deploy ${deployId} failed: ${err.message}`));
  } catch (e) {
    db.prepare("UPDATE deployments SET status = 'failed', log = ?, finished_at = datetime('now') WHERE id = ?")
      .run(`Deploy service error: ${e.message}`, deployId);
  }

  return { deployId, artifact, releaseDir };
}
