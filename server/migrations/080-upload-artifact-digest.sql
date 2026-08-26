-- v2.53.0: give an uploaded release an identity AppCrane computed.
--
-- Before this, an upload recorded deployments.commit_hash = whatever the
-- uploader put in commit_sha, or the literal string 'unknown'. Nothing hashed
-- the bundle, so two different artifacts could claim one SHA and rollback had
-- no way to tell which release it was restoring. commit_hash now carries
-- 'sha256:<digest>' over the received bytes; these columns keep the parts that
-- do not fit in it.
--
-- artifact_sha256      digest of the uploaded file, unprefixed, for querying.
-- artifact_bytes       size as received.
-- artifact_filename    original upload name, for the deploy log and UI.
-- declared_commit_sha  the uploader's claim. RECORDED, NOT TRUSTED — it is
--                      often a genuine git SHA from the machine that built the
--                      bundle and is useful context, but it is the value this
--                      migration exists to stop treating as identity.
-- tree_sha256          digest over the extracted release directory, which is
--                      what remains re-computable once the bundle is unlinked;
--                      compared at rollback and reported, never enforced.
ALTER TABLE deployments ADD COLUMN artifact_sha256 TEXT;
ALTER TABLE deployments ADD COLUMN artifact_bytes INTEGER;
ALTER TABLE deployments ADD COLUMN artifact_filename TEXT;
ALTER TABLE deployments ADD COLUMN declared_commit_sha TEXT;
ALTER TABLE deployments ADD COLUMN tree_sha256 TEXT;

CREATE INDEX IF NOT EXISTS idx_deployments_artifact_sha ON deployments(artifact_sha256);
