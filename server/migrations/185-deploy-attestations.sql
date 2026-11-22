-- Per-deploy supply-chain evidence (services/imageTrust): the CycloneDX SBOM of
-- the image a deploy is about to run, an SLSA v1 provenance statement, and this
-- instance's signature over the image id. The documents live on disk under
-- DATA_DIR/attestations/<slug>/<env>/<deployment id>/; this row says where, what
-- they cover and whether they were produced.
--
-- image_id is the local image id (`docker image inspect --format {{.Id}}`, the
-- sha256 of the image config). It is the identity verify-before-run compares:
-- a tag can be moved to other bytes, an id cannot.
--
-- status: 'signed' (signature + provenance written; sbom_status says whether the
-- SBOM attestation exists too) | 'error' (nothing signed; error says why).
-- origin: 'deploy' (signed by the deploy that built or pulled the image) |
-- 'backfill' (an image that was already running when signing was turned on,
-- signed on an admin's request: trust on first use, not build provenance).
CREATE TABLE IF NOT EXISTS deploy_attestations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  deployment_id INTEGER REFERENCES deployments(id) ON DELETE CASCADE,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env TEXT NOT NULL,
  origin TEXT NOT NULL DEFAULT 'deploy',
  image_ref TEXT NOT NULL,
  image_id TEXT,
  status TEXT NOT NULL,
  error TEXT,
  key_id TEXT,
  dir TEXT,
  sbom_status TEXT,
  sbom_error TEXT,
  sbom_sha256 TEXT,
  sbom_components INTEGER,
  sbom_hash_coverage INTEGER,
  sbom_license_coverage INTEGER,
  license_check_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_deploy_attestations_image ON deploy_attestations(app_id, env, image_id);
CREATE INDEX IF NOT EXISTS idx_deploy_attestations_deploy ON deploy_attestations(deployment_id);
