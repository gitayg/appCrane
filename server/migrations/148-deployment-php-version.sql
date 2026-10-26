-- PHP minor the generated PHP build used for this deployment (dockerfileGenPhp.js
-- via services/phpVersion.js). NULL for every other build. A redeploy of an app
-- whose composer.json states no php requirement keeps the version recorded on
-- its last deployment that went live, so a redeploy never changes the PHP minor
-- underneath it.
ALTER TABLE deployments ADD COLUMN php_version TEXT;

-- Every generated PHP build before this column existed used php:8.3-apache and
-- logged exactly this line (unchanged since the generator shipped).
UPDATE deployments SET php_version = '8.3'
WHERE php_version IS NULL
  AND status IN ('live', 'rolled_back')
  AND log LIKE '%Generated Dockerfile (php:8.3-apache, non-root)%';
