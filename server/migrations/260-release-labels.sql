-- Free-text release label (services/releaseLog.js), e.g. 'rules=v3', so
-- releases can be grouped and compared by what they changed. Set at deploy
-- time (POST /api/apps/:slug/deploy/:env {label}, appcrane_deploy label) or
-- afterwards by an owner, app admin or platform admin; a promote carries the
-- sandbox release's label to production. NULL means no label. Validated at
-- write time: 1-40 of [A-Za-z0-9._=-].
ALTER TABLE deployments ADD COLUMN release_label TEXT;
CREATE INDEX IF NOT EXISTS idx_deployments_release_label ON deployments (app_id, env, release_label);
