-- Per-app runtime. All apps run in Docker containers under Node Alpine images.
-- Full cutover: existing rows get 'docker' via the NOT NULL DEFAULT clause,
-- so the next deploy of any app rebuilds it as a container.
ALTER TABLE apps ADD COLUMN runtime TEXT NOT NULL DEFAULT 'docker';
