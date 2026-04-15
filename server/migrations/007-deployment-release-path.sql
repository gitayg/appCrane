-- Track the on-disk release directory for each deployment
-- so rollback and promote can swap the `current` symlink reliably.
ALTER TABLE deployments ADD COLUMN release_path TEXT;
