-- The full 40-hex commit a release was built from. deployments.commit_hash is
-- abbreviated (git rev-parse --short), and a commit sharing a short prefix can
-- be brute-forced; RCE auto-patch compares commits by exact full SHA only
-- (services/autoPatch/commits.js). NULL for rows written before this column
-- and for image deploys.
ALTER TABLE deployments ADD COLUMN commit_sha TEXT;
