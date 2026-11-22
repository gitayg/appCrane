-- The lockfile a deploy built from (services/deployIntegrity.js): its name at
-- the release root and its sha256. lockfile_name '(none)' means the release
-- had no lockfile; NULL means nothing was recorded (an upload or image deploy,
-- or a row written before this column).
ALTER TABLE deployments ADD COLUMN lockfile_name TEXT;
ALTER TABLE deployments ADD COLUMN lockfile_sha256 TEXT;
