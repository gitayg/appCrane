ALTER TABLE apps ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private';
UPDATE apps SET visibility = 'public' WHERE public_access = 1;
