-- Public access flag: when 1, any authenticated user can access the app (no per-app role required)
ALTER TABLE apps ADD COLUMN public_access INTEGER NOT NULL DEFAULT 0;
