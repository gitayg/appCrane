-- Per-tenant SQLite DB feature (cooperative model). When set, AppCrane injects
-- APPCRANE_TENANT_ROOT into the container and purges a tenant's data dir when
-- that user's app access is revoked. Synced from deployhub.json `multitenant`
-- on every deploy.
ALTER TABLE apps ADD COLUMN multitenant INTEGER NOT NULL DEFAULT 0;
