-- Cron jobs AppCrane creates from an app's vercel.json `crons` (2.138.0).
--
-- kind   'exec' runs `command` with docker exec (every job before this);
--        'http' calls GET http_path on the app's own container over its
--        loopback port, the way Vercel calls a cron path.
-- origin 'manifest' is a job declared in deployhub.json `cron`; 'vercel' is one
--        AppCrane created from vercel.json. Each deploy-time sync touches only
--        the rows of its own origin, so a vercel.json sync never edits or
--        removes a job somebody declared, and the deployhub.json sync no longer
--        removes the vercel.json ones.
-- last_http_status is the status the last http run got back (NULL for exec).

ALTER TABLE app_cron_jobs ADD COLUMN kind TEXT NOT NULL DEFAULT 'exec' CHECK (kind IN ('exec', 'http'));
ALTER TABLE app_cron_jobs ADD COLUMN origin TEXT NOT NULL DEFAULT 'manifest' CHECK (origin IN ('manifest', 'vercel'));
ALTER TABLE app_cron_jobs ADD COLUMN http_path TEXT;
ALTER TABLE app_cron_jobs ADD COLUMN last_http_status INTEGER;
