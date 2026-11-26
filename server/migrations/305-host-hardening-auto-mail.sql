-- The "root-owned copy is older" notice is platform mail (app_id NULL), which
-- idx_email_queue_idem cannot dedupe; this makes its per-version key unique.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_host_hardening_auto
  ON email_queue(idempotency_key) WHERE source = 'host-hardening-auto' AND idempotency_key IS NOT NULL;
