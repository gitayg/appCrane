-- Memory-admission and host-resource alerts are platform mail (app_id NULL),
-- which idx_email_queue_idem cannot dedupe; this makes their idempotency keys
-- (per app per hour, per resource per level per 6 hours) unique.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_capacity_alerts
  ON email_queue(idempotency_key)
  WHERE source IN ('memory-admission', 'host-resources') AND idempotency_key IS NOT NULL;
