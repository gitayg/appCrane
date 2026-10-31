-- AppCrane feedback mail to platform admins (services/feedback/mail.js) has
-- app_id NULL, which idx_email_queue_idem cannot dedupe: SQLite treats every
-- NULL as distinct. This makes the idempotency key itself unique for these
-- rows, so the second feedback in an hour adds no second mail per admin.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_feedback
  ON email_queue(idempotency_key) WHERE source = 'feedback' AND idempotency_key IS NOT NULL;
