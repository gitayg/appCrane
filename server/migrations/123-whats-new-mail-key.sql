-- One "What's new in AppCrane" mail per recipient per release.
--
-- The mail is platform mail (app_id NULL), so idx_email_queue_idem cannot
-- dedupe it: SQLite treats every NULL as distinct in a unique index. This
-- partial index makes the idempotency key itself unique for these rows, so a
-- restart, a crash mid-send, or two processes announcing the same release at
-- once insert each recipient's mail once and the second insert fails.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_whats_new
  ON email_queue(idempotency_key) WHERE source = 'whats-new' AND idempotency_key IS NOT NULL;
