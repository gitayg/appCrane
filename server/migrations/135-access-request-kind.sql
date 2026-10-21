-- One open access request per person per app, enforced by the database.
--
-- Until now only the Launch picker's button stopped a second request; the
-- server took as many as were posted, and two clicks racing each other (or a
-- script) filed duplicates that each e-mailed every owner.
--
-- `kind` is the marker the unique index needs. An access request is still
-- recognised the way every existing reader recognises it, by the message
-- prefix 'Access request for app' (the picker, the MCP list/approve/deny tools,
-- pendingAccessRequestSlugs). The create path freezes that test into this
-- column once, at insert, because a partial index needs a plain stored value:
-- the message is free text that the deny tool rewrites, and LIKE's behaviour
-- depends on a connection pragma, so it cannot sit in an index predicate.
--
-- Open means status != 'done', the same test those readers use (approve and
-- deny both set 'done'), so the picker's "Requested" state, the MCP pending
-- list and this index agree about which request is the open one.
--
-- Backfill marks every existing access request except open duplicates beyond
-- the oldest, which keep kind NULL: they stay visible to the prefix readers
-- exactly as before, and the index can still be built on a database that
-- already holds duplicates. Nothing is closed or rewritten here.
ALTER TABLE enhancement_requests ADD COLUMN kind TEXT;

UPDATE enhancement_requests SET kind = 'access'
WHERE message LIKE 'Access request for app%'
  AND (
    status = 'done' OR user_id IS NULL OR app_slug IS NULL
    OR id = (
      SELECT MIN(e2.id) FROM enhancement_requests e2
      WHERE e2.user_id = enhancement_requests.user_id
        AND e2.app_slug = enhancement_requests.app_slug
        AND e2.status != 'done'
        AND e2.message LIKE 'Access request for app%'
    )
  );

CREATE UNIQUE INDEX IF NOT EXISTS idx_enhancement_requests_open_access
  ON enhancement_requests(user_id, app_slug)
  WHERE kind = 'access' AND status != 'done';
