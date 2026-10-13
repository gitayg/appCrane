-- How far services/dbAuthAlerts.js has read each managed Redis's ACL LOG.
--
-- Redis does not log a failed AUTH anywhere a `docker logs` can see; it keeps
-- it in the in-memory ACL LOG, and it GROUPS repeats: a burst of failures for
-- one username becomes ONE entry whose `count` grows and whose
-- timestamp-last-updated moves (measured on redis:8.10-alpine). So "what is
-- new since the last scan" is a per-entry count delta, not a set of new lines.
--
-- One row per entry seen: the entry is identified by (entry-id,
-- timestamp-created) because entry-ids restart at 0 when the instance
-- restarts, and seen_count is the count already turned into failure rows. In
-- SQLite rather than memory so a restart of AppCrane does not count the
-- whole log a second time. The log is NOT reset after reading: it is the
-- evidence an operator inspects, and reading by id makes a reset unnecessary.
CREATE TABLE IF NOT EXISTS managed_db_redis_acl_seen (
  container_name TEXT NOT NULL,
  entry_id INTEGER NOT NULL,
  created_ms INTEGER NOT NULL,
  seen_count INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (container_name, entry_id, created_ms)
);
