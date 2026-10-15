-- Which coder session a request was sent to (POST /api/coder/:slug/requests/dispatch).
--
-- NULL on every request that was never dispatched and on every row that
-- existed before this migration. A later dispatch of the same request
-- overwrites it: the column names the session now working on it, not a
-- history (the audit log keeps that).
ALTER TABLE enhancement_requests ADD COLUMN coder_session_id TEXT;
