-- Recent SCIM requests, for the IT setup page and troubleshooting a directory
-- sync. Path only (the query string can carry a filter naming a person), the
-- status code and the client address. Pruned to the newest rows on insert
-- (services/scimRequestLog.js).
CREATE TABLE IF NOT EXISTS scim_request_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status INTEGER NOT NULL,
  duration_ms INTEGER,
  ip TEXT
);
