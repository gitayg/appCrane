-- Domains AppCrane has proven an organization controls, by a DNS TXT record
-- appcrane-domain-verification=<token> (services/domainVerification.js).
--
-- Only a verified (or grandfathered 'legacy') domain on the OIDC "join without
-- approval" list lets a new person in without a platform admin's approval; an
-- unverified one sends them to the sign-up request queue instead.
--
-- status:
--   pending     added, TXT record not seen yet
--   verified    TXT record seen with this token
--   unverified  was verified, a later check found the record gone or changed
--   legacy      already on the list before this migration; keeps letting
--               people join (so an upgrade does not stop sign-ups) until it
--               verifies, and the settings page warns about it
-- The token is not a secret: it is published in DNS.
CREATE TABLE IF NOT EXISTS sso_domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL UNIQUE,
  token TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'unverified', 'legacy')),
  verified_at TEXT,
  last_checked_at TEXT,
  last_result TEXT,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_by_link INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

WITH RECURSIVE split(entry, rest) AS (
  SELECT '', lower(replace(replace(COALESCE((SELECT value FROM settings WHERE key = 'oidc_allowed_domains'), ''), ' ', ','), char(10), ',')) || ','
  UNION ALL
  SELECT trim(substr(rest, 1, instr(rest, ',') - 1)), substr(rest, instr(rest, ',') + 1)
    FROM split WHERE rest <> ''
)
INSERT OR IGNORE INTO sso_domains (domain, token, status)
SELECT DISTINCT ltrim(entry, '@'), lower(hex(randomblob(16))), 'legacy'
  FROM split
 WHERE entry <> '' AND entry <> '*' AND instr(ltrim(entry, '@'), '@') = 0;
