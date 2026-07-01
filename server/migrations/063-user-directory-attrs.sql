-- v2.18.0: inherit richer directory attributes from the IdP. Okta (and any
-- SCIM/Universal-Directory source) can push department + address on each user;
-- previously AppCrane dropped everything but name/email. These columns let
-- departmental views (e.g. a Skills Inventory) group/filter by org + place.
--   department ← SCIM enterprise extension `department`
--   region     ← SCIM core address `region`   (state / province)
--   location   ← SCIM core address `locality` (city / office)

ALTER TABLE users ADD COLUMN department TEXT;
ALTER TABLE users ADD COLUMN region TEXT;
ALTER TABLE users ADD COLUMN location TEXT;
