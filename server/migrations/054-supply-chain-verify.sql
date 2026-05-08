-- v2.3.6: supply-chain SHA verification toggle.
--
-- After git clone, AppCrane can ask GitHub directly what the head SHA of
-- the deploying branch is, then compare against `git rev-parse HEAD`. A
-- mismatch fails the deploy before the container swap, defending against
-- a compromised credential pushing to a different ref or a poisoned mid-
-- box rewriting clone bytes.
--
-- Default = '1' (verify ON) on fresh installs. Operators on offline /
-- air-gapped boxes flip to '0' via PUT /api/settings/supply_chain_verify_enabled.

INSERT OR IGNORE INTO settings (key, value) VALUES
  ('supply_chain_verify_enabled', '1');
