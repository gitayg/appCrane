-- v2.10.2: record the last commit AppCrane pushed to a managed app's AMC_*
-- mirror, so supply-chain verify can compare the deploy clone's HEAD to the
-- SHA we authored — instead of querying GitHub's branch HEAD, which is
-- eventually-consistent and lags the mirror push by ~1s. That lag produced a
-- false "local HEAD does not match GitHub" failure on the FIRST deploy after
-- every push_to_managed_app (a read-after-write race in our own pipeline; the
-- external-tampering threat model doesn't apply when AppCrane is the author).

ALTER TABLE apps ADD COLUMN last_managed_push_sha TEXT;
