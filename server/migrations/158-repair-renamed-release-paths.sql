-- Repair release paths left behind by renames before v2.125.6.
--
-- deployments.release_path is absolute, under data/apps/<slug>/. Until
-- v2.125.6 a rename moved that directory without rewriting the stored paths,
-- so rollback and promote refused every release from before the rename with
-- "Release directory missing on disk" (seen 2026-10-28: an app renamed, its
-- redeploys cut off by a restart, and no way back to its last good release
-- without a root shell on the host). app_slug_renames records each rename, so
-- every path under an old slug is pointed at the app's current slug. A chain
-- (a -> b -> c) resolves in one pass: each path names one old slug, and every
-- rename row of the app leads to apps.slug, the slug the directory has now.
UPDATE deployments
SET release_path = replace(release_path, '/apps/' || r.old_slug || '/', '/apps/' || a.slug || '/')
FROM app_slug_renames r JOIN apps a ON a.id = r.app_id
WHERE deployments.app_id = r.app_id
  AND r.old_slug != a.slug
  AND instr(deployments.release_path, '/apps/' || r.old_slug || '/') > 0;
