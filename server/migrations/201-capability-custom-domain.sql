-- Capability approvals: a custom domain served WITHOUT AppCrane sign-in
-- (custom_domain_auth = 0) becomes the capability custom_domain_unprotected.
-- Apps already serving one are grandfathered: nothing about them changes, and
-- they appear on the platform admins' review list as unreviewed.
INSERT INTO capability_requests (app_id, capability, origin, status, requested_scope, scope, reason)
SELECT id, 'custom_domain_unprotected', 'grandfathered', 'approved',
       json_object('domains', json_array(lower(trim(domain)))), json_object('domains', json_array(lower(trim(domain)))),
       'In use before capability approvals existed'
FROM apps
WHERE domain IS NOT NULL AND trim(domain) != '' AND COALESCE(custom_domain_auth, 0) = 0;
