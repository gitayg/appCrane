-- Boxes bootstrapped by an older `crane init` seeded the first user as
-- role='admin'. Role promotion is gated behind platform_admin, so such a box
-- has no platform_admin and no way to create one — platform-owner features
-- (role assignment, hidden apps, platform notification emails) and the CLI's
-- `regenerate-key` default all break. If there is NO platform_admin, promote
-- the oldest admin to platform_admin (the bootstrap owner). No-op once one
-- exists.
UPDATE users
SET role = 'platform_admin'
WHERE id = (
  SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1
)
AND NOT EXISTS (SELECT 1 FROM users WHERE role = 'platform_admin');
