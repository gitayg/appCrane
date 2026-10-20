// What an app list may say about an app the caller has no role on.
//
// A caller with app_role 'none' sees the app only so they can ask for access,
// so the list tells them who to ask and nothing about how the app runs: no
// health, versions, deploy state, URLs, domains, ports or members.

const ACCESS_REQUEST_PREFIX = 'Access request for app';

export function pendingAccessRequestSlugs(db, userId) {
  const rows = db.prepare(`
    SELECT DISTINCT app_slug FROM enhancement_requests
    WHERE user_id = ? AND app_slug IS NOT NULL AND status != 'done'
      AND message LIKE '${ACCESS_REQUEST_PREFIX}%'
  `).all(userId);
  return new Set(rows.map(r => r.app_slug));
}

export function ownerNames(db, appId) {
  return db.prepare(`
    SELECT u.name FROM users u
    JOIN app_user_roles aur ON aur.user_id = u.id
    WHERE aur.app_id = ? AND aur.app_role = 'owner'
    ORDER BY u.id
  `).all(appId).map(r => ({ name: r.name }));
}

export function discoverableApp(app, { owners, hasIcon, accessRequested }) {
  return {
    id: app.id,
    slug: app.slug,
    name: app.name,
    category: app.category ?? null,
    visibility: app.visibility,
    has_icon: hasIcon,
    owner: owners[0] || null,
    owners,
    app_role: 'none',
    access_requested: accessRequested,
  };
}

// The sign-in portal's app rows (POST /api/identity/login, GET /api/identity/me)
// carry their role under `roleKey`.
export function discoverablePortalRow(row, roleKey) {
  return {
    slug: row.slug,
    name: row.name,
    category: row.category ?? null,
    visibility: row.visibility,
    has_icon: row.has_icon,
    [roleKey]: 'none',
  };
}
