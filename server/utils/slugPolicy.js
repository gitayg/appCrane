// Which app slugs may exist (security audit 2026-10-09, H4).
//
// Caddy routes an app with `handle /<slug>*`, and the platform itself is the
// catch-all `handle { reverse_proxy AppCrane }`. Caddy sorts same-named
// directives by path specificity and puts the no-matcher one LAST
// (caddyserver.com/docs/caddyfile/directives), so any app block whose prefix
// matches a platform path wins over the platform: an app named `a` received
// every `/api/...` request — session cookies and API keys included — and one
// named `login` served the sign-in page. The `*` is a plain string prefix, so
// what is refused is a slug any platform path STARTS WITH, not only an equal
// one.
//
// PLATFORM_PATHS is every top-level path server/index.js mounts;
// test/slug-policy.test.js re-reads index.js and fails when one is missing.

import { slugContentCategory } from './slugContent.js';

export const PLATFORM_PATHS = [
  'a2a', 'api', 'app', 'applications', 'appstudio', 'audit', 'audit-page', 'builders', 'catalog',
  'coder', 'crew', 'dashboard', 'docs', 'enhancements-page', 'favicon.svg', 'git', 'launch', 'login',
  'login-legacy', 'mcp', 'my-requests', 'oauth', 'portal', 'public', 'raiseme', 'requests', 'settings',
  'events', 'skills', 'studio', 'surveys', 'tasks', 'users-page', 'adopt', 'intake', 'access-reviews',
  'audit-integrity', '__appcrane',
];

/**
 * Why `slug` may not be used for an app, or null when it may. The one check
 * every create and rename path runs. `user` is the caller: platform admins may
 * use the trust-signal words (they are the platform); nobody may use the rest.
 */
export function slugRefusal(slug, user = null) {
  if (typeof slug !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(slug)) {
    return 'Slug must be lowercase alphanumeric with dashes';
  }
  const shadowed = PLATFORM_PATHS.filter(p => p.startsWith(slug));
  if (shadowed.length) {
    return `Slug '${slug}' is reserved for AppCrane: it would capture AppCrane's own /${shadowed[0]} path (an app is routed at /${slug}*). Choose a different slug.`;
  }
  // Every app also gets `/<slug>-sandbox*`; a second app named that would collide with it.
  if (slug.endsWith('-sandbox')) {
    return `Slug '${slug}' collides with the sandbox path of an app named '${slug.slice(0, -'-sandbox'.length)}'. Choose a different slug.`;
  }
  const content = slugContentCategory(slug);
  if (content === 'offensive') return 'This slug is not allowed. Choose a different slug.';
  if (content === 'impersonation' && user?.role !== 'platform_admin') {
    return 'This slug is not allowed: it reads like an AppCrane page or a trust signal (for example admin, login, '
      + 'support, official) and could mislead the people who open it. Choose a different slug, or ask a platform admin.';
  }
  return null;
}

/**
 * Why `slug` is already taken, or null when it is free. Taken means another
 * app's current slug, or an old slug another app keeps as a redirect: a
 * renamed-away slug stays that app's, or whoever took it next would receive
 * every bookmark and link still pointing at it. `appId` is the app asking —
 * its own old slugs are free for it to return to. Never names the holder.
 *
 * Migration 124 enforces the same rule in the database (triggers on apps), so
 * this is the readable refusal and the trigger is what makes it race-free.
 */
export function slugTakenRefusal(db, slug, appId = null) {
  const live = db.prepare('SELECT id FROM apps WHERE slug = ?').get(slug);
  const alias = db.prepare(`
    SELECT a.id FROM apps a,
      json_each(CASE WHEN json_valid(a.slug_aliases) THEN a.slug_aliases ELSE '[]' END) j
    WHERE j.value = ? LIMIT 1
  `).get(slug);
  const holder = live?.id ?? alias?.id;
  if (holder === undefined || holder === appId) return null;
  return `Slug '${slug}' is already used by another app. Choose a different slug.`;
}
