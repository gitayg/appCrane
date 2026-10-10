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

export const PLATFORM_PATHS = [
  'api', 'app', 'applications', 'appstudio', 'audit', 'audit-page', 'builders', 'catalog',
  'coder', 'dashboard', 'docs', 'enhancements-page', 'favicon.svg', 'launch', 'login',
  'login-legacy', 'mcp', 'my-requests', 'portal', 'public', 'raiseme', 'requests', 'settings',
  'skills', 'studio', 'users-page',
];

/** Why `slug` may not be used for an app, or null when it may. */
export function slugRefusal(slug) {
  if (typeof slug !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(slug)) {
    return 'Slug must be lowercase alphanumeric with dashes';
  }
  const shadowed = PLATFORM_PATHS.filter(p => p.startsWith(slug));
  if (shadowed.length) {
    return `Slug '${slug}' would capture AppCrane's own /${shadowed[0]} path (an app is routed at /${slug}*). Choose a different slug.`;
  }
  // Every app also gets `/<slug>-sandbox*`; a second app named that would collide with it.
  if (slug.endsWith('-sandbox')) {
    return `Slug '${slug}' collides with the sandbox path of an app named '${slug.slice(0, -'-sandbox'.length)}'. Choose a different slug.`;
  }
  return null;
}
