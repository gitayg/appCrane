/**
 * Platform notices — a channel for telling app owners that a platform change
 * can break their app.
 *
 * WHY this exists: v2.39.0 stopped forwarding the visitor's `cc_token` platform
 * cookie into app containers. Correct security fix, shipped silently — at least
 * one app in the fleet was deriving identity from that cookie and learned about
 * the change as an outage. The platform had, and until now still had, no way to
 * say "this is coming, and here is what to do instead".
 *
 * Notices are PLATFORM-AUTHORED and live in this file as source. They are never
 * user input: nothing writes here at runtime, there is no admin CRUD, and the
 * bodies are rendered as trusted prose. That is deliberate — a notice is part of
 * a release, reviewed with the change that motivated it, and it ships and rolls
 * back with that release. It also means the read path has no injection surface.
 *
 * SCOPING is data-driven on purpose, and stays a data match rather than a rules
 * engine: `match: null` means every app; otherwise `match` is an object of
 * apps-table column -> expected value (or array of accepted values), ANDed. That
 * covers the scopes that are actually real ("apps in headless mode", "apps on
 * the legacy runtime") without inventing a predicate language for scopes nobody
 * has needed yet. If a future notice needs something this cannot express, widen
 * it then, with that notice in hand.
 */

/**
 * severity — 'breaking' means an app that does nothing will stop working;
 * 'warning' means it still works but the behaviour it relies on is going away;
 * 'info' is everything else.
 */
export const NOTICES = [
  {
    id: 'cc-token-not-forwarded-2.39.0',
    severity: 'breaking',
    version: '2.39.0',
    published_at: '2026-08-11',
    title: 'Apps no longer receive the visitor\'s cc_token platform cookie',
    body: [
      'As of AppCrane 2.39.0 the reverse proxy removes the `cc_token` cookie from the Cookie header before the request reaches your container. An app backend that read `cc_token` to identify the visitor, or replayed it against the AppCrane API to act as them, now sees nothing where it used to see a session.',
      '',
      'This was a security fix, not a regression: any code running in a hosted app could previously lift a visitor\'s platform session out of that cookie and call the platform API with the visitor\'s full privileges, on every app they happened to open.',
      '',
      'Get identity from the request headers instead. On an authenticated app, AppCrane verifies the visitor itself and sets X-AppCrane-User-Email, X-AppCrane-User, X-AppCrane-User-Role, X-AppCrane-App-Role and X-AppCrane-Is-Admin on the request it proxies to you. Those headers are stripped off the incoming client request first — on every proxied route, forward_auth or not — so what arrives at your app is always platform-issued and cannot be spoofed by a caller. If you need more than the headers carry, call GET /api/me with the visitor\'s own Bearer token.',
      '',
      'Two things to know before you debug a missing header. X-AppCrane-App-Role is the per-app tier and its order is none < viewer < user < admin < owner, so a check for `role === "admin"` denies owners — the highest tier. Use X-AppCrane-Is-Admin (1 or 0) and skip the comparison entirely.', // role:platform-admin-skipped
      '',
      'And read X-AppCrane-Auth-Mode first when identity is missing. It is present on every request AppCrane proxies and tells you which of the cases you are in: `authenticated` means forward_auth ran and the identity headers are verified; `headless` means the app opted out of identity for every route; `bypass` means this particular request was never verified (an auth_bypass_paths prefix, or an app served on its own custom domain). No X-AppCrane-Auth-Mode at all means the request did not come through AppCrane\'s proxy. A headless app therefore does still receive that one header — it is how you tell "identity is off by design" from a broken proxy.',
    ].join('\n'),
    // Scope is every app, and that is the honest answer rather than a lazy one.
    // The cookie strip is emitted unconditionally in the generated Caddyfile —
    // headless apps and path-level auth bypasses included — and the platform has
    // no signal for which apps ever read the cookie, because reading it happened
    // entirely inside the container. Narrowing this scope on a guess would
    // silently exclude the one app that depended on it, which is precisely the
    // failure this channel exists to prevent.
    match: null,
  },
];

/**
 * True when `notice` applies to `app` (a row from the apps table).
 * An absent/null `match` applies to every app.
 */
export function matchesApp(notice, app) {
  if (!notice.match) return true;
  return Object.entries(notice.match).every(([column, expected]) => {
    const actual = app?.[column];
    return Array.isArray(expected) ? expected.includes(actual) : actual === expected;
  });
}

/**
 * Notices that apply to every app, so they can be served without naming an app
 * or reading its configuration. This is the set the public read path returns.
 */
export function globalNotices() {
  return NOTICES.filter(n => !n.match);
}

/** Global notices plus the ones scoped to this specific app. */
export function noticesForApp(app) {
  return NOTICES.filter(n => matchesApp(n, app));
}
