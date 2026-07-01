# AppCrane Changelog

Machine-readable release notes. Each entry is one line: `## <version> — <summary>`.
The dashboard's "What's New" dialog reads this file over raw.githubusercontent
so it can show admins what changed when AppCrane is updated (or about to be).
Keep newest-first; add an entry before every version bump.

## 2.20.1 — Daily digest now shows up to 10 requests per app, with a "read more in AppCrane" link (to the Requests page) for the rest
## 2.20.0 — Redesigned the daily "requests awaiting action" digest: clean HTML grouped by app, each request collapsed to one readable line (the element-picker noise is summarized), with requester/date and a Review button — plus a plain-text fallback
## 2.19.0 — Request-completed / won't-do emails are now signed by the app owner/admin who actioned the request (whoever shipped or closed it), instead of a generic "— AppCrane"
## 2.18.0 — AppCrane now inherits richer directory attributes from the IdP: SCIM syncs each user's department, region (state/province), and location (city) from Okta/Universal Directory; shown and editable on the Users page and returned by /api/auth/me
## 2.17.0 — Merged "My Requests" into the single Requests page, now role-scoped: platform admins see all requests, app owners see their apps' requests, and everyone else sees (and can delete) just their own
## 2.16.0 — New "My Requests" page: every signed-in user can now see the requests they've submitted and delete their own (unless one is actively being worked on)
## 2.15.1 — Removed the redundant "AppCrane" wordmark from the in-app topbar (next to the Production/Sandbox switcher) — it's already shown in the sidebar
## 2.15.0 — Open multiple apps at once, each in its own tab; the app views (and their iframes) now stay alive as you move around the dashboard, so switching tabs is instant and nothing reloads
## 2.14.3 — Skills moved under Settings; sidebar reorganized (Manage/Docs/Settings pinned to the bottom, your account moved into the sidebar); app owners now emailed on any new request to their app
## 2.14.2 — Requests table layout fixed; the update dialog now shows specific release notes; won't-do request emails (with a copy to platform admins); a daily digest of pending requests to app owners
## 2.14.1 — Sidebar & inline-app polish; email the requester when a request is fulfilled, and app admins on access requests
## 2.14.0 — Launcher folded into the sidebar nav; MCP moved under Settings; a What's New dialog on login and on upgrade
## 2.13.0 — Apps now live in the sidebar nav (collapsible), open inline; a Manage page for app owners
## 2.12.0 — Sidebar-nav launcher; each environment's version shown in the app top bar
## 2.11.0 — AWS-aligned MCP naming: `stage`, `secrets`, `cp` (old names kept as aliases)
## 2.10.7 — Agents can push large code files to managed apps via a staged upload
## 2.10.6 — Agents can stage large binaries straight into an app's /data
