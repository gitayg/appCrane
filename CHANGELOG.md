# AppCrane Changelog

Machine-readable release notes. Each entry is one line: `## <version> — <summary>`.
The dashboard's "What's New" dialog reads this file over raw.githubusercontent
so it can show admins what changed when AppCrane is updated (or about to be).
Keep newest-first; add an entry before every version bump.

## 2.21.15 — Collapsing the sidebar now keeps the apps reachable as an icon rail (icons only, still clickable, with the status dot) instead of hiding them entirely
## 2.21.14 — The Dashboard is now overview-only: per-app operations (open, env vars, onboard prompt, request enhancement, delete) were removed from it and live solely on the Manage page — the Applications section just links there now
## 2.21.13 — Renamed the MCP proxy package from @appcrane/mcp to unscoped appcrane-mcp so it publishes with a plain `npm publish` (no npm org to register); verified the name is free and the package packs cleanly (index.js + README only)
## 2.21.12 — Added @appcrane/mcp: a tiny stdio↔HTTP proxy package (npx / Docker) that bridges any MCP client to a remote AppCrane server's appcrane_* tools — for stdio-only clients and an npx/registry install path (direct remote-HTTP connect still works too)
## 2.21.11 — Fixed the light theme: it never actually applied because a leftover chat-UI stylesheet's `:root` (loaded after the admin styles) tied on specificity and won on source order, keeping buttons, inputs, and backgrounds dark. The light theme selector now out-specifies it, and the leftover's dark-only variables get light values
## 2.21.10 — Multi-language builds via Nixpacks: apps with no Dockerfile that aren't Node (Python, Go, Ruby, static, …) now build automatically when the `nixpacks` binary is on the deploy host; without it, the deploy fails with a clear "install nixpacks or add a Dockerfile" message. Node and Dockerfile apps are unchanged
## 2.21.9 — Scheduled off-site backups: nightly upload of the config backup (DB + secrets + app data) to S3 or any S3-compatible store (R2/MinIO), configured in Settings → Backup, with a "Back up now" button. Self-contained SigV4 signing (no AWS SDK); no-op until credentials are entered
## 2.21.8 — Per-app resource graphs: AppCrane now samples CPU/memory every 5 minutes into a 7-day history, and Manage has a per-app chart (📈) of CPU and memory over the last 24h for sandbox + production
## 2.21.7 — Surfaced webhook auto-deploy in Manage: a per-app "Auto-deploy" modal to enable deploy-on-push for sandbox/production, set the branch, copy the webhook URL, and register the hook on GitHub (the receiver already existed)
## 2.21.6 — Licensing reconciled to AGPL-3.0-only across LICENSE/package.json/deployhub.json/README, plus a CONTRIBUTING.md CLA and a COMMERCIAL-LICENSE.md stub that enable the AGPL + commercial dual-licensing model
## 2.21.5 — Platform requests: anyone can file a request against AppCrane itself, visible only to platform admins; Manage now shows only apps you own/admin (not the whole catalogue); CPU/memory limits are locked to platform admins across the API, MCP, and dashboard; and the sidebar version pill refreshes instead of showing a stale value after a deploy
## 2.21.4 — Removed the near-empty admin topbar (reclaims vertical space; everything had moved to the sidebar), and fixed the Users table crushing names/emails to a few characters — it now scrolls horizontally with readable column widths
## 2.21.3 — SSO logins now keep a user's email in sync from the IdP (not just their name); SAML only syncs from a real email attribute, never the NameID/login fallback, so corrected mailboxes aren't clobbered by a shortened username
## 2.21.2 — Managed-app create now reports a duplicate repo name as REPO_EXISTS (recoverable) instead of the misleading REPO_CREATE_FORBIDDEN, and surfaces GitHub's actual error reason
## 2.21.1 — Each sidebar app now shows its owner on a smaller line beneath the name (e.g. "by Len Vo"), and the owner name is a clickable mailto link
## 2.21.0 — Sidebar overhaul: resizable width (drag + persisted), app names wrap instead of truncating, fixed the odd app-row backgrounds, tooltips now show the last-deploy date and all owners; and notifications moved into the sidebar — now owner-scoped, surfacing failing health checks and open requests only for apps you own
## 2.20.2 — Fixed app visibility and public_access being able to drift apart (an app could be publicly reachable yet still prompt users to "Request access"): the invariant now lives in one shared helper that both the REST update and the MCP config tools use
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
