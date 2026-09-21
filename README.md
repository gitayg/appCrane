# AppCrane

**Self-hosted PaaS where the agent is the operator and the platform keeps the receipts.**

[![GitHub stars](https://img.shields.io/github/stars/gitayg/appCrane?style=flat)](https://github.com/gitayg/appCrane/stargazers)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
![Platform: Ubuntu 22.04+](https://img.shields.io/badge/platform-Ubuntu%2022.04%2B-e95420)

AppCrane runs the internal apps your team builds with Claude Code or Cursor, on a server you own. An agent creates the app, deploys it, reads the logs and rolls it back through 59 MCP tools — no browser, no curl — while the platform enforces SSO and per-app roles, records every action against the actor that took it (tagged **agent** or **human**), and keeps app secrets out of reach of the person administering the box.

It is for teams that have to self-host — data residency, a customer contract, an internal-only network — and still have to answer *who deployed this, what was in it, and can we undo it?*

## What is actually uncommon here

Self-hosted PaaS caught up on governance during 2026. Coolify shipped structured audit logging and first-class OIDC; Dokploy shipped SSO, SCIM, custom roles and audit logs. Komodo has had [granular per-resource permissions](https://komo.do/docs/configuration/permissioning) and a full audit trail for longer than either. Most of what used to be a differentiator here no longer is, and the claims below are the ones that survived checking their docs. Four things still stand out:

**1. Governance is in the open-source build, not behind a license key.** SAML 2.0, OIDC, SCIM provisioning, per-app roles and the audit log are all in the AGPL-3.0 build with nothing to activate. Dokploy ships the same category of capability as [Enterprise](https://docs.dokploy.com/docs/core/enterprise), gated on a license key. Coolify's are free, but its changelog lists OIDC and audit logging without SAML or SCIM. Komodo's are free too — GPL-3.0, with per-resource permissions and an audit trail in the box — but its [documented sign-on](https://komo.do/docs/intro) is username/password and OAuth (GitHub, Google, generic OIDC), with no SAML or SCIM in the docs. So the free-versus-paid line is really only Dokploy's; against Coolify and Komodo the difference is which enterprise-directory protocols are covered, not what you have to pay to turn them on.

**2. The built-in agent interface can change things.** Coolify's instance-level MCP server is deliberately **read-only** — ten list/get tools. AppCrane's 59 include `appcrane_deploy`, `appcrane_rollback`, `appcrane_promote`, `appcrane_set_secret` and `appcrane_grant_app_access`. Dokploy's official MCP package is write-capable too, and far larger (508 tools across 49 categories) — AppCrane's surface is smaller by choice, not by capability, and is paired with `appcrane_get_guide(topic="onboarding"|"operations")`, which serves the current playbook from the server so the agent reads the procedure instead of inferring it from a tool list. Komodo ships no MCP server of its own; neither its [repo](https://github.com/moghtech/komodo) nor its docs contain one, and the several that exist are third-party wrappers over its REST API.

**3. The audit log tells an agent from a person.** Every row carries `actor_kind`, so "what did the agents do on this box last week" is one query. The others record a user identity — Komodo's trail records "who made it and when" ([intro](https://komo.do/docs/intro)) — but none of their docs describe separating automated actors from humans.

**4. The operator is locked out of app secrets.** Env-var access follows app assignment, and that holds for `platform_admin` as well — the role that installs and updates the platform cannot read the plaintext of an app it is not assigned to. Reveals are throttled and audited across both doors, HTTP and MCP, so switching transport does not buy a fresh allowance. Komodo documents the opposite arrangement explicitly: marking a variable secret prevents access to the value for [non-admin users](https://komo.do/docs/configuration/variables), which is to say an admin can read it.

Four more that are unusual but worth measuring against your own requirements rather than reading as headlines: **per-tenant data isolation** for deployed apps; repo-less uploads identified by a **server-side SHA-256 over the received bytes** instead of a self-reported commit SHA; a **daily vulnerability digest** mailed per recipient — fleet-wide to a platform admin, own-apps-only to an app owner, so the digest cannot leak which other apps are exposed; and **managed repos**, so an agent can create and ship an app for someone who has no GitHub account at all.

Versus vendor-hosted governed platforms (Replit, Lovable, Retool, Superblocks), the trade is the usual one: their governance is more mature, and your app data, database connections and API keys live on their infrastructure.

### Against self-hosted PaaS

| | AppCrane | Coolify | Dokploy | Komodo | CapRover / Dokku |
|---|---|---|---|---|---|
| Multi-host / fleet deploys | **no — single host** | yes (experimental) | yes, remote servers | yes, agent per host | Swarm cluster (CapRover) |
| Built-in MCP that can deploy | 59 tools, incl. rollback | 10 tools, **read-only** | 508 tools (official package), incl. rollback | community projects only | community projects only |
| SAML 2.0 | yes | not in changelog | Enterprise | not documented | no |
| OIDC | yes | yes (v4.4-rc.1) | Enterprise | yes, generic OIDC | no |
| SCIM provisioning | yes | not in changelog | Enterprise | not documented | no |
| Audit log | yes, agent vs human attributed | yes, structured (v4.1.0) | Enterprise | yes, full change trail | no |
| Governance behind a paid tier | no | no | yes | no | n/a |
| Operator cannot read app secrets | yes | not documented | not documented | **no — admins can** | no |
| Per-tenant data isolation for apps | yes | not documented | not documented | not documented | no |
| Deploy identity for repo-less uploads | server-side SHA-256 | not documented | not documented | not documented | no |
| Core license | AGPL-3.0 | Apache-2.0 | Apache-2.0 + paid Enterprise | GPL-3.0 | open source |

The first row is the one AppCrane loses outright. [Komodo](https://github.com/moghtech/komodo) is built around fleet management: a Core web server plus a stateless [Periphery agent](https://komo.do/docs/setup/connect-servers) on every connected machine, with "no limit to the number of servers you can connect", Docker Swarm management, and declarative resource sync from a git repo. AppCrane has no agent, no host registry and no remote-execution path — it deploys containers on the machine it is installed on, and that is the whole design. [Coolify](https://coolify.io/docs/knowledge-base/server/multiple-servers) and [Dokploy](https://docs.dokploy.com/docs/core/remote-servers) both reach other servers too, and [CapRover](https://caprover.com/docs/app-scaling-and-cluster.html) joins nodes through Docker Swarm.

CapRover and Dokku are in one column because their access model is the same shape: a single admin account (CapRover) or SSH keys where the word `admin` in a key name grants key-management rights (Dokku), with multi-user access an [explicitly out-of-scope](https://github.com/caprover/caprover/discussions/1315) request in one and an unaudited community plugin in the other. That is a reasonable design for a one-operator box; it is not something to put an IdP in front of.

> Checked against each project's own documentation and changelog in September 2026. **"not documented"** means the capability does not appear in their docs — that is not proof it is absent, and a vendor page is a claim, not a test. Verify anything load-bearing on your own install.

**Honest scope.** Coolify has a far larger template marketplace, a much bigger community, and multi-server orchestration; if you want one-click Postgres and hundreds of app templates, use Coolify. Dokploy's API surface is broader than AppCrane's and it sells support with an SLA. Komodo is the better choice the moment the answer involves more than one machine — a fleet of hosts, a Swarm, builds farmed out to spot instances, configuration synced declaratively from git; AppCrane deploys to the box it runs on and nowhere else, so a multi-host estate is not a smaller version of this, it is a different product. Dokku and CapRover are simpler and lighter if one person operates the box. Choose AppCrane when the apps are agent-built, the agent should do the deploying, everything lands on one server you own, and someone will later ask you to prove who did what.

**Why it matters now.** Three things changed in 2026:

- **The bottleneck moved from writing software to operating it.** In Anthropic's [Claude Code study](https://www.anthropic.com/research/claude-code-expertise) (~400k sessions), "operating software" — deploying, configuring, running pipelines — grew from 14% to 21% of sessions while fixing broken code fell from 33% to 19%. Non-engineers now ship deployable code within 7 points of professional engineers. The scarce thing isn't the app any more; it's somewhere safe to run it.
- **Shadow AI became measurable.** The [2026 Verizon DBIR](https://www.verizon.com/business/resources/reports/dbir/) reports shadow-AI detections up 4×, AI use on corporate devices rising 15% → 45% in a year with 67% through non-corporate accounts — and source code as the most commonly submitted data type. Bans make it worse; a sanctioned platform is the answer that works.
- **Governance-by-console is the failure mode.** Platforms that gate every app behind a human clicking through an approval UI stall once there are hundreds of apps. AppCrane's answer is different in kind: the **agent** drives the governed lifecycle over MCP, and the platform records and constrains it — rather than a person mediating each step.

## Features

- **Docker container isolation** — every app runs in its own container; no shared dependencies, no runaway processes
- **Managed databases** — PostgreSQL, MariaDB, MongoDB and Redis provisioned per app (and per tenant), with credentials injected under whatever env-var names the app actually reads. Postgres, MariaDB and Mongo share one server per engine with isolation enforced inside the engine — a Mongo user is scoped to its own database and `listDatabases` returns only that one, which is stricter than Postgres, where `pg_database` leaks every database name. Redis instead gets a container per scope, because its ACLs cannot scope to a numbered database: a user pinned to db 1 can still reach db 2 with `COPY ... DB` and `MOVE`. Mongo runs as a single-node replica set, so change streams and transactions work
- **Per-app container command and volumes** — an app can declare the argv its image needs (`["start-dev"]`) and the paths it actually persists. Commands are argv arrays, never shell strings, so nothing in a stored command can become a second token. Declared paths survive the stop-and-recreate every redeploy performs, and 23 catalogue entries carry paths measured from their own images — so an app that was already installed starts keeping its state without anyone editing it. A newly created mount is seeded from the image's content first, because a bind mount (unlike a named volume) masks what the image ships there: without seeding, declaring `/var/www/html` would hand the app an empty directory where its 7,747 files used to be
- **Managed-app repositories live on the AppCrane host** — a new managed app's code is a bare git repository under `DATA_DIR/repos`, not a GitHub repo: no service account, and the code never leaves the box. Repositories are written with git plumbing (no worktree), isolated from the host's git configuration and hooks, and when two pushes race the newest wins — the push that landed first is parked under a `refs/dropped/` ref, reported back to the pusher, and carried in backups, so it can be recovered. A push can also **delete** files: `appcrane_push_to_managed_app` takes a `deletions` list of repo-relative paths applied to the same commit as the writes, so one call is still one commit (send `files: []` for a pure deletion, and read the removed paths back from the response's `deleted`). Deleting a path the branch does not have is refused by name instead of committed as a no-op — at the git plumbing level it is silent — no path may be written and deleted in the same push, and a push that would leave the repository with no files at all is refused. The `.env*` rule below covers deletions as well as writes. GitHub-backed managed apps do not get this: GitHub's contents API cannot express a deletion, so one is refused rather than quietly dropped. Deploys clone from the local repository and the pre-deploy commit check reads it directly. A push deploys on its own when the app has auto-deploy on for that environment (the same flags and branch filter a GitHub webhook uses), and check-for-updates compares against the local branch. Ask Claude answers from the repository itself through read-only file listing, reading and search pinned to one commit — no container is started; it needs the server's `ANTHROPIC_API_KEY` (per-app subscription credentials are not used for these apps). AppStudio analyzes the repository and files the result as a new request instead of writing code. A coder session now works for these apps: the workspace is cloned from the local repository with no credential of any kind, and shipping a branch to GitHub is refused rather than attempted, because there is no remote to ship to. Releasing is a choice, not a sweep — `GET /api/coder/:slug/session/:id/changes` lists what the agent changed, with a diff per file, and `POST .../release` takes only the paths you name, pushes them to the local repository as one commit, and lets the ordinary auto-deploy carry them to sandbox. A file the agent deleted is released as a deletion, so a rename is one commit rather than a stale file left behind. Releasing is gated on app admin, the same bar as any other write to a managed repository, so a person who may talk to the agent does not automatically ship its work. When the idle container is evicted, anything not yet released is committed to `agent/<userId>/<sessionId>` first — a safety net, never a release: that branch is refused if it matches the branch a push would deploy, so unreviewed work cannot reach sandbox by being walked away from. The agent's conversation is kept too, so returning to a session resumes it instead of starting over, until AppCrane itself restarts. Existing GitHub-backed managed apps move over on their own: on the first boot after upgrading, before AppCrane starts serving, each one is fetched (branches and tags only) into a staging copy and switched to the local repository only when every branch and tag matches GitHub exactly; anything else leaves that app on GitHub and records why. Apps move one at a time, each git operation is killed at a per-app limit and the whole run at a total budget (apps not reached are retried next boot), a failure never stops boot, and the GitHub token is passed to git through its environment, never a URL, config file or command line. While it runs, sign-in for hosted apps is unavailable. Platform admins can see each app's outcome at `GET /api/github-service/repo-migration`; set `APPCRANE_REPO_MIGRATION=off` to skip it.
- **Uploaded apps become Crane-hosted on their own** — on the first boot after upgrading, right after the managed-repo move and before AppCrane starts serving, each app deployed from uploaded bundles is turned into a Crane-hosted app, one at a time, with no deploy and no container touched. Its repository gets one commit holding the release production is running, plus a second commit on top when sandbox runs a different release; each environment's live deployment then points at its commit (the upload's SHA-256 stays in the commit message), so check-for-updates and promote work from the repository. `node_modules` and `.git` at any depth are left out of the repository, symlinks are committed as symlinks (never followed; one pointing outside the release is left out) and the excluded paths are listed per app. Every `.env*` file, at the root or nested, is kept as well, but never in git: its content is stored encrypted in AppCrane's database (so it travels in the data backup) and written back, at its original path and with its original file mode, into that environment's release on every deploy before the build, so build-time keys such as `VITE_*` reach the build exactly as they did from the bundle. The stored file is the base, and that environment's AppCrane environment variables are layered on each time it is written: in a file a production build loads (`.env`, `.env.local`, `.env.production`, `.env.production.local`, `.env.sandbox`, `.env.sandbox.local`, at the root or nested) a key that is also a variable takes the variable's value, with only that line rewritten and comments, order and formatting kept; a variable that no root-level loadable file defines is appended to the root `.env` (created with mode 0600 if the app has none), never to a nested file; example, sample and template files are written as stored. Deploys never change the stored copy, so editing or deleting a variable changes the file on the next deploy that builds a new image (an unchanged commit reuses its cached image). Because the file is part of the build context, its values, including appended variables, are inside the built image. The deploy log names the overridden and appended keys, never their values. Production only ever gets production's files and sandbox only sandbox's; a `.env` symlink pointing outside the release (what promote leaves in production) is not kept; the conversion status shows platform admins the stored paths, never the contents. An app's owner (or a global admin assigned to the app) manages the stored files on the app page under **Stored .env files**, or through `GET /api/apps/:slug/env-files` (paths, env, mode, size and time, no content), `GET /api/apps/:slug/env-files/content?env=&path=` (the content; audited as `env_file.reveal`, throttled and notified like an env-var reveal, sharing its budget), `PUT /api/apps/:slug/env-files` with `{ env, path, content }` (create or replace; `encoding: "base64"` for raw bytes; a new file gets mode 0600, a replaced one keeps its mode; at most 1 MiB of valid UTF-8 that parses as dotenv, a parse error is reported by line number without echoing the content) and `DELETE /api/apps/:slug/env-files?env=&path=`. Paths follow the same rule as the restore (relative, no `..` or `.git`, a `.env*` file name). Changes are audited as `env_file.replace` / `env_file.delete` with the path only and take effect on the next deploy of that environment. Other app members get 403 and an app that is not Crane-hosted gets 409. A push to a Crane-hosted app's repository that contains any `.env*` file (by file name, at any depth, in any letter case, `.env.example` included) is refused whole with `ENV_FILE_IN_PUSH` and nothing is committed; `appcrane_push_to_managed_app` and `appcrane_managed_patch` refuse it before touching the repository, `appcrane_managed_push_chunk` at the first part, and `appcrane_managed_assemble` before committing. The error lists the paths, never the content, and points to environment variables (`appcrane_set_secret`) or the stored file; a refused file's content is also kept out of the MCP audit record. GitHub-backed managed apps are not affected. Values from the bundled root `.env`, overridden by `.env.production` for production or `.env.sandbox` for sandbox, become the app's encrypted environment variables; a variable already set in AppCrane is never overwritten, example/sample/template, development and nested files are not imported, and no value is ever logged or recorded, only key names. An app is left as an upload app, with the reason recorded, when its build depends on the bundled `node_modules`, when its releases are missing, when nothing but excluded content remains, when a `.env` to import is malformed, when a `.env` file is over 1 MiB, or when it is over the size cap (512 MiB, `APPCRANE_UPLOAD_CONVERSION_MAX_BYTES`). Once converted, bundle uploads for that app are refused with 409; push with `appcrane_push_to_managed_app` instead. The upload release directories stay on disk: to revert, set the app's `source_type` back to `upload` and `repo_backend` to NULL and keep its repository where it is (the next boot then leaves it alone). Platform admins see each app's outcome at `GET /api/github-service/upload-conversion`; set `APPCRANE_UPLOAD_CONVERSION=off` to skip it. When sandbox was running different code, its commit is the newest one, so every later deploy — production included — builds sandbox's code; production cannot be redeployed from its own earlier commit, because the pre-deploy check accepts only the latest pushed commit. Legacy upload apps (`source_type='managed_legacy'`, renamed by v2.3.1) are converted too, unless they carry a `github_url`; the status route's `original_source_type` / `revert.source_type` says which type a converted app reverts to. If only one environment still has its uploaded release on disk (for example sandbox after its last uploads failed), the app converts from that one; the other environment's next deploy builds the repository's newest commit.
- **Sign in inside an embedded frame** — an app embedded by a site under the platform's own domain (or an origin the app lists) can sign its user in without leaving the frame: every hop of the sign-in chain (the auth check's redirect, `/login`, `/launch`) drops `X-Frame-Options` and sends the app's `frame-ancestors` policy, and only when the redirect names that app. The deep link now survives sign-in, so a signed-out visitor lands on the app they asked for rather than the dashboard. Password sign-in completes in the frame; OIDC and SAML hand off to the identity provider's own page, which the provider may refuse to frame. AppCrane's embedding policy also wins over the app's own `Content-Security-Policy`: the `frame-ancestors` the app sends for itself is rewritten to the configured policy at the edge (everything else in the app's CSP — its `script-src` and nonce, `object-src`, `form-action` — is passed through untouched), so an app hard-coded to `frame-ancestors 'none'` is still embeddable once someone allows it. When the sign-in page detects it is framed, OIDC and SAML instead show a **Sign in** button that opens the identity provider in a small top-level popup, which closes itself once signed in while the frame reloads into the app. If that sign-in fails (the provider refuses, there is no account, or the attempt expires) the popup stays open with a short reason and a Close button, and the frame stops waiting at once and offers **Sign in** again; a popup simply closed cannot be detected behind a provider's `Cross-Origin-Opener-Policy`, so the button stays usable while the frame waits. The sign-in page confirms a stored session with the server before sending the frame back to the app, so a dead session shows the sign-in form, a user with no role on the app sees "You don't have access", and a chain that keeps bouncing stops after three tries with "Sign-in couldn't complete" instead of reloading forever.
- **Restore onto a bare host, with no registry** — a backup is a set of archives, each written straight to disk and never held in memory: a data archive (database, secrets, icons, per-app `/data` and every declared volume), one archive per managed-app code repository, and a streamed archive of the container images themselves, saved by digest. The data archive records which repositories and commits it expects, so restoring it next to a repository archive from a different backup is reported rather than silently mixed. Export runs off the main thread, so hosted apps keep answering their sign-in checks while a backup is taken, and restore streams the upload to disk with a free-space check instead of a fixed size cap. Symbolic links are archived as links, never followed, so an app cannot pull a host file into a backup through its own `/data`. The scheduled off-site (S3) backup uploads the data archive only, and is a no-op until a bucket and credentials are entered — so a **local** nightly backup is on by default instead of nothing being on by default: it writes `deployhub.db` and `.env` to `DATA_DIR/backups/local` at 04:00 and keeps the newest seven (Settings → Backup changes the hour, the count, or switches it off). That covers a corrupted, deleted or badly-restored database and nothing else — not app icons, per-app `/data`, declared volumes, repositories or images, which would make an unattended nightly job unbounded on the very disk it is protecting. It is not a substitute for an off-site copy, so until an upload has actually completed every backup surface — the settings API, `appcrane_get_backup_status`, the dashboard and the boot log — says **"No off-site copy — everything AppCrane knows lives on this host."** A stored bucket with the schedule off, and a schedule switched on that has never finished, both count as no copy. That matters because a registry is not a backup: `bitnami/*` images 404 after their registry change, and `medusajs/medusa`, `vendureio/vendure` and `crater/crater` all 404 today. When a pull fails, a deploy now falls back to bytes already on the host instead of refusing to start
- **A redeploy that would destroy data asks first** — every deploy recreates the container, so anything outside `/data` and the app's declared volumes is lost. AppCrane inspects the *running* container and warns only when state is genuinely at risk, naming what survives and what does not. It finds that state two ways: paths the image declares as `VOLUME` that nothing mounts, and paths the app has actually **written** (`docker diff`) that no mount covers — the second matters because `VOLUME` is a floor, and every Laravel app persisting to `storage/` declares none at all. Measured across eight real images, only the app with genuinely unprotected state was flagged; a warning that fires on safe apps just teaches people to click through it. The dashboard requires a second confirmation; the API and MCP require an explicit `acknowledge_data_loss`, failing closed — most deploys here come from an agent, and a UI-only warning would miss them
- **Auto-generated Dockerfiles for Node and PHP** — an app with no Dockerfile is built from `node:*-alpine`, or from `php:8.3-apache` when it ships a `composer.json`. Both run non-root and honour the port AppCrane assigns. A PHP build is health-checked at its front controller and held to "answers 200" rather than to AppCrane's `{status, version}` body — AppCrane generates the Dockerfile, not the application, and Laravel and Symfony serve no `/api/health`. Nixpacks still covers everything else
- **Enterprise SSO** — SAML 2.0, OIDC, and SCIM provisioning; connect to Okta, Azure AD, Google Workspace
- **Identity forwarded to apps as headers** — `X-AppCrane-User-Role`, `X-AppCrane-App-Role`, etc. are injected by the proxy after `forward_auth` verifies the user; deployed apps read identity directly off the request without a callback (oauth2-proxy / IAP pattern)
- **`/api/me` endpoint** — canonical "who is the caller" for proxied apps; accepts the `cc_token` cookie, Bearer, or `X-API-Key`; returns global role + per-app role (`?app=<slug>` or `Referer`-inferred)
- **Headless app type** — set `auth_mode: 'headless'` to bypass `forward_auth` entirely on an app; right tool for telemetry ingest, public webhooks, status pages, and single-purpose unauthenticated services
- **TCP (layer-4) ingress** — for apps that aren't HTTP at all (a forward/CONNECT proxy hands back a raw tunnel no reverse proxy can express), a platform admin can publish the container's port directly on the host, with Caddy out of the path. No SSO, no identity headers, no TLS from AppCrane — the app owns authentication completely
- **Dual-plane apps** — `ingress_type: 'dual'` for an app that is both: an HTTP **control plane** still served through Caddy on container port 3000 with every control intact, plus a raw **data plane** on a different port inside the same container, published at `0.0.0.0:<public_port>`. The data-plane port may not be 3000 — that would republish the control plane unauthenticated — and health checks keep probing the control plane, the only plane that can actually answer
- **AppStudio AI pipeline** — AI proposes code improvements on a schedule; you review and approve before anything ships
- **Real-time presence** — see who's active on each app, which environment, and when they last deployed
- **Dual environments** per app: production + sandbox, always-on, separate ports
- **Auto-HTTPS** via Caddy reverse proxy with Let's Encrypt
- **GitHub webhook auto-deploy** on push (HMAC-verified)
- **GitHub App authentication for connected repos** — instead of a long-lived personal access token, a platform admin creates this instance's own GitHub App from Settings → GitHub (GitHub's App-manifest flow; the App is never shared between installs), app builders install it on only the repositories they choose, and an app is attached to its installation from Applications → gh app. AppCrane then clones, pins, runs the pre-deploy commit check, reads pull requests and checks for updates with a one-hour installation token narrowed to that one repository, cached in memory only and handed to git through its environment — never a URL, config file, log line or command line. The App asks for read-only Contents, Metadata and Pull requests, so it cannot push, open pull requests or register a webhook ("Register on GitHub" is refused for an attached app; paste the payload URL on GitHub instead). If an attached app's token cannot be issued, the operation fails with the reason; it never falls back to the app's stored PAT. Apps with no installation keep using their PAT exactly as before. **Webhooks:** the App delivers to `POST /api/github-app/webhook`, verified only by GitHub's `X-Hub-Signature-256` over the raw body with the App's webhook secret (redeliveries of the same `X-GitHub-Delivery` are answered without acting twice). A push to an attached app's deploy branch starts the same auto-deploys as the per-app webhook (same auto-deploy switches and branch filter, audited as `github-app-push-deploy`); tag pushes and branch deletions deploy nothing. An uninstalled or suspended installation, or a repository removed from it, is marked rather than detached, so the attached app fails with that reason instead of silently going back to its PAT; unsuspending or re-adding the repository restores it. Apps created with `CRANE_DOMAIN` set have webhooks active and subscribed to Push from the start; without `CRANE_DOMAIN` they stay off, since GitHub would have no public URL. For an App created before this, press **Send webhook settings to GitHub** in Settings → GitHub (it sets the URL, JSON content type and secret through GitHub's API), then on GitHub open the App under Settings → Developer settings → GitHub Apps → Edit, tick **Active** under Webhook, tick **Push** under Subscribe to events, and Save changes — GitHub's API cannot do those two. The 5-minute PR poller keeps running either way. Not yet covered: AppStudio coding/PR flows, Ask Claude, release notes and the issues mirror still use the PAT, and an instance config export does not carry the App's private key.
- **Stored GitHub credentials stay out of URLs, files and responses** — deploys pass a stored personal access token, the managed-app service-account token or an installation token to git through its environment, never in the clone URL, so it is not in the process list, in error text, or in the `.git/config` git writes into each release. Earlier versions did put it in the URL, which left the token in plain text in every release directory; on boot AppCrane removes those credentials from existing release directories, AppStudio job directories and builder workspaces (only the credential part of the remote URL, never app data or volumes). App responses no longer include any encrypted credential column; the dashboard reads only the `has_*` flags. Each app in the list is labelled with where its code comes from: Crane-hosted, Managed (GitHub), GitHub App, GitHub token or Public GitHub.
- **Zero-downtime deploys** (start new, health check, swap, drain old)
- **Rollback in seconds** (symlink-based, keeps last 5 releases) — the previous release's container image is kept as well, so rolling back one release restarts it instead of rebuilding; change how many older images an app keeps with `image_retention` (default 1, `appcrane_update_app` or the app's settings; 0 keeps only the running image and makes every rollback rebuild)
- **Encrypted env vars** (AES-256-GCM) — admin cannot read them by design
- **Health checks** with auto-restart and email notifications
- **Audit log** for every action
- **MCP server** at `/api/mcp` exposing 59 `appcrane_*` tools — agents operate the platform without ever touching curl, gh, or shell

## Quick Start

**One command** on a fresh Ubuntu server installs and wires up *everything* — Node,
Caddy (with automatic HTTPS), Docker, the systemd service, an encrypted-secrets key,
and your admin user:

```bash
curl -fsSL https://raw.githubusercontent.com/gitayg/appCrane/main/install.sh | sudo bash
```

It prompts for just two things — your **domain** and **admin email** — and is safe to
re-run. When it finishes, point your domain's DNS at the server and you're live.

**Prerequisites:** a fresh Ubuntu server (root / sudo) and a domain whose DNS `A`
record points at it — Caddy provisions TLS automatically on first request.

**Non-interactive** (CI / automation) — no prompts:

```bash
sudo CRANE_DOMAIN=crane.example.com ADMIN_EMAIL=admin@example.com bash install.sh
# flags also work: --domain / --admin-email / --admin-name / --tls-cert / --tls-key
```

<details>
<summary><b>What the installer sets up — and why installing by hand isn't recommended</b></summary>

Everything below is done for you, idempotently, by the one command above:

- **Node.js 22** + AppCrane, with the `crane` CLI linked globally
- **Caddy** — the reverse proxy that routes `<domain>/<slug>` to each app, runs the
  SSO auth, injects the `X-AppCrane-*` identity headers, and auto-provisions TLS —
  **plus** the group, file permissions, and a `sudoers` rule so AppCrane can reload
  Caddy on every deploy
- **Docker** + a **systemd** `appcrane` service (`Restart=always` — survives crashes
  and reboots, and powers one-click self-update)
- A `.env` with a freshly generated `ENCRYPTION_KEY` — **back this up; losing it makes
  every stored secret unrecoverable** — and your admin user (`crane init`)

Installing by hand means reproducing all of that — **especially the Caddy install +
permissions + sudoers**, which is the most-missed step and later surfaces as
permission errors or apps that never receive their identity headers. If you must,
treat [`install.sh`](install.sh) as the source of truth rather than a shortened list.

> **AI sessions (optional).** A coder session runs on whichever credential is
> available, in this order: **the signed-in user's own Claude subscription**, then
> the app's stored credentials, then a platform API key. Exactly one is ever sent
> to the container — Anthropic ranks an API key above a subscription token, so
> sending both would silently bill the wrong account.
>
> For the first, each person generates their own one-year token with
> `claude setup-token` (Pro, Max, Team or Enterprise plan) and saves it under their
> own settings; nobody else, platform admins included, can read, replace or clear
> it. The token does not refresh — it expires a year after it is generated and
> regenerating needs a browser, so AppCrane stores the expiry and shows it.
>
> For a platform-wide key instead: `systemctl edit appcrane --force`, add
> `Environment="ANTHROPIC_API_KEY=sk-ant-..."` under `[Service]`, then
> `systemctl daemon-reload && systemctl restart appcrane`.

</details>

### Deploy your first app

**Apps are created and deployed by an agent over MCP, not from the CLI.** The
installer ran `crane init`, which printed your `dhk_admin_*` key and wrote it to
the CLI config (`crane config --show` to read it back; `crane regenerate-key` on
the box if it is lost). Point Claude Code at the instance once:

```bash
claude mcp add --transport http appcrane https://<your-domain>/api/mcp \
  --header "X-API-Key: dhk_admin_xxxxxxxxxxxxx" \
  --header "X-Github-Token: ghp_your_github_pat"
```

Then ask for the app in a Claude Code session:

> Onboard a new app on AppCrane. Start by calling `appcrane_get_guide` with
> `topic="onboarding"` for the playbook. It is MyApp at slug `myapp`, from
> https://github.com/yourorg/myapp. Deploy it to sandbox and give
> sarah@example.com access.

The agent calls `appcrane_create_app`, then `appcrane_deploy`, then
`appcrane_grant_app_access` — and the app is reachable at
`https://<your-domain>/myapp`. The dashboard's **Add Application** button hands
you the same prompt, pre-filled with this instance's URL and your key.

Prefer to drive it yourself? The dashboard at `https://<your-domain>` creates and
deploys apps through the same routes, and the REST API underneath them
(`POST /api/apps`, `POST /api/apps/:slug/deploy/:env`) takes the same
`X-API-Key`. See [Deploying without GitHub](#deploying-without-github) for the
repo-less path.

## CLI Reference

**`crane` is the platform operator's tool, not the app owner's.** It installs the
box, terminates TLS, moves instance config, recovers a lost key, reloads Caddy and
repairs drift — nine commands, listed in full below. App operations (create,
deploy, roll back, promote, secrets, logs, access) are **not** in the CLI: the
agent-facing surface was retired in v2.6.0 and lives on the MCP server and the
REST API. See [App operations](#app-operations-mcp-or-rest) below.

### Install and first run
```bash
crane init --email admin@example.com          # First run: create the admin directly in the DB
                                              # (--name defaults to "admin"); prints the dhk_admin_* key
crane setup-https --domain crane.example.com  # Install Caddy, configure HTTPS, set up the firewall
crane update                                  # Pull latest code from GitHub and restart AppCrane
```

### Connection and identity
```bash
crane status                              # Server health and all apps
crane me                                  # Show current user info
crane config --show                       # Show CLI config
crane config --url http://localhost:5001  # Set API URL
crane config --key dhk_admin_xxx          # Set API key
```

### Recover a lost API key
Run on the box — it writes the database directly. Defaults to the platform
admin; override to target a specific account:
```bash
crane regenerate-key                      # Regenerate the platform owner's key
crane regenerate-key --email you@ex.com   # ...for a specific user by email
crane regenerate-key --user-id 1          # ...or by user id
```

### Proxy and drift repair
```bash
crane caddy --show                        # Show the current generated Caddyfile
crane caddy --reload                      # Regenerate and reload Caddy config
crane reconcile --dry-run                 # Preview orphaned filesystem apps
crane reconcile                           # Register them into the DB and reload Caddy
```

`regenerate-key` and `reconcile` open the database **without migrating it** —
the server owns migrations and applies them on boot. If the code on disk is
newer than the schema, both refuse with the number of pending migrations rather
than altering the database under a running server. `crane init` is the one
command that does migrate: it is the bootstrap, and there is no server yet.

### Migrate config between instances
Move the platform `settings` (including encrypted secrets) to another AppCrane —
without sharing encryption keys. Export keeps secrets ciphertext; import
re-encrypts them with the target instance's own key.
```bash
# On the SOURCE instance:
crane config export --out config.json

# Copy config.json to the TARGET, then on the TARGET:
OLD_ENCRYPTION_KEY=<source ENCRYPTION_KEY> crane config import config.json
```
The source `ENCRYPTION_KEY` (from the source's `.env`) is needed only to decrypt
the secrets during import; it is used transiently, never stored. One-way values
(e.g. the SCIM token, stored as a hash) can't be migrated — the import lists them
to regenerate on the target. Delete `config.json` afterward.

## App operations (MCP or REST)

Everything an app owner does runs over MCP — the primary door, documented in
[MCP (for AI agents)](#mcp-for-ai-agents) — or over the REST routes underneath,
which take the same `X-API-Key`. Both are audited identically and both enforce
the same per-app roles.

| Operation | MCP tool | REST |
|---|---|---|
| Create an app | `appcrane_create_app` | `POST /api/apps` |
| List / inspect | `appcrane_list_apps`, `appcrane_get_app` | `GET /api/apps`, `GET /api/apps/:slug` |
| Deploy | `appcrane_deploy` | `POST /api/apps/:slug/deploy/:env` |
| Deploy history / log | `appcrane_list_releases`, `appcrane_get_deploy_log` | `GET /api/apps/:slug/deployments/:env`, `…/:id/log` |
| Roll back | `appcrane_rollback` | `POST /api/apps/:slug/rollback/:env` |
| Promote sandbox → production | `appcrane_promote` | `POST /api/apps/:slug/promote` |
| Env vars / secrets | `appcrane_set_secret`, `appcrane_get_secret`, `appcrane_reveal_secret` | `GET` / `PUT /api/apps/:slug/env/:env`, `DELETE …/:key` |
| Grant access | `appcrane_grant_app_access` | `PUT /api/apps/:slug/users` |
| Health | `appcrane_get_health` | `GET` / `PUT /api/apps/:slug/health/:env` |
| Backups | `appcrane_run_backup_now`, `appcrane_get_backup_status` | `POST /api/apps/:slug/backup/:env`, `GET /api/apps/:slug/backups` |
| Runtime logs | `appcrane_get_logs` | `GET /api/:slug/logs/:env` |
| Audit log | — (read it in the dashboard) | `GET /api/audit`, `GET /api/:slug/audit` |

Deploying to **production** needs the `deploy.production` permission on the app;
sandbox is the default everywhere. A deploy that would destroy unmounted state
refuses until it is passed `acknowledge_data_loss` — see the redeploy warning in
[Features](#features).

### Deploying without GitHub

An app does not need a repo. Create it with `source_type: "upload"` and ship
releases as bundles (`.zip`, `.tar.gz`, `.tgz`):

```bash
curl -F file=@dist.zip -F env=sandbox \
     -H "X-API-Key: $CRANE_KEY" \
     https://<your-domain>/api/apps/myapp/deploy/upload
```

The response carries `artifact.sha256` — AppCrane computes it over the bytes it
received, before extraction, and records it as the release identity
(`commit_hash = sha256:<digest>`). Compare it against the digest you computed
locally to confirm what was deployed is what you sent. Any `commit_sha` you pass
is stored alongside as context and is explicitly *not* trusted as the identity.

Agents hold personal MCP keys (`dhk_mcp_*`), which are allow-listed to
`/api/mcp` and `/api/files/staged` only, so they take the same path in two
steps: `POST /api/files/staged` to upload the bytes, then
`appcrane_deploy_artifact(slug, env, token)`. This is also the deploy route that
still works when a repo-based path is broken — an expired service-account PAT
returns 401 on every managed-repo write, and this one never contacts GitHub.

## MCP (for AI agents)

AppCrane is MCP-first. One `claude mcp add` and the agent gets 59
`appcrane_*` tools — list apps, deploy, roll back, set/get secrets, read
logs, manage access, scan for vulnerable dependencies, the lot. Tool
names are AWS-aligned (`stage`, `set_secret`/`get_secret`, `cp`).

```bash
claude mcp add --transport http appcrane https://crane.example.com/api/mcp \
  --header "X-API-Key: dhk_admin_or_user_xxxxxxxxxxxxx" \
  --header "X-Github-Token: ghp_your_github_pat"
```

Then in any Claude Code session:

> Onboard a new app. Start by calling `appcrane_get_guide` with `topic="onboarding"` for the playbook.

The agent pulls the current guide from the server, so edits propagate
without a redeploy of your tooling. `topic="operations"` returns the
post-onboarding reference (deploy lifecycle, troubleshooting fast
failures, access management, etc.).

## Architecture

```
Ubuntu Server
├── Caddy (reverse proxy, auto-HTTPS)
│   ├── myapp.example.com          → production app
│   └── myapp-sandbox.example.com  → sandbox app
├── Docker (container isolation)
│   ├── myapp-production           ← isolated container per env
│   └── myapp-sandbox
├── AppCrane API (:5001)
│   ├── Express 5 + SQLite
│   ├── Health checker (cron)
│   ├── SSO (SAML / OIDC / SCIM)
│   ├── AppStudio AI pipeline
│   └── Presence (WebSocket)
└── /data/apps/myapp/
    ├── production/releases/       (symlink-based, last 5)
    └── sandbox/releases/
```

Every container is published to **loopback only** (`127.0.0.1:<port>:3000`), so
Caddy is the only way in. The exception is an app with `ingress_type` `tcp` or
`dual`, which additionally publishes a port at `0.0.0.0:<public_port>` — outside
Caddy, and outside every control Caddy provides. A `tcp` app publishes container
port 3000 itself; a `dual` app publishes a *different* container port and leaves
3000 loopback-only behind Caddy. See
[§6 below](#6-tcp-layer-4-ingress--no-proxy-no-identity).
AppCrane believes `X-Forwarded-For` only from proxies named in `TRUST_PROXY` (default `loopback`, i.e. Caddy on the same host), so per-client rate limits, the login throttle and logged addresses see the real client; if your proxy runs on another address, set `TRUST_PROXY` to that address — `true` and hop counts are refused because they would let any client choose its own address.

## Security

- **Init locked to localhost** — admin setup only from the server itself
- **API key auth** — all requests require `X-API-Key` header
- **Admin isolation** — admin cannot read env vars or `/data/`; enforced at middleware level
- **AES-256-GCM** encrypted env vars at rest
- **Webhook HMAC** verification for GitHub
- **SCIM deprovisioning** — removing a user from your IdP revokes AppCrane access automatically
- **All actions audited** — who did what, when
- **Vulnerability scanning of the apps you host, not just the platform** — every deploy scans what it just shipped and records the result against that deployment. Source apps are read from their lockfiles and queried against [OSV](https://osv.dev): `package-lock.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (9.x), `composer.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `poetry.lock`, `Pipfile.lock`. Apps deployed from an image are scanned with a pinned Trivy against the **resolved digest** — `name@sha256:…`, the bytes actually running, not whatever the tag points at today. The scan **reports and never blocks**: a scanner that is missing, slow or wrong cannot fail your deploy. Each finding carries the version that fixes it, read from the full OSV advisory — the batch endpoint returns only advisory ids, and an advisory that cannot be fetched records the scan as an error rather than claiming no fix exists. **Coverage is reported as arithmetic, not as a word**: every report leads with `COVERAGE: <covered> of <rows> app/stage rows have a usable scan result (<percent>%)`, names how many were skipped, errored or never scanned, and lists the top reasons rows were skipped, counted, from the reason each row recorded. `assurance` still reads none / partial / complete and still means exactly that — but `partial` spans 1% to 99%, so it never travels without the counts beside it.

**Commit verification runs alongside the build, not in front of it** — the GitHub head-SHA cross-check starts as soon as the clone finishes and is awaited at the container gate, so its latency (~27 ms on a healthy GitHub, 1.5–4.5 s when it hits the retry backoff) is hidden behind `docker build` instead of delaying it; a failure still aborts the deploy with the same message before any container is started or stopped, and its lines still appear in the deploy log — now after the build output rather than before it.

**Image builds are pinned to BuildKit** (`DOCKER_BUILDKIT=1`) rather than inheriting whatever the host docker CLI defaults to; measured here at ~18.6 s vs ~29.0 s for a cold build of a ~126 MB Node image with identical output, and the classic builder now prints a removal notice on every use — set `APPCRANE_DOCKER_BUILDKIT=0` on the AppCrane host to override.

### Supply chain — SBOM + build provenance

A deployment self-updates straight from git (`/api/self-update` runs `git fetch`
+ `git reset --hard origin/main`), so the question a reviewer asks is "how do I
know the source I pulled is the source you published?" Every tagged release
answers it with four attached artifacts:

| Artifact | What it is |
|---|---|
| `appcrane-<tag>-source.tar.gz` | Reproducible `git archive` of the tagged tree (tracked files only) |
| `appcrane-sbom.cdx.json` | CycloneDX SBOM of the **production** dependency tree |
| `appcrane-sbom.spdx.json` | Same, SPDX format |
| `SHA256SUMS.txt` | Checksums for all of the above |

The source archive carries **build provenance and an SBOM attestation** signed
via sigstore keyless (GitHub artifact attestations) — no long-lived signing key
exists to be stolen. Verify a downloaded archive with:

```bash
gh attestation verify appcrane-<tag>-source.tar.gz --repo gitayg/appCrane
```

Dev dependencies are deliberately excluded from the SBOM — they aren't shipped
to a deployment, and including them would overstate the real attack surface.

**Uploaded releases** get the equivalent of a commit SHA rather than being
exempt from the question. AppCrane hashes the bundle server-side, before
extraction, and stores that digest as the release identity — so "is what is
running what was reviewed?" has an answer for an app with no repo. Before
v2.53.0 it did not: `commit_hash` held whatever the uploader typed, or the
literal string `unknown`, and two unrelated bundles could claim one SHA.

## Identity contract for deployed apps

Apps deployed on AppCrane never need to implement their own auth. The Caddy proxy verifies every request against `/api/identity/verify` *before* forwarding it to the container, and the result is delivered to the app in three complementary ways. Apps should consume them in this **precedence order**:

> Maintain an existing open-source app and want to know what deeper integration buys you? [SKIFF.md](SKIFF.md) is the maintainer-facing guide — identity, app-defined roles, managed databases, email, health and per-tenant data, level by level, with the contract for each.

### 1. Request headers (zero-fetch, recommended)

Caddy `copy_headers` the verified identity onto the upstream proxy request. The app reads them directly:

| Header | Value | Notes |
|---|---|---|
| `X-AppCrane-Auth-Mode` | `authenticated` \| `headless` \| `bypass` | Always present on every proxied request, including ones with no identity. Read it first. |
| `X-AppCrane-User` | email | Backward-compat single identifier. Set on `authenticated` requests. |
| `X-AppCrane-User-Id` | numeric id (string) | Set on `authenticated` requests. |
| `X-AppCrane-User-Email` | email | Granular. May be absent if the user has no email. |
| `X-AppCrane-User-Name` | display name, `encodeURIComponent`-d | `decodeURIComponent` on read. May be absent. |
| `X-AppCrane-User-Role` | `platform_admin` \| `admin` \| `user` | Platform-wide tier, raw token. **Not** a per-app permission. |
| `X-AppCrane-App-Role` | `owner` \| `admin` \| `user` \| `viewer` | Per-app role — the one to gate on. An explicit `app_user_roles` row wins over the global-admin fallback, so a platform admin who owns the app arrives as `owner`, not `admin`. |
| `X-AppCrane-Is-Admin` | `1` \| `0` | `1` when the per-app role is `admin` or `owner`. Use it instead of comparing role strings. |
| `X-AppCrane-App-Roles` | comma-separated keys, e.g. `approver,auditor` | The roles **the app defines for itself** — a different system from `X-AppCrane-App-Role` above. AppCrane stores and issues them; the app enforces them, and no AppCrane authz check ever reads them back. A user may hold several (a union, not a ladder). **Omitted entirely** when they hold none, so `split(',')` can't produce a phantom `''` role. Section 5 below. |

**Trust model:** the Caddy generator wraps the `request_header -X-AppCrane-*` strips and the `forward_auth` block in a `route { … }` so they execute in written order — Caddy's own directive sort would otherwise run the strips *after* `forward_auth` and delete the identity it had just copied. Caddy zeroes out any client-set `X-AppCrane-*` headers first, then `copy_headers` re-injects only what `/verify` returned. The strips are emitted on **every** route that proxies an app, including headless apps and `auth_bypass_paths` prefixes where no `forward_auth` runs at all — a route that verifies nobody must not accept the caller's own `X-AppCrane-Is-Admin`. Header smuggling is impossible — what the app receives is guaranteed platform-issued. Caddy also strips the platform's `cc_token` session cookie out of `Cookie` before it reaches any container (v2.39.0), so an app can't read a visitor's platform session and act as them — **apps must take identity from these headers, never from a cookie**.

**Identity does not require SSO.** `/api/identity/verify` resolves a session from `X-API-Key` or from `Authorization: Bearer` / the `cc_token` cookie against `identity_sessions`. SSO is one way to create such a session; local password login and API keys are others. An instance with no IdP still injects the full header set for logged-in users.

**Absence semantics:** on an `authenticated` app an unverified visitor never reaches the container at all (Caddy fails closed at `forward_auth` and redirects to `/login`), so **presence = trusted**. Identity legitimately absent means `X-AppCrane-Auth-Mode` is `headless` (whole app opted out) or `bypass` (this path is in `auth_bypass_paths`, **or** the app is served on its own custom domain) — in every case the request is served with no verified identity and the app owns its own authn. No `X-AppCrane-Auth-Mode` at all means the request didn't come through AppCrane's proxy — i.e. direct-to-container. A custom-domain app *is* proxied and does get `X-AppCrane-Auth-Mode: bypass`.

**Role ordering:** `none` < `viewer` < `user` < `admin` < `owner`. `appRole === 'admin'` is a bug — it denies owners.

```js
// Express example
const RANK = { none: 0, viewer: 1, user: 2, admin: 3, owner: 4 }
const atLeast = (appRole, min) => (RANK[appRole] ?? 0) >= RANK[min]

app.use((req, res, next) => {
  const mode    = req.get('X-AppCrane-Auth-Mode')   // 'authenticated' | 'headless' | 'bypass'
  const role    = req.get('X-AppCrane-User-Role')   // platform tier
  const appRole = req.get('X-AppCrane-App-Role')    // 'owner' | 'admin' | 'user' | 'viewer'
  const email   = req.get('X-AppCrane-User-Email') || req.get('X-AppCrane-User')
  req.user = (mode === 'authenticated' && role)
    ? { id: req.get('X-AppCrane-User-Id'), email, role, appRole, isAppAdmin: atLeast(appRole, 'admin') }
    : null
  next()
})
```

### 2. `GET /api/me` (when you need more than the basics)

Returns the full user object — name, email, username, global role — plus the per-app role for whatever app the caller is asking about. Same origin as the app, so the browser auto-sends `cc_token`; no SDK or token plumbing required:

```js
const r = await fetch('/api/me')        // ?app=<slug> optional; Referer-inferred otherwise
if (r.status === 401) { location.href = '/login?redirect=' + encodeURIComponent(location.href); return }
const { user, app_role } = await r.json()
```

Auth precedence inside `/api/me`:
1. `cc_token` cookie (proxied apps' default — `httpOnly`, browser-managed).
2. `Authorization: Bearer <session>` (CLI / programmatic).
3. `X-API-Key: dhk_*` (admin / agent keys).

App slug resolution:
1. Explicit `?app=<slug>` query.
2. `Referer`-inferred (first path segment; sandbox-suffix retry).
3. Lean global-only payload if neither resolves.

### 3. Headless apps — opt out entirely

For services where the *whole app* is meant to be unauthenticated — telemetry ingest, public webhooks, status pages, the squash CLI's `ping`/`stats` — set the app's `auth_mode` to `headless` (owner-only toggle in the Launcher, or `appcrane_set_app_meta slug=<…> auth_mode=headless` via MCP). The Caddy block then skips `forward_auth` and `copy_headers`: no identity headers, no `/api/me`, no `cc_token` (that cookie is stripped for every app regardless). The incoming `X-AppCrane-*` strip is **not** skipped — a headless route verifies nobody, so it must not let a caller supply its own identity headers either. `X-AppCrane-Auth-Mode: headless` still arrives, so the app can distinguish "identity is off by design" from a misconfigured proxy. The app's own server takes responsibility for any payload-level authn it needs (HMAC, install-id, IP allowlist, etc.).

Pick by shape:
- **The whole app is unauth ingest** → headless app (clean separation, smaller blast radius).
- **Mostly-auth app with a couple of public endpoints** → keep `authenticated`, gate the public paths at the app's own router.

### 4. Per-tenant DB (multitenancy) — opt in

Opt in with `"multitenant": true` in `deployhub.json` and AppCrane gives each of
your app's users an isolated SQLite database on the persistent `/data` volume —
you don't build tenant isolation yourself. A tenant is **(org, user)**, where
`org` is the user's email domain. This is **fully opt-in**: apps that don't set
the flag are completely unaffected.

When enabled, AppCrane injects `APPCRANE_TENANT_ROOT=/data/tenants`. Use the
[`appcrane-tenant`](packages/tenant) helper to derive the tenant DB from the
identity headers above (section 1) — no path-building by hand:

```js
import { tenantDb } from 'appcrane-tenant'

app.get('/api/notes', (req, res) => {
  const db = tenantDb(req)   // opens /data/tenants/<org>/u<userId>/db.sqlite
  res.json({ notes: db.prepare('SELECT * FROM notes').all() })
})
```

`tenantDbPath(req)` returns just the path if you use a different SQLite driver.
Each tenant also gets a `storage/` dir (`tenantStorageDir(req)` / `tenantFile(req, name)`)
for files. Set `"tenant_quota_mb": <n>` in `deployhub.json` to cap per-tenant
usage — AppCrane injects it and `assertTenantQuota(req)` throws once a tenant is
full (the quota covers DB + storage).

Always build tenant paths via the helper (never from raw user input) — the
identity headers are platform-signed and the org slug is sanitised against
traversal. When a user's access is revoked, AppCrane purges that tenant's dir
automatically — using this very helper's `orgFromEmail`, which the platform
imports rather than copies, so the path it deletes is the path your app wrote.
Consumer domains (e.g. `gmail.com`) share an `org` label, but
isolation is per-user, so data never mixes. The helper isn't on npm yet — copy
[`packages/tenant/index.js`](packages/tenant/index.js) or depend on it by path;
see the [multitenant-notes example](examples/multitenant-notes).

### 5. App-defined roles — the app's own vocabulary

An app can define roles of its own — `approver`, `auditor`, `reviewer` — and
AppCrane hands each user's set to the app on every request. **AppCrane is the
authority, the app is the enforcer**: the platform stores who holds which key and
issues it, and has no opinion on what the key permits.

The two are separate systems on purpose, down to separate tables and separate
wire fields. An app-defined role never confers an AppCrane privilege, and no
AppCrane authorization check reads one — otherwise an app owner could invent a
role named `admin`, assign it to themselves, and author their own escalation from
a settings form. For the same reason `owner`, `admin`, `user`, `viewer`, `none`
and `platform_admin` are rejected as keys, keys must match
`/^[a-z][a-z0-9_-]{0,31}$/`, and an app may define at most 16 of them (which also
bounds the header's length by design rather than by discovery).

- **On the server:** `X-AppCrane-App-Roles`, comma-separated and sorted, absent
  when the user holds none. A user may hold several — they are a union, so test
  set membership rather than equality. It is stripped off the client request and
  re-issued by `/verify` like every other identity header.
- **In the browser:** `GET /api/me?app=<slug>` returns `app_roles: [...]` beside
  `app_role` (`[]` when none).
- **Explicit grants only.** A `platform_admin` holds no app-defined role unless
  someone granted it, and neither does the app's `owner` — unlike `app_role`,
  there is no global-admin fallback. Holding an app role while being a plain
  platform `user` is the normal case, not an edge case.
- **Managed by** the app's own owner/admin tier, over
  `/api/apps/<slug>/app-roles` (note: not `/roles`, which is the platform tier) or
  the `appcrane_list_app_roles` / `appcrane_create_app_role` /
  `appcrane_set_user_app_roles` MCP tools. Deleting a role cascades its grants.

```js
const appRoles = new Set((req.get('X-AppCrane-App-Roles') || '').split(',').filter(Boolean))
if (!appRoles.has('approver')) return res.status(403).json({ error: 'approver role required' })
```

### 6. TCP (layer-4) ingress — no proxy, no identity

Sections 1–5 all rest on the same assumption: Caddy is in front of the app. Some
apps aren't HTTP and cannot be proxied at all — the motivating case is a
forward/**CONNECT** proxy, where the client opens a raw TCP connection and gets a
tunnel back, which no HTTP reverse proxy can express. For those, a **platform
admin** (not the app owner) can set `ingress_type: 'tcp'` — `PUT /api/apps/<slug>`
or `appcrane_set_app_ingress` — and AppCrane publishes the production container's
port on the host at `0.0.0.0:<public_port>`, the next time the container is
recreated (a deploy, or the restart route — the publish is a `docker run` flag, so
nothing changes on a running container). The existing loopback publish stays and
sandbox is unaffected; this adds a door rather than moving one.

**Two port ranges, and they are not the same numbers.** A host port AppCrane
*allocates* comes from a dedicated band, 31000 through 31999, so an operator
firewalls one predictable block. A host port named **explicitly** may be anything
in 1024–65535 — because clients are configured with a port by hand or by MDM, and
a fleet already pointing at 8080 is not something the platform gets to overrule.
Narrowing the range was never the safety property: the guards that refuse a port
apply at every value (WHATWG-blocked ports, AppCrane's own listening port, any
port the slot allocator could hand a container, and the partial unique index that
gives one host port to one app). A port outside the auto band just needs its own
firewall rule.

**The container must still answer `/api/health` over HTTP**, whatever its
`ingress_type`: the deploy gate polls it for 30 s and rolls the release back
without a 200 carrying `status` and `version`. So `tcp` ingress serves apps that
*also* speak HTTP on the container port — true of the motivating CONNECT proxy —
and an app speaking **only** a non-HTTP protocol cannot be deployed today. Note
too that the publish covers the whole container port, so every HTTP route on it,
including that health endpoint and any admin route, is exposed alongside the raw
protocol.

That door has **none** of the controls above, and none of the ones AppCrane
gained in v2.35–v2.41: no `forward_auth`, no `X-AppCrane-*` identity headers
(nothing injects or strips them), no per-request audit, no rate limiting, no
security headers, and no TLS terminated by AppCrane. **The app owns
authentication completely.** It is *not* `auth_mode: 'headless'` — a headless app
still goes through Caddy and still gets TLS, security headers and the
`X-AppCrane-Auth-Mode: headless` stamp.

**`ingress_type: 'dual'` — an app with both planes (v2.45.0).** Some apps are
genuinely both: an HTTP **control plane** (admin UI, REST API) that must keep
everything Caddy gives it, plus a raw **data plane** whose clients are already
pinned to a specific host port. Under `tcp` that was inexpressible, because both
publishes targeted the same hardcoded container port — so `tcp` could only
re-expose the very port Caddy was already serving. A `dual` app names a second
port inside its container:

```
control plane   Caddy → 127.0.0.1:<slot port> → container:3000
data plane      raw   → 0.0.0.0:<public_port> → container:<data_plane_port>
```

The control plane is untouched — same URL, same SSO, same identity headers, same
access logs. Only the data plane is undefended, and the loss table above is what
it loses. Three rules make that split real:

- **`data_plane_port` may not be 3000**, and a request that sets it is refused
  with a 400. Port 3000 is the container's HTTP control plane, the port Caddy
  proxies to; publishing it raw would re-expose the app's ordinary HTTP origin
  with no TLS, no `forward_auth`, no identity headers and no audit — exactly the
  surface Caddy is in the path to protect, with no signal to the operator that
  they had done it. `dual` with **no** `data_plane_port` is refused for the same
  reason: the publish must target *some* container port, 3000 is the only other
  one there, and AppCrane will not guess. The runtime refuses such a row too — it
  emits no public `-p` at all rather than falling back to 3000.
- **Health checks follow the control plane.** A `tcp` app gets a TCP handshake
  because it cannot answer an HTTP probe; a dual app can, so it keeps the ordinary
  HTTP health check on container port 3000 and its data plane is never probed. A
  handshake on a raw listener succeeds as long as the socket is bound, so probing
  the data plane would let a wedged control plane — the plane users actually reach
  — report healthy and a broken release go green.
- **The host port is unique; the container port deliberately is not.** The partial
  unique index on `apps(public_port)` still gives one host port to one app.
  `data_plane_port` has no such constraint and should not gain one: container
  network namespaces are separate, so two apps can each run a data plane on
  container port 8081 without ever meeting.

`dual` is a third enum value rather than a flag on an `http` app because
`ingress_type` is the field an operator, an audit entry and an MCP payload all read
to learn what doors an app has — a row saying `http` while the app published a raw
port would make that field actively wrong. It also fails safe: code that predates
`dual` compares `=== 'tcp'`, gets `false`, and takes the HTTP path, which is the
correct one for a dual app. An app that sets nothing is still `http` and behaves
exactly as before; a pre-v2.45.0 `tcp` app still publishes container port 3000 and
still gets its handshake health check.

An app on a published port can still authenticate against the platform if it
chooses to: `GET /api/me?app=<slug>` verifies a `Bearer` token or `X-API-Key: dhk_*`
the client supplied, and `POST /api/service/*` authenticates the app itself with
the `APPCRANE_SERVICE_TOKEN` injected into every container. Both go over the
docker bridge (`CRANE_INTERNAL_URL`), not through Caddy.

`public_port` is allocated and stored per app (never derived from the app's slot,
which can be reassigned), unique across apps, and every change — including
`data_plane_port` — is written to the audit log as `app-ingress-change`. Both
numbers are pinned: they survive a flip back to `http` so that flipping forward
restores the ports a client fleet is already configured for, and they read back as
`null` while the app is not publishing. On the way back in `data_plane_port` is
re-validated; `public_port` is not — a held number is reinstated as-is, so re-pin
it explicitly if the app has been parked on `http` while the platform grew.
Flipping a `dual` app to `tcp` is refused while it still holds a
`data_plane_port`, because `tcp` publishes container port 3000 and the flip would
silently repoint the same host port onto the control plane; send
`data_plane_port: null` in the same request to drop the data plane on purpose.
**Treat publishing as the exposing act** — do
not assume a host firewall is holding the port shut. A Docker publish is a DNAT
rule evaluated in `FORWARD` that never traverses `INPUT`, so a plain `ufw deny`
does **not** block it; filter in the `DOCKER-USER` chain or upstream of the host.
And where the platform runs behind SDP, the boundary that exists is the
perimeter: a published port is reachable by everything inside it from the moment
the container is recreated.

Switching back to `http` stops the publish but does **not** close the port: the
running container keeps the binding until it is recreated, so redeploy or restart
the app before treating the exposure as revoked. Because that port is still bound,
AppCrane keeps it **reserved to that app** rather than returning it to the pool —
no other app can be allocated a number a live container still holds — and releases
it automatically when the container comes back without the publish. Until then the
app reports the number as `pending_port_release` on every read surface, so nothing
claims the port is closed while it is open.

For a CONNECT proxy specifically: a published port is reachable by everything that
can already reach the host, so on an SDP-fronted deployment that is everyone inside
the perimeter rather than the internet. A gap in the app's proxy authentication is
therefore an **unaudited egress path out of the perimeter**, and AppCrane logs none
of it because the traffic never touches Caddy. The app's `407 Proxy-Authenticate`
path is the security boundary — the ingress isn't.

## Permission Model

| Action | Admin | App User |
|--------|-------|----------|
| Create/delete apps | Yes | No |
| Assign users | Yes | No |
| Server health | Yes | No |
| Deploy / rollback / promote | **No** | Yes (own apps) |
| View/edit env vars | **No** | Yes (own apps) |
| Configure health/webhooks | **No** | Yes (own apps) |
| Backups | **No** | Yes (own apps) |

## Tech Stack

Node.js 22, Express 5, SQLite, Docker, Caddy 2, SAML/OIDC/SCIM, AES-256-GCM, Commander.js, Ubuntu 22.04+

## License

[GNU AGPL v3](LICENSE). Free and open source — use, modify, and self-host. If you run a modified version as a network service, you must make your source available under the same license. Need to run private modifications as a service, or embed AppCrane in a proprietary product? A [commercial license](COMMERCIAL-LICENSE.md) is available.

## Feedback & Contributions

Open an issue: https://github.com/gitayg/appCrane/issues

Pull requests welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) first. It includes the short CLA that keeps AppCrane's dual-licensing (AGPL + commercial) possible.
