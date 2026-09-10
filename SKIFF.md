# Skiff — integrating an existing open-source app with AppCrane

You maintain an open-source application. It already builds, already ships a
container image, and already runs on someone's docker host. This document is
about the next question: what does your app *gain* by knowing AppCrane is in
front of it, and exactly what do you have to implement to collect it?

Everything described here is shipping platform behaviour, not a roadmap. Each
capability is a contract you can code against today; where a behaviour changed
recently, the release that changed it is named so you can check it against the
instance you are targeting (`GET /api/info` returns `version`).

Two existing documents go deeper than this one and are the authority where they
overlap:

- [`server/services/guides/onboarding.md`](server/services/guides/onboarding.md)
  — the full identity contract, per-tenant databases, TCP ingress, path-level
  auth bypass, custom domains.
- [`server/services/guides/email.md`](server/services/guides/email.md) — the
  outbound email service in full, including attachments and error codes.

This guide is the maintainer's path through them, arranged as levels. Level 0 is
"it runs". Each level after that is one capability: what it buys you, the exact
contract, a sample, and what breaks if you get it wrong. They are independent —
take level 2 and skip level 5 if that is what your app needs.

---

## Level 0 — It runs, and it is listed

**What you gain.** An operator installs your app from the catalogue instead of
writing a compose file, and AppCrane owns the reverse proxy, TLS, per-app access
control, logs, resource limits, rollback and deploy history around it.

**The contract.** AppCrane starts your container with these in the environment:

| Env var | Value |
|---|---|
| `PORT` | the port the container is expected to listen on (default `3000`) |
| `DATA_DIR` | `/data` — always mounted, always the persistent path |
| `CRANE_URL` | the platform's public base URL |
| `CRANE_INTERNAL_URL` | `http://host.docker.internal:<port>` — AppCrane, reachable from inside the container |
| `APPCRANE_SERVICE_TOKEN` | this app's credential for the service API (level 6) |

An image that ignores `$PORT` — most third-party images do, odoo listens on
8069, BookStack's image on 80 — declares its real port instead, and AppCrane
publishes against that (`apps.container_port`, set at install from the catalogue
entry's `port`).

If AppCrane *builds* your app from source and you ship your own `Dockerfile`, it
is validated before the build. Hard failures: no `FROM`; no `EXPOSE`; an
`EXPOSE` that does not include the expected port; a final stage that declares
`USER root` / `USER 0`; a secret-shaped `ENV` (`ENV *_TOKEN=`, `*_PASSWORD=`,
`*_KEY=` …). Warnings: a final stage that declares no `USER` at all (an error
when the instance sets `APPCRANE_REQUIRE_NONROOT=1`), `VOLUME /data`, and any
`ENV` of `DATA_DIR` / `CRANE_URL` / `CRANE_INTERNAL_URL`, which AppCrane
overrides at runtime. None of this runs for a prebuilt image — an image app is
pulled, digest-pinned and started.

**Getting listed.** The catalogue is a single manifest in this repo:
[`server/services/appCatalog.json`](server/services/appCatalog.json). Add an
entry by pull request. Every field beyond the first eight is optional, and
`null` is a legitimate answer — a wrong value fails a deploy, a missing one just
asks the operator:

```json
{
  "name": "Helpdesk",
  "slug": "helpdesk",
  "category": "Support",
  "repo": "example-org/helpdesk",
  "image": "example-org/helpdesk",
  "home": "https://helpdesk.example.com",
  "license": "MIT",
  "short": "Ticketing and shared inboxes",
  "port": 8080,
  "health": "/healthz",
  "url_env": "APP_URL",
  "secrets": [
    { "env": "APP_KEY", "bytes": 32, "encoding": "base64", "prefix": "base64:", "label": "Application key" }
  ],
  "needs": {
    "engine": "postgres",
    "required": true,
    "env": { "host": "DB_HOST", "port": "DB_PORT", "name": "DB_NAME", "user": "DB_USER", "password": "DB_PASSWORD" },
    "url_env": "DATABASE_URL"
  }
}
```

- `port` — the port the **image** listens on, not 3000.
- `health` — a path that answers 200 on a healthy container (level 1).
- `url_env` — the variable that must hold the app's **own** base URL. Only the
  installing browser can fill it; the value depends on the routing chosen in the
  install dialog.
- `secrets` — a *declaration*, never a value: `{env, bytes, encoding, prefix,
  label}`. The bytes are drawn in the operator's browser with
  `crypto.getRandomValues` and posted straight to the app's encrypted env store.
  Nothing in the catalogue endpoint generates, stores or returns a secret — that
  endpoint is readable by every logged-in user.
- `needs` — the managed-database wiring (level 5).

**Failure mode.** Declare the wrong `port` and the deploy publishes a port
nothing is listening on: the 30-second health probe times out and the container
is torn down, which reads as "the app is broken", not "the manifest is wrong".

---

## Level 1 — A health endpoint the platform understands

**What you gain.** Deploy validation that fails fast and rolls back instead of
promoting a wedged container, a monitor that goes red for a real reason, and a
dashboard that can state which version is *actually* running.

**The contract.** After starting the new container, AppCrane probes
`http://localhost:<published-port><health-path>` — the loopback port the
container publishes on the host, never the public URL — for 30 seconds. The path resolves in this
order:

1. `be.health` from `deployhub.json`, if the app is built from source;
2. `apps.health_path` — what the catalogue entry's `health` and the Deploy
   dialog write;
3. `/api/health`.

What counts as a pass depends on the source type:

| App | Passing response |
|---|---|
| built by AppCrane from source | `200` **and** a JSON body carrying both `status` and `version` |
| `source_type: image` (v2.66.2+) | `200`. Nothing more. |

The relaxation for image apps is deliberate: `{status, version}` is AppCrane's
own convention and a third-party image has never heard of it. BookStack answered
`/status` with `{"database":true,"cache":true,"session":true}` — a richer signal
than AppCrane asks for — and was torn down for two missing field names.

**Serve the full shape anyway.** A bare 200 clears the deploy gate, but
`version` is what `GET /api/apps/<slug>/live-version/<env>` reads out of the same
body to answer "what is live right now" — with no `version` field the dashboard
has nothing to show, and a deploy that silently kept the old image looks
identical to one that landed.

```js
// Express. No auth on this route: AppCrane probes the host's loopback
// publish of your port directly, never through the proxy.
import { readFileSync } from 'fs'
const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url)))

app.get('/healthz', (req, res) => {
  res.json({ status: 'ok', version })
})
```

The background monitor probes the same path and treats **200 as healthy**,
nothing else. As of **v2.67.1** it honours `apps.health_path` when the app's
health config still holds the default `/api/health` — before that, an app could
deploy green against `/status` and then sit permanently red because the monitor
was probing a path that 404s.

**Failure mode.** An endpoint that returns 200 only after warm-up longer than
30 s fails the deploy and rolls back. An endpoint behind your app's own login
returns 302 and fails too — keep the health path unauthenticated.

---

## Level 2 — Persistence: `/data` and nothing else

**What you gain.** Uploads, search indexes, generated artifacts and SQLite files
that survive a deploy, a rollback and a host restart, without you writing any
volume configuration.

**The contract.** Every container gets `/data` mounted and `DATA_DIR=/data`.
It is per-app and per-environment; on the host it lives at
`/data/apps/<slug>/<env>/shared/data/…`. Everything else in the container
filesystem is replaced on the next deploy.

```js
const dataDir = process.env.DATA_DIR || '/data'
const db = new Database(`${dataDir}/helpdesk.sqlite`)
```

**Failure mode.** An app that defaults its storage to `/app/uploads` or
`/var/lib/<app>` looks fine for a week and loses everything on the next ship.
If your app hardcodes a data path, make it configurable and document which
variable AppCrane should point at `/data`.

---

## Level 3 — Identity: delete your login page

**What you gain.** No user table, no password reset flow, no session store, no
SSO integration to maintain. AppCrane authenticates every request at the proxy
and hands you the verified user as request headers. Zero fetches, zero
libraries.

**The contract.** Caddy runs `forward_auth` against `/api/identity/verify`
before forwarding, and copies the result onto the upstream request:

| Header | Value |
|---|---|
| `X-AppCrane-Auth-Mode` | `authenticated` \| `headless` \| `bypass`. **Always present** on anything AppCrane proxies. Read it first. |
| `X-AppCrane-User` | email — the back-compat single identifier |
| `X-AppCrane-User-Id` | numeric id, as a string |
| `X-AppCrane-User-Email` | email; may be absent if the user has none |
| `X-AppCrane-User-Name` | display name, `encodeURIComponent`-d — `decodeURIComponent` on read |
| `X-AppCrane-User-Role` | `platform_admin` \| `admin` \| `user` — the **platform-wide** tier, not a permission on your app |
| `X-AppCrane-App-Role` | `owner` \| `admin` \| `user` \| `viewer` — the per-app tier |
| `X-AppCrane-Is-Admin` | `1` \| `0` — precomputed "may administer THIS app" |
| `X-AppCrane-App-Roles` | **plural** — your app's own roles (level 4) |

**Trust model.** Caddy strips every `X-AppCrane-*` header off the client request
*before* `forward_auth` runs, then re-injects only what `/api/identity/verify`
returned. Header smuggling is impossible: a `curl -H 'X-AppCrane-User-Role:
platform_admin'` never reaches you. On `authenticated`, **presence = trusted**.
On `headless` or `bypass`, nothing verified anything — treat any `X-AppCrane-*`
value on such a request as untrusted input.

**Never read the `cc_token` cookie.** Caddy strips it by name out of `Cookie`
before the request reaches any container, unconditionally, headless apps
included (v2.39.0). It is the *platform* session and is accepted as a bearer by
AppCrane's own API — an app that lifted it out of `Cookie` could call the
platform API as the visitor. Identity on the server is the headers, full stop.

**Identity does not require SSO.** `/api/identity/verify` resolves a session
from `X-API-Key`, from `Authorization: Bearer`, or from the platform cookie.
SAML/OIDC is one way a session exists; local password login and API keys are
others. "We have no IdP" never explains missing headers — check
`X-AppCrane-Auth-Mode`.

**Roles are ordered: `none` < `viewer` < `user` < `admin` < `owner`.** Gate as
"at least X", never equality. `appRole === 'admin'` denies the app's *owner* —
the most privileged user there is — from every admin surface it guards.

```js
// The one role check. Copy it; don't invent a variant.
const RANK = { none: 0, viewer: 1, user: 2, admin: 3, owner: 4 }
const atLeast = (appRole, min) => (RANK[appRole] ?? 0) >= RANK[min]

app.use((req, res, next) => {
  const mode = req.get('X-AppCrane-Auth-Mode')
  const name = req.get('X-AppCrane-User-Name')
  req.user = mode === 'authenticated' && req.get('X-AppCrane-User-Role')
    ? {
        id:         req.get('X-AppCrane-User-Id'),
        email:      req.get('X-AppCrane-User-Email') || req.get('X-AppCrane-User'),
        name:       name && decodeURIComponent(name),
        role:       req.get('X-AppCrane-User-Role'),   // platform tier
        appRole:    req.get('X-AppCrane-App-Role'),    // per-app tier
        isAppAdmin: req.get('X-AppCrane-Is-Admin') === '1',
      }
    : null
  next()
})

app.get('/settings', (req, res) => {
  if (!req.user?.isAppAdmin) return res.status(403).json({ error: 'Admin access required' })
  // identical: if (!atLeast(req.user.appRole, 'admin')) { ... }
  res.json(settings())
})
```

**In the browser**, where request headers are invisible, `GET /api/me?app=<slug>`
on the same origin returns the same facts (the slug is also inferred from
`Referer`, so a plain `fetch('/api/me')` from a page under `/<slug>/` works):

```js
const r = await fetch('/api/me')          // platform cookie is sent automatically
const { user, app_role, app_roles } = await r.json()
```

Use `/api/me` for **display**, the headers for **authorization**: for a global
admin who has been deliberately demoted on one app, the two disagree, and the
header is the one that honours the demotion. The onboarding guide documents that
divergence in full.

**Failure mode.** Writing `=== 'admin'` locks owners out. Reading identity
without checking `X-AppCrane-Auth-Mode` means a headless or bypassed request —
where the headers are unverified client input — is treated as a logged-in user.

---

## Level 4 — Authorization in your app's own vocabulary

**What you gain.** Your app's domain roles — `approver`, `agent`, `auditor` —
are granted and audited in AppCrane's UI, by the app's owner, and arrive on every
request. You keep the enforcement; you drop the roles table, the grant UI and
the admin screen that goes with it.

**Singular vs plural. This is the mistake this level exists to prevent.**

| Header | Whose vocabulary | Governs |
|---|---|---|
| `X-AppCrane-App-Role` (**singular**) | AppCrane's, fixed | Who may deploy the app, read its env vars, delete it, manage its members. You cannot add to it. |
| `X-AppCrane-App-Roles` (**plural**) | **yours**, freely invented | Whatever your code says it governs. |

**AppCrane ships facts, not policy.** AppCrane is the authority — it stores who
holds which key and delivers the answer on every request. Your app is the
enforcer: AppCrane has no idea what an `approver` may do and never asks. That
split is a security boundary, which is what makes it safe to let an app owner
invent roles from a form: an app-defined key can never confer an AppCrane
privilege, because no AppCrane authorization check reads these keys. For the
same reason `owner`, `admin`, `user`, `viewer`, `none` and `platform_admin` are
rejected as keys — the two vocabularies stay disjoint.

**The contract.** `X-AppCrane-App-Roles: approver,auditor` — comma-separated,
sorted, no spaces, and **absent entirely** (never empty) when the user holds
none, so a `split(',')` cannot hand you a phantom role named `''`. Keys match
`/^[a-z][a-z0-9_-]{0,31}$/`, 16 per app maximum, and are immutable once created.
They are a **union, not a ladder** — test membership, never equality.

```js
const rolesOf = (req) =>
  new Set((req.get('X-AppCrane-App-Roles') || '').split(',').filter(Boolean))

app.post('/tickets/:id/approve', (req, res) => {
  // A user may hold SEVERAL roles and they are a union. Test membership.
  if (!rolesOf(req).has('approver')) {
    return res.status(403).json({ error: 'This action requires the approver role' })
  }
  res.json(approve(req.params.id))
})
```

In the browser, the same keys arrive as `app_roles` on `GET /api/me?app=<slug>`
— an array, `[]` when the user holds none.

Roles are defined and granted by the app's **owner or admin** (AppCrane's tier),
through the dashboard, the MCP tools `appcrane_list_app_roles` /
`appcrane_create_app_role` / `appcrane_set_user_app_roles`, or REST under
`/api/apps/<slug>/app-roles` (`GET`, `POST`, `PATCH /:id`, `DELETE /:id`,
`GET /members`, `PUT /members/:userId`). Note `/app-roles`, not `/roles` — the
latter is the platform tier.

A `platform_admin` does **not** implicitly hold your roles; grants are always
explicit. Deleting a role cascades its grants. **Document your keys** — the
operator granting them needs to know that `approver` is what your app checks.

**Failure mode.** Treating the plural header as a ladder (`roles[0] === 'admin'`)
or comparing it for equality gives the wrong answer as soon as someone holds two
roles. Assuming an empty string when the user holds none produces a role named
`''` that your `has()` checks will never match but your logs will.

---

## Level 5 — A database you do not provision

**What you gain.** Postgres or MariaDB, provisioned on request, with credentials
that appear in your container's environment before it starts — under the
variable names *your app already reads*. No compose file, no credential
handling, no init container.

**The contract.** The platform runs one shared Postgres and one shared MariaDB
(`SUPPORTED_ENGINES = ['postgres', 'mariadb']`). Provisioning is explicit —
`POST /api/apps/<slug>/database`, or the button in the dashboard — and creates
**one database and one login role per app**. Isolation is enforced *inside the
engine* by grants (`REVOKE ALL ON DATABASE … FROM PUBLIC`, `REVOKE ALL ON SCHEMA
public FROM PUBLIC`, a `NOSUPERUSER NOCREATEDB` role; per-database `GRANT` on
MariaDB with no `WITH GRANT OPTION`), not by the network: app containers share
one bridge with inter-container traffic dropped, and reach the engine through
`host.docker.internal`, the same host-gateway route as `CRANE_INTERNAL_URL`.

Injection is a lookup, not a convention. Your catalogue entry's `needs` block
records **your** spelling, and AppCrane maps credentials onto it before the
container starts:

```json
"needs": {
  "engine": "postgres",
  "required": true,
  "env": { "host": "DB_HOST", "port": "DB_PORT", "name": "DB_NAME", "user": "DB_USER", "password": "DB_PASSWORD" },
  "url_env": "DATABASE_URL",
  "note": "Free-text note shown to whoever installs the app."
}
```

- Declare discrete fields, a single URL variable, or both — apps that read
  either are common, and both are injected.
- A field mapped to `null` is **skipped**, not injected empty. Use that when
  your app genuinely does not read that value from the environment.
- The URL form is `scheme://user:pass@host:port/db` with the password
  percent-encoded.
- **An env var the operator set by hand always wins.** Someone who set `DB_HOST`
  is pointing the app at a database they chose; overriding it would repoint a
  live app at an empty one and look like data loss.
- The link from the app back to your manifest entry is `apps.catalog_slug`,
  written at install. An app not installed from the catalogue gets nothing
  injected, and the deploy log says so.

```js
// Read them like any other config; they are present before your process starts.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,   // or DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD
})
```

**Failure mode.** A `needs.env` that names variables your app does not actually
read produces a container that starts, finds no configuration, and either falls
back to SQLite or crash-loops — with correct credentials sitting unused in its
environment. Declaring an engine the platform does not manage (the manifest has
entries needing `mongo`; the platform provisions only Postgres and MariaDB)
means the operator must bring their own and set the variables by hand.

---

## Level 6 — Outbound email without SMTP credentials

**What you gain.** Your app sends mail — ticket notifications, digests, reports
with attachments — with no mailbox, no API key, no SPF/DKIM work, and no
deliverability problem of its own.

**The contract** (full detail in
[`guides/email.md`](server/services/guides/email.md)):

`POST {CRANE_INTERNAL_URL}/api/service/email`, with
`X-AppCrane-Service-Token: {APPCRANE_SERVICE_TOKEN}`. Both variables are
injected into every container on every deploy — no toggle, no setup.

```js
async function notify(toEmail, subject, body) {
  const res = await fetch(`${process.env.CRANE_INTERNAL_URL}/api/service/email`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-AppCrane-Service-Token': process.env.APPCRANE_SERVICE_TOKEN,
    },
    body: JSON.stringify({ to: toEmail, subject, text: body }),
  })
  if (res.status !== 202) throw new Error(`email failed (${res.status}): ${await res.text()}`)
  return res.json()   // { queued: true, queue_id }
}

// The recipient is already on the request:
await notify(req.get('X-AppCrane-User-Email'), 'Your export is ready', 'Open the app to download it.')
```

Body fields: `to`, `subject`, `text` / `html`, plus optional `replyTo`,
`fromName`, `env`, `idempotencyKey` and `attachments` (base64, max 10 files,
3 MB total decoded). Returns `202` immediately; a worker delivers async with
retries.

Constraints worth designing around:

- **Server-side only.** The endpoint is reachable only from inside the container
  via `host.docker.internal`, 404s on the public domain, and rejects any request
  that arrived through the proxy (`403`). Never call it from frontend code.
- **Registered platform users only.** An arbitrary address returns `400`. Your
  app cannot email a customer who has no account on the platform.
- **The from address is the platform's.** You choose the display name per send
  (`fromName`, defaulting to the app's name); the queue renders it as
  `<name> via <slug> (AppCrane)` and appends a footer naming the app, so an app
  cannot present itself as somebody else.
- Errors: `400` bad recipient or missing fields, `401` bad token, `403` came
  through the proxy, `429` send budget exhausted — back off and retry.

**Failure mode.** Building the send into browser code fails closed (no token, no
route). Assuming arbitrary recipients — an app that emails external customers —
does not fit this service; keep your own transport for that path.

---

## Level 7 — Per-tenant isolation, provided rather than built

**What you gain.** A private data store per user, with the isolation *and the
purge-on-revoke* handled by the platform. When an operator removes someone's
access, that person's data is deleted; you write no cleanup job.

**The contract.** Opt in with `"multitenant": true` in `deployhub.json` (a
source-built app — a prebuilt image ships no manifest and this is not read).
AppCrane then injects `APPCRANE_TENANT_ROOT=/data/tenants`, and
`APPCRANE_TENANT_QUOTA_BYTES` if you also set `"tenant_quota_mb": <n>`.

A tenant is **(org, user)**, where `org` is the user's email domain. Derive the
path from the identity headers, never from raw input, and keep the derivation
exactly as the onboarding guide writes it — AppCrane's purge computes the
identical path. The full helper, with storage and quota functions plus tests,
lives at `packages/tenant` in this repo; the guide's
[per-tenant section](server/services/guides/onboarding.md) has the drop-in
snippet.

**Failure mode.** A derivation that differs from the documented one — a
different sanitiser, a username instead of the numeric id — leaves data the
purge cannot find, which is the exact failure this level exists to prevent.

---

## Level 8 — Finding out when the platform changes under you

**What you gain.** A machine-readable channel telling you that a platform
release changed something your app depends on, readable from inside your own
container with no credentials.

**The contract.**

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /api/notices` | none — public | `{ notices: [...] }` that apply to every app |
| `GET /api/apps/<slug>/notices` | authenticated, and access to that app | global notices plus any scoped to that app's configuration |
| `GET /api/info` | none — public | `version`, plus `notices: { url, count }` — a cheap poll |

Each notice carries `id`, `severity` (`breaking` / `warning` / `info`),
`version`, `published_at`, `title` and `body`. `/api/notices` and `/api/me` are
on the platform passthrough list, so your app's own frontend can `fetch` them
directly and render a banner — the request reaches the platform rather than
being rewritten back into your app's prefix.

This channel exists because it did not: when v2.39.0 stopped forwarding the
platform cookie, apps that had been reading it simply broke, with no warning
anywhere.

**Failure mode.** Pinning integration behaviour to a platform version you never
re-check. Poll `count` on `/api/info` from wherever you already have a
health-adjacent job, or read the list at boot.

---

## The levels at a glance

| Level | Capability | You implement | You stop maintaining |
|---|---|---|---|
| 0 | Runs, and is listed | `$PORT`, non-root, a catalogue entry | compose files, install docs |
| 1 | Health | 200 + `{status, version}` at a declared path | — |
| 2 | Persistence | write under `DATA_DIR` | volume configuration |
| 3 | Identity | read `X-AppCrane-*`, gate with `atLeast` | login, sessions, SSO |
| 4 | Your own roles | read `X-AppCrane-App-Roles`, enforce | roles table, grant UI |
| 5 | Managed database | a `needs` block naming your variables | provisioning, credentials |
| 6 | Outbound email | POST to the service API | SMTP, deliverability |
| 7 | Per-tenant data | `multitenant: true` + the documented derivation | isolation, deletion on offboard |
| 8 | Notices | poll `/api/info`, read `/api/notices` | finding out the hard way |

---

## What Skiff certification would add

Everything above is available to any app today, unilaterally, with no
involvement from us. Certification would add the parts an integration cannot
give itself:

- **A defined checklist.** The levels above turned into pass/fail criteria an
  implementation can be measured against, rather than prose to interpret.
- **A review.** A maintainer-facing pass over the integration — the role gate,
  the health shape, the `needs` block, the failure modes named in each level —
  by someone who has seen the ways they go wrong.
- **A mark.** A visible signal on the catalogue entry that the app was reviewed
  at a stated level, so an operator installing it knows what to expect before
  the first deploy.

The programme itself — what the levels are called, where the bar sits, who
reviews and how often it is re-checked — is being shaped with the first
maintainers who want in, deliberately, rather than announced and then adjusted
around them. If that is you, open an issue titled **`Skiff`** on
https://github.com/gitayg/appCrane/issues describing your app and which levels
you already meet. That is the whole intake process at the moment.
