# AppCrane backlog

Work that was considered and deliberately **not** done, with the reasoning that
led there. The point of this file is that a future reader can weigh the tradeoff
again instead of rediscovering it — so each entry records what the option would
buy, what it would cost, and what tipped the decision. An entry leaves this file
when it ships (into `CHANGELOG.md`) or when it is decided against permanently
(rewrite it here as a "no", don't delete the reasoning).

Newest first.

---

## Caddy `layer4` — reconsidered for dual-plane apps, rejected again, v2.45.0

**Status:** rejected for this case. v2.45.0 shipped `ingress_type: 'dual'` — a
second `docker run -p 0.0.0.0:<public_port>:<data_plane_port>` publish beside the
existing loopback one, Caddy untouched. This is the **second** time the `layer4`
plugin has been weighed and declined; the entry below records the first (v2.42.0).
Read both before opening it a third time.

**Why it came back.** v2.42.0's `tcp` ingress served an app that is entirely
non-HTTP. v2.45.0's case is different: an app with an HTTP **control plane** that
must stay behind Caddy *and* a raw **data plane** whose clients are already
configured for host port 8080. Because that app is partly HTTP, "let Caddy carry
both planes" looks plausible in a way it did not for a pure CONNECT proxy — so the
option was genuinely re-examined rather than waved off.

**Why it lost again, and the reasons are not the same ones as last time.**

- **Stock Caddy cannot pass raw TCP at all.** This is the decisive fact and it is
  not a preference: layer-4 proxying is not in the standard Caddy distribution.
  Using it means an `xcaddy` build with a pinned plugin version, shipped and
  maintained by us — a custom binary in place of the stock package, in front of
  **every app on the box**. A regression in that build takes down the whole
  platform; the direct publish's failure mode is confined to the one app whose
  port is published. That trade was disqualifying for one app in v2.42.0 and it is
  no worse now.
- **A direct publish is actually passthrough; `layer4` is a proxy.** For a data
  plane the requirement is that the client's bytes reach the container unaltered.
  Docker implements the publish as a DNAT rule (see the `DOCKER-USER`/`FORWARD`
  note in `onboarding.md`): the kernel rewrites the destination and the client's
  source address survives. A `layer4` route is a userspace proxy — it terminates
  one connection and opens another — which puts a hop in a path whose whole point
  is that there isn't one, and re-raises peer-address preservation
  (proxy-protocol, or the app losing the client IP) that the direct publish does
  not have to solve.
- **It buys nothing the dual model needs.** `layer4`'s advantages are platform TLS
  in front of a plain TCP upstream, connection logging, and SNI fan-out. A dual
  app already has all the platform TLS and logging that matters on its **control**
  plane, through ordinary Caddy. What the data plane needs is a specific host port
  and raw bytes, which is precisely what a publish gives.
- **Simpler, and it reuses what already exists.** `dual` needed one nullable
  column, one validator and one changed `-p` argument. The `public_port` allocator,
  the partial unique index, the reservation-across-flip behaviour and the
  `app-ingress-change` audit all came from v2.42.0 unchanged.

**What would change the answer** is unchanged from the entry below — several apps
needing raw TCP, a requirement that AppCrane terminate TLS for them, or a
compliance need for platform-side connection logs on non-HTTP traffic. Note that
one thing *did* move in `layer4`'s favour: `public_port` and now `data_plane_port`
are stored per-app values, so a `layer4` listener could adopt both as-is. The
blocker is the custom binary, not the data model.

---

## Caddy `layer4` for non-HTTP apps (Option A) — deferred, v2.42.0

**Status:** deferred. v2.42.0 shipped Option B instead — publishing the
container's port directly on the host (`0.0.0.0:<public_port>`), Caddy out of the
layer-4 path entirely. See `## TCP (layer-4) ingress` in
`server/services/guides/onboarding.md`.

**What it is.** [`mholt/caddy-l4`](https://github.com/mholt/caddy-l4) is a Caddy
plugin that adds TCP/UDP proxying to Caddy. With it, a raw-TCP app would be
another block in the Caddyfile AppCrane already generates — Caddy would listen on
the public port and proxy the connection to the container, instead of Docker
publishing the container's port on the host.

**What it would buy.**

- **One config surface.** Every app's ingress would stay in the generated
  Caddyfile. Today a TCP app's ingress lives in `docker run -p` args and an
  `apps.public_port` column, so "what is listening on this box" has two answers.
- **Platform TLS termination.** `layer4` can terminate TLS in front of a plain
  TCP upstream, so an app could get a Let's Encrypt certificate from AppCrane
  without implementing TLS itself. Under Option B a TCP app is plaintext unless
  it does its own TLS.
- **Connection logging.** Caddy would see and log every connection —
  open/close, bytes, peer address. Option B gives AppCrane *no* visibility into
  the traffic at all; the app is the only place a tunnel can be logged.
- Room to grow: SNI-based routing to several TCP apps behind one port, and
  proxy-protocol support, both of which Option B cannot express.

**What it would cost, and why that lost.**

- **A custom Caddy binary.** `layer4` is not in the standard distribution; using
  it means building Caddy with `xcaddy` and shipping that binary. AppCrane
  installs stock Caddy from Caddy's own apt repo today (`install.sh`:
  `apt-get install -y caddy`), so this adds a build step to installation, to
  `/api/self-update`, and to every upgrade path — plus the job of tracking
  upstream Caddy security releases ourselves instead of getting them from the
  package feed.
- **Blast radius.** That binary fronts **every** app on the box. A regression in
  a custom build takes down the whole platform, not one app. Option B's failure
  mode is confined to the one app whose port is published.
- **The trade.** One app needs raw TCP. Swapping the proxy that every app depends
  on, and taking on the maintenance of a custom build, is disproportionate to
  that. Option B needed a migration, an allocator, a docker-run flag and a
  protocol-aware health probe — and it left Caddy untouched.

**What would change the answer.** Several apps needing raw TCP; a requirement
that AppCrane terminate TLS for them; or a compliance need for
platform-side connection logs on non-HTTP traffic. If any of those arrive, the
work is: `xcaddy` build in CI with a pinned plugin version, a verified-checksum
install path, the generator emitting `layer4` blocks from `apps.public_port`, and
a rollback to stock Caddy that doesn't strand TCP apps. Note that Option A and
Option B are not mutually exclusive — `public_port` is already an allocated,
stored, per-app value, so a `layer4` listener could adopt it as-is.
