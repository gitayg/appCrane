# AppCrane Changelog

Machine-readable release notes. Each entry is one line: `## <version> — <summary>`.
The dashboard's "What's New" dialog reads this file over raw.githubusercontent
so it can show admins what changed when AppCrane is updated (or about to be).
Keep newest-first; add an entry before every version bump.

## 2.50.1 — Report the runtime, so the floor can actually be checked.

v2.50.0 raised the supported Node floor to 22 and warned at boot when a host was below it. The very next question — *what is the production host running?* — turned out to be unanswerable: `getSystemInfo()` reported hostname, CPU, memory and disk, and not the runtime. The boot warning goes to the startup log, so the only way to check a live host was shell access.

`GET /api/server/health` now includes `node_version` and `node_major`. `node_major` is a number, deliberately: a string would make `node_major < NODE_FLOOR` compare lexically and quietly report a modern host as out of date.

A floor nothing can be checked against is a floor on paper.

## 2.50.0 — The Node floor moves to 22, and three files now have to agree about it.

Two Dependabot PRs — chalk 6 and better-sqlite3 13 — both declare `engines.node >= 22`. `install.sh` provisioned **Node 20**. Neither PR could be merged safely, and the reason had nothing to do with either dependency.

Nothing was positioned to catch it:

- **CI runs on Node 22**, so every check was green on a runtime no production host was guaranteed to have.
- **`package.json` declared no `engines` field at all**, so npm never warned that a dependency wanted a newer runtime.
- **`install.sh` only upgrades a host that is BELOW its baseline**, and self-update is `git reset --hard` + `npm install`, which never touches the runtime. A box installed when the floor was 20 stays on 20 through every update, silently.

Node 20 left long-term support in April 2026, so the move was overdue independently of these two PRs.

The floor is now 22 in `install.sh`, in `package.json` `engines`, and in a `NODE_FLOOR` constant that warns at boot. Six tests assert all three agree, plus that the README tells operators the same number and that CI never runs *older* than the floor — drift in any one of the four turns a test red, verified by drifting each.

**The boot check warns; it does not exit.** Refusing to start would take a running platform down during an upgrade, which is a worse failure than the mismatch it reports. It prints on every boot, with the upgrade command, until someone fixes it deliberately.

**This does not upgrade any existing host.** It changes what a *fresh* install provisions and makes an out-of-date runtime loud. A host already on Node 20 needs `curl -fsSL https://deb.nodesource.com/setup_22.x | sudo bash - && sudo apt-get install -y nodejs` before it should take chalk 6 or better-sqlite3 13.

## 2.49.3 — Deleting a dependency instead of upgrading it 98 versions.

Dependabot opened a PR to take `@anthropic-ai/sdk` from 0.39.0 to 0.120.0 — 98 releases, about 18 months. Before reviewing that, the question worth asking was what the SDK is for.

**One import in the entire repository**, in `server/services/appAnalyzer.js`, added in v1.10.0 for an "AI-powered Add from GitHub wizard" that analysed a repo and pre-filled app config. The wizard is gone: `analyzeGithubRepo` — the only function that touches the SDK — has **no callers anywhere**. No route exposes it, no dynamic import reaches it, and no "analyze" UI survives in the SPA.

The one surviving reference was `resetClient()`, called on API-key rotation to invalidate a cached client that nothing had created for some time. Its comment justified itself with *"POST /chat is the only other SDK consumer"* — and there is no `/chat` route. That comment had been describing a system that no longer existed.

Every real AI path in AppCrane hands `ANTHROPIC_API_KEY` to the **Claude Code CLI** (`generator.js` installs `@anthropic-ai/claude-code` into containers) and reads it per invocation. `ask.js`, `coder.js` and `agents.js` all check the key; none of them imports the SDK.

So the safest upgrade was removal: `appAnalyzer.js` deleted (166 lines), `@anthropic-ai/sdk` dropped from `package.json`, the `resetClient()` block replaced by a note explaining why nothing needs invalidating. PR #1 closed rather than merged.

How it got orphaned is worth recording, because the same move could do it again: `2dc0a27` (v1.27.7) deleted a dormant `oneShot.js` and *rerouted* key-rotation reset into `appAnalyzer`. Cleaning up one dead module wired the survivor to a second dead one, which left `appAnalyzer` looking referenced while its only real function had none.

Verified by the path that actually touched the deleted code: `PUT /api/appstudio/anthropic-key` returns 200 and the rotated key reaches `process.env`. Suite 723/723, and one fewer outbound-network-capable dependency for the scanner to track.

## 2.49.2 — Be told a fix exists, before the gate has to stop the build.

v2.49.1 made the dependency scan blocking, which is the last line of defence. This is the first: `.github/dependabot.yml`, opening upgrade PRs weekly for npm and monthly for GitHub Actions.

Grouped on purpose. Ungrouped, ~40 direct and transitive packages produce a PR each and the queue becomes noise nobody reads — the same failure this is meant to fix, arriving by a different route. Majors stay ungrouped and arrive one at a time: nodemailer 8 → 9 was a major with a behaviour change nothing in the suite exercises, and it deserved its own review rather than a line in a batch of thirty. Actions are included because every workflow pins by full SHA, which is correct for supply-chain reasons and means the pins rot unless something rewrites them.

**The file is only half the fix, and the smaller half.** Dependabot **alerts are disabled on the repository** — `GET /vulnerability-alerts` returns 404 and `automated-security-fixes` reads `{"enabled": false}`. That is why nothing was said for nine weeks: GitHub was never going to mention the CVEs at all. No committed file can turn that on; it is two API calls, recorded at the bottom of the new config.

## 2.49.1 — Seven dependency advisories, and the reason nobody saw them.

**`npm audit` reported seven advisories. CI had been green on every push.** The scan step ran OSV-Scanner with `continue-on-error: true` and there was no gate after it, so the job reported "Security Scan: success" regardless of what it found, and the results went to the GitHub Security tab where nobody was looking.

The two that were raised directly:

| Package | Was | Now | Fix available since |
|---|---|---|---|
| adm-zip | 0.5.17 | **0.6.0** | 2026-07-10 — six weeks |
| nodemailer | 8.0.5 | **9.0.5** | 2026-06-17 (9.0.1) — nine weeks |

The adm-zip one deserves its severity here rather than in the abstract. A crafted ZIP triggers a 4 GB allocation, and `POST /api/apps/:slug/deploy/upload` is gated on `requireAppAccess` — any user with access to any app, not a platform admin. The extraction runs in the **AppCrane server process**, which no `--memory` flag constrains, on a host with **zero swap**. That is the same mechanism as the August OOM incident, reachable on request.

The nodemailer `raw`-option bypass is *not* reachable — the transport is plain SMTP with no `raw` and no `jsonTransport` — but the upgrade also clears a CRLF injection in `List-*` headers and an OAuth2 TLS validation flaw, and there was no reason to stay behind.

Five more went with them, four transitive and one direct: `@xmldom/xmldom`, `form-data`, `qs`, `body-parser`, and `multer` 2.1.1 → 2.2.0. `npm audit` now reports zero. Full suite green on the upgraded tree.

**And the gate is real now.** The OSV job gained a blocking step that mirrors the one Semgrep has had since v2.27.0: the scan stays non-failing so the SARIF always reaches the Security tab, and a separate step fails the build on any finding. Turned on at the moment the count hit zero, which is the only cheap time to do it. An advisory with no fix goes in a named `IGNORED` map with a reason and a date — one reviewable line — rather than switching the gate off again.

A check that cannot fail is a dashboard, not a check.

## 2.49.0 — The three AppCrane-owned items from the August incident review.

**`--memory-swap` is now pinned to `--memory`.** A container started with only `--memory=512m` gets a combined ceiling of *twice* that by Docker's default, so the configured number was an understatement of what the container could take. The review's own case ran `--memory=512m --memory-swap=1g` and so read as having 512 MB of swap to fall back on; the host had zero swap, the kernel enforced 512 MB of RAM and nothing else, and the extra 512 MB was a contract nothing could deliver. Pinning the two makes the configured number the real ceiling. Measured against a live daemon rather than read off the docs: `--memory=512m` alone yields `memory.swap.max=536870912` inside the container, and adding `--memory-swap=512m` yields `0`.

**Restart retries drop from 5 to 2.** The policy direction was already right — `on-failure`, not `unless-stopped`, contrary to the review's first draft. Five consecutive restarts of a process that OOMs under load re-pressure a host that has no memory to give, five times.

**A memory budget, reported and never enforced.** `appcrane_memory_budget` answers what the platform has committed against what the host has: 50+ apps at the 512 MB default commit roughly 25 GB on a 7.6 GB box. `PUT /api/apps/:slug` now returns a `memory_budget` assessment when a limit changes. It does **not** block, deliberately — the fleet is already about 3x over-committed, so a gate would reject every ordinary edit from the moment it shipped, including edits that *reduce* the total. A control you must disable to get work done is not a control. The numbers are configured ceilings, not measured usage, and every surface says so.

**And a fix for a bug v2.48.0 shipped yesterday.** `appcrane_check_resource_limits` ran `SELECT id, slug, max_ram_mb, max_cpu_percent FROM apps`. There is no such column — limits live in `apps.resource_limits`, a JSON TEXT column — so the tool threw `no such column: max_ram_mb` on every call. Its tests passed because they handed the comparison hand-built `{ max_ram_mb: 512 }` objects and never a database row: a fixture shaped to match the code cannot catch the code being wrong about the schema. Limits are now read through one helper that parses the column, and the regression test calls the tool against a real database. The first version of *that* test asserted the query string instead of running the tool, and stayed green against the restored bug — the same mistake one layer up.

723 tests. The three implementation items were built by parallel agents with disjoint file ownership and each checked by an adversarial verifier; every claim relayed here was re-run independently before release.

## 2.48.0 — Backup and resource limits are answerable from an agent.

**An incident review recorded "no SQLite backup exists" as an open risk.** AppCrane has shipped scheduled S3/R2 backup since v2.21.9, and the nightly zip covers `deployhub.db`, `.env`, icons and appdata. It is a no-op until a bucket and credentials are entered — and there was no way to ASK whether that had happened except by opening Settings. A five-minute settings task got filed as a missing capability.

Three tools make it answerable. `appcrane_get_backup_status` returns a verdict rather than raw settings, because the states that matter look alike from the config alone: configured-but-disabled, enabled-but-never-run, enabled-but-failing, and enabled-but-**overdue** (a nightly job whose last success was three days ago reads identically to a healthy one unless someone measures). `appcrane_run_backup_now` proves the credentials work instead of finding out at 03:00. `appcrane_set_backup_config` sets the rest, and **refuses to enable an incomplete configuration** — an enabled backup with no destination fails silently every night while every surface reports it enabled, which is worse than being plainly off.

All three are platform-admin only, checked as the first statement in each handler: the destination bucket receives a copy of every secret AppCrane holds, so pointing it elsewhere is an exfiltration path, not a misconfiguration. The secret access key is write-only — encrypted at rest, never returned by any read surface, and recorded in the audit log as a fact rather than a value.

**And the same blind spot, one subsystem over.** `--memory` and `--cpus` are `docker run` flags, exactly like a port publish: changing a limit rewrites the row and nothing else until the container is **recreated**. Every surface reported the configured number, so a container running with *no* memory limit was indistinguishable from one running at 512 MB.

That is not theoretical. The same review examined an app configured `max_ram_mb: 512` whose clamd was OOM-killed at 992 MB RSS — figures that cannot both be true — and no AppCrane surface could say which. Settling it took an `ssh` and a `docker inspect`. (It turned out the limit *was* applied, and the real story was `--memory-swap=1g` against a host with zero swap; the point stands that nothing could tell you either way.)

`appcrane_check_resource_limits` compares every app row against the limits actually in force, fleet-wide, in two `docker` calls. `state: not_applied` on memory means no limit at all — that container can take the whole host. Unreadable Docker answers `unknown`, never "unlimited".

Twenty-five tests, each verified failing first: treating "no limit" as applied turns the headline case red; reporting an unreadable container as unlimited turns the honesty test red; dropping the float tolerance on NanoCpus turns a healthy container into a false positive; leaking the S3 secret into the status payload, allowing a non-platform admin, and enabling an unconfigured backup each turn their own test red.

## 2.47.0 — Changing a published port is one step again, not three.

**Moving a port an app was already publishing was refused outright**, with a message telling the operator to set `ingress_type='http'`, redeploy, then pin the new number and deploy again. Four actions to change one integer.

The hazard behind the refusal was real, and it still is. The pin is the only thing reserving a number: overwrite it and the old port returns to the pool while a live container is still bound to it, so the allocator can hand it to another app — whose `docker run` dies with "port is already allocated" while traffic to that port keeps reaching the *original* app. Silent cross-app redirection.

But the refusal was a workaround, and the code said so:

> Refused rather than tracked: recording "still bound to X while pinned to Y" needs a second column, and the two-step below reuses the release path that is already audited and tested.

v2.46.0 built that second store. So the state is now recorded instead of refused: the old number moves to **draining** — still owned, still impossible to hand to anyone else, but no longer the app's pinned port — and the existing release-on-recreate hook drops it the moment the container binding it is replaced. Set the new port, redeploy, done.

`host_port` remains the registry's primary key, so a draining port is still an owner and the global "one app per port" invariant is untouched. What changed is `UNIQUE (app_id, env)`, now a **partial** index over `state='pinned'`: an app mid-move legitimately holds two ports for one environment — the one it is moving to, and the one its container still answers on. Exactly one may be pinned.

Re-pin twice before redeploying and both old numbers drain. AppCrane cannot tell which one the running container holds, and reserving one it does not need is strictly safer than reissuing one it does.

The release hook is now per-environment, so a sandbox re-pin frees its own old port on a sandbox recreate — without that half it would have stayed reserved forever, since the hook only ever ran for production.

Twenty-three tests over the registry, eight of them on draining, each verified failing first: deleting the old row instead of draining it (the pre-2.47 hazard, restored) turns five red including the one asserting another app cannot take the port; letting `claim()` wipe draining rows turns the same five red; and skipping the drain on recreate leaks the number out of the pool. The rewritten `PORT_STILL_HELD` test keeps its original safety assertion word for word — a live container's port is still never handed to another app — while now asserting the move succeeds.

## 2.46.0 — A published port per environment: sandbox can have its own.

**The raw data plane existed only in production, so the first time anyone spoke the actual protocol to it was after it went live.** `docker.js` refused outright — `if (env !== 'production') return null` — and the reason on record was "one `public_port` per app but two containers, so the second `docker run` dies with 'port is already allocated'". That argues against **one** port on two containers. It never argued against **two different** ports; sandbox was excluded because there was only one number to go round, and the safe way to allocate one number between two containers is to give it to the one with real clients.

There are two numbers now. `public_port` publishes the production container, `sandbox_public_port` publishes the sandbox one, each on its own host port, both able to run at the same time. The container side stays shared — that is a property of the image, and it is the same image in both environments.

**Why a registry table and not a second column.** The single `UNIQUE` index on `apps(public_port)` was quietly doing real work: no two apps could share a host port. A second column cannot express that, because SQLite cannot enforce uniqueness *across* two columns as one value space — app A's sandbox port could equal app B's production port with every constraint satisfied, and the clash would surface as a failed `docker run` partway through a deploy, naming a port that looks unclaimed in the dashboard. `app_host_ports` is keyed **by the port**, so the invariant stays in the schema where it was. The per-environment columns remain as the fast read path and are written in the same transaction; the registry is the authority.

**Rollout is opt-in, deliberately.** No app gains a sandbox port by upgrading, and none is allocated at deploy time. One appears only when a platform admin sets it. A published port has no forward_auth, no TLS from AppCrane, no identity headers and no audit, and the sandbox container runs the least reviewed code on the platform — handing a second one to every publishing app because the schema changed would open doors nobody asked for, at deploy time, when nobody is watching.

Every guard a production publish passes, a sandbox publish passes identically. A dual app whose `data_plane_port` is the control plane publishes nothing in **either** environment — otherwise sandbox would have been a second route to the exposure v2.45.0 exists to prevent, reached by a path the guard tests never look at.

Available in the ingress panel, on `PUT /api/apps/<slug>`, and through `appcrane_set_app_ingress`. Platform admin only, like the rest of ingress.

Thirty-two tests, each verified failing first. Reverting the collision check to the old single-column query turns four cross-environment tests red — including the case a second column would have allowed. Letting a sandbox publish skip the data-plane guard turns the exposure test red. Dropping the registry delete on release turns three red, because the port leaks out of the pool. And against a real Docker daemon: both containers started at once, each answering on its own host port, each keeping its own loopback control plane — the "port is already allocated" failure the old rule existed to avoid, demonstrated not to happen.

## 2.45.3 — "Configured" and "actually published" are now two different answers.

**AppCrane reported a port mapping that existed nowhere.** `appcrane_get_app_ingress` answered `published_as: 0.0.0.0:8080 -> container:10800` for an app whose container bound nothing at all — and every other read surface agreed, because all of them described the app ROW. Nothing described the running container. The operator who trusted it spent an afternoon on SDP, DNS and firewall rules for a port that was never opened.

The cause is structural rather than a bug: a port publish is a `docker run` argument. Setting ingress on an app that is already running changes the row and nothing else — the container keeps the command line it was created with until it is **recreated**.

Underneath that sits a trap worth naming on its own: **not every restart recreates.** The health checker's automatic restart is `docker restart`, which reuses the existing container and therefore its bindings, so an app can bounce all day and never publish. Only a path through `startApp()` applies it — `POST /api/apps/<slug>/restart/<env>`, a deploy, or a rollback.

**Every ingress read now compares the row against the container.** `publish_applied` is `true`, `false`, or `null`, and `publish_drift` carries a state and a remedy:

- `not_applied` — configured, container binds nothing. The message says to recreate, and says a plain `docker restart` will not do it.
- `stale` — the container publishes a *different* mapping, naming both what clients reach now and what was configured.
- `orphan` — the row publishes nothing but the container still binds a port. `pending_port_release` covers this when AppCrane made the change; this catches a row edited directly or restored from a backup.
- `unknown` — the container could not be read. Reported as `applied: null`, **never** as "not published": answering "closed" because we failed to look would be the same class of wrong answer this change removes.

`published_as` now carries the verdict inline — `— CONFIGURED BUT NOT LIVE: …` — because an agent reading that one string was the reader that got misled. It is annotated **only** when the container was read and found lacking; an unreadable daemon leaves the string clean and says so in `publish_applied`.

In the dashboard the ingress icon turns **amber** for a configured-but-not-live publish, outranking the red "this app is exposed" colour: red means a port is open, and the whole point here is that it is not.

**Cost control:** one `docker ps` for the entire catalog, cached briefly and invalidated whenever a container is created or destroyed — not an inspect per app, which would have put a subprocess spawn per app on the platform's hottest endpoint.

Twenty-four tests, each verified failing first. Making the comparison always report "applied" turns the live reproduction red; counting the loopback control-plane publish as a public port turns the parser tests red; restoring the old always-report-intent string turns the payload tests red. The live test reproduces the incident exactly — start an app as plain http, set it to dual, confirm it reads NOT applied and the port really is refused, then recreate and confirm both flip.

## 2.45.2 — Opening Settings made 48 API calls to show one tab. Now it makes 15.

**Measured, before and after, in a browser against a real instance with 12 apps:** 48 requests → 15. `/api/apps` went from 5 to 1.

**Every tab was mounted on arrival.** The ten panels under Settings were only hidden with `display: none`, so opening the page ran the fetches for all of them — Users, Audit, GitHub, Mail, Backup, Branding, Roles, Skills and MCP all loaded to show you Security. Tabs are now mounted the first time they are shown and kept mounted afterwards, so a half-filled form still survives switching away and back; the cost is just paid per tab actually opened, once each.

The worst of it was invisible from the code: the Users panel fetches `/api/apps/<slug>/identity/users` **once per app**. On the 12-app test instance that was 12 extra requests nobody asked for; on a 57-app instance it is 57. Not mounting the tab removes the whole fan-out.

**`/api/server/tls-check` no longer runs on every visit.** It reaches out to the internet twice — hstspreload.org, and the platform's own domain to see its certificate from outside — and both calls were awaited *in series* behind an 8-second timeout each, with nothing cached. Up to 16 seconds, for an answer made of DNS, a certificate and a public preload list. The two probes now run together, and the result is cached for 10 minutes, keyed on the domain and the TLS mode so uploading a certificate is reflected immediately rather than up to the TTL later. `?refresh=1` forces a re-probe, which is what the panel uses after saving.

**GETs already in flight are shared.** Three panels asked for `/api/apps` independently in the same tick and the server built that payload three times. Entries live only for the duration of the request, so a second caller shares a response it would have waited for anyway — deliberately not a TTL cache, so no one can read a stale one.

Five tests cover the tls-check behaviour, each verified failing first: re-serialising the probes, disabling the cache, and dropping the TLS mode from the cache key each turn the expected test red. One of them was found to be vacuous while doing this — the fixture produced an empty `warnings` array either way, so a build that dropped warnings from the cached payload passed it. The fixture now emits a real warning, and the test asserts the fixture still does.

## 2.45.1 — The dual data plane, measured against a real Docker daemon.

**2.45.0 shipped with the live behaviour verified by hand and nothing in the suite holding it.** The existing tests prove the *argv* — via a `docker` shim that records what it was called with — which is the right test for "did we build the command line we meant to" and the wrong one for "does that command line do what we think", because a shim agrees with whatever the code says. `test/data-plane-e2e.test.js` starts real containers and connects real sockets.

Four tests: one container answering on both planes with a distinct marker on each, so a pass cannot come from reaching the wrong one; the data plane refusing to be an HTTP server; a dual row **written straight into the database** with `data_plane_port = 3000` publishing nothing at all; and a plain HTTP app still getting exactly one loopback binding and no other.

The guard test writes its row directly on purpose. A write-boundary validator cannot see a restored backup, a migration, or a hand-edited row — those are precisely the cases where the runtime edge is the only thing standing between the HTTP origin and a public port with no TLS, forward_auth, identity or audit.

**Two things the writing of it found, both now load-bearing:**

*Docker's userland proxy accepts before the container listens.* The first draft waited for the port to accept, then asserted on the body — so it connected instantly, read nothing, and failed. Worse, it means "read nothing" cannot distinguish a port that was never published from one that was published but unbacked. The guard test therefore asserts on `connected` — the kernel refusing — and never on an empty read.

*A key-shape assertion passes while the origin is exposed.* When the guard is removed, the leaked publish lands under the **same** `3000/tcp` key as the loopback one, because both target container port 3000. `Object.keys(bindings)` still reads `['3000/tcp']`. The assertion is now "no binding anywhere has a non-loopback host IP", which names the actual danger and catches it head-on.

All four were mutation-tested rather than trusted green: removing the runtime 3000 guard turns the security test red; pointing the publish at `CONTAINER_PORT` turns the two-plane tests red; adding one stray `-p` turns the regression test red. Ports are allocated, never literals — a hand-written port number was tried and an unrelated listener on the same number answered the probe instead of the container, which is a test that measures the wrong process and can pass while the feature is broken.

Skips with a reason when no Docker daemon answers, verified both ways (binary absent, and binary present with the daemon unreachable).

## 2.45.0 — An app can now serve HTTP through Caddy and a raw port at the same time.

**The problem: raw TCP was all-or-nothing.** `ingress_type='tcp'` (2.42.0) publishes the container's port 3000 straight onto the host, which means the app's *only* plane is the unauthenticated one — its web UI comes out on the same raw port, with no TLS, no SSO, no identity headers and no request audit. An app that speaks HTTP to people and a non-HTTP protocol to machines had to give up Caddy entirely to get the second one.

**`ingress_type='dual'` splits the two.** The HTTP control plane stays exactly where it was — container port 3000, bound to loopback, fronted by Caddy with forward_auth, `X-AppCrane-*` identity, security headers and access logs. A second port *inside the same container* — the new per-app `data_plane_port` — is published raw at `0.0.0.0:<public_port>` alongside it. Clients that were already configured for a fixed port (8080, say) reach the data plane directly; browsers keep going through the front door.

**The guard this whole feature rests on: `data_plane_port` can never be 3000.** Pointing the raw publish at the control plane would put the origin Caddy exists to protect onto a public port with no TLS, no forward_auth, no identity and no audit — the precise thing 'dual' was added to avoid. So it is refused twice, independently: at the write boundary (`validateDataPlanePort`, on the REST route and the MCP tool alike) and again at the runtime edge, where a row whose `data_plane_port` is missing or is 3000 publishes *nothing at all* rather than falling back to a default. A hand-edited database row does not get a second chance.

Flipping a dual app to `tcp` is likewise refused while it still has a data-plane port pinned, because that flip would silently repoint the same host port at 3000.

**Nothing changes for an ordinary app.** The 57 apps on plain HTTP ingress get no second `-p` and their `docker run` line is unchanged — asserted against a recorded, vendored copy of the v2.44.2 argv, element for element, so an accidental extra flag fails the build. A pure-tcp app still targets container port 3000. Verified with `caddy adapt` across all six app shapes (http/public/headless/tcp/dual/dual-public): the config compiles, and no compiled upstream anywhere points at a data-plane port.

Platform-admin only, per app, in App Settings and via `appcrane_set_app_ingress`. Host ports are allocated from 31000-31999 or named explicitly, and are checked for collisions against every other app.

## 2.44.2 — Tests for the supply-chain work, and a watchdog for the way they keep failing.

**The supply-chain changes shipped in 2.44.0 with no tests.** The agent that wrote them finished; the agent that was to test them died mid-run, and the cross-check died with the machine, so the gap went out in the release. It is closed now: 11 tests over `verifyCommitSha` and the generated build.

Writing them found that the first draft was worthless. The mock returned GitHub's git-refs shape (`object.sha`) where the code reads the branch shape (`commit.sha`), so every "success" looked like *200 with no commit SHA* — which fails closed. The mismatch tests were therefore passing because the mock was broken, not because a mismatch was detected. Fixing the shape is what actually exercised the escape hatch, which correctly refuses a mismatch even when set: "could not check" is negotiable, "checked and it is wrong" is not.

**A watchdog for local-only test assumptions.** Four tests in one week passed here and failed on the runner, each costing a red release and a patch, and none of them a product bug — the suite was green while being wrong. They had one shape: an assumption true on this machine and not on that one.

`scripts/check-test-portability.sh` now refuses the three that bit us — a baseline read out of git (meaningful only until it is committed, and unreachable anyway under a shallow checkout), docker host-gateway networking without a reachability probe (the runner cannot route it, so everything 502s, and checking that Docker *exists* is not a guard because it does), and a wait that resolves on the first result followed by an assertion of several. It runs in the pre-commit hook and in CI beside the other three watchdogs.

It caught its own first bug: `grep -rn` prefixes `file:line:` before the comment marker, so the comment filter never matched and the checker flagged the comments that exist to warn against this exact practice. Mutation-tested in both directions.

Deliberately narrow — every rule is a mistake this repo actually made, not a style opinion.

## 2.44.1 — The disk-quota test waited for the first mail and asserted two.

`waitFor` returns as soon as its array is non-empty, so the test resumed the moment the owner's alert landed, called `settle()`, and then asserted that both the owner and the platform admin had been mailed. The sends are sequential, so the slower the machine the wider the gap: green on every local run, red on the CI runner, which reported only the owner.

The product was never wrong — recipients are resolved in one synchronous query and mailed in a loop. The test now waits for the full recipient set rather than the first arrival.

The other `waitFor` sites in that file assert exactly one message, where waiting for any and then settling is sound; only this one expected more than it waited for.

## 2.44.0 — The rest of the security review.

Everything left on the external reviewer's list that was ours to fix, in one upgrade.

**Auth-bypass routes have an access log again.** A bare `log_skip` suppressed the entire log line for exactly the route class that is deliberately unauthenticated — so the least-protected surface on the platform was also the only one with no record. It existed to keep a token out of Caddy's log storage, and the code comment has named filtered logging as the intended fix since v2.7.28. The whole query string is now redacted rather than the line dropped, keeping method, host, path, status, IP and duration. Redacting everything rather than a named parameter is deliberate: the parameter belongs to the app's own CLI protocol, so a guessed list would silently miss the one that matters.

Access logging is emitted only when a bypass route actually exists, so an install with no exemptions is byte-identical to before.

**Custom-domain sites get the baseline security headers.** HSTS, nosniff, referrer-policy and permissions-policy were emitted once inside the `CRANE_DOMAIN` block, so an app on its own hostname inherited none of them — the apps most likely to be shared externally were the ones without the platform's baseline. Both site blocks now emit one shared constant rather than a second, weaker variant; this file already carries two comments about security rules that drifted when they existed in two copies.

**`frame_ancestors` can finally narrow.** It merged as a union with the platform-wide registrable-domain default, so an app could only ever widen the wildcard — an app that wanted to be embedded nowhere had no way to say so. `'none'` is now an opt-out sentinel. It was chosen because it is the one value with no coherent current meaning to break: an app setting it today gets `frame-ancestors 'self' https://*.example.com 'none'`, and under the CSP3 grammar `'none'` is only admissible as the sole source, so that policy denies nothing at all. Every other value keeps exact union semantics. Applied in `mergeAncestors` rather than the Caddy generator alone, so the in-iframe SSO login step agrees with the app's own policy instead of remaining frameable.

**Plaintext secret reads are throttled and surfaced.** v2.42.1 made them audited; an audit trail nobody reads is forensics, not detection. Owners are now notified, coalesced to one notice per person per app per 30 minutes — fifteen identical emails for one editing session teaches people to filter them.

The throttle numbers come from the real client rather than a guess: the Environment tab re-reveals after every set and delete, so an honest session is 15–20 reveals in minutes, and the limit is 30 per 10 minutes. A throttle that fires during genuine incident response is one an operator demands be removed, and then there is none. The budget counts per user and app across **both** doors — the REST `env-reveal` and the MCP `secret-reveal` — and across sandbox and production, so switching protocol or environment does not buy a fresh allowance. It reads from the audit log rather than process memory, so a restart does not hand an attacker a clean budget.

**App-sent email carries attribution and a rate limit.** The display name was caller-controlled on a real corporate mailbox, the sending app was recorded in the database but never appeared in the rendered message, and nothing was rate-limited. Recipients were already bounded to registered platform users, so this was spoofing and volume rather than an open relay.

**Supply chain: verification fails closed.** The HEAD-SHA check treated any GitHub error or non-2xx as a pass, so a network blip was indistinguishable from a verified commit. Lockfile handling and dependency scanning on tenant builds follow the lenient-default pattern established by `APPCRANE_REQUIRE_NONROOT` — warn by default, operator opts into enforcement — because breaking the next deploy of every lockfile-less app at once is not a security improvement.

**Read-only MCP keys.** Keys were all-or-nothing: any agent holding one could deploy, set env, delete apps and grant roles. A key can now be issued read-only, enforced centrally in the dispatcher rather than per-tool, with an unclassified tool treated as a write by default so tool #45 is safe without anyone remembering. Existing keys are unchanged — absent means full access.

**Tenant disk usage now alerts.** The quota was an injected environment variable with nothing watching it, so an app could fill the host disk and take every app down with it. Real enforcement still needs a project quota or a loopback image; this is the detection half.

461 → 517 tests.

## 2.43.1 — The container-isolation test compared the fix against itself.

`container-network-isolation.test.js` diffed the generated `docker run` argv against `git show HEAD:server/services/docker.js`. That was meaningful while the fix was uncommitted — HEAD was v2.42.0 — and became self-referential the instant it was committed: HEAD then contained the change, so the diff was empty and the anchor assertion ("HEAD really did start containers with no `--network`") was false. Five tests passed locally and failed on the first push.

It was also unusable in CI regardless. `actions/checkout` runs shallow with no tags, so `HEAD~1` and release tags are both unreachable on the runner — pinning either would have failed there while passing locally, which is the same defect wearing a different hat.

The baseline is now a vendored snapshot, `test/fixtures/docker.pre-isolation.js`, frozen at v2.42.0. The diff machinery is worth keeping — it catches a reordered publish or a changed bind address, not just a missing flag — so only its source changed.

## 2.43.0 — Removing someone was granting them secrets; containers could reach each other.

Four security fixes, shipped together so the fleet takes one upgrade rather than four.

**Removing someone from an app was granting them production secrets.** `PUT /api/apps/:slug/roles` with `app_role: 'none'` — how the admin UI's dropdown *removes* people — wrote a `'none'` row **and unconditionally inserted an `app_users` membership row**. `requireAppUser` reads exactly that table, so the "removed" person gained access they had never had: `?reveal=true` returns **decrypted production environment variables**, with `backup` / `restore` / `copy-data` alongside. Reproduced end to end: a user with no relationship to an app got `403`; an admin set them to `none`; the same request then returned the app's plaintext secrets.

What let it survive is that every human-visible signal disagreed with the one path that mattered. The dashboard showed `none`. `/api/me` reported `none`. Caddy's `forward_auth` denied them at `/<slug>`. Only `requireAppUser` said yes — and that is the gate in front of the plaintext. `'none'` now deletes from both tables; absence is the only representation of "no role", because checks cannot disagree about a row that does not exist. **Migration 073 clears the memberships this already created — every existing `app_role='none'` row is a live grant until it runs.**

**Removal via the Users modal left the platform tier behind.** `PUT /:slug/users` deleted `app_users` and pruned app-defined grants but never touched `app_user_roles`, so `resolveAppRole` still returned the removed member's old tier instead of `none` and `/api/identity/verify` let them back through Caddy. Verify went 200 → 403 after the fix. The same table pair as above, in the opposite direction — fixing one half was not enough.

**Any container could reach any other container.** Containers started with no `--network`, so every app sat on the default `docker0` bridge and could reach every other app on port 3000 directly — bypassing Caddy, `forward_auth`, identity headers, audit and rate limiting. One compromised app reached all of them.

The obvious fix does not survive this platform's size: a user-defined network isolates its members from *other* networks but not from each other, so isolation would mean one network per app, and Docker's default address pools yield only ~16–31 bridge networks before creation fails. At ~57 apps that breaks the platform at around the sixteenth, with an opaque subnet error at deploy time. Instead there is **one shared network with the bridge driver's inter-container communication disabled** (`com.docker.network.bridge.enable_icc=false`) — isolation without the address-pool ceiling, and nothing to tear down when an app is deleted. Verified against live containers: a sibling is unreachable on port 3000 on that network and reachable on an otherwise identical one without the flag, while the published `127.0.0.1` port Caddy uses still works.

Also added, conservatively: `--pids-limit`, `--security-opt no-new-privileges`, `--cap-drop NET_RAW`. Deliberately **not** `--read-only`, which breaks any app writing outside `/data`.

**Non-root containers are now actually checked.** The validator errored only when the *last* `USER` line was literally `USER root` — so `USER 0`, `USER root:root`, and a Dockerfile with **no `USER` line at all** all passed and ran as root. The last of those is the default shape, which is why it mattered. It also read the last `USER` in the file rather than in the final build stage, so a multi-stage Dockerfile setting `USER node` in a builder and nothing afterwards was reported as safe while running as root.

Explicit root is now a hard error (a deliberate act, and the guides already documented the rule). A **missing** `USER` warns on every deploy rather than failing, because turning the common case into an error would fail the next deploy of most apps at once — an outage dressed as a security fix, and it would also block deploying the fix. Operators flip `APPCRANE_REQUIRE_NONROOT=1` once their estate is clean. Nothing about the running fleet changes on upgrade; this makes the problem visible and fixable, not impossible.

**The per-key MCP app scope was silently inert.** `users.mcp_app_scope` exists and `mcpTools.js` reads it, but `requireAuth` built `req.user` for `dhk_mcp_*` keys from a hand-picked column list that omitted it — so every scope an operator set on the only MCP key type that exists was ignored, including `'[]'`. The other two auth paths select the whole row and were never affected, which is why the restriction appeared to work when tested with an API key or a portal session.

**Plaintext secret reads are audited.** Writes were (`env-set`, `env-delete`); reads were not, so the log recorded who *changed* a secret but not who took a copy. `?reveal=true` now emits `env-reveal`. Only the reveal — the masked list is the ordinary Environment-tab render.

Both hardening switches are now documented in `.env.example`. They were not, which is the same inert-config failure as the MCP scope above.

396 → 461 tests.

## 2.42.0 — Raw TCP ingress: apps that aren't HTTP can be reached directly.

Some apps don't speak HTTP. The motivating case is a forward/CONNECT proxy: a client opens a TCP connection and gets a tunnel back, which no HTTP reverse proxy can express. Those apps now get their container port published straight onto the host, with Caddy entirely out of the layer-4 path.

**The actual blocker was never Caddy.** Every container has always been published to `127.0.0.1` only — a deliberate loopback bind, and the reason raw TCP was impossible. So this ships as a direct Docker publish rather than Caddy's `layer4` plugin, which would have meant a custom `xcaddy` build and swapping the binary that fronts every app on the box. That option is recorded in the new `BACKLOG.md` with what it would buy, so the trade doesn't have to be rediscovered.

**The port is pinned, not pooled.** An operator sets it in the app's settings and hands it to clients by hand or by MDM, so it is a stored column — never derived from `slot`, which can be reassigned — allocated once from 31000–31999 and kept. Flipping to `http` stops publishing but the reservation stays with the app that owns it; another app asking for that number is refused, and flipping back returns the same one. Returning it to a shared pool would let a later app be allocated it while clients still point at the old number, which is a silent cross-app redirection — worse than a dead port.

Platform-admin only, and audited. An owner changing their own `auth_mode` is one thing; opening a host port is another.

**Two blockers found by review, both of which would have shipped a broken feature.**

A TCP app could never have deployed. There are two health checks, and making the periodic one protocol-aware wasn't enough: `deployer.js` runs a *mandatory* HTTP probe right after the container starts, and since v2.2.11 failure reverts to the previous image and throws. A CONNECT proxy can't answer an HTTP GET, so the deploy failed the gate and rolled back before the periodic checker ever ran. Both are protocol-aware now — a TCP app's gate proves the listener accepts a connection on the loopback port, so it passes before any firewall step and doesn't depend on an allocation existing. An HTTP app's gate is unchanged: same probe, same 30s envelope, same message, same rollback.

And re-pinning a *live* TCP app to a different port silently freed the old one while the container was still bound to it — the exact cross-app redirection the pinned model exists to prevent, reached by a path the flip logic couldn't see. Now refused with `PORT_STILL_HELD`, but only when the app is genuinely publishing: a port allocated before the first deploy is bound by nothing, and re-pinning then is both safe and the common case.

**A TCP app's green deploy means less than an HTTP app's** — it proves a socket accepted a connection, not that the protocol works. AppCrane can't speak the app's protocol. That's stated at the gate and in the guide rather than left for someone to infer from a green dot.

**What a published port gives up**, stated plainly in the UI, the guide, the README and the MCP tools: no `forward_auth`, no identity headers, no per-request audit, no rate limiting, no security headers, no TLS from AppCrane. Every control shipped since v2.35 assumes Caddy is the only door.

Two claims in that copy were wrong and are corrected. A Docker publish is a DNAT rule evaluated in `FORWARD` that never traverses `INPUT`, so a plain `ufw deny` does **not** filter it — `DOCKER-USER` or upstream. And where the platform runs behind SDP the boundary is the perimeter, not the internet, which makes a proxy-auth gap an unaudited egress path rather than a public open relay. The docs test used to *require* the retracted "two keys" wording; it now requires the accurate version, and the corrected prose is pinned so a revert fails CI.

277 → 391 tests.

## 2.41.2 — Seeing who holds an app's roles needs the owner/admin tier.

`GET /api/apps/:slug/app-roles/members` and the `members` block of `appcrane_list_app_roles` returned the full roster — name, email, platform tier — to any member of the app, while every other roster read in AppCrane (`GET /:slug/identity/users`, `appcrane_list_app_members`) already required owner/admin. That was an inconsistency rather than a decision, and it let any member enumerate their colleagues.

The **catalog** stays open to members on purpose. Knowing which roles exist is what you need to read your own and to avoid duplicating a key; knowing who holds them is not the same question. So the MCP tool still enters on membership and returns the roles either way — the roster now rides along only for an owner/admin, with a stated reason when it doesn't.

The 403 is worded for what was actually attempted: asking who holds a role no longer gets told you may not "manage" roles, which sends people looking for the wrong problem.

No UI impact — the Access button only renders for apps where the viewer is a global admin or the app's own owner/admin ([Applications.tsx:1014](studio-web/src/pages/Applications.tsx:1014)), exactly the tier the gate now requires.

## 2.41.1 — The live-Caddy test now skips where it cannot run, instead of failing CI.

`identity-transparency.test.js` starts a real Caddy container and asserts on what an app container actually *receives* — which needs the container to reach stub upstreams on the host via `--add-host host.docker.internal:host-gateway`. That hop does not route back to the host on a GitHub Actions runner, so Caddy answered 502 for every route and seven assertions failed.

A 502 there says nothing about the config under test. Failing on it is a false negative that reds the gate on every push and teaches people to ignore it — which is exactly what happened: **v2.40.0 and v2.41.0 both shipped with Watchdog red and it went unnoticed**, because only the Security Scan was checked before tagging.

The test gated on Docker being *present*, which was never the right question; the right one is whether the container can reach the host. It now preflights that hop and skips with the reason when it cannot. Locally, where the networking works, all 31 checks still run — the same file's static assertions against the adapted Caddy JSON run everywhere regardless, and cover the same invariants structurally.

## 2.41.0 — Apps can define their own roles, and a person can hold several.

An app declares roles in Manage › Access — `approver`, `auditor`, `dispatcher`, whatever it needs — assigns any number of them to a person, and reads them back from `/api/me` or the `X-AppCrane-App-Roles` header. AppCrane is the role **authority**; the app is the policy **enforcer**. AppCrane never decides what `approver` means.

**The rule the whole design is built around: an app-defined role confers nothing on AppCrane.** If the two systems shared a namespace or a lookup, any app owner could invent a role called `admin`, assign it to themselves, and watch it flow into a platform authorization check — privilege escalation authored through a settings form. So they live in their own tables, arrive on their own wire field, and nothing in `requireAppUser`, `requireAppAccess`, `permissions.js`, `resolveAppRole` or the `is_admin` computation reads them. They are carried, never consulted.

Keys are validated server-side against `/^[a-z][a-z0-9_-]{0,31}$/`, with `owner`, `admin`, `user`, `viewer`, `none` and `platform_admin` reserved, and a cap of 16 roles per app. The charset is not cosmetic — these keys travel in an HTTP header, so anything outside it is a header-injection surface, and the two bounds together mean the header's worst case is known by design rather than discovered in production.

New tables `app_defined_roles` and `app_role_grants` (migration 071). `app_user_roles` — AppCrane's own tier, one row per person per app, governing deploy and env and delete — is untouched. Different question, different table.

`X-AppCrane-App-Roles` joins `IDENTITY_HEADERS`, so it is stripped from the incoming client request on every proxied route and re-issued only by `forward_auth`. Verified against real Caddy across all seven route shapes: 20 app-proxying blocks, 98 invariants, including that the v2.40.0 `route { }` ordering still holds and the `cc_token` strip still runs after `forward_auth`.

**The bug worth recording.** Five independent verifiers found the same one: revoking a person's app access deleted their membership and tier but left their role grants behind. On a **public** app `resolveAppRole` falls back to `viewer` rather than `none`, so the deny gate never fired — the hosted app went on enforcing a role AppCrane believed it had taken away, and re-adding the person silently restored every role with no audit event. The orphaned grant was also invisible (the roster inner-joins members) and unremovable (writes refuse non-members), so an owner could not have cleaned it up.

Fixed at both layers. Every revoke path now clears grants, and — more importantly — `roleKeysForUser` joins `app_users`, so a grant is live only while its holder is still a member. That is the single choke point both `/api/me` and the header read through, which means a future revoke path that forgets the delete cannot reopen the hole. Confirmed end to end: after revocation the header is absent and `/api/me` returns `[]`; re-adding does not resurrect; and an orphaned grant is inert on every surface.

`/api/me` and `/api/identity/verify` had also disagreed about the same question — `/api/me` returned `app_roles` for a user AppCrane denies, while `verify` correctly withheld them. Since the guide tells app authors either surface is valid, an app's choice of read path silently decided whether revocation worked. Both now withhold at the same point.

204 → 277 tests, including a new revocation file that pins all three revoke paths, non-resurrection, and orphan inertness — with a baseline test so the absence-assertions cannot pass vacuously.

## 2.40.0 — Identity headers actually reach apps now. They never have.

The headline fix is one nobody was looking for. Caddy sorts directives by TYPE, not by source order, and `request_header` sorts **after** `reverse_proxy`. `forward_auth` is a `reverse_proxy` under the hood — so in every app block, the identity strip that reads as "strip the client's headers, then verify, then hand the verified ones to the app" actually compiled to: verify, copy the identity on, **then delete every one of them**, then proxy to the app.

Confirmed against real Caddy by adapting the generated Caddyfile and reading the compiled handler order. On v2.39.0 the app upstream is handler 11; the six `DELETE X-AppCrane-*` handlers are 5 through 10, after `forward_auth` at 2. **Hosted apps have never received `X-AppCrane-User`, `-User-Id`, `-User-Email`, `-User-Name`, `-User-Role` or `-App-Role`.** The Caddyfile source looks correct, which is why config inspection never caught it — only the adapted JSON or live traffic shows it.

That single bug explains a week of debugging across two apps: one team concluded identity requires SSO (it does not — `/api/identity/verify` resolves a session from an API key or a `cc_token`/Bearer session, and SSO is merely one way to create one), and an app denied its own owner from Settings because no role header ever arrived. Wrapping the strip and `forward_auth` in a `route { }` block fixes it, because `route` preserves source order.

**Expect apps to behave differently on this deploy.** Apps that currently see no identity will suddenly see all of it. That is the intended outcome, but it is a real behaviour change — watch one app before rolling wide.

**`X-AppCrane-Auth-Mode`** — `authenticated` | `headless` | `bypass`, present on every proxied request including headless. "No identity headers" was one symptom with four causes: headless mode, a path-level auth bypass, a broken forward_auth, or not being proxied at all. An app can now read which. Stripped-then-set, so a forged value never survives.

**`X-AppCrane-Is-Admin`** — `1` | `0`, computed by the platform with the correct precedence: global `admin`/`platform_admin`, **or** per-app `admin`/**`owner`**. Apps kept re-deriving this with `=== 'admin'` and locking out owners, the highest tier. Deliberately **absent** rather than `0` on headless and bypass routes, where nothing is verified — a `0` there would read as "verified, not an admin", which is a worse lie than saying nothing. Branch on `X-AppCrane-Auth-Mode` to tell them apart.

Headless routes now strip incoming `X-AppCrane-*` too. They never did — `stripIncoming` sat behind `if (!isHeadless)` — so a curl could hand a headless app any identity it liked, verbatim. Pre-existing, but shipping a new privilege bit without closing it would have turned a stale-identity nuisance into a forgeable admin flag.

**`auth_mode` is readable.** It was settable via the update route and listed in `ALLOWED_APP_COLS`, but absent from every app payload — write-only configuration. Now returned by the app config view and by `appcrane_get_app`, defaulting to `authenticated` where the column is NULL.

**The identity guide was wrong in ways that caused the bugs above.** It claimed a `platform_admin` "always reads as `X-AppCrane-App-Role: admin` on every app" — false, because `resolveAppRole` returns the explicit per-app row first and the global-admin short-circuit is only a fallback. It also documented absence of the role header as "not verified, so presence = trusted", omitting headless entirely. Both corrected, alongside the canonical role check (ordering `none < viewer < user < admin < owner`, and why `=== 'admin'` is a bug), an explicit "never derive identity from the `cc_token` cookie", and the correction that identity does not require SSO. A test now pins the guide's precedence claim against the real `resolveAppRole`, so the doc fails CI if the code moves under it.

**Platform notices.** v2.39.0 removed the cookie an app was quietly depending on, with no way to warn anyone. `/api/notices` carries platform-authored notices (public — it names no app and no user, same reasoning as `/api/info`), and `/api/apps/:slug/notices` carries app-scoped ones behind `requireAuth` + `requireAppAccess`. Seeded with the v2.39.0 cookie change.

125 → 204 tests.

## 2.39.0 — Hosted apps no longer receive the visitor's platform session cookie.

Caddy forwards `Cookie` verbatim to app containers. Apps are mounted same-origin at `/<slug>` and `cc_token` is `path=/`, so a logged-in visitor's browser attached the platform session to every request into the app — and `cc_token` is also accepted as a bearer, because `authedUser` runs the same `sessionUserFor()` on the cookie and on `Authorization`. An app's own backend could therefore read the session straight off the request and call the platform API as whoever visited.

Verified end-to-end on a seeded instance before the fix. A lifted `platform_admin` session reached `/api/settings`, `/api/users`, `/api/audit` and the RBAC matrix — everything v2.38.0 had just locked down — because the token *is* the authority; the role checks were working correctly and simply saw an admin. Worse, `?reveal=true` returned the **decrypted** env vars of an app the admin was not assigned to, since `platform_admin` bypasses `requireAppUser` entirely. `auditMiddleware` runs on `PUT`/`DELETE` only, so none of the reads produced a log line, and the session stays valid 24 hours.

The chain: deploy an app (self-service, so any user), get a privileged user to open it once, read their session out of your own request logs, then drain every secret on the box silently.

Fixed at delivery. Every `handle` block that proxies to an app now strips `cc_token` from the `Cookie` header before forwarding — by name, never the whole header, since apps set their own cookies and a blanket removal would sign every user out of every hosted app. The `(^|;\s*)` anchor matters: without it an app cookie named `my_cc_token` would match on the substring and be corrupted.

Applied **unconditionally**, unlike the existing `X-AppCrane-*` strip which sits behind `if (!isHeadless)`. Headless apps skip `forward_auth` and get no identity headers, but a browser still sends them the cookie — they need this most.

Nothing legitimate loses access. Apps read identity from the `X-AppCrane-*` headers, and an app's server reaches the platform over `/api/service` with its own `APPCRANE_SERVICE_TOKEN` off the docker bridge. The documented `fetch('/api/me')` pattern is untouched: that request matches the platform catch-all, not an app block, so the browser still sends the cookie straight to AppCrane.

The rule lives in one module-scope function rather than being pasted per block — the same-origin redirect check and the identity-header list have each already drifted between copies in this codebase.

Validated against real Caddy 2 (`caddy adapt`, exit 0), and the adapted JSON carries both directives as compiled `search_regexp` replacements on all 13 emission points — the rule is proven, not assumed.

**A global role no longer grants access to app data or secrets.** `requireAppUser` — the gate on env vars, backup/restore/copy-data, health config, notifications and webhooks — returned early for `platform_admin` with no assignment check at all. That is what escalated a lifted admin session into every app's plaintext secrets, and it contradicted the rule `envVars.js` states at the top of its own file. Assignment is authoritative for every role now. A platform admin who needs access assigns themselves through the normal member-management route, which is admin-gated and audited — turning a silent, invisible capability into a deliberate, attributable act.

That change also fixes a bug underneath it: the `admin` branch used to run *before* the assignment lookup, so an admin who did exactly what the error message said — assign themselves — stayed blocked. The advice was unreachable. Checking membership first makes it true for both admin tiers.

18 new tests (107 → 125). The Caddy tests assert per-`handle`-block rather than "the string appears somewhere", cover headless and auth-bypass routes, and pin the header semantics: token removed in every position, app cookies preserved byte-for-byte, `my_cc_token` untouched, no leading or doubled separator. The authz tests pin every role/assignment combination plus the *shape* of the fix — that no role check runs ahead of the membership lookup. Both sets are mutation-tested: removing the cookie strip from one block fails and names the exposed routes; reinstating the `platform_admin` early return fails two tests.

## 2.38.0 — Platform config is admin-only, SSO redirect validated server-side, and the login page works again.

A second credentialed WAS scan reported platform config readable by a low-privilege account, plus the open redirect from the previous round. Triage found the scan was right on both, and three things it could not see.

**Settings are gated per key, and the gate is now real.** `GET /api/settings` had no auth middleware of its own — the 401 an anonymous caller saw came from an unrelated router (`logs.js` does a pathless `router.use(requireAuth)` and was mounted at the broader `/api` earlier in the chain). Reorder two lines in `server/index.js` and every setting was public. What auth it did get was `requireAuth`, meaning any user or any `dhk_user_*` key.

Protection was a 6-key denylist, and it had already drifted: `backup_s3_secret_enc` (the encrypted S3 backup secret) and `backup_s3_access_key_id` (an AWS access key ID in cleartext) were added by a later feature and never denylisted. That is the failure mode of a denylist, so it is now an allowlist — `server/utils/settingsVisibility.js` classifies each key PUBLIC / AUTHED / ADMIN, **defaulting to ADMIN**. A setting added by a future feature that forgets this file becomes unreadable rather than public.

Bulk `GET /api/settings`, `role-permissions/catalog` (the whole RBAC matrix) and `github-service/config` are platform-admin only. No longer readable by an ordinary user: the S3 backup credentials, `saml_idp_sso_url`, `graph_tenant_id`, `graph_client_id`, `oidc_client_id`, `oidc_discovery_url`, `tls_cert_file`, `tls_key_file`, `scim_enabled`, `credcheck_state`, and the `github_mcp_*` / `platform_embed_*` / `email_from_*` families.

**An SSO-only instance was still showing the password form.** Three routers — `userMcpKeys`, `logs`, `monitoring` — are each mounted at the bare `/api` with a pathless `requireAuth`, so from their mount point down they 401 any `/api/*` request that reaches them, theirs or not. That swallowed the login page's deliberately credential-less fetch of `auth_sso_only`; `Login.tsx` read `value` off the 401 body, got `undefined`, and left `ssoOnly` false. Confirmed against unmodified v2.37.0. `/api/settings` now mounts ahead of all three — safe only because it finally carries its own auth.

**Open redirect, server side.** v2.35.0 fixed the SPA; `/api/auth/oidc/start` still had the same weak check (`startsWith('/') && !startsWith('//')`), which accepts `/\evil.example` and `/%09/evil.example` — Express percent-decodes query values, so `%09` arrives as a real tab and browsers strip it back into `//evil.example`. SAML `start` validated nothing at all. Both now use a shared `server/utils/safeRedirect.js`, and both callbacks re-validate rather than trusting that `start` sanitised anything — SAML RelayState is browser-POSTed and may never have passed through `start`.

**SSO deep-link redirect works again.** Both callbacks gated the forward on `startsWith('http')` — inverted. On the OIDC side `start` could only ever produce a `/`-prefixed value, so the redirect was always dropped and every SSO login landed on the default page. On the SAML side it did the opposite, forwarding exactly the absolute cross-origin values a browser can POST; `forwardToLaunch` was the only thing catching those. Two bugs masking each other: fixing the feature naively would have shipped the open redirect.

**And the bug that fix introduced.** Restoring the forward moved the SPA onto a branch that skips its token scrub, leaving `?oidc_token=` — a live platform bearer — in the URL during a deep-link navigation. With `Referrer-Policy: strict-origin-when-cross-origin` a same-origin hop sends the full URL as Referer, and tenant apps are served same-origin at `/<slug>`, so any app named in a deep link would have received other users' session tokens in its access logs. The scrub now happens before the branch, in `Login.tsx` and `AdminApp.tsx`, and a test asserts it in the built bundle — not just the source, since `docs/admin-app/` is what production serves.

`forwardToLaunch` also held a fourth copy of the same-origin rule, drifted to reject a literal space, so a legitimate `?redirect=/apps/foo?q=a+b` was dropped and logged as an attack. All four copies now share one module.

43 new tests (64 → 107).

## 2.37.0 — Deleted the nine dead pre-SPA pages; the CSP carve-out is down to one file.

v2.36.1 had to widen the `unsafe-inline` carve-out to the whole `docs/` tree because nine pre-SPA pages still carried inline `<script>`. Those pages were already unreachable — `/dashboard`, `/applications`, `/settings`, `/users-page`, `/app`, `/coder`, `/audit-page`, `/enhancements-page` and `/dashboard-new` have all served the React SPA for several releases — but `express.static` kept exposing them at their literal `/docs/<name>.html` URL. Unrouted, unmaintained, and holding the security policy hostage.

They're gone. The carve-out is now a one-entry set (`LEGACY_INLINE_PAGES`), and the default **flips back to secure**: any HTML added under `docs/` from here on is served with `script-src 'self'`. `guide.html` moved onto the hardened policy as part of the change.

`login.html` is the one exception left. It's ~2600 lines of inline script and it's the auth fallback, so blanking it would lock people out of the box. Retiring it means extracting that script to a file — deliberately not bundled into a release that's otherwise deletions.

Two new tests: one asserts the carve-out stays a single named page (adding to it fails CI), one asserts the nine deleted pages stay deleted. Verified live — `guide.html` and the SPA shell now serve `script-src 'self'`, `login.html` keeps the exception, all nine URLs return 404.

Also: the README now states the positioning directly. Tools for AI-built internal apps split along two axes — vendor-hosted vs self-hosted, governed vs ungoverned — and the self-hosted-and-governed corner is empty. Lovable, Replit, Retool and Superblocks have the SSO and audit but run your app data on their multi-tenant cloud; Coolify, Dokku, CapRover and Dokploy give you the infrastructure and no governance at all. The README says which one AppCrane is, cites why the gap matters now (Anthropic's Claude Code study: "operating software" 14% → 21% of sessions; 2026 Verizon DBIR: shadow-AI detections up 4×, source code the most-submitted data type), and states plainly where Coolify is the better choice.

## 2.36.1 — v2.36.0's carve-out covered one page; nine others needed it.

A deeper audit — prompted by asking the obvious question, "are you *sure* nothing else has inline script?" — found the v2.36.0 check had been shallow. It inspected **2** HTML files. The static routes actually serve **15**, and ten of them carry inline `<script>`: `dashboard.html`, `applications.html`, `settings.html`, `users-page.html`, `app.html`, `coder.html`, `audit-page.html`, `enhancements-page.html`, `dashboard-new.html` and `login.html`. Five also use inline `on*=` handlers — 23 in `app.html`, 14 in `dashboard.html`.

These are pre-SPA pages that nothing routes to any more (`/dashboard`, `/applications` and friends all serve the SPA shell), but `express.static` still exposes them at their literal `/docs/<name>.html` URL — so under v2.36.0's policy they would have rendered blank.

The carve-out now covers all of them, and it **allowlists the SPA shell** rather than denylisting known-bad filenames: anything under `docs/` that isn't the built SPA gets the legacy policy. A legacy page added later therefore fails safe — it keeps working — instead of breaking silently in production. The SPA itself, which is what users actually load, keeps the hardened policy.

The test that missed this now **enumerates** the static trees instead of naming files, checks inline handlers and `javascript:` URLs as well as `<script>` blocks, and asserts the allowlist shape. It reported all ten offenders on its first run.

Worth noting these ten files appear to be dead. Deleting them would let the carve-out and the weaker policy disappear entirely — a good follow-up, but a bigger call than a header fix.

## 2.36.0 — `script-src` drops `'unsafe-inline'`. The CSP now actually stops XSS.

The scan's "Permissive Content Security Policy" finding (25 instances) was pointing at `script-src 'self' 'unsafe-inline'`. With `'unsafe-inline'` present a CSP gives close to no XSS protection — injected markup executes exactly as readily as first-party code. This was deferred from v2.35.1 as needing a proper audit rather than a blind edit; that audit is done.

**Nothing the policy covers uses inline script.** The admin SPA's shell loads a single external module, `raiseme.html` has no `<script>` at all, and the setup/crash pages generated in `index.js` are style-only. So the directive came out at no cost.

**One page genuinely needs it**, and it's legacy: `docs/login.html` carries ~2,600 lines of inline script and predates the SPA. Since v2.33.0 both `/login` and `/portal` forward to the SPA, leaving it reachable only at `/login-legacy` — so rather than hold the platform's CSP hostage to it, it gets its own `LEGACY_LOGIN_CSP`. Both paths that serve it are covered: the embed branch and the static `/docs` route, either of which would have blanked the page under the hardened policy. When `/login-legacy` is eventually deleted, the constant goes with it.

**`style-src` keeps `'unsafe-inline'` on purpose.** The React codebase uses `style={{…}}` throughout; removing it means refactoring every inline style or hashing each one, and blocking inline *styles* is worth a small fraction of blocking inline *scripts*. A partial win isn't worth breaking the UI, and a test documents the choice so it reads as deliberate.

`test/csp-policy.test.js` enforces both halves — the policy stays hardened, *and* the pages it covers stay free of inline scripts and inline event handlers. Adding an inline `<script>` to the SPA now fails in CI instead of silently blanking the app in production.

## 2.35.1 — `no-store` on API responses. I was wrong that the rest of the scan was noise.

Having called the remaining Low/Info findings "likely proxied-app noise", reading them turned up one that wasn't: **`/api/me` was served with no `Cache-Control` at all**. It returns the caller's id, name, email and role. HTML got `no-store` via `sendHtml()` and SSE routes set their own, but ordinary JSON responses got nothing — so an identity payload was cacheable by the browser and by any intermediary sitting in front of it. The same applied to `/api/apps` and every other authenticated read.

API responses now default to `no-store`, set before the routes so a handler can still override (SSE keeps `no-cache`). **App icons are deliberately exempt** — public, unchanging, and fetched once per app for every sidebar and tile render; making them uncacheable would be a pure regression for no privacy gain.

The other two were as expected. **PII Fields (6)** are all the login form's `<input placeholder="Email or username">` — the plugin's own Solution field is blank; nothing to fix. **CSP `Report-To` (17)** wants a live reporting endpoint to collect violations; worth having eventually, not worth a stub that reports nowhere.

One genuine item found while reading and deliberately **not** fixed here: the SPA's CSP carries `script-src 'self' 'unsafe-inline'`, which is what the "Permissive Content Security Policy" finding (25) is pointing at. `'unsafe-inline'` materially weakens XSS protection, but removing it needs the inline-script usage audited and probably a nonce — too big to land blind alongside a header fix.

## 2.35.0 — Open redirect fixed, plus baseline security headers for every proxied app.

From a credentialed Tenable WAS scan of the production host. Of 3 High / 30 Medium / 114 Low, the genuinely exploitable finding was a **Medium** — all three Highs were false positives (they flagged AppCrane's own tool descriptions as "tool poisoning" and `appcrane_get_guide`'s playbook as "prompt injection"; the "unauthenticated MCP server" was a credentialed scanner mistaking its own session for none — every MCP route is `requireAuth`).

**Open redirect (CWE-601), proven by the scanner.** It requested `/login?redirect=//3dc5a9db-….com` and the browser landed on that host. Three call sites gated on `redirect.startsWith('/')`, which is not a same-origin test: `//attacker.com` starts with a slash and is an absolute cross-origin URL. A phishing link on the real login page could therefore bounce a victim off-platform. New `isSafeRedirect()` rejects `//`, `/\`, absolute URLs, schemes and control characters, and is applied at all three sites; `forwardToLaunch` drops an unsafe target server-side too, so the hostile value never reaches the next URL. A test pins the exact payload from the scan.

**Baseline security headers at the Caddy site level.** AppCrane's own `/api/*` responses already carried HSTS and nosniff; **proxied app** responses carried neither, because Caddy passed the container's headers through untouched. One site-level block now defaults `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, `X-Permitted-Cross-Domain-Policies` and `Permissions-Policy`, and strips the `X-Powered-By`/`Server` banners the app containers leak — roughly 124 findings from one place. Set with `?` (set-if-absent) so an app that deliberately sets its own value keeps it.

**`X-Frame-Options` is deliberately NOT set globally**, though it would clear another 25 findings: a blanket `SAMEORIGIN` would break the per-app iframe embedding added in v2.24.5/v2.25.0. `frame-ancestors` supersedes it and is emitted per app. A test asserts its absence so nobody "fixes" the scanner finding by breaking a shipped feature.

**RFC 9116 `security.txt`** at `/.well-known/security.txt` — the documented channel for reporting a vulnerability. The contact is configurable (`security_contact` setting or `SECURITY_CONTACT` env), never hardcoded, since AppCrane is self-hosted by whoever runs it; unset serves 404, because a security.txt pointing at an unread address is worse than none. The value is validated as a single-line `mailto:`/`https:`/`tel:` URI so it can't forge extra directives, and `Expires` rolls a year ahead of each request so the file can't go stale.

Also investigated and closed without change: the **v1 UUID** finding is not AppCrane's — the repo has no uuid dependency and uses only `crypto.randomUUID()` (v4), for temp directory names, never tokens.

**Also in this release — Launch picker search and sort.** A search box filters on name, builder, owner email, slug *and* category, because people look for an app by whatever they remember about it, not just its title. A Name/Category toggle switches between one flat grid and a grid per category; the choice persists in `localStorage`, since sort order is a standing preference rather than a per-visit decision.

## 2.34.0 — **Launch** in the left nav.

`/launch` became the post-login landing page in v2.33.0, but it had no nav entry — you could only get there by clicking an individual app, or by knowing that `/` happens to redirect there. Navigating anywhere else left no way back to the picker short of editing the URL. It now leads the sidebar, above Dashboard, with a new 2×2 grid icon: the conventional launcher glyph, and a deliberate contrast with Dashboard's uneven bento rectangles sitting directly beneath it.

`NavLink` matches descendants, so the entry stays highlighted while you're inside an app at `/launch/<slug>` rather than un-highlighting the moment you open something.

## 2.33.0 — The tile picker is now the home screen.

`/` and unknown routes already landed on `/launch`, so the picker was *almost* home — but signing in didn't go there. Both SSO paths defaulted to `/applications`, and the server bounced `/login` and `/portal` to the same place, so after authenticating you arrived at the Manage table rather than the apps you can open. Three entry points, two destinations, none of them the picker.

All of them now land on `/launch`. It already rendered the SPA's `<Login>` when unauthenticated exactly as `/applications` did, so this changes only where you arrive *after* authenticating.

One interaction had to move with it: v2.24.5 put the per-app frame-ancestors headers on `/applications` because that was where `/login` bounced. With sign-in landing on `/launch`, that route now uses `sendAdminSpa` too — otherwise the in-iframe SSO step this platform supports would have started coming up blank again. The SPA's redirect loop-guard also learned `launch`, so `?redirect=/launch` no longer triggers a pointless extra navigation to the page already rendering.

## 2.32.1 — A ⋯ menu on each picker tile, and a sandbox-only app no longer opens a dead URL.

Each tile gets a ⋯ control revealing **version** (production and sandbox, whichever exist), **builder** (the app's owner, email on hover), and **open in a new tab** — the last pointing at the env a click would actually land on, so the menu can't offer a URL the frame wouldn't use. The control is a sibling of the tile button rather than a child (nesting interactive elements is invalid), which is what `.launcher-tile-cell` was already built for. It appears on hover to keep a wall of tiles calm, but stays visible on keyboard focus and while its own menu is open; the menu closes on outside click or Escape, and those listeners are only registered while a menu is actually open.

**Fixed while answering "are you showing production only?"** — no, and the check surfaced a real defect. `buildStage` chose the env purely on health (`healthy`), but health reads `unknown` for any app without a health-check row, which is the common case. So an app live *only in sandbox* scored `unknown` on both sides, fell through to production, and opened a URL with nothing behind it. Deployment presence now decides first and health only breaks ties: production is preferred, with sandbox used when production has no live deployment at all, or when production is failing while sandbox passes. TypeScript caught the missing `deploy.status` on `AppRow` in the process.

## 2.32.0 — With nothing open, `/launch` now shows the apps you can open as tiles.

The empty state was a rocket glyph and "Pick an app from the sidebar" — which assumes you know the sidebar holds apps, and gives someone with exactly one app nothing to click. It now renders that user's openable apps as a tile grid, so the empty state *is* the picker. Clicking a tile opens it exactly as the sidebar does (both go through the same `onSelect` → `/launch/<slug>`).

- Reuses the `.launcher-*` styles orphaned when the standalone Launcher merged into the nav in v2.13.0 — the CSS outlived its component, so this matches the established look instead of inventing a second one, and puts dead CSS back to work.
- Apps come from `/api/apps`, which is already role-filtered server-side, so the grid shows exactly what this user may open with no client-side filtering to get wrong.
- Only apps with a **live** deployment in either env are shown — a tile that can only 503 is worse than no tile. Apps exist but none are live, and the message says so rather than implying you have nothing.
- Renders nothing while loading, so someone with plenty of apps never sees "no apps" flash first.
- New `.lstage-picker` variant top-aligns and scrolls (the shared `.lstage-empty` centres a small block, which is wrong for a grid) and caps width so tiles stay a readable size on wide displays.

## 2.31.2 — The sandbox version pill showed a stale number that changed when you clicked it.

The app topbar renders the production and sandbox version pills side by side, but only the **active** env's version was ever refreshed against the running container. Both start from the deploy *record* (`app.<env>.deploy.version` — what AppCrane last recorded shipping), which diverges from reality after a rollback, a restart onto an older image, or a partly-failed deploy. So the inactive pill kept showing the stale record until you clicked its tab, at which point the probe finally ran and the number changed in front of you — the UI appearing to contradict itself rather than catch up.

Both envs are now probed on open, on env switch, and on refresh, so each pill reflects what its container is actually serving from the first render. Two independent copies of the same defect are fixed — `AppFrame.tsx` and the frame effect in `Applications.tsx`; the app-list `fetchVersions` already did this correctly. An env that isn't deployed or isn't answering keeps its recorded value rather than blanking a readable pill, and both probes carry a cancellation guard.

## 2.31.1 — Stop leaking the GitHub service-account identity to app owners.

An app owner reporting a failed push was able to quote `github GET /repos/<service-account>/AMC_<slug> → 401: Bad credentials` verbatim. That string came straight out of `githubService.apiFetch`, and MCP tool errors propagate through `callTool` to the caller's agent — so every owner of every managed app could read the platform's privileged GitHub identity, the internal `AMC_*` naming convention, and the live health of the shared credential, out of a single failed operation.

Nothing secret was exposed — no token value — but it contradicts the managed-app premise ("the end user never sees github.com") and names the exact account an attacker would target. Four messages carried it: the generic `apiFetch` error, `FILE_NOT_FOUND`, `REPO_EXISTS` (including an `existing: "<owner>/<repo>"` field echoed in the response body), `REPO_CREATE_FORBIDDEN` (three times), and `REPO_NOT_FOUND`.

Thrown messages are now owner-safe and *more* actionable — a 401 says the platform credential was rejected, that nothing on the owner's side can fix it, and that a platform admin should refresh it under Settings → GitHub. The full path and upstream text go to the server log and to `err.detail`, which is never returned. Covered by `test/github-error-redaction.test.js`, which asserts the account name cannot appear in a thrown message while still surviving on `detail` for operators.

**Still exposed, deliberately not changed here:** `appcrane_get_app` returns `config.github_url`, which for a managed app is `https://github.com/<service-account>/AMC_<slug>`, and `appcrane_create_managed_app` returns `repo.html_url` by documented design. Masking those changes a documented response shape that onboarding agents rely on — worth a decision rather than a silent change.

## 2.31.0 — "CPU — Last 7 Days" on the dashboard, per app, sandbox + production combined.

The same shape as the visitors chart, answering the other question that matters on a small host: *which app is burning the box?* When one workload saturates the cores, Caddy gets nothing and every app goes dark — so "which app is expensive" deserves the same visibility as "which app has users".

No new collection was needed: `metricsSampler` has been recording per-app, per-env CPU every 5 minutes with 7-day retention since v2.21.8 (`metrics_history`), and nothing on the dashboard ever surfaced it. The window matches exactly what is retained.

- New `GET /api/dashboard/app-cpu` (admin), shaped identically to `/api/dashboard/app-activity` so it reuses the existing chart.
- **Sandbox and production are summed, not averaged** — an app's cost to the box is what both containers burn together, and averaging would halve an app whose sandbox sits idle, which is backwards for spotting a hog. Aggregation is average-per-env-per-day, then summed across envs.
- Apps are sorted busiest-first so legend colours track the lines worth reading, and apps with no samples are omitted rather than drawn as flat zero lines.
- Values keep one decimal, and the axis does too when the whole series is sub-integer — otherwise a fleet of quiet 0.4% apps renders as a row of zeroes.
- `TrendChart` gained optional `emptyText` and `fmt` props instead of being copied.

## 2.30.2 — The real cause of the six-hour CI hang: a test, not the product.

2.30.1 fixed a genuine socket leak in the MCP test, but the hang survived it. `--test-timeout` (added in the same release) then named the culprit: `update-snapshot.test.js`, timing out with **every assertion passing**.

The test simulated "snapshot target can't be created" by pointing `DATA_DIR` at `/proc/nonexistent-cannot-create`. That path doesn't exist on macOS, so it failed fast locally — but on Linux, `mkdirSync(..., { recursive: true })` beneath `/proc` **never returns**. Reproduced in a `node:22` container and isolated to that one call: `existsSync` returned in 0 ms, the loop around it exited in 0 iterations, and `mkdirSync` had to be killed. The product code was never involved.

The unwritable target is now a path rooted *inside a regular file*, which fails `ENOTDIR` immediately on every OS and regardless of whether the process runs as root, and `DATA_DIR` is restored via `t.after()` so a failing assertion can't leak it into the next test. Verified 34/34 on Linux in 6.8 s — the same environment that previously hung for six hours — and unchanged on macOS.

Lesson worth keeping: never simulate "this path can't be written" with a kernel-virtual filesystem.

## 2.30.1 — CI was broken by the gates added in 2.27.0; both are fixed.

Neither failure was a real finding — both were defects in the checks themselves, which is the worse kind: a red X that looks like a vulnerability, and a gate that could never gate.

- **Semgrep gate never ran a scan.** It invoked `semgrep ci --severity=ERROR`, but `--severity` belongs to `semgrep scan`, not `semgrep ci` — so every run since 2.27.0 died on argument parsing with exit 2. The gate now parses the SARIF the preceding step already produces: deterministic, no second scan (halving the job), and it judges exactly what gets uploaded to the Security tab. Verified locally against warnings-only (passes), one ERROR (fails, with a file/line annotation) and a missing SARIF (fails — no scan means nothing was verified).
- **`npm test` hung in CI until GitHub's 6-hour ceiling.** `fetch` (undici) pools keep-alive sockets and `server.close()` only stops *new* connections, so the MCP protocol test's listener never released — every test passing, the process never exiting. It drained locally and didn't on CI. Sockets are now dropped explicitly and the server unref'd.
- Defence in depth for both: `timeout-minutes: 10` on the watchdog job and `--test-timeout=120000` on the suite, so a future hang fails in minutes rather than silently consuming a six-hour run.

## 2.30.0 — Snapshots now protect the upgrade that delivers them.

v2.27.0 snapshotted the database and `.env` inside `/api/self-update` — but that handler runs the code **already running**, so a box on an older build pulls the new one without ever executing the new snapshot logic. The first upgrade onto a build with the feature was precisely the one it couldn't protect, which is the upgrade most worth protecting.

The fix follows from where the risk actually is. `git reset --hard` doesn't touch your data at all: `data/` and `.env` are gitignored, so the pull leaves them alone. What mutates the database is the **migrations applied on first boot of the new code** — and that is new code. So `initDb()` now snapshots before applying migrations. That covers the delivering upgrade, and also covers paths that skip `/api/self-update` entirely: a manual `git pull`, a container rebuild, a restore onto a newer build. Gated on migrations actually being pending, so ordinary restarts don't accumulate snapshots; the manifest records `reason` (`pre-migration` / `pre-update`) and which migrations were pending.

Two bugs found while testing it, both in v2.27.0 code:
- **Snapshot ids are second-resolution**, so two snapshots in the same second shared a directory — and since `VACUUM INTO` refuses to overwrite, the second silently kept the *first* one's database. Ids are now uniquified.
- **A snapshot whose database copy failed still reported `ok: true`**, telling an operator they had a restore point that contained no database. It now reports `ok: false` with the reason. A snapshot that isn't a restore point must not claim to be one.

## 2.29.2 — Two supply-chain / injection hardenings found by a squash security review.

- **All 14 GitHub Action references pinned to full commit SHAs** (tag kept as a trailing comment so upgrades stay reviewable). Mutable tags were the #1 supply-chain primitive of 2025–26: `tj-actions/changed-files` had every tag v1–v45 retargeted to a malicious commit, and the `trivy-action` compromise force-pushed 76 of 77 tags. Tag repointing is invisible in a diff and, for free-tier orgs, isn't even in the audit log. This was an awkward gap next to v2.26.0's SBOM + provenance work — attesting our own artifacts while trusting eight movable third-party refs.
- **`preflightCheck.js` no longer interpolates a path into a shell string.** `test -e "${absPath}"` became `sh -c 'test -e "$1"' sh <path>` — the script is constant and the path arrives as a positional parameter. It was not exploitable: `preflightEntryCheck` rejects `[;&|<>$\`]` and the whitespace split blocks newlines, so only `"` could get through and that merely adds an argument to `test`. But the safety lived in a denylist two functions upstream rather than at the call site, which stops holding the moment that regex is relaxed or another caller reaches the helper directly — and unescaped input in a shell string is the single bug class behind most 2026 self-hosted-PaaS RCEs.

Review coverage, for the record: squash `security_domains`, plus taint analysis for `command-exec`, `ssrf-net` and `execFileSync` (no flows), plus manual triage of all 16 shell/exec call sites. Everything else was already sound — `shellQuote()` is the canonical POSIX escape, agent session ids are regex-validated before reaching a shell, `dockerfileGen` uses `JSON.stringify`, and git invocations pass argv arrays rather than shell strings.

## 2.29.1 — Self-review of 2.26–2.29 with fresh eyes; seven fixes, all in code shipped this session.

- **Self-update reported failure on a successful upgrade.** The `logAudit` call in `/api/self-update` sat unguarded *after* `git reset --hard` and `npm install`. A throw there jumped to the catch, answered `500 UPDATE_FAILED`, and skipped the process exit — leaving new code on disk, old code in memory, no restart, and an operator told the upgrade failed when it had actually applied. Now wrapped: an audit write is never worth inverting the outcome of a completed upgrade.
- **Snapshots could land where the manifest didn't point.** `updateSnapshot.dataDir()` fell back to `process.cwd()/data` while `selfUpdateDataDir()` used a module-relative path; with `DATA_DIR` unset and a cwd other than the repo root they diverged silently, discovered only at restore time. Both now resolve identically.
- **Audit pagination counted the whole table.** `total` ignored `?app=`, `?action=` and `?actor=`, so filtered queries advertised pages that don't exist. It now carries the same `WHERE`.
- **Fail-closed auditing only covered agents.** `APPCRANE_AUDIT_REQUIRED=1` refused to proceed on MCP but the REST middleware swallowed every audit error — a guaranteed trail for agent actions, best-effort for human ones. REST now reports `500 AUDIT_UNAVAILABLE` under the flag, with a message stating plainly that the action may already have applied and was *not* rolled back. It cannot promise otherwise: the hook runs after the handler, so honest reporting is the only thing on offer.
- Snapshot directories are `0700` (the `.env` copy was already `0600`, but the listing shouldn't be enumerable). Dead no-op ternary removed from MCP version negotiation. Protocol version negotiated once per request instead of three times, so the header and handshake can't drift.

## 2.29.0 — MCP protocol brought up to date, by negotiation rather than cutover. The server answered `initialize` with a hardcoded `2024-11-05` — the original revision, four behind current. `2026-07-28` is a breaking revision: it drops the `initialize` handshake and `Mcp-Session-Id` entirely (the protocol is stateless), adds a mandatory `server/discover`, and removes `ping`. AppCrane now **negotiates per request** — `params.protocolVersion`, `_meta['io.modelcontextprotocol/protocolVersion']`, or the `MCP-Protocol-Version` header — supporting `2024-11-05` through `2026-07-28`, echoing the agreed revision in a response header, and serving `server/discover` for new clients while `initialize` and `ping` keep answering for old ones. A client that states no version gets exactly what it got before. A hard flip would have disconnected every long-lived agent pointed at the instance, which for a self-hosted platform means cutting off work already in flight; both shapes are correct simultaneously because AppCrane's surface is tools-only, with no sessions, subscriptions, sampling or roots — which is where the breaking changes actually bite. Covered by `test/mcp-protocol.test.js` (31/31 suite green).
## 2.28.0 — Agent action audit trail, and a plaintext-secret leak in the audit log.

**Secrets were being written to `audit_log` in plaintext.** `auditMcpCall` stringified MCP arguments verbatim, so `appcrane_set_secret({value})`, `appcrane_create_app({github_token})` and `appcrane_set_app_meta({github_token})` stored the credential in the clear — quietly undoing the AES-256-GCM encryption those same values get everywhere else, and making the audit log the softest place on the box to steal a credential from. New `redactAuditArgs()` masks by key *name* (`…_token`, `…secret`, `password`, `value`, `credential`, `old_key`, …), records size rather than bytes so "rotated" stays distinguishable from "cleared", masks nested/array-nested values, and truncates oversized strings so a file push can't write megabytes per call into SQLite. The REST audit middleware now uses it too, replacing a hand-maintained `delete` list whose own comment warned it "MUST include any future secret-bearing keys" — a rule that fails silently and permanently the first time someone forgets.

**Agent vs human attribution.** `audit_log.actor_kind` (migration 070, backfilled from `users.kind`, denormalized so the trail stays true if a user is later deleted or reclassified) records whether an action came from an AI agent or a person. `GET /api/audit?actor=agent|human` filters on it and the response carries an actor breakdown. With most platform work now arriving over MCP, "what did the agents do here" was previously unanswerable — it's the question auditors and incident responders ask, GitHub's audit log added the same distinction as `actor_is_agent`, and OWASP's Agentic Top 10 (ASI05) asks for every agent-executed command to be attributable.

Covered by `test/audit-redact.test.js` and `test/audit-actor.test.js` (23/23 suite green).

## 2.27.0 — Upgrade safety + a per-app authorization gate, and the three real access-control bugs the gate found.

**Pre-update data snapshots.** `/api/self-update` already rolled CODE back when a new version wouldn't boot (`previous_sha`), but that does nothing for DATA — the canonical failure in this category is an update that damages persistent state (Coolify's update path once clobbered the key that made every encrypted value readable). AppCrane now snapshots the SQLite database (`VACUUM INTO`, a consistent point-in-time copy of the live DB) and `.env` (which holds `ENCRYPTION_KEY`) into `DATA_DIR/update-snapshots/<ts>/` immediately before `git reset --hard`. Last 5 retained. The API response reports the restore point — and says so explicitly when a snapshot could NOT be taken, so an operator is never left assuming one exists. Restore stays deliberately manual. Covered by `test/update-snapshot.test.js`.

**Per-app authorization watchdog** (`scripts/check-route-authz.mjs`, wired into CI with `--strict`). Every route taking an app identifier must prove the caller may access THAT app — via middleware, a file-level guard, or an in-handler check. Missing tenant scoping (IDOR) is one of the two bug classes behind the 2026 disclosure wave against comparable self-hosted PaaS products. Semgrep is now a real gate too: ERROR-severity findings fail the build instead of `continue-on-error`, and a `.semgrepignore` stops the minified SPA bundle generating false positives. The test suite now runs in CI.

**Three access-control fixes the watchdog surfaced on its first run:**
- `coder.js` `GET /:slug/session/:id` — verified the session belonged to the app but never that the *caller* could access it, so any authenticated user could read another app's coder transcript (its source-code conversation). Every sibling route already called `getApp()`; this one didn't.
- `ask.js` `GET /active/:appSlug` — no authentication at all; anyone could probe whether an app slug existed and had work running.
- `identity.js` `GET /app-updates/:slug` — a valid session proved who, not what they could see; users could read update history for apps they had no access to.
## 2.26.0 — Supply-chain artifacts for every tagged release. A new `release-supply-chain.yml` workflow generates a CycloneDX + SPDX SBOM of the **production** dependency tree, builds a reproducible `git archive` source tarball, signs it with **build provenance + an SBOM attestation** via sigstore keyless (GitHub artifact attestations — no long-lived signing key to steal), and attaches all of it plus `SHA256SUMS.txt` to the release. Answers the obvious question about the `git reset --hard origin/main` self-update path: verify with `gh attestation verify <archive> --repo gitayg/appCrane`. Also targets EU CRA Art. 14 (reporting obligations start 2026-09-11) and the CycloneDX ≥1.6 / SPDX ≥3.0 formats named by BSI TR-03183-2. The workflow passes every interpolated value through `env:` rather than inlining `${{ }}` into `run:`, and validates the ref charset — the same injection class being gated in CI next.
## 2.25.3 — Dashboard banner for failing platform credentials (platform_admin only). Closes the gap where a dead Microsoft Graph mail token can't email its own failure alert — the admin now sees it in the UI regardless. The 15-min credential checker records the error in `settings.credcheck_state`; new `GET /api/credentials/health` (platform_admin gated, deliberately NOT on the public `/api/info`) returns any currently-failing credential; a red banner in the admin layout surfaces it on every page for platform admins. Verified with a live server (platform_admin → failing list; user → 403; unauth → 401).
## 2.25.2 — Platform credential health checker. Every 15 minutes AppCrane probes its integration credentials — the Microsoft Graph mail client secret and the GitHub service-account PAT — and emails every platform admin when one stops working (expired/rotated/revoked). Probes skip cleanly when a credential isn't configured. State is tracked in `settings.credcheck_state` so it alerts on the transition to failing (not every tick), re-alerts at most once/day while still broken, and sends a recovery notice when it comes back. New `server/services/credentialChecker.js` + `probeGraph()`/`probeServiceAccount()`; started alongside the email worker. Verified locally (6/6: first-fail alert, dedup, 24h re-alert, recovery, skip-clears-state, no-admin safety).
## 2.25.1 — Email attachments. `POST /api/service/email` now accepts an `attachments` array (`[{ filename, content(base64), contentType? }]`, max 10 files / 3 MB total), threaded end-to-end: validated + stored on the queue row (migration 069), sent via Microsoft Graph (`fileAttachment` contentBytes) or SMTP/nodemailer, and cleared from the row once sent. Validation rejects non-base64 content, path-separator/`..` filenames, and over-count/over-size with a 400. Documented in the email + onboarding guides.
## 2.25.0 — Same-site iframe embedding on by default. Apps (and the in-iframe SSO login step) are now embeddable by any host under the platform's OWN registrable domain — the eTLD+1 of CRANE_DOMAIN, derived via the Public Suffix List so an apex domain yields `*.opswat.com`, never `*.com`. Emitted as a `frame-ancestors` allowlist merged into every app's Caddy block + the SPA login-render path, and merged with any per-app `frame_ancestors`. A platform admin can disable it or override the domain in Settings → Security → "App embedding" (`GET`/`PUT /api/settings/embed/config`). **Security-posture note for upgrades:** this ships enabled, so on upgrade every app becomes framable by its platform's own subdomains (a same-org trust boundary — clickjacking surface is limited to your own DNS; turn it off if you don't want it). The ordinary dashboard stays `SAMEORIGIN`. New dep: `psl`. Verified: default-on emits `*.<registrable>` on plain apps + login step, merges with per-app policy, honors the override, and off reverts to per-app-only
## 2.24.5 — SSO-gated apps can now be iframe-embedded. Setting an app's `frame_ancestors` already relaxed framing on the app's own responses, but the in-iframe SSO step (`/login` → `/applications` SPA render) still sent the global `X-Frame-Options: SAMEORIGIN`, so an unauthenticated embed came up blank. The per-app frame-ancestors treatment (drop XFO + emit `frame-ancestors`) — which previously lived only on the stranded `/login-legacy` handler — now also applies to the SPA login-render path, scoped to requests whose `redirect` targets an app an admin opted into embedding. The ordinary dashboard keeps `SAMEORIGIN`. Verified with a live server: embeddable-app redirect → no XFO + frame-ancestors; plain dashboard and non-opted-in redirects → SAMEORIGIN. Documented in the onboarding guide (Embedding an app in an iframe)
## 2.24.4 — AppCrane owns the custom-domain lifecycle: domain **redirect aliases**. When an app's custom domain changes (X→Y), the old domain is automatically kept alive as a 301 redirect to the new one (path+query preserved, TLS auto-provisioned) so already-sent login links and bookmarks don't break — no hand-edited Caddyfile. Aliases are owner/admin-managed via the 🌐 domain control or `POST`/`DELETE /api/apps/<slug>/domain-aliases`; MCP `appcrane_set_app_meta` auto-seeds on domain change too. New table `app_domain_aliases` (migration 068), Caddy emits `<alias> { redir https://<primary>{uri} permanent }` only when prod is live. Documented in the onboarding guide's Custom domains section
## 2.24.3 — Dashboard "Top apps" leaderboard now shows owner attribution ("by <owner>" under each app name), resolved from the app's owner in app_user_roles; the leaderboards endpoint returns owner_name/owner_email per app (LEFT JOIN so unowned apps still list)
## 2.24.2 — Document multitenancy in the agent onboarding guide (`appcrane_get_guide`): a "Per-tenant databases" section so app-building agents discover the per-tenant DB/storage/quota feature and wire it up automatically, instead of the user having to spell it out each time
## 2.24.1 — Remove the unused `public/index.html` marketing landing page: it isn't wired into the app (root `/` redirects to `/login`; no route or link points to it), so it was dead weight. `public/favicon.svg` and `public/raiseme.html` — the only served assets under `public/` — are untouched
## 2.24.0 — Per-tenant DB (multitenancy), phase 3: per-tenant file storage + quota. `appcrane-tenant` gains `tenantStorageDir`/`tenantFile` (a `storage/` dir per tenant, with basename-only filename safety), `tenantUsage`, `tenantQuotaBytes`, and `assertTenantQuota`. Apps cap usage with `"tenant_quota_mb": <n>` in deployhub.json → AppCrane injects `APPCRANE_TENANT_QUOTA_BYTES`; the quota covers DB + storage, and revoke already purges both. Adds a repo-level drift-guard test (`npm test`) that fails if the server and helper org-derivations ever diverge, plus storage/quota coverage in the example. Additive only — no AppCrane runtime/UI change, existing apps unaffected
## 2.23.0 — Per-tenant DB (multitenancy), phase 2: ship the `appcrane-tenant` helper (`packages/tenant`) so apps stop copying the snippet — `tenantDb(req)` / `tenantDbPath(req)` derive an isolated `/data/tenants/<org>/u<userId>/db.sqlite` from the signed identity headers, with better-sqlite3 as an optional peer dep (path-only usage is dependency-free). Adds a runnable `examples/multitenant-notes` app and unit tests. Also hardens the org derivation (server + helper) against a path-traversal edge case — an email like `a@..` now falls back to org `unknown` instead of escaping the tenant root. Additive only: no AppCrane runtime/UI change, existing apps unaffected (the package is isolated from AppCrane's install — root is not an npm workspace)
## 2.22.0 — Per-tenant DB (multitenancy), phase 1: apps opt in with `"multitenant": true` in deployhub.json and AppCrane gives each app-user an isolated SQLite DB on the persistent /data volume. Tenant = (org, user) where org is the email domain; files live at `/data/tenants/<org>/u<userId>/db.sqlite`. AppCrane injects `APPCRANE_TENANT_ROOT=/data/tenants` into multitenant containers, and purges a tenant's data dir when that user's app access is revoked (`appcrane_revoke_app_access`). Cooperative isolation model — the app derives the tenant path from the platform-signed identity headers it already receives (documented in README → Identity contract §4). Fully backward-compatible: existing apps need no changes, there is no user-facing UI change, and the upgrade is a single additive column (migration 067). Phase 2 (a published `@appcrane/tenant` helper) and phase 3 (per-tenant storage + quotas) to follow
## 2.21.49 — Repo hygiene: gitignore scip code-index artifacts (`*.typescript.scip`) and `.DS_Store` so they stop showing up as untracked (no runtime change)
## 2.21.48 — Document the `crane regenerate-key` platform_admin targeting + `--email` / `--user-id` flags in the in-app Docs → Operator CLI section and the README CLI reference
## 2.21.47 — Fix `crane regenerate-key`: it targeted `role='admin'` with a non-deterministic `LIMIT 1`, so it could regenerate a lower-privilege admin's key (or fail with "No admin user found") instead of the platform owner's. It now targets `role='platform_admin'` only, oldest-id first, and adds `--email <e>` / `--user-id <n>` to regenerate a specific account. Also fixed the root cause: `crane init` now seeds the bootstrap user as `platform_admin` (not `admin`) — role promotion is itself gated behind platform_admin, so a fresh box seeded as `admin` could never obtain one. Migration 066 promotes the lone bootstrap admin to platform_admin on already-deployed boxes that have no platform_admin (no-op otherwise)
## 2.21.46 — Document `crane config export` / `crane config import` in the in-app Docs → Operator CLI section, with a short "migrating settings between instances" note (re-encrypt-on-import, `OLD_ENCRYPTION_KEY`, why it's CLI-only)
## 2.21.45 — Config migration is CLI/API only again: removed the Settings → Migration UI tab (added in 2.21.44). Export/import stays available via `crane config export` / `crane config import` and the platform-admin `/api/config/{export,import}` endpoints — keeping this sensitive operation, and especially entering the source ENCRYPTION_KEY, off the web surface (it requires shell access to the box + the admin key)
## 2.21.44 — Config export/import is now in the UI too: Settings → Migration (platform-admin only) — export downloads the config file, and import takes the file + the source instance's ENCRYPTION_KEY (a masked field) and re-encrypts secrets with this instance's key, showing what was imported/re-encrypted and which one-way values to regenerate. Same platform-admin-gated endpoints as the CLI; the source key is used transiently and never stored
## 2.21.43 — `crane config export` / `crane config import`: migrate a whole instance's settings (including encrypted secrets) to another AppCrane in one command, instead of hand-dumping SQL. Export snapshots the settings table with secrets left as ciphertext (no plaintext on disk); import re-encrypts each secret with the TARGET instance's own key (decrypt-with-source-key → encrypt-with-target-key), so nothing is done by sharing encryption keys. Encrypted values are detected by their structure (not a hand-maintained key list), and one-way values like the SCIM token hash are reported to regenerate on the target. New GET /api/config/export + POST /api/config/import (platform-admin). Round-trip verified: a secret encrypted under key A is readable under key B after migration
## 2.21.42 — Installer validates manual TLS certs up front. If --tls-cert/--tls-key (or TLS_CERT_FILE/TLS_KEY_FILE) are passed, it now fails early with a clear message when a path is missing or only one of the pair is given — instead of silently writing the path into .env and leaving Caddy to fail later loading a nonexistent cert. Placing the certs remains the operator's step (the installer references the path, it doesn't fetch certs); this just turns a silent late failure into an upfront one
## 2.21.41 — Installer now makes manually-provided TLS certs readable by Caddy. When --tls-cert/--tls-key (or TLS_CERT_FILE/TLS_KEY_FILE) are passed, AppCrane writes `tls <cert> <key>` into the Caddyfile and Caddy reads those files as the `caddy` user — but a root-owned 600 cert/key (how they usually land) fails with a permission error and Caddy won't serve TLS. The installer now chowns them root:caddy at mode 640 (key stays non-world-readable) and makes the containing dir caddy-traversable. Verified in a container: the caddy user goes from "Permission denied" to reading the key
## 2.21.40 — Installer no longer crashes on a minimal image without `sudo`. `/etc/sudoers.d/` is created by the sudo package; on an image where sudo isn't preinstalled, writing the Caddy sudoers file failed and `set -e` aborted the whole install before Docker/systemd/crane-init ever ran. Now `sudo` is in the base packages and the directory is `mkdir -p`'d defensively. Found by running install.sh for real in a systemd Ubuntu 24.04 container — which also validated end-to-end that base packages, Node, Caddy, npm install, the encryption-key `.env`, the Docker health-gate, safe-boot startup, `/api/info`, and `crane init` (status → ready) all work
## 2.21.39 — Installer now grants a non-root AppCrane permission to reload Caddy (polkit rule). AppCrane's code runs bare `systemctl reload caddy` (not sudo); when the service runs as a non-root user, that hits polkit — "Interactive authentication required" — and the reload fails silently, so generated Caddy config never reaches the running proxy and apps get no X-AppCrane-* identity headers (visible as caddy_reload_status.ok=false in /api/info). The installer now drops /etc/polkit-1/rules.d/49-appcrane-caddy.rules allowing the run user to manage caddy.service only. Root installs are unaffected. (The existing NOPASSWD sudoers rule for manual `sudo systemctl reload caddy` stays.)
## 2.21.38 — Two installer fixes: (1) the "wait for the API" readiness probe now hits /api/info (public, and the declared health endpoint) instead of /api/health, which is auth-gated and always 401'd — so the probe silently timed out and proceeded blind on every install; now it actually confirms the API is up. (2) The mixed-Docker detection matches any docker-ce* package (e.g. docker-ce-rootless-extras left by an earlier get.docker.com run), not just an exact docker-ce, and prints the packages found plus the remove command
## 2.21.37 — Installer now auto-repairs the common Docker-won't-start causes instead of just reporting them: it strips a conflicting `hosts` key from /etc/docker/daemon.json (backing the file up) — the #1 cause of "no sockets found via socket activation" — warns on an invalid-JSON daemon.json, and detects a docker.io + docker-ce package conflict with the exact remove command. Combined with the socket-first start + reset-failed + daemon health-check from 2.21.36, a wedged Docker on a re-used box now self-heals rather than dead-ending the install
## 2.21.36 — Installer now guarantees the Docker daemon is actually running, not just installed. It brings Docker up socket-first (dockerd runs with -H fd:// and gets its listener from docker.socket — starting docker.service alone gives "no sockets found via socket activation"), clears any rate-limited failed state (systemctl reset-failed), and then verifies `docker version` responds before continuing — failing loudly with the likely causes (a "hosts" entry in daemon.json, or docker.io + docker-ce both installed) instead of proceeding to an AppCrane that can't start (its unit Requires=docker.service). Previously a present-but-wedged Docker slipped straight through to a dead service
## 2.21.35 — Installer's Caddy GPG-key import is now non-interactive (`gpg --dearmor --batch --yes`). A keyring file left by an earlier/partial run made gpg prompt "overwrite?" on /dev/tty, which fails with no TTY (piped SSH, CI, the documented curl-pipe) and broke the install with `curl: (23) Failure writing output` — so a re-run could never get past Caddy. Now idempotent
## 2.21.34 — Installer now boots AppCrane via scripts/safe-boot.sh, not `node server/index.js` directly. The v2.21.33 fix reconstructed the systemd unit from an old (pre-safe-boot) revision, so a fresh install would have lost self-update crash-recovery — safe-boot.sh is the out-of-process wrapper that git-resets to the previous SHA when a self-update crashes on boot (a migration can kill node before the in-process rollback runs). ExecStart now points at it, matching how existing hosts run
## 2.21.33 — Fixed a broken installer + rewrote the install docs. install.sh referenced scripts/upgrade-to-docker.sh, which a past "drop PM2" refactor deleted while leaving the call in place — so every fresh install ran Node/Caddy/clone/npm/.env and then exited 127 at the Docker/systemd step, never installing the service or running crane init (which is why fresh boxes kept needing manual systemd/Caddyfile/sudoers finishing). The Docker install + systemd unit are now inlined directly in install.sh (self-update was never affected). The README also now leads unmistakably with the one-command installer, documents the non-interactive form, and drops the old "Or manually" steps that omitted Caddy entirely and made hand-setup look mandatory
## 2.21.32 — Made AppCrane's source discoverable: package.json now carries `repository`, `homepage`, and `bugs` (pointing at the GitHub repo) plus `private: true`, so agents/tools that inspect the package — `npm view`, `npm repo`, or just reading package.json — find where it's distributed from instead of concluding there's no source. Added a "Distribution & updating" note to CLAUDE.md explaining the self-update-from-git-origin model (the README already had install steps; the pointers just weren't where tooling looks first)
## 2.21.31 — An explicit admin Caddy reload (POST /api/caddy/reload) now always actually reloads. The skip-if-unchanged optimization compares the generated config to the file on disk, which says nothing about what the running Caddy process has loaded — so a drifted process (started before a config feature existed, or after a silently-failed reload) could never be recovered through the API: every call just answered "unchanged: true" and did nothing. That's how a correct on-disk `copy_headers` never reached the live proxy, leaving apps with no X-AppCrane-* identity headers despite verify emitting them. Internal callers (deploy, app update) keep the optimization; pass ?force=0 to opt back into it
## 2.21.30 — Platform admins now see hidden apps in the sidebar too (previously filtered out for everyone), each marked with a small eye-off badge so it's clear the app is hidden from regular users. Non-platform-admins are unaffected — they still never receive hidden apps
## 2.21.29 — AppCrane's own notification emails now send as the app's name — a deploy or health alert for AgentClub arrives from "AgentClub <aimi@opswat.com>" instead of the generic shared-mailbox name. Deploy success/fail, health up/down, and the test notification each pass the app's name as the sender display name (the address stays platform-controlled, so apps still can't spoof the sender). Apps sending via /api/service/email already defaulted to their own name; only the platform's notifications were missing it
## 2.21.28 — New GET /api/directory endpoint apps can call for a people-picker / email autocomplete: returns { users: [{ name, email }] } for active users only — the IdP-synced corp directory, name+email only (no ids, roles, or attributes, unlike the admin-only /api/users). Same auth as /api/me (a proxied app frontend just `fetch('/api/directory')`; the cc_token cookie authenticates it), added to the app passthrough. Apps should cache it
## 2.21.27 — Secrets no longer leak into agent transcripts: `appcrane_get_secret` now returns MASKED values (is-set, length, a last-3-char preview, and a sha256 fingerprint — short values are fully masked), so checking config never puts a plaintext secret in the conversation. A new `appcrane_reveal_secret` returns the plaintext of ONE key on demand — explicit, single-key (never the whole env), and audit-logged — for the rare case a human needs the actual value. The old behavior (one call dumping every decrypted secret) is gone
## 2.21.26 — Inline edits on the Manage table now flash a brief green ✓ after a value is committed, so a save is visibly confirmed (complements the existing Esc-to-revert)
## 2.21.25 — Manage screen UX + accessibility overhaul: the table now reads as data, not a form — cells (name, description, RAM, CPU, images) show plain text and turn into an input only when clicked/activated (click-to-edit); per-app action bar collapses behind the row's expand toggle (one clean row per app instead of two); raised muted-text contrast to WCAG AA on dark; keyboard-accessible sortable headers (role/aria-sort/Enter-Space); visible focus rings on all controls; aria-labels on every inline input and icon button; Esc-to-revert / Enter-to-commit on name & description edits; a "showing N of M" count with a Clear-filters button and a friendlier empty state; a loading skeleton instead of a false "no apps" flash; responsive column-hiding by class instead of brittle positional nth-child; the emoji action glyphs are now crisp inline SVG icons (accent-tinted when a feature is configured); and a bulk multi-select — checkbox column + select-all, with a bar to set visibility/tag or delete across many apps at once
## 2.21.24 — Manage now has a sortable "Storage" column showing each app's total on-disk footprint (release checkouts + persistent /data, across sandbox + production) — the number that actually sums to host disk usage, so you can rank disk hogs at a glance. Backed by a new admin-only GET /api/dashboard/app-storage (one bulk scan). The per-env /data breakdown stays in the row drill-down
## 2.21.23 — Fixed promote for managed apps that ship a git-tracked `data/` directory: promote used to copy the sandbox release tree and strip every top-level `data` entry (reserved for the runtime volume symlink), which also deleted a `data/` source dir the app's Dockerfile copies at build time — so the production build failed ("file not found in build context: stat data") even though the identical sandbox build succeeded. Managed apps now promote by building a fresh clone at the exact tested sandbox commit (same as GitHub-source apps); only upload apps (no repo) still use the copy path
## 2.21.22 — Dashboard now shows an "Active Now" stat: how many users are currently active in the system (active accounts with an app open or a platform action in the last 15 minutes), next to the total-users count. Refreshes every 30s with the rest of the dashboard; backed by a new admin-only GET /api/dashboard/active-users
## 2.21.21 — Self-update now waits out active MCP agents before restarting: if an MCP tool call is in flight (or one ran in the last 10s), /api/self-update drains — waiting up to 45s (configurable via ?wait=<seconds>) for the connection to go quiet — then proceeds, instead of cutting the agent off mid-operation. It only refuses (409 MCP_ACTIVE) if the agent never settles; ?force=1 skips the wait. Complements the existing builds-in-flight guard
## 2.21.20 — Manage now shows persistent-storage usage: expanding an app's row reports how much its /data volume is using, per environment (💾 next to each of Production and Sandbox). Computed on demand (walks the volume) via a new GET /api/apps/:slug/storage endpoint, so it only runs for apps you actually drill into
## 2.21.19 — Deploys no longer leak disk on failure: a failed deploy left its half-cloned `releases/<ts>-git` checkout behind, and the "keep last 5" prune ran only on success — so an app that kept failing to deploy accumulated release dirs until the host hit ENOSPC (no space left on device). Now old releases are pruned at the START of every deploy and in the failure handler (not just on success), the failed attempt's own checkout is removed, and pruning is symlink-safe (the live `current` release is never deleted)
## 2.21.18 — Friendlier auth wall: when a browser navigation lands on a protected route without a valid session, AppCrane now shows a branded "Your session has expired — Sign in" page (with a button back to login that returns you where you were) instead of dumping the raw `{"error":{"code":"UNAUTHORIZED"...}}` JSON. Programmatic/API callers still get JSON unchanged
## 2.21.17 — Pure-MCP large-file push for managed apps: three new MCP tools push big files without any HTTP upload. `appcrane_managed_push_chunk` + `appcrane_managed_assemble` split a large source into small parts (each optionally SHA-256-verified), reassemble server-side, verify the whole, and commit in one commit — so 100+ KB files push reliably without the model emitting them inline. `appcrane_managed_patch` edits an existing file by applying a unified diff (content-matched, so it survives small line drift and fails loudly rather than committing a corrupt file), letting an agent change only the touched hunks
## 2.21.16 — Entering the dashboard now lands on the app picker ("Select an app to open") instead of the overview Dashboard; the Dashboard is still one click away in the nav
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
