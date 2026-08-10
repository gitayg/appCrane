import { getDb } from '../db.js';
import { getPortsForSlot } from './portAllocator.js';
import { isLinux } from './platform.js';
import log from '../utils/logger.js';
import { parseBypassPaths } from '../utils/authBypassPaths.js';
import { isValidDomainFormat } from '../utils/customDomain.js';
import { platformEmbedAncestors, mergeAncestors } from '../utils/embed.js';

const CADDY_ADMIN = process.env.CADDY_ADMIN_URL || 'http://localhost:2019';

/**
 * Remove the platform session cookie from a request before it reaches an app
 * container. Emitted with 8-space indent for `handle` blocks; see
 * PLATFORM_COOKIE_STRIP_SITE for the site-level (4-space) variant.
 *
 * Defined once, at module scope, deliberately: this is the third security rule
 * in this codebase that exists in more than one place, and the previous two
 * (the same-origin redirect check, the identity-header list) both drifted
 * between copies. One definition, two indentations.
 */
function platformCookieStrip(indent) {
  return `${indent}request_header Cookie "(^|;\\s*)cc_token=[^;]*" ""\n` +
         `${indent}request_header Cookie "^;\\s*" ""\n`;
}

/**
 * Generate full Caddy config JSON (path-based routing).
 * Note: the Caddyfile format (generateCaddyfile) is used in production via systemctl reload.
 */
export function generateCaddyConfig() {
  const db = getDb();
  const apps = db.prepare('SELECT * FROM apps').all();
  const cranePort = parseInt(process.env.PORT || '5001');
  const liveRows = db.prepare("SELECT app_id, env FROM deployments WHERE status = 'live'").all();
  const liveSet = new Set(liveRows.map(r => `${r.app_id}:${r.env}`));
  const routes = [];

  for (const app of apps) {
    const ports = getPortsForSlot(app.slot);
    const slug = app.slug;

    // Sandbox path route — only if a live sandbox deployment exists
    if (liveSet.has(`${app.id}:sandbox`)) {
      routes.push({
        match: [{ path: [`/${slug}-sandbox*`] }],
        handle: [
          { handler: 'rewrite', strip_path_prefix: `/${slug}-sandbox` },
          { handler: 'reverse_proxy', upstreams: [{ dial: `localhost:${ports.sand_be}` }] },
        ],
      });
    }

    // Production path route — only if a live production deployment exists
    if (liveSet.has(`${app.id}:production`)) {
      routes.push({
        match: [{ path: [`/${slug}*`] }],
        handle: [
          { handler: 'rewrite', strip_path_prefix: `/${slug}` },
          { handler: 'reverse_proxy', upstreams: [{ dial: `localhost:${ports.prod_be}` }] },
        ],
      });
    }
  }

  // Catch-all → AppCrane
  routes.push({
    handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: `localhost:${cranePort}` }] }],
  });

  return {
    apps: {
      http: {
        servers: {
          srv0: {
            listen: [':443', ':80'],
            routes,
            automatic_https: {},
          },
        },
      },
    },
  };
}

/**
 * Generate Caddyfile format — path-based routing on a single CRANE_DOMAIN.
 * Apps are served at /{slug}/* and /{slug}-sandbox/* under the crane domain.
 * Sandbox routes are listed first so their longer prefix wins mutual-exclusivity.
 */
export function generateCaddyfile() {
  const db = getDb();
  const apps = db.prepare('SELECT * FROM apps').all();
  const cranePort = process.env.PORT || 5001;
  const craneDomain = process.env.CRANE_DOMAIN || null;
  const liveRows = db.prepare("SELECT app_id, env FROM deployments WHERE status = 'live'").all();
  const liveSet = new Set(liveRows.map(r => `${r.app_id}:${r.env}`));

  // Platform-default embedding allowlist (same registrable domain), merged into
  // every app's frame-ancestors unless an admin disabled it. v2.25.0.
  const platformFa = platformEmbedAncestors(db);

  // TLS mode: manual cert (DB settings or env vars) or ACME (Caddy default)
  const tlsRows = db.prepare("SELECT key, value FROM settings WHERE key IN ('tls_cert_file','tls_key_file')").all();
  const tlsMap = Object.fromEntries(tlsRows.map(r => [r.key, r.value || '']));
  const certFile = tlsMap.tls_cert_file || process.env.TLS_CERT_FILE || '';
  const keyFile  = tlsMap.tls_key_file  || process.env.TLS_KEY_FILE  || '';
  const manualTls = certFile && keyFile;

  // Any *.caddy files in /etc/caddy/sites/ are imported and never overwritten by AppCrane.
  // Put custom domains (e.g. your own static sites) there.
  let caddyfile = '# Managed by AppCrane - do not edit manually\n\nimport /etc/caddy/sites/*.caddy\n\n';

  if (!craneDomain) {
    caddyfile += '# CRANE_DOMAIN not configured — no routing generated\n';
    return caddyfile;
  }

  caddyfile += `${craneDomain} {\n`;
  if (manualTls) {
    caddyfile += `    tls ${certFile} ${keyFile}\n\n`;
  }

  // ── Baseline security headers for every response on this domain (v2.35.0) ──
  //
  // AppCrane's own Express routes already set these (server/index.js), but a
  // PROXIED app response carries only whatever its container emitted — which
  // for a typical Express app is nothing, plus an X-Powered-By banner. A
  // credentialed WAS scan flagged exactly that split: /api/* had HSTS and
  // nosniff, /<slug> had neither. Setting them at the site level covers both
  // AppCrane and every app it fronts, in one place.
  //
  // `?` = set only if absent, so an app that deliberately sets its own value
  // keeps it and AppCrane's own headers aren't duplicated. `-` strips.
  //
  // Deliberately NOT set here: X-Frame-Options. A blanket SAMEORIGIN would
  // break the per-app embedding built in v2.24.5/v2.25.0 — `frame-ancestors`
  // supersedes XFO and is emitted per app below, where the policy is actually
  // known. Clearing a scanner finding by breaking a shipped feature is a bad
  // trade. Content-Security-Policy is likewise left to each app: forcing a
  // default-src onto arbitrary customer apps would break them.
  caddyfile += `    header {\n`;
  caddyfile += `        ?Strict-Transport-Security "max-age=31536000; includeSubDomains"\n`;
  caddyfile += `        ?X-Content-Type-Options "nosniff"\n`;
  caddyfile += `        ?Referrer-Policy "strict-origin-when-cross-origin"\n`;
  caddyfile += `        ?X-Permitted-Cross-Domain-Policies "none"\n`;
  // Deny the powerful features no AppCrane-hosted app has asked for. Apps that
  // need one can override, since `?` yields to a value the app already set.
  caddyfile += `        ?Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()"\n`;
  // Server banners: version/stack disclosure, no upside.
  caddyfile += `        -X-Powered-By\n`;
  caddyfile += `        -Server\n`;
  caddyfile += `    }\n\n`;

  for (const app of apps) {
    const ports = getPortsForSlot(app.slot);
    const slug = app.slug;

    // Permanent redirects for any old slugs (after a rename)
    let aliases = [];
    try { aliases = JSON.parse(app.slug_aliases || '[]'); } catch (_) {}
    for (const alias of aliases) {
      caddyfile += `    handle /${alias}-sandbox* {\n`;
      caddyfile += `        redir /${slug}-sandbox{uri} permanent\n`;
      caddyfile += `    }\n\n`;
      caddyfile += `    handle /${alias}* {\n`;
      caddyfile += `        redir /${slug}{uri} permanent\n`;
      caddyfile += `    }\n\n`;
    }

    // Per-app embedding policy: when frame_ancestors is set we override the
    // default-locked iframe headers from any upstream so embedders listed in
    // the policy can iframe this app. Default (NULL) → no override; any
    // headers from the upstream pass through.
    const fa = mergeAncestors(platformFa, app.frame_ancestors);

    // Sandbox — longer prefix /${slug}-sandbox* wins over /${slug}* via mutual exclusivity.
    // Pass the full prefix on the verify URL so identity.js can reconstruct the
    // original request URL even when Caddy's directive ordering strips the
    // prefix before forward_auth runs (the X-Forwarded-Uri header otherwise
    // arrives as '/' and the post-auth redirect points to the wrong place).
    // v2.7.19: identity-forwarding contract. /api/identity/verify emits
    // X-AppCrane-* response headers; Caddy's forward_auth `copy_headers`
    // copies them onto the upstream proxy request so the deployed app
    // reads identity directly off the request (no /api/me callback).
    // SECURITY: we MUST strip any incoming X-AppCrane-* from the client
    // first — otherwise a curl with `X-AppCrane-User-Role: platform_admin`
    // would arrive at the app and be trusted. The strip + copy_headers
    // pair guarantees what the app receives is platform-issued.
    const IDENTITY_HEADERS = [
      'X-AppCrane-User',
      'X-AppCrane-User-Id',
      'X-AppCrane-User-Email',
      'X-AppCrane-User-Name',
      'X-AppCrane-User-Role',
      'X-AppCrane-App-Role',
    ];
    const stripIncoming = IDENTITY_HEADERS
      .map(h => `        request_header -${h}\n`).join('');
    const copyFromVerify = `            copy_headers ${IDENTITY_HEADERS.join(' ')}\n`;

    // v2.39.0: the platform session cookie must never reach an app container.
    //
    // Caddy forwards Cookie verbatim, apps are mounted same-origin at /<slug>,
    // and cc_token is `path=/` — so a logged-in visitor's browser attaches it to
    // every request into the app. cc_token is ALSO accepted as a bearer
    // (authedUser runs the same sessionUserFor() on the cookie and on
    // Authorization), so an app's own backend could read it off the request and
    // call the platform API as whoever visited. Verified end-to-end: a lifted
    // platform_admin session reached /api/settings, /api/users, /api/audit, and
    // — because platform_admin then bypassed requireAppUser — the DECRYPTED env
    // vars of every app on the box via ?reveal=true, for the 24h life of the
    // session. That bypass is closed too (v2.39.0, middleware/auth.js), but this
    // strip is the one that stops the token arriving in the first place.
    //
    // Nothing legitimate needs it. Apps read identity from the X-AppCrane-*
    // headers above, and an app's server reaches the platform through
    // /api/service with its own APPCRANE_SERVICE_TOKEN, off the docker bridge.
    // The documented `fetch('/api/me')` pattern is unaffected: that request
    // matches the platform catch-all, not this app block, so the browser still
    // sends the cookie straight to AppCrane.
    //
    // Strip by NAME, never the whole header — apps set their own cookies and a
    // blanket `-Cookie` would log every user out of every hosted app. Two
    // passes: the first removes the pair wherever it sits, the second tidies the
    // separator it can leave at the front. The `(^|;\s*)` anchor is load-bearing
    // — without it a legitimate app cookie named e.g. `my_cc_token` would match
    // on the substring and be corrupted.
    //
    // UNCONDITIONAL, unlike stripIncoming: headless apps skip forward_auth and
    // get no identity headers, but the browser still sends them the cookie, so
    // they need this strip most of all.
    const stripPlatformCookie = platformCookieStrip('        ');

    // v2.7.22: headless apps bypass forward_auth entirely — no identity,
    // no role headers, no per-app verify round-trip. Right tool for pure
    // unauthenticated services (telemetry ingest, public webhooks,
    // status pages). For authenticated apps, the strip + forward_auth +
    // copy_headers pair runs as before.
    const isHeadless = app.auth_mode === 'headless';

    // v2.7.27: path-level auth bypass — narrower than headless mode. For
    // each entry in auth_bypass_paths, emit a child `handle` BEFORE the
    // parent that omits forward_auth so a CLI client (e.g. aghook → WS)
    // can authenticate itself via a token in the query string. Caddy's
    // `handle` is longest-prefix-wins inside a site block, so the child
    // wins regardless of emission order — emitting it first keeps the
    // file readable as "exceptions then catch-all."
    //
    // SECURITY INVARIANTS we keep on the bypass block:
    //   1. stripIncoming runs on the bypass path too — a curl with
    //      X-AppCrane-User-Role: platform_admin must NOT reach the app
    //      just because forward_auth is off.
    //   2. log_skip suppresses the access log line entirely for these
    //      paths. The token aghook puts in the query string would
    //      otherwise sit in Caddy's log storage. Granular query-param
    //      redaction in Caddy's `log filter` would be cleaner but
    //      requires syntax that hasn't been verified against this
    //      install's caddy `adapt`; the app emits a redacted
    //      connect-log line on its side as the agreed compensating
    //      control. v2.7.28+ can swap to filtered logging in place.
    //   3. flush_interval -1 + transport read/write_timeout 0 keep
    //      long-lived idle WS connections from being cut by AppCrane.
    //      Caddy's default global idle_timeout (5m) is far above
    //      aghook's 25s keepalive and is not overridden here.
    // Skipped entirely when the app is headless (whole app is already
    // open) or the env isn't deployed (the parent block already 503's).
    const bypassPaths = isHeadless ? [] : parseBypassPaths(app.auth_bypass_paths, e =>
      log.warn(`[caddy] app ${app.slug}: bad auth_bypass_paths entry — ${e.message} (ignored)`));
    // mountPrefix = the per-env path mount, e.g. "/agentclub-sandbox" or
    // "/agentclub". The bypass path P (e.g. "/ws/local-runner") is appended
    // to form the child handle path; the strip_prefix removes the SAME mount
    // so the app sees its native /ws/local-runner.
    const emitBypass = (mountPrefix, bypassPath, port) => {
      caddyfile += `    handle ${mountPrefix}${bypassPath}* {\n`;
      caddyfile += `        log_skip\n`;
      caddyfile += stripPlatformCookie;
      caddyfile += stripIncoming;
      caddyfile += `        uri strip_prefix ${mountPrefix}\n`;
      caddyfile += `        reverse_proxy 127.0.0.1:${port} {\n`;
      caddyfile += `            flush_interval -1\n`;
      caddyfile += `            transport http {\n`;
      caddyfile += `                read_timeout 0\n`;
      caddyfile += `                write_timeout 0\n`;
      caddyfile += `            }\n`;
      caddyfile += `        }\n`;
      caddyfile += `    }\n\n`;
    };
    for (const p of bypassPaths) {
      if (liveSet.has(`${app.id}:sandbox`))    emitBypass(`/${slug}-sandbox`, p, ports.sand_be);
      if (liveSet.has(`${app.id}:production`)) emitBypass(`/${slug}`,         p, ports.prod_be);
    }

    caddyfile += `    handle /${slug}-sandbox* {\n`;
    if (liveSet.has(`${app.id}:sandbox`)) {
      caddyfile += stripPlatformCookie;
      if (!isHeadless) {
        caddyfile += stripIncoming;
        caddyfile += `        forward_auth 127.0.0.1:${cranePort} {\n`;
        caddyfile += `            uri /api/identity/verify?app=${slug}&prefix=/${slug}-sandbox\n`;
        caddyfile += copyFromVerify;
        caddyfile += `        }\n`;
      }
      if (fa) {
        caddyfile += `        header Content-Security-Policy "frame-ancestors ${fa}"\n`;
        caddyfile += `        header -X-Frame-Options\n`;
      }
      caddyfile += `        uri strip_prefix /${slug}-sandbox\n`;
      caddyfile += `        reverse_proxy 127.0.0.1:${ports.sand_be}\n`;
    } else {
      caddyfile += `        respond "Not deployed" 503\n`;
    }
    caddyfile += `    }\n\n`;

    // Production
    caddyfile += `    handle /${slug}* {\n`;
    if (liveSet.has(`${app.id}:production`)) {
      caddyfile += stripPlatformCookie;
      if (!isHeadless) {
        caddyfile += stripIncoming;
        caddyfile += `        forward_auth 127.0.0.1:${cranePort} {\n`;
        caddyfile += `            uri /api/identity/verify?app=${slug}&prefix=/${slug}\n`;
        caddyfile += copyFromVerify;
        caddyfile += `        }\n`;
      }
      if (fa) {
        caddyfile += `        header Content-Security-Policy "frame-ancestors ${fa}"\n`;
        caddyfile += `        header -X-Frame-Options\n`;
      }
      caddyfile += `        uri strip_prefix /${slug}\n`;
      caddyfile += `        reverse_proxy 127.0.0.1:${ports.prod_be}\n`;
    } else {
      caddyfile += `        respond "Not deployed" 503\n`;
    }
    caddyfile += `    }\n\n`;
  }

  // v2.8.0: the internal app service API (/api/service/*) must NOT be reachable
  // from the public domain — apps call it only via the docker host-gateway.
  // 404 it here, before the catch-all that would otherwise proxy it to AppCrane.
  caddyfile += `    handle /api/service* {\n`;
  caddyfile += `        respond 404\n`;
  caddyfile += `    }\n\n`;

  // Everything else → AppCrane itself
  caddyfile += `    handle {\n`;
  caddyfile += `        reverse_proxy 127.0.0.1:${cranePort}\n`;
  caddyfile += `    }\n\n`;

  // Friendly crash page when a proxied app is down (container exited, port
  // refused, etc.). Caddy turns connection-refused into a 502, we catch
  // 502/503/504 here, rewrite to AppCrane's /api/_crashed handler which
  // extracts the slug from the original path and renders a friendly HTML
  // page with a link to logs.
  caddyfile += `    handle_errors {\n`;
  caddyfile += `        @appdown expression \`{err.status_code} in [502, 503, 504]\`\n`;
  caddyfile += `        handle @appdown {\n`;
  caddyfile += `            rewrite * /api/_crashed{uri}\n`;
  caddyfile += `            reverse_proxy 127.0.0.1:${cranePort}\n`;
  caddyfile += `        }\n`;
  caddyfile += `    }\n`;
  caddyfile += `}\n`;

  // ── Custom-domain passthrough apps (v2.10.0) ──────────────────────────
  // When an app has `domain` set, serve it at the ROOT of that domain with NO
  // forward_auth, NO topbar, NO path prefix — the app does its own auth, and
  // AppCrane is just the deploy/ops layer. Maps to the PRODUCTION backend and
  // is emitted only when prod is live. TLS is auto-provisioned by Caddy (ACME)
  // for the domain — needs its DNS pointed at this host + ports 80/443 open.
  // The /<slug> path under CRANE_DOMAIN stays (admin/ops access).
  //
  // We still strip any incoming X-AppCrane-* so a client can't smuggle forged
  // platform identity into an app that does its own auth. The format is
  // re-validated here so a bad DB value can't produce a broken Caddyfile
  // (Caddy `adapt` would refuse the reload anyway, but better to skip cleanly).
  const IDENTITY_STRIP = [
    'X-AppCrane-User', 'X-AppCrane-User-Id', 'X-AppCrane-User-Email',
    'X-AppCrane-User-Name', 'X-AppCrane-User-Role', 'X-AppCrane-App-Role',
  ];
  const emittedDomains = new Set([(craneDomain || '').toLowerCase()]);
  for (const app of apps) {
    const domain = (app.domain || '').trim().toLowerCase();
    if (!domain) continue;
    if (!isValidDomainFormat(domain)) {
      log.warn(`[caddy] app ${app.slug}: invalid custom domain "${app.domain}" — skipped`);
      continue;
    }
    if (emittedDomains.has(domain)) {
      log.warn(`[caddy] custom domain "${domain}" already used — skipping duplicate on ${app.slug}`);
      continue;
    }
    if (!liveSet.has(`${app.id}:production`)) continue; // prod not live → no site block
    emittedDomains.add(domain);
    const ports = getPortsForSlot(app.slot);
    caddyfile += `\n${domain} {\n`;
    for (const h of IDENTITY_STRIP) caddyfile += `    request_header -${h}\n`;
    // Belt-and-braces: cc_token is host-only (no Domain attribute), so a browser
    // never sends it to a custom domain — this block is a different origin. The
    // strip costs one line and holds if that cookie ever gains a Domain, or if a
    // custom domain is ever pointed at a host that does receive it.
    caddyfile += platformCookieStrip('    ');
    caddyfile += `    reverse_proxy 127.0.0.1:${ports.prod_be}\n`;
    caddyfile += `}\n`;
  }

  // ── Domain aliases → 301 redirect to the app's primary domain (v2.24.4) ──
  // A migrated-away domain (old bookmark, already-sent login link) keeps working
  // by permanently redirecting to the app's current custom domain, path+query
  // preserved. Emitted only when the primary is itself emitted above (prod live,
  // valid domain) — otherwise the redirect target would 404. TLS for the alias
  // is auto-provisioned by Caddy (ACME) as long as its DNS still points here.
  const primaryByAppId = new Map(apps.map(a => [a.id, (a.domain || '').trim().toLowerCase()]));
  const aliasRows = db.prepare('SELECT app_id, domain FROM app_domain_aliases').all();
  for (const r of aliasRows) {
    const alias = (r.domain || '').trim().toLowerCase();
    const primary = primaryByAppId.get(r.app_id) || '';
    if (!alias || !primary || alias === primary) continue;
    if (!isValidDomainFormat(alias) || !isValidDomainFormat(primary)) continue;
    if (!liveSet.has(`${r.app_id}:production`)) continue; // primary block not emitted → skip
    if (emittedDomains.has(alias)) {
      log.warn(`[caddy] alias domain "${alias}" already used — skipping duplicate`);
      continue;
    }
    emittedDomains.add(alias);
    caddyfile += `\n${alias} {\n    redir https://${primary}{uri} permanent\n}\n`;
  }

  return caddyfile;
}

/**
 * Push config to Caddy admin API and reload.
 */
export async function reloadCaddy({ force = false } = {}) {
  if (!isLinux()) {
    const config = generateCaddyfile();
    log.info('[Caddy mock] Would write Caddyfile:\n' + config);
    return { success: true, mock: true };
  }

  // Write Caddyfile and reload via systemctl (most reliable)
  try {
    const { writeFileSync, readFileSync, existsSync, mkdirSync, readdirSync, unlinkSync } = await import('fs');
    const { execFileSync } = await import('child_process');
    const caddyfile = generateCaddyfile();

    // Pre-apply validation: write to a tmp path, run `caddy adapt` against
    // it to confirm it parses cleanly. Only swap into /etc/caddy/Caddyfile
    // if it does. Prevents a bad config from breaking routing for every app
    // at once.
    //
    // We use `caddy adapt` rather than `caddy validate` because validate
    // runs full provisioning — including loading TLS certs from
    // /etc/caddy/certs/. AppCrane runs as `ubuntu` (UID 1000) but the certs
    // are owned by the `caddy` user, so validate fails with EACCES and the
    // new Caddyfile is silently never written (the failure is .catch()'d at
    // every callsite as a log.warn). `adapt` parses the Caddyfile to JSON
    // without touching certs, exits non-zero on syntax errors — exactly
    // what we want here.
    const tmpPath = '/tmp/Caddyfile.appcrane-validate';
    writeFileSync(tmpPath, caddyfile);
    try {
      execFileSync('caddy', ['adapt', '--config', tmpPath, '--adapter', 'caddyfile'], {
        timeout: 8000, stdio: 'pipe',
      });
    } catch (validateErr) {
      const detail = validateErr.stderr?.toString().trim() || validateErr.message;
      log.error(`Caddy adapt failed — refusing reload. Config:\n${caddyfile}\nError: ${detail}`);
      return { success: false, error: `Generated Caddyfile is invalid: ${detail}` };
    }

    // Skip-if-unchanged: byte-identical reads of the existing Caddyfile mean
    // a reload would just disrupt live connections for no reason. Cheap to
    // check, common case during routine app touches.
    const livePath = '/etc/caddy/Caddyfile';
    let prev = '';
    try { prev = readFileSync(livePath, 'utf8'); } catch (_) { /* first run */ }
    // v2.21.31: `force` bypasses this. The comparison is generated-vs-FILE, which
    // says nothing about what the RUNNING Caddy process has loaded. A process can
    // drift from the file (e.g. it was started before a config feature existed, or
    // an earlier reload silently failed) and then every subsequent call returns
    // `unchanged: true` and never reloads — leaving the live proxy permanently
    // stale with no way to recover through the API. That's exactly how a
    // correct-on-disk `copy_headers` never reached the running process.
    if (prev === caddyfile && !force) {
      log.info('Caddy config unchanged — skipping reload.');
      return { success: true, unchanged: true };
    }

    // Backup-before-overwrite. /etc/caddy/.appcrane-backups/Caddyfile-<ts>.
    // Keeps the last 10; older are pruned. Manual rollback is then a
    // straight `cp` away — no replay of DB state needed.
    if (prev && prev !== caddyfile) {
      try {
        const backupDir = '/etc/caddy/.appcrane-backups';
        if (!existsSync(backupDir)) mkdirSync(backupDir, { recursive: true });
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        writeFileSync(`${backupDir}/Caddyfile-${stamp}`, prev);
        const files = readdirSync(backupDir).filter(f => f.startsWith('Caddyfile-')).sort();
        const stale = files.slice(0, Math.max(0, files.length - 10));
        for (const f of stale) {
          try { unlinkSync(`${backupDir}/${f}`); } catch (_) { /* best-effort */ }
        }
      } catch (e) {
        log.warn(`Caddy backup failed (non-fatal): ${e.message}`);
      }
    }

    writeFileSync(livePath, caddyfile);
    execFileSync('systemctl', ['reload', 'caddy'], { timeout: 10000, stdio: 'pipe' });

    // Post-reload verification. systemctl reload returns 0 even when Caddy
    // logs the reload but rejects the config internally. Hit the admin API
    // to confirm Caddy is actually answering — a non-2xx or timeout means
    // we should restart rather than leave it half-loaded.
    let adminOk = true;
    try {
      const r = await fetch(`${CADDY_ADMIN}/config/`, { signal: AbortSignal.timeout(2000) });
      adminOk = r.ok;
    } catch (_) {
      adminOk = false;
    }
    if (!adminOk) {
      log.warn('Caddy admin API not responsive after reload — escalating to restart.');
      try {
        execFileSync('systemctl', ['restart', 'caddy'], { timeout: 15000, stdio: 'pipe' });
        log.info('Caddy restarted after unresponsive reload.');
        return { success: true, restarted: true };
      } catch (restartErr) {
        log.error(`Caddy restart after bad reload failed: ${restartErr.message}`);
        return { success: false, error: `Reload completed but admin API unresponsive; restart also failed: ${restartErr.message}` };
      }
    }

    log.info('Caddy reloaded: ' + caddyfile.split('\n').filter(l => l.includes('{')).map(l => l.trim().split(' ')[0]).join(', '));
    return { success: true };
  } catch (e) {
    log.error(`Caddy reload failed: ${e.message}`);
    // Try restart instead of reload
    try {
      const { execFileSync } = await import('child_process');
      execFileSync('systemctl', ['restart', 'caddy'], { timeout: 15000, stdio: 'pipe' });
      log.info('Caddy restarted (reload failed)');
      return { success: true, restarted: true };
    } catch (e2) {
      log.error(`Caddy restart also failed: ${e2.message}`);
      return { success: false, error: e.message };
    }
  }
}
