import { statSync } from 'fs';
import { dirname } from 'path';
import { getDb } from '../db.js';
import { getPortsForSlot } from './portAllocator.js';
import { isLinux } from './platform.js';
import log from '../utils/logger.js';
import { parseBypassPaths } from '../utils/authBypassPaths.js';
import { isValidDomainFormat } from '../utils/customDomain.js';
import { platformEmbedAncestors, mergeAncestors } from '../utils/embed.js';
import { safeFrameAncestors } from '../utils/frameAncestors.js';
import {
  isolationDomain, isolationTls, appHost, RESERVED_APP_PATH,
  APP_SESSION_COOKIE, HANDOFF_STATE_COOKIE, PLATFORM_SESSION_COOKIE_ISOLATED, PLATFORM_SESSION_COOKIE_LEGACY,
} from './appOrigin.js';

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

// Per-app origins (services/appOrigin.js): on an app host, and on a custom
// domain that runs AppCrane sign-in, the app sees none of AppCrane's session
// cookies — the legacy and __Host- platform cookies, and the app-scope cookie
// its own host holds. Same two-pass, anchored shape as platformCookieStrip.
function isolatedCookieStrip(indent) {
  const names = [PLATFORM_SESSION_COOKIE_LEGACY, PLATFORM_SESSION_COOKIE_ISOLATED, APP_SESSION_COOKIE, HANDOFF_STATE_COOKIE].join('|');
  return `${indent}request_header Cookie "(^|;\\s*)(${names})=[^;]*" ""\n` +
         `${indent}request_header Cookie "^;\\s*" ""\n`;
}

/**
 * The identity headers /api/identity/verify issues and forward_auth copies onto
 * the upstream request. Every one of them is stripped off the CLIENT request
 * first, everywhere an app is proxied — otherwise a curl with
 * `X-AppCrane-User-Role: platform_admin` would arrive at the app and be trusted.
 *
 * Module scope for the same reason platformCookieStrip is: this list previously
 * existed twice (the crane-domain block and the custom-domain block) and is
 * exactly the kind of duplicated security rule that drifts. One definition,
 * several indentations.
 */
const IDENTITY_HEADERS = [
  'X-AppCrane-User',
  'X-AppCrane-User-Id',
  'X-AppCrane-User-Email',
  'X-AppCrane-User-Name',
  'X-AppCrane-User-Role',
  'X-AppCrane-App-Role',
  // v2.40.0: the platform's own answer to "is this person an admin here?",
  // computed in /api/identity/verify with the correct precedence (owner counts).
  // Apps kept re-deriving it from App-Role with `=== 'admin'` and locking owners
  // — the highest tier — out of their own settings pages.
  'X-AppCrane-Is-Admin',
  // v2.41.0: the roles the APP defines for itself (approver, auditor...),
  // comma-separated. AppCrane is the authority that issues them; the app is the
  // enforcer. Which is exactly why this line matters: the app's own permission
  // checks read this header, so if a client could send it, every hosted app's
  // authorization would be self-service. Stripped here, re-issued by /verify.
  'X-AppCrane-App-Roles',
  // v2.97.0: the signature over all of the above, keyed per app, so an app can
  // reject identity that did not come through here. A client-sent pair would
  // be rejected by a verifying app anyway; stripping it keeps the rule simple.
  'X-AppCrane-Identity-Ts',
  'X-AppCrane-Identity-Sig',
  // v2.125.14: the v2 signature, which also covers X-AppCrane-Auth-Via. Not in
  // copy_headers, it would never reach the app; not stripped, a client could
  // send its own (and a verifier prefers v2).
  'X-AppCrane-Identity-Sig-V2',
  // v2.124.0: 'app-key' when the caller signed in with a personal app sign-in
  // key (dhk_uak_*) instead of a browser session. An app that lets a script do
  // less than its person relies on it, so a client must not be able to send it.
  'X-AppCrane-Auth-Via',
];

/**
 * v2.40.0: X-AppCrane-Auth-Mode — which identity path this route runs.
 *
 * "No X-AppCrane-* headers arrived" used to be one symptom with four causes:
 * headless mode, a path-level auth bypass, a broken forward_auth, or the app not
 * being proxied by AppCrane at all. An app author had no way to tell them apart,
 * and four separate debugging sessions this week ended at that ambiguity. This
 * header is a constant per route, so the app can read it and know immediately
 * whether identity was ever coming.
 *
 * Set (two args), not add — a client's forged value is replaced, not appended
 * to. The explicit strip in front is belt-and-braces so the invariant survives a
 * future edit that turns this into an `+` add.
 */
const AUTH_MODE_HEADER = 'X-AppCrane-Auth-Mode';

function identityStrip(indent) {
  return IDENTITY_HEADERS.map(h => `${indent}request_header -${h}\n`).join('');
}

/**
 * Baseline response-header policy for a site AppCrane fronts (v2.35.0).
 *
 * AppCrane's own Express routes already set these (server/index.js), but a
 * PROXIED app response carries only whatever its container emitted — which for a
 * typical Express app is nothing, plus an X-Powered-By banner. A credentialed WAS
 * scan flagged exactly that split: /api/* had HSTS and nosniff, /<slug> had
 * neither. Setting them at the site level covers both AppCrane and every app it
 * fronts, in one place.
 *
 * `?` = set only if absent, so an app that deliberately sets its own value keeps
 * it and AppCrane's own headers aren't duplicated. `-` strips.
 *
 * Deliberately NOT set here: X-Frame-Options. A blanket SAMEORIGIN would break
 * the per-app embedding built in v2.24.5/v2.25.0 — `frame-ancestors` supersedes
 * XFO and is emitted per app below, where the policy is actually known. Clearing
 * a scanner finding by breaking a shipped feature is a bad trade.
 * Content-Security-Policy is likewise left to each app: forcing a default-src
 * onto arbitrary customer apps would break them.
 *
 * v2.44.0 — module scope, emitted by BOTH site blocks. This shipped inside the
 * CRANE_DOMAIN block only, so an app with its own custom domain (a separate
 * `${domain} { … }` site, which inherits nothing) was served with no HSTS, no
 * nosniff, no referrer policy and its X-Powered-By intact. The apps with their
 * own hostname — the ones most likely to be handed to someone outside the
 * platform — were the ones without the platform's baseline. Same fix shape as
 * IDENTITY_HEADERS and platformCookieStrip: one definition, both sites.
 */
const BASELINE_HEADERS =
  `    header {\n` +
  `        ?Strict-Transport-Security "max-age=31536000; includeSubDomains"\n` +
  `        ?X-Content-Type-Options "nosniff"\n` +
  `        ?Referrer-Policy "strict-origin-when-cross-origin"\n` +
  `        ?X-Permitted-Cross-Domain-Policies "none"\n` +
  // Deny the powerful features no AppCrane-hosted app has asked for. Apps that
  // need one can override, since `?` yields to a value the app already set.
  `        ?Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()"\n` +
  // Server banners: version/stack disclosure, no upside.
  `        -X-Powered-By\n` +
  `        -Server\n` +
  `    }\n`;

// CVE-2026-111497 ("Node2Shell"): Node's bundled Brotli decoder before 22.23.4 /
// 24.22.1 / 26.12.1 can be driven to an out-of-bounds write by a malformed body,
// and Express 5 / body-parser 2.x decode `Content-Encoding: br` bodies for any
// client. Refused at the edge for every hosted app, ahead of every route: a
// `handle` with a named matcher keeps its written position among `handle`
// blocks (Caddy sorts only single-path matchers by specificity), so emitted
// first it runs first; the adapted order is pinned by test/caddy-brotli-guard.test.js.
// Caddy's header matcher is case-sensitive, so the case-insensitive
// header_regexp form is used. A platform admin can turn it off for an app
// fleet that really accepts Brotli uploads.
export const BROTLI_GUARD_KEY = 'edge_refuse_brotli_bodies';

export function brotliGuardEnabled(db) {
  const v = db.prepare('SELECT value FROM settings WHERE key = ?').get(BROTLI_GUARD_KEY)?.value;
  return v == null || String(v).trim().toLowerCase() !== 'off';
}

const BROTLI_REFUSAL =
  `    @brotli_body header_regexp Content-Encoding "(?i)(^|,)\\s*br\\s*(,|$)"\n` +
  `    handle @brotli_body {\n` +
  `        header Accept-Encoding "gzip, deflate"\n` +
  `        respond "Request bodies compressed with Brotli (Content-Encoding: br) are not accepted." 415\n` +
  `    }\n`;

/**
 * Access log for the crane domain, with every query-string value redacted.
 *
 * Emitted only when at least one auth-bypass route exists (see emitBypass).
 * Through v2.43.1 those routes carried a bare `log_skip`: the ONE route class
 * that deliberately runs no forward_auth was also the one with no request record
 * at all. The reason was real — a CLI client authenticates itself with a token in
 * the query string, and an unfiltered access log would park that token in log
 * storage — but dropping the whole line was the wrong side of the trade, and the
 * comment on emitBypass has named filtered logging as the intended fix since
 * v2.7.28.
 *
 * Verified against caddy:2 (`caddy adapt` + a live container), not assumed:
 *   - the filter survives adaptation as
 *     fields["request>uri"] = {filter: "regexp", regexp: "\\?.*", value: "?redacted"},
 *     so it is doing something rather than merely parsing;
 *   - a real request to /<slug>/ws/runner?token=… is logged as
 *     "uri":"/<slug>/ws/runner?redacted" — record kept, secret gone;
 *   - Caddy already logs Cookie and Authorization as "REDACTED" on its own, so
 *     the query string was the only credential channel left to close.
 *
 * The WHOLE query string goes, not a named parameter: `query { replace token … }`
 * needs the parameter name, and the name belongs to the app's own CLI protocol —
 * AppCrane does not know it and must not guess. Losing query VALUES platform-wide
 * is a feature here anyway: the SSO handoff puts tokens in URLs too.
 *
 * Access logging in Caddy is host-scoped (server.logs.logger_names is keyed by
 * host), so it cannot be narrowed to just the exempt paths — enabling it for the
 * bypass route enables it for the whole crane domain. Custom-domain sites are
 * unaffected: the adapter emits them into `skip_hosts`, so they stay unlogged
 * (confirmed in the adapted JSON) rather than falling through to an UNFILTERED
 * default logger.
 */
const ACCESS_LOG_DEFAULT = '/var/log/caddy/access.log';

/**
 * Where the redacting access log is written: CADDY_ACCESS_LOG_FILE, else
 * /var/log/caddy/access.log — the directory Caddy's Ubuntu package creates,
 * owned by the `caddy` user the service runs as.
 *
 * Through v2.125.19 the log had no `output`, so every line went to stderr and
 * from there into the systemd journal: one production box took ~19.7k JSON
 * lines a day that way, into a journal that reached 4 GB and helped fill the
 * disk. A file Caddy rotates itself has a hard size bound; the journal had none
 * that AppCrane set.
 *
 * The value is written into the Caddyfile verbatim, so anything but a plain
 * absolute path — a space, quote, brace or newline could add directives — falls
 * back to the default instead.
 */
function accessLogPath() {
  const p = process.env.CADDY_ACCESS_LOG_FILE;
  if (!p) return ACCESS_LOG_DEFAULT;
  if (/^(\/[A-Za-z0-9_.-]+)+$/.test(p) && !p.split('/').some(seg => seg === '.' || seg === '..')) return p;
  log.warn(`[caddy] CADDY_ACCESS_LOG_FILE is not a plain absolute path — using ${ACCESS_LOG_DEFAULT}`);
  return ACCESS_LOG_DEFAULT;
}

/**
 * Whether the log file's directory exists, checked when the Caddyfile is built.
 *
 * Caddy refuses a config whose log file it cannot open, and a refused reload
 * escalates to a restart in reloadCaddy — so pointing at a directory that is not
 * there could take Caddy down on a box that self-updated into this change (one
 * whose Caddy did not come from the apt package that creates /var/log/caddy).
 * Without the directory the loggers keep stderr, filter and all, and AppCrane
 * warns once per process. Existence only: AppCrane may run as a user that cannot
 * write there, while Caddy (as `caddy`) can, so writability here proves nothing.
 * Replaceable for tests via setAccessLogDirCheck.
 */
let accessLogDirExists = (dir) => {
  try { return statSync(dir).isDirectory(); } catch { return false; }
};
export function setAccessLogDirCheck(fn) { accessLogDirExists = fn; }
let warnedMissingLogDir = false;

function accessLogOutput(indent) {
  const file = accessLogPath();
  const dir = dirname(file);
  if (!accessLogDirExists(dir)) {
    if (!warnedMissingLogDir) {
      warnedMissingLogDir = true;
      log.warn(`[caddy] ${dir} does not exist — Caddy's redacted access log stays on stderr (the journal). ` +
        `Create it, owned by the user Caddy runs as, to get a rotated ${file}.`);
    }
    return '';
  }
  return `${indent}output file ${file} {\n` +
         `${indent}    roll_size 50MiB\n` +
         `${indent}    roll_keep 5\n` +
         `${indent}    roll_keep_for 14d\n` +
         `${indent}}\n`;
}

/**
 * Body shared by both redacting loggers below: the query-string filter and the
 * rotated file. One definition, so the access and error streams cannot drift.
 *
 * Rotation: 50 MiB per file, 5 rolled files, none older than 14 days — at most
 * 300 MiB on disk even with no compression (Caddy gzips rolled files by default,
 * so in practice far less). At the incident's ~20k lines a day (0.5-1 KB each,
 * 10-20 MB/day) that is roughly two weeks of history, so the bounds agree.
 */
function redactedLogBody(indent) {
  return `${indent}format filter {\n` +
         `${indent}    wrap json\n` +
         `${indent}    fields {\n` +
         `${indent}        request>uri regexp "\\?.*" "?redacted"\n` +
         `${indent}    }\n` +
         `${indent}}\n` +
         accessLogOutput(indent);
}

function bypassAccessLog() {
  return `    # Access log with query strings redacted — an auth-bypass path carries its\n` +
         `    # token in the query, and this domain's log must not become a token store.\n` +
         `    log {\n` +
         redactedLogBody('        ') +
         `    }\n`;
}

/**
 * Global-options logger for Caddy's per-request ERROR stream, emitted whenever
 * bypassAccessLog is.
 *
 * Measured against caddy:2, not assumed: once a site has a `log` block, a request
 * that fails (a 502 while the app is down, say) is also logged as
 * `http.log.error.log0` — and the site's own logger includes only
 * `http.log.access.log0`, so that record fell through to Caddy's DEFAULT logger:
 * unfiltered, to stderr, to the journal, with "uri":"…?token=<the token>" intact.
 * Including the whole `http.log.error` namespace here sends it through the same
 * filter to the same file (Caddy pools one writer per filename; stderr, filtered,
 * when accessLogOutput has no directory to write to), and the adapter
 * adds it to the default logger's `exclude`, so the unfiltered copy is gone.
 */
function bypassErrorLog() {
  return `    log appcrane_errors {\n` +
         `        include http.log.error\n` +
         redactedLogBody('        ') +
         `    }\n`;
}

function authMode(indent, mode) {
  return `${indent}request_header -${AUTH_MODE_HEADER}\n` +
         `${indent}request_header ${AUTH_MODE_HEADER} "${mode}"\n`;
}

/**
 * Matches the `frame-ancestors` directive inside a Content-Security-Policy value.
 *
 * Anchored to a directive boundary — start of value or a `;` — and NOT the bare
 * string, because the bare string also matches inside another directive's VALUE.
 * Measured against caddy:2 with `default-src 'self'; report-uri
 * https://r.example.com/frame-ancestors/x; frame-ancestors 'none'`: the
 * unanchored form rewrote the report-uri path and swallowed the rest of that
 * directive, the anchored form left it alone.
 *
 * The boundary — `;` and the spacing that follows it — is captured, not
 * consumed, and `${1}` puts it back. So the app's own separator survives byte
 * for byte: a policy whose FIRST directive is frame-ancestors does not gain a
 * leading `;` or a leading space, and one written `…;  frame-ancestors` keeps
 * its two spaces. Same shape as the cookie strip above.
 */
const CSP_FRAME_ANCESTORS = '(?i)(^\\s*|;\\s*)frame-ancestors[^;]*';

/**
 * Make AppCrane's embedding policy the one the browser actually enforces
 * (v2.77.0), overriding whatever `frame-ancestors` the app sends for itself.
 *
 * Until now this was two flat lines — `header Content-Security-Policy
 * "frame-ancestors <policy>"` plus `header -X-Frame-Options` — and the first of
 * them did NOT do what it reads like. A plain `header` set is applied before the
 * proxy runs, and reverse_proxy then ADDS the upstream's own CSP alongside it. An
 * app sending `…; frame-ancestors 'none'; …` produced a response carrying TWO
 * CSP headers, and a browser enforces every policy it is given: the intersection
 * is empty and the app-viewer frame stayed blocked no matter what the platform
 * or the app admin configured. Measured through caddy:2, not reasoned:
 *
 *   upstream: CSP "…; frame-ancestors 'none'; …"
 *   response: CSP: frame-ancestors <ours>          <- AppCrane's
 *             CSP: …; frame-ancestors 'none'; …    <- the app's, still enforced
 *
 * What this emits instead, and why each op is there:
 *
 *   - a REPLACEMENT of the app's own frame-ancestors with the platform policy.
 *     Everything else in the app's CSP — script-src and its nonce, connect-src,
 *     object-src, form-action — is carried through untouched, which a `>` set
 *     (the obvious alternative) would have destroyed: measured, `header
 *     >Content-Security-Policy "frame-ancestors …"` replaces the WHOLE header and
 *     the app loses its own protections along with its framing rule.
 *   - an ADDED header carrying only `frame-ancestors <policy>`, because a
 *     replacement cannot create what is not there: an app whose CSP has no
 *     frame-ancestors, and an app that sends no CSP at all, must still END UP
 *     with the platform's. It is the same value the replacement just wrote, so
 *     the two policies intersect to exactly that and the added header restricts
 *     nothing else (it carries no other directive, not even default-src).
 *   - `defer`, which is the load-bearing word. A header replacement is NOT
 *     deferred by default: measured, `header Content-Security-Policy <find>
 *     <replace>` on its own ran before the proxy, saw no upstream header, and
 *     changed nothing at all. The old two-line form accidentally deferred its
 *     sibling ops because a bare `-Field` delete adapts to `deferred: true` — so
 *     dropping the X-Frame-Options strip (which is what a `'none'` policy does)
 *     silently un-deferred the rest. Stating `defer` removes that coupling.
 *
 * Content-Security-Policy-Report-Only is deliberately left alone: it blocks
 * nothing, so an app's report-only frame-ancestors cannot veto the platform's
 * policy, and rewriting it would corrupt the app's own violation reports.
 */
function embedHeaderBlock(fa, indent) {
  const inner = indent + '    ';
  return `${indent}header {\n` +
         `${inner}Content-Security-Policy "${CSP_FRAME_ANCESTORS}" "\${1}frame-ancestors ${fa}"\n` +
         `${inner}+Content-Security-Policy "frame-ancestors ${fa}"\n` +
         // A deny-everything policy has no embedder to unlock, so stripping the
         // app's own X-Frame-Options would only discard legacy protection for
         // browsers predating CSP2's frame-ancestors.
         (fa === "'none'" ? '' : `${inner}-X-Frame-Options\n`) +
         `${inner}defer\n` +
         `${indent}}\n`;
}

/**
 * Isolated mode, on the platform host: the old /<slug> address of an app path
 * that machine clients use. Everything else on that address is a 308 to the
 * app host, and a client that does not re-send a POST on a 308 (ureq follows
 * one only for GET, HEAD, OPTIONS and TRACE) got the redirect back as its
 * answer: on crane, 28 Oct 2026, every relayed haivecontrol device went silent
 * for two days while its polls (GET) still followed the redirect.
 *
 * So a request that is NOT a GET or HEAD, to an exempt path (or anywhere in a
 * headless app), is proxied to the app here instead. Safe on the dashboard's
 * origin because nothing of the app runs there as that origin, and nothing of
 * the dashboard reaches the app:
 *   - GET and HEAD still redirect, so a browser never renders an app page here;
 *   - every response carries CSP sandbox (an opaque origin, for a form POST a
 *     browser renders) and nosniff, and loses any Set-Cookie;
 *   - the whole Cookie header is dropped, so the dashboard session never
 *     reaches the app, and forged identity headers are stripped as everywhere;
 *   - the response loses every header a browser applies to the whole origin
 *     (LEGACY_ORIGIN_HEADERS), and HSTS is forced to the platform's value, so
 *     the app cannot clear the dashboard's cookies, weaken its HSTS, grant
 *     itself CORS, or point its error reports at the app.
 */
const LEGACY_ORIGIN_HEADERS = [
  'Set-Cookie', 'Clear-Site-Data', 'Access-Control-*', 'Link', 'Refresh', 'Location',
  'NEL', 'Report-To', 'Reporting-Endpoints', 'Service-Worker-Allowed', 'Origin-Agent-Cluster',
  'Cross-Origin-*', 'Timing-Allow-Origin', 'Content-Security-Policy-Report-Only',
];
function legacyMachineRoute(app, mount, port, bypassPaths, live = true) {
  const paths = !live ? [] : app.auth_mode === 'headless' ? [`${mount}*`] : bypassPaths.map(p => `${mount}${p}*`);
  if (!paths.length) return '';
  return `        @legacy_machine {\n` +
         `            path ${paths.join(' ')}\n` +
         `            not method GET HEAD\n` +
         `        }\n` +
         `        handle @legacy_machine {\n` +
         `            request_header -Cookie\n` +
         identityStrip('            ') +
         authMode('            ', 'bypass') +
         `            uri strip_prefix ${mount}\n` +
         `            header {\n` +
         `                Content-Security-Policy "sandbox"\n` +
         `                X-Content-Type-Options "nosniff"\n` +
         `                >Strict-Transport-Security "max-age=31536000; includeSubDomains"\n` +
         LEGACY_ORIGIN_HEADERS.map(h => `                -${h}\n`).join('') +
         `                defer\n` +
         `            }\n` +
         `            reverse_proxy 127.0.0.1:${port} {\n` +
         `                flush_interval -1\n` +
         `            }\n` +
         `        }\n`;
}

/** The body of an isolated /<slug> handle: the 308, behind the legacy machine
 *  route when there is one. `redir` sorts ahead of `handle` inside a block, so
 *  with a machine route the redirect needs a handle of its own to come second. */
function redirOrLegacy(app, mount, port, bypassPaths, host, live = true) {
  const redir = `redir https://${host}{uri} 308\n`;
  const legacy = legacyMachineRoute(app, mount, port, bypassPaths, live);
  if (!legacy) return `        ${redir}`;
  return legacy + `        handle {\n            ${redir}        }\n`;
}

/**
 * The body of a site block that serves ONE app at the root of its own host:
 * an isolated app host (<slug>.<domain>, <slug>-sandbox.<domain>) or a custom
 * domain with custom_domain_auth = 1. Same security rules as the /<slug>
 * routes on the platform host, with these differences:
 *
 *   - forward_auth asks /api/identity/verify in isolated mode (verifyUri), which
 *     accepts only this host's app-scope cookie and sends a signed-out browser
 *     through the one-time handoff on the platform host.
 *   - /__appcrane/* (handoff landing, sign-out) and exactly /api/me and
 *     /api/directory go to AppCrane with the Host header unchanged, so AppCrane
 *     knows which app and environment is asking.
 *   - prefix (app hosts only): a path that is exactly /<prefix> or under
 *     /<prefix>/ loses that prefix before the app sees it, so links and
 *     APP_BASE_PATH written for the /<slug> mount keep working; any other path
 *     reaches the app unchanged. The rewrite sits inside the route AFTER
 *     forward_auth (`uri` otherwise sorts ahead of it), so verify receives the
 *     original URI in X-Forwarded-Uri and the handoff returns there.
 */
function isolatedSiteBody(o) {
  const { cranePort, port, verifyUri, prefix, isHeadless, fa } = o;
  // A bypass entry under /__appcrane would out-rank the AppCrane route below
  // (longer path wins) and hand the sign-in landing to the app.
  const reserved = RESERVED_APP_PATH.toLowerCase();
  const bypassPaths = o.bypassPaths.filter(p => {
    const lp = p.toLowerCase();
    return lp !== reserved && !lp.startsWith(reserved + '/');
  });
  let s = BASELINE_HEADERS + '\n';
  if (o.refuseBrotli) s += o.refuseBrotli + '\n';
  if (bypassPaths.length) s += bypassAccessLog();
  s += '\n';
  if (prefix) s += `    @appcrane_compat path ${prefix} ${prefix}/*\n\n`;

  for (const p of [`${RESERVED_APP_PATH}/*`, '/api/me', '/api/directory']) {
    s += `    handle ${p} {\n`;
    s += `        reverse_proxy 127.0.0.1:${cranePort}\n`;
    s += `    }\n\n`;
  }

  // Each exempt path at the root and, for a client still using the /<slug>
  // mount (a redirect from the platform host), under the prefix too.
  for (const p of bypassPaths) {
    for (const mount of prefix ? [prefix, ''] : ['']) {
      s += `    handle ${mount}${p}* {\n`;
      s += isolatedCookieStrip('        ');
      s += identityStrip('        ');
      s += authMode('        ', 'bypass');
      if (mount) s += `        uri strip_prefix ${mount}\n`;
      s += `        reverse_proxy 127.0.0.1:${port} {\n`;
      s += `            flush_interval -1\n`;
      s += `            transport http {\n`;
      s += `                read_timeout 0\n`;
      s += `                write_timeout 0\n`;
      s += `            }\n`;
      s += `        }\n`;
      s += `    }\n\n`;
    }
  }

  const compat = prefix ? `uri @appcrane_compat strip_prefix ${prefix}\n` : '';
  s += `    handle {\n`;
  s += authMode('        ', isHeadless ? 'headless' : 'authenticated');
  if (isHeadless) {
    s += isolatedCookieStrip('        ');
    s += identityStrip('        ');
    if (compat) s += `        ${compat}`;
  } else {
    // Same route-wrapped order as emitForwardAuth on the platform host, for the
    // same reasons: strip forged identity, verify, strip the session cookies,
    // then rewrite.
    s += `        route {\n`;
    s += identityStrip('            ');
    s += `            forward_auth 127.0.0.1:${cranePort} {\n`;
    s += `                uri ${verifyUri}\n`;
    s += `                copy_headers ${IDENTITY_HEADERS.join(' ')}\n`;
    s += `            }\n`;
    s += isolatedCookieStrip('            ');
    if (compat) s += `            ${compat}`;
    s += `        }\n`;
  }
  if (fa) s += embedHeaderBlock(fa, '        ');
  s += `        reverse_proxy 127.0.0.1:${port}\n`;
  s += `    }\n`;

  if (prefix) {
    // Crash page: AppCrane names the app from the first path segment, which on
    // an app host is no longer in the URI, so it is put back.
    s += `\n    handle_errors {\n`;
    s += `        @appdown expression \`{err.status_code} in [502, 503, 504]\`\n`;
    s += `        handle @appdown {\n`;
    s += `            rewrite * /api/_crashed${prefix}{uri}\n`;
    s += `            reverse_proxy 127.0.0.1:${cranePort}\n`;
    s += `        }\n`;
    s += `    }\n`;
  }
  return s;
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
  // Per-app origins (services/appOrigin.js): null = off, and then nothing below
  // differs from a box that never had the setting.
  const isoDomain = craneDomain ? isolationDomain(db) : null;
  const isoTls = isoDomain ? isolationTls(db) : null;

  // App hosts without a wildcard certificate get on-demand TLS, which Caddy
  // issues only for a name AppCrane's ask endpoint approves (an existing app).
  // Global options must be the first block of the file, ahead of the import —
  // so they are collected here and put in front of the body on return, once the
  // sites below have decided whether the redacting error logger is needed.
  let globalOpts = '';
  if (isoDomain && !isoTls) {
    globalOpts += `    on_demand_tls {\n`;
    globalOpts += `        ask http://127.0.0.1:${cranePort}/api/identity/tls-ask\n`;
    globalOpts += `    }\n`;
  }
  const withGlobals = (body) => '# Managed by AppCrane - do not edit manually\n\n' +
    (globalOpts ? `{\n${globalOpts}}\n\n` : '') + body;
  let caddyfile = 'import /etc/caddy/sites/*.caddy\n\n';

  if (!craneDomain) {
    caddyfile += '# CRANE_DOMAIN not configured — no routing generated\n';
    return withGlobals(caddyfile);
  }

  caddyfile += `${craneDomain} {\n`;
  if (manualTls) {
    caddyfile += `    tls ${certFile} ${keyFile}\n\n`;
  }

  // ── Baseline security headers for every response on this domain (v2.35.0) ──
  // See BASELINE_HEADERS. The custom-domain site blocks below emit the same
  // constant — a site block inherits nothing from this one.
  caddyfile += BASELINE_HEADERS + '\n';
  const refuseBrotli = brotliGuardEnabled(db) ? BROTLI_REFUSAL : '';
  if (refuseBrotli) caddyfile += refuseBrotli + '\n';

  // Auth-bypass routes are parsed here rather than in the app loop because the
  // answer is needed twice: once to decide whether this site needs the
  // query-redacting access log (a site-level directive, so it has to be written
  // above the loop) and once to emit the routes themselves. parseBypassPaths
  // warns on a bad entry, and parsing twice would log every warning twice.
  const bypassByApp = new Map();
  for (const app of apps) {
    // v2.7.22: a headless app skips forward_auth for everything, so a per-path
    // exemption on it is meaningless — same rule the loop applied inline before.
    const paths = app.auth_mode === 'headless' ? [] : parseBypassPaths(app.auth_bypass_paths, e =>
      log.warn(`[caddy] app ${app.slug}: bad auth_bypass_paths entry — ${e.message} (ignored)`));
    bypassByApp.set(app.id, paths);
  }
  // Only when a bypass route is actually emitted: an env that isn't live gets no
  // handle block, and an install with no exemptions keeps its current behaviour
  // (Caddy logs no access lines at all unless a site asks for them).
  const anyBypassRoute = apps.some(a => bypassByApp.get(a.id).length > 0 &&
    (liveSet.has(`${a.id}:sandbox`) || liveSet.has(`${a.id}:production`)));
  // Isolated: the bypass routes live on the app hosts, not here.
  // Isolated, the old /<slug> address still passes machine requests through
  // (legacyMachineRoute), so the log shows who has not moved yet.
  const anyHeadlessLive = apps.some(a => a.auth_mode === 'headless' &&
    (liveSet.has(`${a.id}:sandbox`) || liveSet.has(`${a.id}:production`)));
  if (anyBypassRoute || (isoDomain && anyHeadlessLive)) caddyfile += bypassAccessLog() + '\n';

  for (const app of apps) {
    const ports = getPortsForSlot(app.slot);
    const slug = app.slug;

    // Permanent redirects for any old slugs (after a rename)
    let aliases = [];
    try { aliases = JSON.parse(app.slug_aliases || '[]'); } catch (_) {}

    // Isolated: no app is served on this host any more. Its /<slug> mounts and
    // old slugs redirect to the app's own host, path and query kept (308, so a
    // POST stays a POST); the app host strips the /<slug> prefix again. An env
    // that is not live keeps its 503, since there is no app host to send it to.
    if (isoDomain) {
      for (const alias of aliases) {
        for (const [env, mount] of [['sandbox', `/${alias}-sandbox`], ['production', `/${alias}`]]) {
          caddyfile += `    handle ${mount}* {\n`;
          caddyfile += redirOrLegacy(app, mount, env === 'sandbox' ? ports.sand_be : ports.prod_be,
            bypassByApp.get(app.id), appHost(db, slug, env), liveSet.has(`${app.id}:${env}`));
          caddyfile += `    }\n\n`;
        }
      }
      for (const [env, mount] of [['sandbox', `/${slug}-sandbox`], ['production', `/${slug}`]]) {
        caddyfile += `    handle ${mount}* {\n`;
        if (liveSet.has(`${app.id}:${env}`)) {
          caddyfile += redirOrLegacy(app, mount, env === 'sandbox' ? ports.sand_be : ports.prod_be,
            bypassByApp.get(app.id), appHost(db, slug, env));
        } else {
          caddyfile += `        respond "Not deployed" 503\n`;
        }
        caddyfile += `    }\n\n`;
      }
      continue;
    }

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
    //
    // v2.44.0: mergeAncestors honours the `'none'` opt-out, so an app's value can
    // now NARROW the platform default instead of only widening it — see
    // utils/embed.js.
    // The column is re-checked here, not trusted: it is written by more than one
    // path, and it lands inside a quoted directive (utils/frameAncestors.js).
    const fa = mergeAncestors(platformFa, safeFrameAncestors(app.frame_ancestors));

    // Emitted identically on the sandbox and production routes below. The ops
    // and the reason each one is there: see embedHeaderBlock.
    const embedHeaders = !fa ? '' : embedHeaderBlock(fa, '        ');

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
    //
    // The strip runs on EVERY route that proxies an app, forward_auth or not.
    // A headless route verifies nobody, which is exactly why it must not let a
    // client hand its own X-AppCrane-Is-Admin to the container: "we don't
    // authenticate" must not degrade into "we accept the caller's word for it".
    const stripIncoming = identityStrip('        ');

    // v2.40.0: the strip and forward_auth must be wrapped in `route`, and this
    // is not cosmetic. Caddy sorts directives by its own fixed order, not by the
    // order they appear in the file, and `forward_auth` sorts AHEAD of
    // `header`/`request_header`. So a strip written above forward_auth compiles
    // BELOW it: copy_headers writes the identity onto the request, and the strip
    // then deletes every one of those headers before the app proxy runs. The
    // app receives nothing.
    //
    // That is not a theory. Adapted with `caddy adapt` and then run against
    // caddy:2 with a live verify upstream and an echo upstream: in the shape
    // this file emitted through v2.39.0 the app received ZERO X-AppCrane-*
    // headers; wrapping the pair in `route` (which preserves written order for
    // its contents) delivers the platform values and still drops forged ones —
    // including headers /verify does NOT issue, which copy_headers alone would
    // leave in place because it only overwrites what it copies.
    //
    // This is the most likely real cause of "app X gets no identity headers",
    // which has been variously blamed on SSO, on the app, and on a stale Caddy
    // process. `uri strip_prefix` still compiles ahead of forward_auth, so
    // X-Forwarded-Uri behaviour and the ?prefix= compensation in identity.js are
    // unchanged.
    //
    // The v2.39.0 cc_token strip has to live INSIDE this route, after
    // forward_auth, and that placement is load-bearing in the other direction.
    // `request_header` sorts after `forward_auth` but BEFORE `route`, so a
    // cookie strip left at handle level compiles ahead of the whole route and
    // /api/identity/verify never sees cc_token. For browser traffic that cookie
    // is the only session source (identity.js reads it when there is no
    // Authorization and no X-API-Key), so /verify would take its
    // `!token && !apiKey` branch and 302 every logged-in visitor to /login —
    // which then bounces them back, forever. Written order inside the route is
    // preserved: verify reads the cookie, then it is stripped before the app.
    const emitForwardAuth = (verifyUri) =>
      `        route {\n` +
      identityStrip('            ') +
      `            forward_auth 127.0.0.1:${cranePort} {\n` +
      `                uri ${verifyUri}\n` +
      `                copy_headers ${IDENTITY_HEADERS.join(' ')}\n` +
      `            }\n` +
      platformCookieStrip('            ') +
      `        }\n`;

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
    // UNCONDITIONAL, like stripIncoming: headless apps skip forward_auth and get
    // no platform identity, but the browser still sends them the cookie, so they
    // need this strip most of all. On the forward_auth path the strip is emitted
    // inside the route by emitForwardAuth instead — see the ordering note there.
    const stripPlatformCookie = platformCookieStrip('        ');

    // v2.7.22: headless apps bypass forward_auth entirely — no identity,
    // no role headers, no per-app verify round-trip. Right tool for pure
    // unauthenticated services (telemetry ingest, public webhooks,
    // status pages). For authenticated apps, the strip + forward_auth +
    // copy_headers pair runs as before.
    const isHeadless = app.auth_mode === 'headless';

    // The mode this app's own /<slug> routes run. Emitted on every proxied
    // request below, headless included — a headless app is precisely the case
    // where "I received no identity" needs an explanation on the wire.
    const stampAuthMode = authMode('        ', isHeadless ? 'headless' : 'authenticated');

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
    //      just because forward_auth is off. Same for the Auth-Mode stamp:
    //      it is set (not added) to 'bypass' so the app can tell "this
    //      request took the exempt path" from "forward_auth is broken",
    //      and so a client cannot claim 'authenticated' on the one route
    //      where nothing verified it.
    //   2. v2.44.0: these routes ARE access-logged, with the query string
    //      redacted by bypassAccessLog() above. They used to carry
    //      `log_skip` — the token aghook puts in the query string would
    //      otherwise have sat in Caddy's log storage — which left the one
    //      deliberately-unauthenticated route class as the only one with no
    //      request record. The filter syntax the old comment could not
    //      verify has now been checked against caddy:2 end to end; see
    //      the comment above ACCESS_LOG_DEFAULT.
    //   3. flush_interval -1 + transport read/write_timeout 0 keep
    //      long-lived idle WS connections from being cut by AppCrane.
    //      Caddy's default global idle_timeout (5m) is far above
    //      aghook's 25s keepalive and is not overridden here.
    // Skipped entirely when the app is headless (whole app is already
    // open) or the env isn't deployed (the parent block already 503's).
    const bypassPaths = bypassByApp.get(app.id);
    // mountPrefix = the per-env path mount, e.g. "/agentclub-sandbox" or
    // "/agentclub". The bypass path P (e.g. "/ws/local-runner") is appended
    // to form the child handle path; the strip_prefix removes the SAME mount
    // so the app sees its native /ws/local-runner.
    const emitBypass = (mountPrefix, bypassPath, port) => {
      caddyfile += `    handle ${mountPrefix}${bypassPath}* {\n`;
      caddyfile += stripPlatformCookie;
      caddyfile += stripIncoming;
      caddyfile += authMode('        ', 'bypass');
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
      caddyfile += stampAuthMode;
      if (isHeadless) {
        caddyfile += stripPlatformCookie;
        caddyfile += stripIncoming;
      } else {
        caddyfile += emitForwardAuth(`/api/identity/verify?app=${slug}&prefix=/${slug}-sandbox`);
      }
      caddyfile += embedHeaders;
      caddyfile += `        uri strip_prefix /${slug}-sandbox\n`;
      caddyfile += `        reverse_proxy 127.0.0.1:${ports.sand_be}\n`;
    } else {
      caddyfile += `        respond "Not deployed" 503\n`;
    }
    caddyfile += `    }\n\n`;

    // Production
    caddyfile += `    handle /${slug}* {\n`;
    if (liveSet.has(`${app.id}:production`)) {
      caddyfile += stampAuthMode;
      if (isHeadless) {
        caddyfile += stripPlatformCookie;
        caddyfile += stripIncoming;
      } else {
        caddyfile += emitForwardAuth(`/api/identity/verify?app=${slug}&prefix=/${slug}`);
      }
      caddyfile += embedHeaders;
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

  // v2.106.0: Crew's A2A endpoint and its discovery card, named explicitly
  // instead of left to the catch-all below. Caddy picks the MOST SPECIFIC
  // matching `handle` path, so an app block left over from before the slug
  // policy (an app or old alias named `a` or `a2`) would otherwise capture
  // /a2a — every agent token sent to it would land in that app. `/a2a*` is
  // longer than any such prefix, so it wins. reverse_proxy flushes
  // text/event-stream responses immediately, which the A2A SSE stream needs.
  caddyfile += `    handle /a2a* {\n`;
  caddyfile += `        reverse_proxy 127.0.0.1:${cranePort}\n`;
  caddyfile += `    }\n\n`;
  // git clone/fetch (routes/gitHttp.js), named for the same reason: an app
  // left over as `g`, `gi` or `git` would otherwise receive every clone's API key.
  caddyfile += `    handle /git/* {\n`;
  caddyfile += `        reverse_proxy 127.0.0.1:${cranePort}\n`;
  caddyfile += `    }\n\n`;
  caddyfile += `    handle /.well-known/agent-card.json {\n`;
  caddyfile += `        reverse_proxy 127.0.0.1:${cranePort}\n`;
  caddyfile += `    }\n\n`;
  // MCP OAuth (routes/oauth.js), named for the same reason as /git/*: a legacy
  // app `o`, `oa`, `oau` or `oauth` would otherwise receive every client's
  // authorization code, refresh token and client secret. The metadata documents
  // cannot be shadowed by a slug (none starts with '.'), but they are what an
  // MCP client trusts to find the token endpoint, so they are pinned too.
  caddyfile += `    handle /oauth/* {\n`;
  caddyfile += `        reverse_proxy 127.0.0.1:${cranePort}\n`;
  caddyfile += `    }\n\n`;
  caddyfile += `    handle /.well-known/oauth-* {\n`;
  caddyfile += `        reverse_proxy 127.0.0.1:${cranePort}\n`;
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

  // ── Per-app hosts (isolation on) ─────────────────────────────────────────
  // One site per live app environment, at the root of its own host. The rules
  // are the /<slug> routes' rules — see isolatedSiteBody. frame-ancestors keeps
  // the app's policy and adds the platform origin, because the dashboard frames
  // apps in its app tabs and is no longer same-origin with them. A policy of
  // 'none' stays 'none' (CSP admits no other source next to it), and an app
  // with no policy is left to its own headers, as on the platform host.
  if (isoDomain) {
    const tlsLine = isoTls
      ? `    tls ${isoTls.cert} ${isoTls.key}\n\n`
      : `    tls {\n        on_demand\n    }\n\n`;
    for (const app of apps) {
      const ports = getPortsForSlot(app.slot);
      const appFa = mergeAncestors(platformFa, safeFrameAncestors(app.frame_ancestors));
      const fa = !appFa || appFa === "'none'" ? appFa : mergeAncestors(appFa, `https://${craneDomain}`);
      for (const [env, prefix, port] of [
        ['sandbox', `/${app.slug}-sandbox`, ports.sand_be],
        ['production', `/${app.slug}`, ports.prod_be],
      ]) {
        if (!liveSet.has(`${app.id}:${env}`)) continue;
        caddyfile += `\n${appHost(db, app.slug, env)} {\n`;
        caddyfile += tlsLine;
        caddyfile += isolatedSiteBody({
          cranePort, port, prefix, fa, refuseBrotli,
          verifyUri: `/api/identity/verify?app=${app.slug}&env=${env}&host=isolated`,
          isHeadless: app.auth_mode === 'headless',
          bypassPaths: bypassByApp.get(app.id),
        });
        caddyfile += `}\n`;
      }
    }
  }

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
  //
  // Auth-Mode is stamped 'bypass' here, the same value the per-path exemption
  // uses: AppCrane is proxying the request but has deliberately not verified
  // anyone on it. Not 'headless' — that names the app's auth_mode column, and an
  // sso app on a custom domain still gets full identity on its /<slug> route, so
  // reporting 'headless' would be a lie about the app's configuration. What the
  // app learns either way is the thing it needs: identity is not coming on THIS
  // request, and the absence is deliberate rather than a broken proxy.
  const emittedDomains = new Set([(craneDomain || '').toLowerCase()]);
  // An app host already has its site block; a custom domain naming one is a
  // duplicate site address, which Caddy refuses.
  if (isoDomain) {
    for (const app of apps) {
      for (const env of ['sandbox', 'production']) {
        if (liveSet.has(`${app.id}:${env}`)) emittedDomains.add(appHost(db, app.slug, env));
      }
    }
  }
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
    // custom_domain_auth = 1: the app's normal AppCrane sign-in on its custom
    // domain too, through the same handoff as an app host (production, no
    // /<slug> prefix to undo, no embedding override, as before). With or
    // without isolation. A headless app has no sign-in to apply.
    if (app.custom_domain_auth && app.auth_mode !== 'headless') {
      caddyfile += isolatedSiteBody({
        cranePort, refuseBrotli,
        port: ports.prod_be,
        prefix: null,
        fa: null,
        verifyUri: `/api/identity/verify?app=${app.slug}&env=production&host=isolated`,
        isHeadless: false,
        bypassPaths: bypassByApp.get(app.id),
      });
      caddyfile += `}\n`;
      continue;
    }
    // v2.44.0: the same baseline the crane domain gets. A site block inherits
    // nothing from another site block, so through v2.43.1 an app on its own
    // hostname was served with no HSTS, no nosniff, no referrer or permissions
    // policy, and with its container's X-Powered-By banner intact — while the
    // same app's /<slug> route under CRANE_DOMAIN had all of it. Caddy holds the
    // TLS cert for this domain (ACME) and serves it over HTTPS, so HSTS is a
    // true statement about it.
    caddyfile += BASELINE_HEADERS;
    caddyfile += refuseBrotli;
    caddyfile += identityStrip('    ');
    caddyfile += authMode('    ', 'bypass');
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

  // Any site that access-logs also gets its error stream redacted; see bypassErrorLog.
  if (caddyfile.includes(bypassAccessLog())) globalOpts += bypassErrorLog();
  return withGlobals(caddyfile);
}

/**
 * Run a command WITHOUT blocking the event loop.
 *
 * Every call below used to be execFileSync. The reload path spends most of a
 * second inside them — `systemctl reload` and, when it escalates, `systemctl
 * restart` — and with execFileSync that is the whole of Node's single thread
 * stopped: AppCrane answered nothing at all for that window, including the
 * health checks that decide whether an app is up, and including the response
 * of the very request that asked for the reload.
 *
 * The rejection carries `.stderr` and `.message` the same way execFileSync's
 * throw did, which is all the callers below read off it.
 */
async function run(file, args, opts) {
  const { execFile } = await import('child_process');
  const { promisify } = await import('util');
  return promisify(execFile)(file, args, opts);
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
      await run('caddy', ['adapt', '--config', tmpPath, '--adapter', 'caddyfile'], {
        timeout: 8000,
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
    await run('systemctl', ['reload', 'caddy'], { timeout: 10000 });

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
        await run('systemctl', ['restart', 'caddy'], { timeout: 15000 });
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
      await run('systemctl', ['restart', 'caddy'], { timeout: 15000 });
      log.info('Caddy restarted (reload failed)');
      return { success: true, restarted: true };
    } catch (e2) {
      log.error(`Caddy restart also failed: ${e2.message}`);
      return { success: false, error: e.message };
    }
  }
}
