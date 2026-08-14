import { readFileSync } from 'fs';
import { join } from 'path';

const FORBIDDEN_ENV_PATTERNS = [
  /ENV\s+\w*(SECRET|PASSWORD|PASS|TOKEN|KEY|CRED|AUTH)\w*\s*=/i,
];

// `USER root`, `USER root:root`, `USER 0`, `USER 00` and `USER 0:0` all land in
// the root namespace. The pre-v2.42.1 check only matched the literal `root`, so
// `USER 0` declared root and passed.
const ROOT_USER = /^(root|0+)(:|$)/i;

// The exact pre-v2.42.1 rule, kept verbatim. See the no-regression guard below.
const HEAD_ROOT_AT_END = /^USER\s+root$/i;

/**
 * Resolve the USER the final build stage actually runs as.
 *
 * A USER instruction applies only to the stage it appears in, and a stage
 * inherits the USER of its parent image — so the *last* USER line in the file
 * is not necessarily the one the container runs as. A multi-stage Dockerfile
 * that sets `USER node` in the build stage and nothing in the final stage runs
 * as root, which the pre-v2.42.1 "last USER line" check reported as safe.
 *
 * Returns the declared user string, or null when the final stage inherits from
 * an external base image we cannot inspect from here (no image is pulled at
 * validation time), i.e. the Dockerfile never states who it runs as.
 */
function finalStageUser(lines) {
  const stages = new Map(); // stage name (lowercased) -> effective USER or null
  let stageName = null;
  let user = null;
  let inStage = false;

  for (const line of lines) {
    // `FROM [--platform=…] <image|stage> [AS <name>]`
    const from = line.match(/^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/i);
    if (from) {
      if (inStage && stageName) stages.set(stageName, user);
      const parent = from[1].toLowerCase();
      stageName = from[2] ? from[2].toLowerCase() : null;
      // Building on an earlier named stage inherits that stage's USER.
      user = stages.has(parent) ? stages.get(parent) : null;
      inStage = true;
      continue;
    }
    const u = line.match(/^USER\s+(\S+)/i);
    // A USER built from a build arg or env var (`USER ${APP_USER}`) cannot be
    // resolved here — no build is run at validation time — and `ARG U=root` /
    // `USER ${U}` is root. Treating the literal `${U}` as a declared non-root
    // name would silence the missing-USER finding for a root container, so an
    // unresolvable value counts as not declared.
    if (u && inStage) user = u[1].includes('$') ? null : u[1];
  }

  return user;
}

/**
 * Drop the bodies of BuildKit heredocs (`COPY <<EOF …`), which are file
 * contents, not instructions. Without this, a config written inline is parsed
 * as Dockerfile: an nginx.conf whose first line is `user nginx;` reads as a
 * declared non-root USER and silences the finding for a root container.
 *
 * Fails open — if the terminator never appears the whole file is kept, so a
 * stray `<<` in a shell command cannot swallow a real USER line and turn a
 * passing Dockerfile into a failing one.
 */
function stripHeredocs(rawLines) {
  const out = [];
  for (let i = 0; i < rawLines.length; i++) {
    const open = rawLines[i].match(/<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?/);
    out.push(rawLines[i]);
    if (!open) continue;
    const end = rawLines.findIndex((l, j) => j > i && l.trim() === open[1]);
    if (end === -1) continue; // no terminator — keep everything
    i = end;
  }
  return out;
}

/**
 * Validate a user-provided Dockerfile.
 * Returns { valid: true } or { valid: false, errors: [...], warnings: [...] }
 *
 * Rules:
 *  - Must EXPOSE a port (must match expectedPort if provided)
 *  - Final build stage must declare a non-root USER
 *  - Must not hardcode secrets in ENV instructions
 *  - Must not override managed env vars (APP_BASE_PATH, CRANE_URL, DATA_DIR)
 *  - Must not bind-mount or reference /data in VOLUME (AppCrane manages that)
 */
export function validateDockerfile(releaseDir, { expectedPort } = {}) {
  const path = join(releaseDir, 'Dockerfile'); // nosemgrep: path-join-resolve-traversal — releaseDir is an internal computed path
  let content;
  try {
    content = readFileSync(path, 'utf8');
  } catch (_) {
    return { valid: false, errors: ['Dockerfile not found'], warnings: [] };
  }

  const errors = [];
  const warnings = [];
  const lines = content.split('\n').map(l => l.trim()).filter(Boolean);

  // --- EXPOSE check ---
  const exposePorts = [];
  for (const line of lines) {
    const m = line.match(/^EXPOSE\s+(\d+)/i);
    if (m) exposePorts.push(parseInt(m[1], 10));
  }
  if (!exposePorts.length) {
    errors.push('Dockerfile must include an EXPOSE instruction (e.g. EXPOSE 3000)');
  } else if (expectedPort && !exposePorts.includes(expectedPort)) {
    errors.push(`Dockerfile EXPOSE ${exposePorts.join(',')} does not match expected port ${expectedPort} from crane.yaml`);
  }

  // --- Non-root USER in the final stage ---
  // A container with no USER runs as root, which is the case the "last USER
  // line" check missed entirely: root is what you get by *omission*, so the
  // common Dockerfile — no USER anywhere — was the one that slipped through.
  //
  // Declaring root explicitly is a deliberate act, so it stays a hard error.
  // *Omitting* USER is what most existing apps do, and failing them all at once
  // would take the platform down on upgrade rather than secure it — so a missing
  // USER is a loud per-deploy warning by default, and a hard error once the
  // operator sets APPCRANE_REQUIRE_NONROOT=1 (same opt-in-to-enforce shape as
  // APPCRANE_AUDIT_REQUIRED). Once the fleet's Dockerfiles declare a USER, the
  // operator flips the flag and omission becomes unshippable.
  const instructions = stripHeredocs(lines);
  const runAs = finalStageUser(instructions);

  // No-regression guard. Scoping the check to the final stage is the correct
  // analysis, but pairing it with warn-by-default made one real shape WEAKER
  // than before: `USER root` in a NON-final stage with no USER in the final
  // stage was the file's last USER line, so the old rule BLOCKED the deploy —
  // and the final-stage rule alone would only warn, quietly shipping a container
  // that runs as uid 0 where the author was previously forced to fix it. This
  // re-applies the old rule verbatim (same regex, same whole-file "last USER
  // line" reading), so it can only block what already fails to deploy today.
  const userLines = instructions.filter(l => /^USER\s+/i.test(l));
  const lastUser = userLines[userLines.length - 1];
  const rootAtEndUnderOldRule = Boolean(lastUser) && HEAD_ROOT_AT_END.test(lastUser);

  if (runAs !== null && ROOT_USER.test(runAs)) {
    errors.push(`Container must not run as root (final stage declares USER ${runAs}). Add "USER <non-root-user>" after your setup steps.`);
  } else if (rootAtEndUnderOldRule) {
    errors.push(`Container must not run as root (the last USER instruction is "${lastUser}"). Add "USER <non-root-user>" to the final build stage.`);
  } else if (runAs === null) {
    const fix =
      'Container runs as root: the final build stage declares no USER. ' +
      'Add "USER <non-root-user>" (e.g. "USER node") after your setup steps. ' +
      'Declare it even if your base image is already non-root, so a base-image ' +
      'change cannot silently hand the container back to root.';
    if (process.env.APPCRANE_REQUIRE_NONROOT === '1') {
      errors.push(fix);
    } else {
      warnings.push(`${fix} This is a warning today and will become a deploy-blocking error.`);
    }
  }

  // --- Hardcoded secrets ---
  for (const line of lines) {
    for (const pattern of FORBIDDEN_ENV_PATTERNS) {
      if (pattern.test(line)) {
        errors.push(`Do not hardcode secrets in Dockerfile ENV: "${line.slice(0, 80)}". Use AppCrane env vars instead.`);
        break;
      }
    }
  }

  // --- Managed env vars override ---
  // APP_BASE_PATH is no longer runtime-managed (build-arg only); your Dockerfile
  // can declare ARG APP_BASE_PATH to receive it at build time.
  const MANAGED_VARS = ['CRANE_URL', 'CRANE_INTERNAL_URL', 'DATA_DIR'];
  for (const line of lines) {
    if (!/^ENV\s+/i.test(line)) continue;
    for (const v of MANAGED_VARS) {
      if (line.includes(v)) {
        warnings.push(`ENV ${v} is managed by AppCrane at runtime — your Dockerfile value will be overridden.`);
      }
    }
  }

  // --- VOLUME /data ---
  for (const line of lines) {
    if (/^VOLUME\b/i.test(line) && line.includes('/data')) {
      warnings.push('VOLUME /data is managed by AppCrane. Your VOLUME instruction may conflict with the mounted data directory.');
    }
  }

  // --- FROM must exist ---
  const hasFrom = lines.some(l => /^FROM\s+/i.test(l));
  if (!hasFrom) {
    errors.push('Dockerfile must start with a FROM instruction.');
  }

  return { valid: errors.length === 0, errors, warnings };
}
