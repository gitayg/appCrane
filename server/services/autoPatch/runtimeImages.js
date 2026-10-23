// Fresh base images on every build, and a record of which base each image was
// built on.
//
// `docker build` without --pull reuses whatever copy of `FROM php:8.3-apache`
// the host already has, so a host that cached the tag before a security
// release keeps building on the old runtime for as long as the cache lives.
// Measured on Docker 29.6.1 / buildx 0.35.0 with a FROM whose registry is
// unreachable but whose tag is cached locally:
//
//   BuildKit, --pull     fails: "failed to resolve source metadata for ..."
//   BuildKit, no --pull  builds on the cached copy
//   classic,  --pull     fails: "failed to resolve reference ..."
//   classic,  no --pull  builds on the cached copy
//
// So --pull alone would turn every offline or rate-limited build into a failed
// deploy. Instead each literal base is pulled first with `docker pull`; a pull
// that fails leaves the cached copy in place and puts a warning in the deploy
// log, and the build then runs without --pull on what is local (both builders
// use the local image store, measured above). Only a FROM AppCrane cannot read
// as a literal reference (an ARG in an app's own Dockerfile) makes the build
// itself run with --pull, retried once without it when the failure is a pull
// failure.
//
// The final stage's base and the digest it resolved to are written onto the
// built image as labels, which is how runtime patching later knows what an
// image was built on.

import { readFileSync } from 'fs';
import { join } from 'path';

export const BASE_IMAGE_LABEL = 'appcrane.base.image';
export const BASE_DIGEST_LABEL = 'appcrane.base.digest';
export const APP_DOCKERFILE_PULL_KEY = 'pull_base_images_app_dockerfiles';

const PULL_FAILURE = [
  /failed to resolve source metadata/i,
  /failed to resolve reference/i,
  /toomanyrequests/i,
  /pull access denied/i,
  /error pulling image configuration/i,
  /TLS handshake timeout/i,
  /i\/o timeout/i,
  /no such host/i,
  /connection refused/i,
];

export const isPullFailure = (out) => PULL_FAILURE.some((re) => re.test(String(out || '')));

/** Pull bases for an app's own Dockerfile? Platform setting, ON unless an admin stored 'false'. */
export function pullForAppDockerfiles(db) {
  const raw = db?.prepare('SELECT value FROM settings WHERE key = ?').get(APP_DOCKERFILE_PULL_KEY)?.value ?? null;
  return raw === null ? true : String(raw).trim().toLowerCase() !== 'false';
}

/** The FROM lines of a Dockerfile: [{ ref, stage, literal }]. */
export function parseFroms(text) {
  const out = [];
  const lines = String(text || '').replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const raw of lines) {
    const m = raw.match(/^\s*FROM\s+(.+)$/i);
    if (!m) continue;
    const words = m[1].trim().split(/\s+/).filter((w) => !w.startsWith('--'));
    if (!words.length) continue;
    const ref = words[0];
    const asIdx = words.findIndex((w, i) => i > 0 && w.toLowerCase() === 'as');
    const stage = asIdx > 0 && words[asIdx + 1] ? words[asIdx + 1].toLowerCase() : null;
    out.push({ ref, stage, literal: !ref.includes('$') });
  }
  return out;
}

/** External images a build needs: literal ones to pull, and whether any could not be read. */
export function pullPlan(froms) {
  const stages = new Set();
  const pull = [];
  let unreadable = false;
  for (const f of froms) {
    const isStage = stages.has(f.ref.toLowerCase());
    if (f.stage) stages.add(f.stage);
    if (isStage || f.ref.toLowerCase() === 'scratch') continue;
    if (!f.literal) { unreadable = true; continue; }
    if (!pull.includes(f.ref)) pull.push(f.ref);
  }
  return { pull, unreadable };
}

/** The external image the final stage runs on (following stage aliases), or null. */
export function finalBase(froms) {
  const byStage = new Map();
  for (const f of froms) if (f.stage) byStage.set(f.stage, f);
  let cur = froms[froms.length - 1];
  for (let hops = 0; cur && hops < froms.length; hops++) {
    const next = byStage.get(cur.ref.toLowerCase());
    if (!next || next === cur) break;
    cur = next;
  }
  if (!cur || !cur.literal || cur.ref.toLowerCase() === 'scratch' || byStage.has(cur.ref.toLowerCase())) return null;
  return cur.ref;
}

/** { registry, repo, tag, digest } for a reference, Docker Hub defaults applied. */
export function normalizeRef(ref) {
  let rest = String(ref);
  let digest = null;
  const at = rest.indexOf('@');
  if (at >= 0) { digest = rest.slice(at + 1); rest = rest.slice(0, at); }
  const parts = rest.split('/');
  let registry = 'docker.io';
  if (parts.length > 1 && (parts[0].includes('.') || parts[0].includes(':') || parts[0] === 'localhost')) registry = parts.shift();
  let last = parts.pop();
  let tag = null;
  const colon = last.lastIndexOf(':');
  if (colon >= 0) { tag = last.slice(colon + 1); last = last.slice(0, colon); }
  parts.push(last);
  let repo = parts.join('/');
  if (registry === 'docker.io' && !repo.includes('/')) repo = `library/${repo}`;
  return { registry, repo, tag: tag || (digest ? null : 'latest'), digest };
}

/** The digest in a RepoDigests list that belongs to `ref`'s repository. */
export function digestFor(ref, repoDigests) {
  const want = normalizeRef(ref);
  for (const entry of repoDigests || []) {
    const n = normalizeRef(entry);
    if (n.registry === want.registry && n.repo === want.repo && n.digest) return n.digest;
  }
  return null;
}

/**
 * Pull each base, then resolve the final base's digest.
 * `run(args, opts)` runs a docker command and resolves stdout or rejects.
 * Returns { buildPull, labelArgs, base: { image, digest } | null, warnings }.
 */
export async function prepareBuildBase({ contextDir, dockerfileText, appDockerfile = false, db, run, onLog }) {
  let text = dockerfileText;
  if (text == null) {
    try { text = readFileSync(join(contextDir, 'Dockerfile'), 'utf8'); } catch (_) { text = ''; }
  }
  const froms = parseFroms(text);
  const { pull, unreadable } = pullPlan(froms);
  const wanted = !appDockerfile || pullForAppDockerfiles(db);
  const warnings = [];
  if (wanted) {
    for (const ref of pull) {
      try {
        await run(['pull', '--quiet', ref], { timeout: 5 * 60 * 1000 });
        onLog?.(`Pulled the latest ${ref}`);
      } catch (e) {
        const why = String(e?.message || e).split('\n').map((l) => l.trim()).filter(Boolean).pop() || 'unknown error';
        const w = `⚠ Could not pull a fresh ${ref} (${why.slice(0, 300)}); building on the copy already on this host, which may be missing security fixes.`;
        warnings.push(w);
        onLog?.(w);
      }
    }
  } else if (pull.length) {
    onLog?.(`Not pulling ${pull.join(', ')}: pulling bases for app Dockerfiles is turned off in Settings`);
  }
  const image = finalBase(froms);
  let digest = null;
  if (image) {
    try { digest = digestFor(image, JSON.parse(await run(['image', 'inspect', image, '--format', '{{json .RepoDigests}}'], { timeout: 30000 }) || '[]')); } catch (_) { digest = null; }
  }
  const labelArgs = image ? ['--label', `${BASE_IMAGE_LABEL}=${image}`, ...(digest ? ['--label', `${BASE_DIGEST_LABEL}=${digest}`] : [])] : [];
  return { buildPull: wanted && unreadable, labelArgs, base: image ? { image, digest } : null, warnings };
}

/**
 * Run the build; when it was asked to --pull and failed on the pull, run it
 * once more without --pull on the cached copy, with a warning.
 * `runBuild(args)` resolves on success and rejects with the build output.
 */
export async function buildWithPullFallback({ args, buildPull, runBuild, onLog }) {
  if (!buildPull) return runBuild(args);
  const withPull = [args[0], '--pull', ...args.slice(1)];
  try {
    return await runBuild(withPull);
  } catch (e) {
    if (!isPullFailure(e?.message)) throw e;
    onLog?.('⚠ Could not pull a fresh base image for this build; building again on the copies already on this host, which may be missing security fixes.');
    return runBuild(args);
  }
}

/** Distinct tag for a rebuild of the same commit, so the image it replaces keeps its own tag. */
export const freshBaseTag = (tag, now = Date.now()) => `${tag}-rt${now.toString(36)}`;
