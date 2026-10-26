// Is this runtime version affected by a known remote-code-execution advisory,
// and is there a fix on the same branch?
//
// Source of truth is OSV. OSV has no ecosystem for the PHP interpreter itself
// (Packagist is Composer packages), but it carries PHP runtime advisories under
// ecosystem "Bitnami", package "php", with SEMVER ranges (measured 2026-10-22:
// POST /v1/query {php, Bitnami, 8.3.30} returned 24 advisories including
// BIT-php-2026-109618 and BIT-php-2026-109619; /v1/vulns/CVE-2026-109618 itself
// was a 404). Only advisories classifyAdvisory() calls code execution count.
//
// runtime-advisories.json is merged in, so a host that cannot reach OSV still
// knows PHP2Shell. Node is added the same way: a RUNTIMES entry naming the
// image env var and the OSV package (Bitnami "node"), plus list entries.
// Measured 2026-10-23: POST /v1/query {node, Bitnami, 22.22.0} returns
// BIT-node-2026-111497 (alias CVE-2026-111497) with ranges fixed 22.23.4 /
// 24.22.1 / 26.12.1 and nothing for 25.x, which Node no longer patches; the
// bundled entry also covers 25. A Node release line is its major (22.x), where
// a PHP branch is major.minor (8.3), so `branch` says which a runtime uses.

import { readFileSync } from 'fs';
import { classifyAdvisory } from './classify.js';

const OSV_QUERY = 'https://api.osv.dev/v1/query';
const TIMEOUT_MS = 20_000;

export const RUNTIMES = Object.freeze({
  php: { label: 'PHP', env: 'PHP_VERSION', probe: ['php', '-r', 'echo PHP_VERSION;'], osv: { ecosystem: 'Bitnami', name: 'php' }, enabled: true },
  node: { label: 'Node.js', env: 'NODE_VERSION', probe: ['node', '-p', 'process.versions.node'], osv: { ecosystem: 'Bitnami', name: 'node' }, enabled: true, branch: 'major' },
});

export function loadBundled() {
  return JSON.parse(readFileSync(new URL('./runtime-advisories.json', import.meta.url), 'utf8'));
}

/** [major, minor, patch, pre] or null. A pre-release (8.5.0RC2) sorts below its release. */
export function parseVersion(v) {
  const m = String(v || '').trim().match(/^v?(\d+)\.(\d+)(?:\.(\d+))?(.*)$/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3] || 0), m[4] ? 1 : 0];
}

export function compareVersions(a, b) {
  const x = parseVersion(a);
  const y = parseVersion(b);
  if (!x || !y) throw new Error(`not a version: ${!x ? a : b}`);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return y[3] - x[3];
}

export const branchOf = (v, runtime) => {
  const p = parseVersion(v);
  if (!p) return null;
  return RUNTIMES[runtime]?.branch === 'major' ? `${p[0]}.x` : `${p[0]}.${p[1]}`;
};

/**
 * Where `version` falls in OSV SEMVER `events`.
 * { affected: false } | { affected: true, fixed: string|null, sameBranch: boolean }
 */
export function fixFor(version, events, runtime) {
  let introduced = null;
  for (const e of events || []) {
    if (e.introduced !== undefined) { introduced = e.introduced; continue; }
    const end = e.fixed ?? e.last_affected;
    if (introduced === null || end === undefined) continue;
    const from = introduced === '0' ? '0.0.0' : introduced;
    const inside = compareVersions(version, from) >= 0
      && (e.fixed !== undefined ? compareVersions(version, e.fixed) < 0 : compareVersions(version, e.last_affected) <= 0);
    if (inside) {
      if (e.fixed === undefined) return { affected: true, fixed: null, sameBranch: false };
      return { affected: true, fixed: e.fixed, sameBranch: branchOf(e.fixed, runtime) === branchOf(version, runtime) };
    }
    introduced = null;
  }
  if (introduced !== null && compareVersions(version, introduced === '0' ? '0.0.0' : introduced) >= 0) {
    return { affected: true, fixed: null, sameBranch: false };
  }
  return { affected: false };
}

function cveOf(id, aliases) {
  return [id, ...(aliases || [])].find((a) => /^CVE-\d{4}-\d+$/.test(a)) || id;
}

function osvEvents(record, pkg) {
  const events = [];
  for (const a of record.affected || []) {
    if (a.package?.ecosystem !== pkg.ecosystem || a.package?.name !== pkg.name) continue;
    for (const r of a.ranges || []) if (r.type === 'SEMVER' || r.type === 'ECOSYSTEM') events.push(...(r.events || []));
  }
  return events;
}

/** OSV records for this runtime version, or throws when OSV cannot be asked. */
export async function queryOsvRuntime(runtime, version, fetchFn = fetch) {
  const pkg = RUNTIMES[runtime].osv;
  const res = await fetchFn(OSV_QUERY, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package: pkg, version }), signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`OSV returned HTTP ${res.status}`);
  return (await res.json())?.vulns || [];
}

/**
 * Every RCE advisory affecting `version`, from OSV and the bundled list.
 * Returns { runtime, version, affected, advisories: [{ id, aliases, summary, fixed, sameBranch, source }],
 *   fixedVersion, unsupportedBranch, osv: 'ok'|'unreachable' }.
 * fixedVersion is the lowest same-branch version that fixes every advisory;
 * unsupportedBranch is true when at least one has no fix on this branch.
 */
export async function runtimeAdvisories(runtime, version, { osvRecords, fetchFn = fetch, bundled = loadBundled() } = {}) {
  const pkg = RUNTIMES[runtime]?.osv;
  if (!pkg || !parseVersion(version)) throw new Error(`cannot check ${runtime} ${version}`);
  let records = osvRecords;
  let osv = 'ok';
  if (!records) {
    try { records = await queryOsvRuntime(runtime, version, fetchFn); } catch (_) { records = []; osv = 'unreachable'; }
  }
  const found = new Map();
  for (const r of records) {
    if (!classifyAdvisory(r).rce) continue;
    const f = fixFor(version, osvEvents(r, pkg), runtime);
    if (!f.affected) continue;
    const id = cveOf(r.id, r.aliases);
    found.set(id, { id, aliases: [r.id, ...(r.aliases || [])].filter((a) => a !== id), summary: r.summary || '', fixed: f.fixed, sameBranch: f.sameBranch, source: 'osv' });
  }
  for (const b of bundled.advisories || []) {
    if (b.runtime !== runtime || found.has(b.id)) continue;
    const f = fixFor(version, b.events, runtime);
    if (!f.affected) continue;
    found.set(b.id, { id: b.id, aliases: b.aliases || [], summary: b.summary || '', fixed: f.fixed, sameBranch: f.sameBranch, source: 'bundled', campaign: b.campaign || null });
  }
  const advisories = [...found.values()].sort((a, b) => a.id.localeCompare(b.id));
  const unsupportedBranch = advisories.some((a) => !a.sameBranch);
  let fixedVersion = null;
  if (advisories.length && !unsupportedBranch) {
    fixedVersion = advisories.map((a) => a.fixed).reduce((m, v) => (compareVersions(v, m) > 0 ? v : m));
  }
  return { runtime, version, affected: advisories.length > 0, advisories, fixedVersion, unsupportedBranch, osv };
}
