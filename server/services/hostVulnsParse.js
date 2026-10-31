// Parsers for the host-vulnerability check (hostVulns.js). Pure functions over
// command output, so the tests can feed them output captured from real Ubuntu
// and Debian machines.

/**
 * `pro security-status --format json` (ubuntu-pro-client, _schema_version 0.1).
 * Fields relied on, as measured on 20.04, 22.04 and 24.04:
 *   packages[]: { package, version, service_name, status, origin, download_size }
 *   summary.reboot_required: "yes" | "no"
 * `version` is the CANDIDATE; pro does not report the installed version.
 * Only status "upgrade_available" can be installed now; anything else (an ESM
 * update that needs an attached Pro subscription) is counted, not listed.
 * Returns null when the output is not that shape, so the caller falls back to apt.
 */
export function parseProSecurityStatus(stdout) {
  let j;
  try { j = JSON.parse(stdout); } catch (_) { return null; }
  if (!j || !Array.isArray(j.packages)) return null;
  const packages = [];
  let unavailable = 0;
  for (const p of j.packages) {
    if (p.status !== 'upgrade_available') { unavailable++; continue; }
    packages.push({ name: String(p.package), installed: null, candidate: String(p.version), service: p.service_name || null });
  }
  return { packages, unavailable, schema: j._schema_version ?? null };
}

// `apt-get -s dist-upgrade` lines, measured:
//   Inst libc6 [2.31-0ubuntu9.17] (2.31-0ubuntu9.18 Ubuntu:20.04/focal-updates, Ubuntu:20.04/focal-security [amd64])
//   Inst tzdata [2026e-0+deb12u1] (2026f-0+deb12u1 Debian-Security:12/oldstable-security [all])
//   Inst openssl (3.0.2-0ubuntu1.30 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])   <- newly installed, no [installed]
const INST = /^Inst (\S+) (?:\[([^\]]+)\] )?\((\S+) (.+) \[[^\]]+\]\)\s*$/;

/**
 * Security upgrades from a simulated dist-upgrade: an Inst line is security
 * when one of its sources is a "-security" pocket. dist-upgrade, not upgrade,
 * because a kernel security fix arrives as new packages that `upgrade` holds back.
 */
export function parseAptSimulate(stdout) {
  const packages = [];
  for (const line of String(stdout).split('\n')) {
    const m = INST.exec(line);
    if (!m) continue;
    const sources = m[4].split(',').map((s) => s.trim());
    if (!sources.some((s) => /-security$/.test(s))) continue;
    packages.push({ name: m[1], installed: m[2] || null, candidate: m[3], service: null });
  }
  return { packages };
}

/** `dpkg-query -W -f='${Package} ${Version}\n' a b c` -> Map(name -> version). */
export function parseDpkgVersions(stdout) {
  const out = new Map();
  for (const line of String(stdout).split('\n')) {
    const m = /^(\S+) (\S+)$/.exec(line.trim());
    if (m) out.set(m[1], m[2]);
  }
  return out;
}

/**
 * `apt-config dump APT::Periodic`: the merged value of every apt.conf.d file,
 * which is what apt.systemd.daily acts on (20auto-upgrades alone can be
 * overridden by a later file, as Docker's ubuntu image does with Enable "0").
 * An interval of 0 or a missing key means off.
 */
export function parseAptPeriodic(stdout) {
  const v = {};
  for (const line of String(stdout).split('\n')) {
    const m = /^APT::Periodic::(\S+) "(.*)";$/.exec(line.trim());
    if (m) v[m[1]] = m[2];
  }
  const on = (k) => v[k] != null && v[k] !== '' && v[k] !== '0';
  return {
    updatePackageLists: v['Update-Package-Lists'] ?? null,
    unattendedUpgrade: v['Unattended-Upgrade'] ?? null,
    periodicEnable: v.Enable ?? null,
    enabled: on('Update-Package-Lists') && on('Unattended-Upgrade') && v.Enable !== '0',
  };
}

/** /etc/os-release -> { id, idLike[], versionId, prettyName }. */
export function parseOsRelease(text) {
  const v = {};
  for (const line of String(text).split('\n')) {
    const m = /^([A-Z_]+)=(.*)$/.exec(line.trim());
    if (m) v[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return {
    id: v.ID || null,
    idLike: (v.ID_LIKE || '').split(/\s+/).filter(Boolean),
    versionId: v.VERSION_ID || null,
    prettyName: v.PRETTY_NAME || null,
  };
}

/** /var/run/reboot-required.pkgs: one package per line, repeats possible. */
export function parseRebootPkgs(text) {
  return [...new Set(String(text || '').split('\n').map((s) => s.trim()).filter(Boolean))];
}
