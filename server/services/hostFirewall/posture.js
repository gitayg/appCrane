import { getDb } from '../../db.js';
import { IMDS_FIX } from '../secretsProvider/imdsProbe.js';
import { defaultRun } from './exec.js';
import { dbPorts, readDockerPublishes, computeDesired } from './desired.js';
import { CHAIN, SKELETON_CHAIN, FAMILIES, parseChain, sameEntries, permissionDenied, HELPER } from './rules.js';
import { readHostNet, isPublicAddr, defaultReadFile, readHostNetworkState, stateSaysEnforcing, HOST_NETWORK_STATE } from './hostNet.js';
import { parseRules, evaluateInput } from './inputEval.js';

// The host's real network posture, read from the rules the kernel holds and
// the sockets that are listening. Nothing here sends a packet off the host.

export const SEVERITY_ORDER = Object.freeze({ high: 0, medium: 1, low: 2, info: 3 });
const HARDENING_FIX = 'Apply Host limits on this page, or run sudo bash scripts/host-hardening.sh on the server.';

export function tableArgs() { return ['-w', '-S']; }
export const SS_ARGS = Object.freeze(['-Hltn']);

/** { policy, unconditionalDrop, dockerUser: [lines], chain, rules } from `iptables -S`. */
export function parseTable(text) {
  const lines = String(text || '').split('\n').map(l => l.trim()).filter(Boolean);
  const policy = /^-P INPUT (\S+)$/m.exec(lines.join('\n'))?.[1] || null;
  const dockerUser = lines.filter(l => l.startsWith(`-A ${SKELETON_CHAIN} `));
  const unconditionalDrop = lines.some(l => /^-A INPUT -j (DROP|REJECT)\b/.test(l));
  return {
    policy,
    unconditionalDrop,
    dockerUser,
    chain: parseChain(text),
    rules: parseRules(text),
  };
}

/** How DOCKER-USER sends external traffic through APPCRANE-PUBLISH. */
export function skeletonState(dockerUser, ext) {
  const jumpAt = dockerUser.findIndex(l => new RegExp(`-j ${CHAIN}$`).test(l));
  if (jumpAt < 0) return { state: 'not_applied', iface: null };
  const iface = / -i (\S+)/.exec(dockerUser[jumpAt])?.[1] || null;
  const dropAt = dockerUser.findIndex((l, i) => i > jumpAt && l === `-A ${SKELETON_CHAIN} -i ${iface} -j DROP`);
  if (!iface || dropAt < 0) return { state: 'no_drop', iface };
  if (ext && iface !== ext) return { state: 'wrong_interface', iface };
  return { state: 'applied', iface };
}

/** Addresses a TCP port listens on, from `ss -Hltn`. */
export function listenAddrs(text, port) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const cols = line.trim().split(/\s+/);
    const local = cols[3];
    if (!local) continue;
    const i = local.lastIndexOf(':');
    if (Number(local.slice(i + 1)) !== port) continue;
    out.push(local.slice(0, i).replace(/^\[|\]$/g, '').replace(/%.*$/, ''));
  }
  return [...new Set(out)];
}

const coversV4 = (a) => a === '*' || a === '0.0.0.0' || /^\d+\.\d+\.\d+\.\d+$/.test(a);
const coversV6 = (a) => a === '*' || a.includes(':');

let imdsCache = null;
export function getCachedImds() { return imdsCache; }
export function setCachedImds(result, at = Date.now()) { imdsCache = { at, result }; }
export function _resetPostureForTests() { imdsCache = null; }

async function readFamily(run, fam) {
  const r = await run(fam.bin, tableArgs());
  if (r.missing) return { state: 'no_binary' };
  if (r.code !== 0) return { state: permissionDenied(r.stderr) ? 'no_permission' : 'error', error: (r.error || r.stderr || `exit ${r.code}`).trim().split('\n')[0] };
  return { state: 'read', table: parseTable(r.stdout) };
}

function finding(id, severity, message, fix) {
  return { id, severity, message, fix };
}

/**
 * { applicable, at, findings, families, listen, imds, desired, strays, docker }.
 * deps: { platform, run, port, lastSync }.
 */
export async function computePosture({ deps = {}, db = getDb(), now = Date.now() } = {}) {
  const platform = deps.platform ?? process.platform;
  const run = deps.run ?? defaultRun;
  const port = deps.port ?? Number(process.env.PORT || 5001);
  const lastSync = deps.lastSync ?? null;
  const uid = deps.uid !== undefined ? deps.uid : (typeof process.getuid === 'function' ? process.getuid() : null);
  const at = new Date(now).toISOString();
  if (platform !== 'linux') {
    return { applicable: false, at, reason: 'Not applicable: AppCrane is not running on Linux, so there is no host firewall to read.', findings: [], families: {}, desired: [], strays: [] };
  }

  const findings = [];
  const families = {};
  const net = await readHostNet(run);
  const state = readHostNetworkState(deps.readFile ?? defaultReadFile);
  for (const fam of FAMILIES) {
    const f = await readFamily(run, fam);
    const ext = net.ext[fam.id];
    families[fam.id] = { state: f.state, error: f.error || null, ext_interface: ext };
    if (f.state === 'no_permission') {
      Object.assign(families[fam.id], { skeleton: stateSaysEnforcing(state) ? 'applied' : 'not_applied', skeleton_source: 'state' });
    }
    if (f.state !== 'read') continue;
    const sk = skeletonState(f.table.dockerUser, ext);
    Object.assign(families[fam.id], {
      input_policy: f.table.policy,
      skeleton: sk.state,
      skeleton_source: 'rules',
      skeleton_interface: sk.iface,
      docker_user: f.table.dockerUser,
      chain: f.table.chain,
      table: f.table,
    });
  }

  if (families.v4.state === 'no_binary') {
    return { applicable: false, at, reason: 'Not applicable: iptables is not installed on this host.', findings: [], families: stripTables(families), desired: [], strays: [] };
  }

  const dockerRead = await readDockerPublishes(run);
  const desired = computeDesired(dbPorts(db), dockerRead, net);

  for (const fam of FAMILIES) {
    const f = families[fam.id];
    const label = fam.id === 'v4' ? 'IPv4' : 'IPv6';
    if (f.state === 'no_binary') {
      findings.push(finding(`firewall-unreadable-${fam.id}`, 'info', `${fam.bin} is not installed, so the ${label} firewall was not read.`, null));
      continue;
    }
    if (f.state !== 'read') {
      const expected = f.state === 'no_permission' && uid !== 0;
      findings.push(finding(`firewall-unreadable-${fam.id}`, expected ? 'info' : f.state === 'no_permission' ? 'medium' : 'low',
        expected
          ? `AppCrane is not root, so it cannot read the ${label} firewall; the host network findings here come from host hardening's state file (${HOST_NETWORK_STATE}).`
          : `The ${label} firewall could not be read: ${f.error}`,
        f.state === 'no_permission' && !expected ? 'AppCrane runs as root but the kernel refused it; check the unit for a capability bounding set.' : null));
      if (f.state === 'no_permission' && f.skeleton === 'not_applied') {
        findings.push(finding(`host-network-not-applied-${fam.id}`, 'high',
          `Host network section not applied (${label}), according to host hardening's state file: ${SKELETON_CHAIN} does not drop what ${CHAIN} leaves, so every port Docker publishes on 0.0.0.0 is reachable from the internet, whatever ufw says.`,
          HARDENING_FIX));
      }
      continue;
    }
    if (f.skeleton === 'not_applied') {
      findings.push(finding(`host-network-not-applied-${fam.id}`, 'high',
        `Host network section not applied (${label}): ${SKELETON_CHAIN} does not send external traffic through ${CHAIN}, so every port Docker publishes on 0.0.0.0 is reachable from the internet, whatever ufw says.`,
        HARDENING_FIX));
    } else if (f.skeleton === 'no_drop') {
      findings.push(finding(`host-network-no-drop-${fam.id}`, 'high',
        `${SKELETON_CHAIN} (${label}) jumps to ${CHAIN} but does not drop what it leaves, so ports AppCrane did not publish are still reachable.`,
        HARDENING_FIX));
    } else if (f.skeleton === 'wrong_interface') {
      findings.push(finding(`host-network-interface-${fam.id}`, 'medium',
        `${SKELETON_CHAIN} (${label}) filters ${f.skeleton_interface}, but the default route now uses ${f.ext_interface}, so traffic arriving on ${f.ext_interface} is not filtered.`,
        HARDENING_FIX));
    }
    if (!f.chain.exists || f.chain.foreign.length || !sameEntries(f.chain.entries, desired.accept)) {
      findings.push(finding(`publish-chain-drift-${fam.id}`, 'medium',
        `${CHAIN} (${label}) does not match the ports AppCrane publishes${f.chain.exists ? '' : ': the chain does not exist'}.`,
        'AppCrane re-syncs it on every container start and stop and every 5 minutes. If this stays, see Job Health > Host network policy.'));
    }
    if (f.input_policy === 'ACCEPT' && !f.table.unconditionalDrop) {
      findings.push(finding(`input-accept-${fam.id}`, 'low',
        `The ${label} INPUT policy is ACCEPT, so every port a host process listens on is reachable unless a rule drops it.`,
        'Set a default-deny INPUT policy that allows only SSH, 80 and 443 (for example with ufw).'));
    }
  }

  if (lastSync?.status === 'failed') {
    findings.push(finding('publish-chain-sync-failed', 'high',
      `${lastSync.reason} Ports AppCrane publishes may be dropped, and a changed publish is not reflected.`,
      /not running as root/.test(lastSync.reason || '') ? `Apply Host limits again so scripts/install-host-hardening.sh installs ${HELPER} and its sudoers rule, or run AppCrane as root.` : 'See Job Health > Host network policy for the error.'));
  }

  for (const s of desired.strays) {
    const fam = s.host_ip.includes(':') && families.v6.skeleton ? 'v6' : 'v4';
    const sk = families[fam].skeleton || null;
    const [severity, verdict] = sk === 'applied'
      ? ['low', `The firewall drops it from ${families[fam].skeleton_interface || families[fam].ext_interface || 'the public interface'}${families[fam].skeleton_source === 'state' ? ' (per host hardening\'s state file)' : ''}.`]
      : sk === null
        ? ['medium', 'The firewall could not be read, so whether it is reachable from outside was not measured.']
        : ['high', 'It is reachable from the internet.'];
    findings.push(finding(`stray-publish:${s.container}:${s.proto}/${s.port}`, severity,
      `${s.container} publishes ${s.proto}/${s.port} on ${s.host_ip}, which AppCrane did not publish${s.claimed_by ? ` (that port belongs to ${s.claimed_by.slug} ${s.claimed_by.env})` : ''}. ${verdict}`,
      'Recreate that container without the publish, or bind it to 127.0.0.1.'));
  }
  if (desired.docker === 'unreadable') {
    findings.push(finding('docker-unreadable', 'low', `Docker could not be read (${desired.docker_error}), so stray publishes were not checked.`, null));
  }

  const ss = await run('ss', [...SS_ARGS]);
  const listen = ss.code === 0 ? listenAddrs(ss.stdout, port) : null;
  if (listen === null) {
    findings.push(finding('appcrane-port-unmeasured', 'info', `Could not read listening sockets (ss), so whether port ${port} is reachable was not measured.`, null));
  } else {
    const open = [];
    const unmeasured = [];
    const pub = listen.filter(a => isPublicAddr(a, net));
    const stateDrops = !!state && Number(state.app_port) === port && ['appcrane-input', 'refused', 'ufw'].includes(state.input_mode);
    for (const fam of FAMILIES) {
      const f = families[fam.id];
      const label = fam.id === 'v4' ? 'IPv4' : 'IPv6';
      if (!pub.some(fam.id === 'v4' ? coversV4 : coversV6)) continue;
      if (f.state === 'read') {
        const v = evaluateInput(f.table.rules, { proto: 'tcp', dport: port, iface: net.ext[fam.id] || net.ext.v4 });
        if (v.verdict === 'ACCEPT') open.push(`${label}: ${v.by}${v.uncertain.length ? `; ${v.uncertain.length} rule(s) not understood were skipped` : ''}`);
      } else if (!stateDrops) {
        unmeasured.push(label);
      }
    }
    if (open.length) {
      const ext = families.v4.ext_interface || '<external interface>';
      findings.push(finding('appcrane-port-public', 'high',
        `AppCrane's own port ${port} listens on ${pub.join(', ')} and INPUT lets it in (${open.join('; ')}), so the API answers from the internet without Caddy in front.`,
        `Drop tcp/${port} from ${ext} in INPUT, for example iptables -I INPUT -i ${ext} -p tcp --dport ${port} -j DROP (and persist it), or set HOST=127.0.0.1 when only Caddy connects to AppCrane.`));
    } else if (unmeasured.length) {
      findings.push(finding('appcrane-port-unmeasured', 'info',
        `AppCrane's own port ${port} listens on ${pub.join(', ')}, and the ${unmeasured.join(' and ')} firewall could not be read, so whether INPUT lets it in was not measured.`, null));
    }
  }

  const imds = imdsCache?.result || { status: 'not_measured', detail: 'not measured yet' };
  if (imds.status === 'exposed') {
    findings.push(finding('imds-exposed', 'high',
      `App containers can reach the instance metadata service (${imds.detail}), so they can read the instance role's credentials.`,
      `${IMDS_FIX}; then apply Host limits, whose network section drops container traffic to 169.254.169.254.`));
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.id.localeCompare(b.id));
  return {
    applicable: true, at, findings, families: stripTables(families), listen: { port, addresses: listen },
    host_network_state: state,
    imds: { ...imds, measured_at: imdsCache ? new Date(imdsCache.at).toISOString() : null },
    desired: desired.accept, strays: desired.strays, docker: desired.docker,
  };
}

function stripTables(families) {
  const out = {};
  for (const [k, v] of Object.entries(families)) {
    const { table, ...rest } = v;
    out[k] = rest;
  }
  return out;
}
