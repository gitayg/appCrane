// APPCRANE-PUBLISH, the chain AppCrane's server owns. Host hardening's network
// section owns DOCKER-USER and jumps here for traffic from the external
// interface; anything this chain does not ACCEPT falls through to that
// section's DROP.
//
// Ports are matched on conntrack's ORIGINAL destination port: by the time a
// packet reaches FORWARD, Docker's DNAT has already rewritten --dport to the
// container's port. --ctstate DNAT limits the ACCEPT to flows Docker's DNAT
// rewrote, so a packet routed straight at a container address is not admitted.

export const CHAIN = 'APPCRANE-PUBLISH';
export const SKELETON_CHAIN = 'DOCKER-USER';
export const FAMILIES = Object.freeze([
  { id: 'v4', bin: 'iptables', restore: 'iptables-restore' },
  { id: 'v6', bin: 'ip6tables', restore: 'ip6tables-restore' },
]);
export const PROTOCOLS = Object.freeze(['tcp', 'udp']);

export function validEntry(e) {
  return PROTOCOLS.includes(e?.proto) && Number.isInteger(e?.port) && e.port >= 1 && e.port <= 65535;
}

export function ruleLine({ proto, port }) {
  if (!validEntry({ proto, port })) throw new Error(`refusing to write a rule for ${proto}/${port}`);
  return `-A ${CHAIN} -p ${proto} -m conntrack --ctstate DNAT --ctorigdstport ${port} --ctdir ORIGINAL -j ACCEPT`;
}

export function sortEntries(list) {
  const seen = new Map();
  for (const e of list) seen.set(`${e.proto}/${e.port}`, { proto: e.proto, port: e.port });
  return [...seen.values()].sort((a, b) => (a.proto === b.proto ? a.port - b.port : a.proto < b.proto ? -1 : 1));
}

// --noflush leaves every other chain alone; declaring this chain creates it
// when missing and empties it when present, and COMMIT swaps the table in one
// step, so there is no moment with a half-written list.
export function renderRestore(list) {
  const lines = ['*filter', `:${CHAIN} - [0:0]`];
  for (const e of sortEntries(list)) lines.push(ruleLine(e));
  lines.push('COMMIT', '');
  return lines.join('\n');
}

const RULE_RE = new RegExp(`^-A ${CHAIN} -p (tcp|udp) -m conntrack --ctstate DNAT --ctorigdstport (\\d+) --ctdir ORIGINAL -j ACCEPT$`);

/**
 * Parse `iptables -S` text (one chain or the whole table) for this chain.
 * { exists, entries: [{proto, port}], foreign: [lines that are not ours] }.
 */
export function parseChain(text) {
  const out = { exists: false, entries: [], foreign: [] };
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trim();
    if (line === `-N ${CHAIN}`) { out.exists = true; continue; }
    if (!line.startsWith(`-A ${CHAIN} `)) continue;
    out.exists = true;
    const m = RULE_RE.exec(line);
    if (m) out.entries.push({ proto: m[1], port: Number(m[2]) });
    else out.foreign.push(line);
  }
  return out;
}

export function sameEntries(a, b) {
  const x = sortEntries(a).map(e => `${e.proto}/${e.port}`);
  const y = sortEntries(b).map(e => `${e.proto}/${e.port}`);
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

export function chainMissing(stderr) {
  return /No chain\/target\/match by that name|chain .* does not exist|doesn't exist/i.test(String(stderr || ''));
}

export function permissionDenied(stderr) {
  return /Permission denied|you must be root|Operation not permitted/i.test(String(stderr || ''));
}

// When AppCrane is not root it changes APPCRANE-PUBLISH only through this
// root-owned helper, installed with a sudoers rule by
// scripts/install-host-hardening.sh. It validates every argument itself.
export const HELPER = '/usr/local/lib/appcrane/appcrane-publish-chain.sh';
export const HELPER_MAX_ARGS = 512;

export function helperArgs(list) {
  return ['-n', HELPER, ...sortEntries(list).map((e) => {
    if (!validEntry(e)) throw new Error(`refusing to pass ${e?.proto}/${e?.port} to the helper`);
    return `${e.proto}:${e.port}`;
  })];
}

export function sudoRefused(stderr) {
  return /^sudo: /m.test(String(stderr || '')) || /a password is required|is not in the sudoers|not allowed to execute/i.test(String(stderr || ''));
}
