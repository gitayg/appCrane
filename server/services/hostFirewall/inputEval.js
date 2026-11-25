// What INPUT does with a new connection from the internet to one port, by
// walking `iptables -S` rule by rule in order, into jumped chains and back, as
// the kernel does: the first ACCEPT, DROP or REJECT wins, and the policy
// decides when INPUT runs out. So an early explicit DROP of the port (host
// hardening's APPCRANE-INPUT at position 1, or a prepended ufw deny) wins over
// a later ACCEPT.
//
// The packet: NEW, from a public source address, arriving on the default
// route's interface, to an address of the host. A rule with a match this does
// not understand is skipped and listed in `uncertain`.

const VERDICTS = new Set(['ACCEPT', 'DROP', 'REJECT']);
const NO_VALUE = new Set(['--syn', '-f', '--fragment']);
const IGNORED_MODULES = new Set(['tcp', 'udp', 'multiport', 'comment', 'conntrack', 'state', 'addrtype', 'limit', 'hashlimit', 'pkttype']);
const TARGET_OPTIONS = new Set(['--reject-with', '--log-prefix', '--log-level', '--log-tcp-options', '--log-ip-options', '--log-uid', '--nflog-group', '--nflog-prefix']);

export function tokenize(line) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"|(\S+)/g;
  let m;
  while ((m = re.exec(line))) out.push(m[1] !== undefined ? m[1] : m[2]);
  return out;
}

/** { policies: {chain: policy}, chains: Map(chain -> [tokens after -A chain]) } */
export function parseRules(text) {
  const policies = {};
  const chains = new Map();
  for (const raw of String(text || '').split('\n')) {
    const t = tokenize(raw.trim());
    if (t[0] === '-P' && t.length >= 3) policies[t[1]] = t[2];
    else if (t[0] === '-N' && t[1]) { if (!chains.has(t[1])) chains.set(t[1], []); }
    else if (t[0] === '-A' && t[1]) {
      if (!chains.has(t[1])) chains.set(t[1], []);
      chains.get(t[1]).push({ line: raw.trim(), tokens: t.slice(2) });
    }
  }
  return { policies, chains };
}

const inRange = (port, spec) => spec.split(',').some((p) => {
  const [a, b] = p.split(':').map(Number);
  return port >= a && port <= (Number.isFinite(b) ? b : a);
});

const anySource = (v) => v === '0.0.0.0/0' || v === '::/0';
const specialDest = (v) => /^(127\.|224\.|2[3-4]\d\.|255\.255\.255\.255)/.test(v) || /^::1(\/128)?$/.test(v) || /^ff/i.test(v);

function ifaceMatches(spec, iface) {
  if (spec.endsWith('+')) return iface !== null && iface.startsWith(spec.slice(0, -1));
  if (iface === null) return !/^(lo|docker0|br-|veth|tailscale|wg|tun)/.test(spec);
  return spec === iface;
}

/** { match: bool, target, uncertain: bool } */
export function matchRule(tokens, pkt) {
  let neg = false;
  let target = null;
  let uncertain = false;
  let match = true;
  const set = (m) => { if (!(neg ? !m : m)) match = false; neg = false; };
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    const val = NO_VALUE.has(tok) ? null : tokens[i + 1];
    const step = () => { if (!NO_VALUE.has(tok)) i += 1; };
    if (tok === '!') { neg = true; continue; }
    if (tok === '-j' || tok === '-g') { target = val; step(); continue; }
    if (target) { if (TARGET_OPTIONS.has(tok)) step(); continue; }
    switch (tok) {
      case '-p': case '--protocol': set(val === 'all' || val === pkt.proto || (val === '6' && pkt.proto === 'tcp') || (val === '17' && pkt.proto === 'udp')); break;
      case '-i': case '--in-interface': set(ifaceMatches(val, pkt.iface)); break;
      case '-o': case '--out-interface': set(false); break;
      case '-s': case '--source': set(anySource(val)); break;
      case '-d': case '--destination': set(!specialDest(val)); break;
      case '-m': case '--match':
        if (!IGNORED_MODULES.has(val)) { uncertain = true; match = false; }
        break;
      case '--dport': case '--destination-port': case '--dports': case '--destination-ports': set(inRange(pkt.dport, val)); break;
      case '--sport': case '--source-port': case '--sports': case '--source-ports': set(false); break;
      case '--ctstate': case '--state': set(val.split(',').includes('NEW')); break;
      case '--dst-type': set(val.split(',').includes('LOCAL')); break;
      case '--src-type': set(false); break;
      case '--pkt-type': set(val === 'unicast'); break;
      case '--icmp-type': case '--icmpv6-type': set(false); break;
      case '--tcp-flags': set(true); i += 1; break;
      case '--syn': set(true); break;
      case '-f': case '--fragment': set(false); break;
      case '--comment': case '--limit': case '--limit-burst':
      case '--hashlimit': case '--hashlimit-burst': case '--hashlimit-mode': case '--hashlimit-name':
      case '--hashlimit-upto': case '--hashlimit-above': case '--hashlimit-htable-expire': neg = false; break;
      default: uncertain = true; match = false; if (val !== undefined && !String(val).startsWith('-')) i += 1; continue;
    }
    step();
  }
  return { match, target, uncertain };
}

/**
 * { verdict: 'ACCEPT'|'DROP'|'REJECT', by: rule line or 'policy <P>', uncertain: [lines] }.
 * pkt: { proto: 'tcp'|'udp', dport, iface (null when unknown) }.
 */
export function evaluateInput(parsed, pkt) {
  const uncertain = [];
  const walk = (chain, depth) => {
    if (depth > 32) return null;
    for (const rule of parsed.chains.get(chain) || []) {
      const r = matchRule(rule.tokens, pkt);
      if (r.uncertain) uncertain.push(rule.line);
      if (!r.match || !r.target) continue;
      if (VERDICTS.has(r.target)) return { verdict: r.target, by: rule.line };
      if (r.target === 'RETURN') return null;
      if (parsed.chains.has(r.target)) {
        const inner = walk(r.target, depth + 1);
        if (inner) return inner;
      }
    }
    return null;
  };
  const hit = walk('INPUT', 0);
  const policy = parsed.policies.INPUT || 'ACCEPT';
  return { ...(hit || { verdict: policy, by: `policy ${policy}` }), uncertain };
}
