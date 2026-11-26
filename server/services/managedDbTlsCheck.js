// Whether a login's connections use TLS, measured in the engine: the gate
// between "Prepare TLS" (the deploy hands the app the CA) and "Require TLS"
// (the engine refuses the login without it). Pure SQL builders and parsers;
// managedDb.measureLoginTls() runs them.
//
//   postgres  pg_stat_ssl joined with pg_stat_activity: every CURRENT client
//             connection of the login, TLS or not, exactly.
//   mariadb   the managed server runs with performance_schema off (measured:
//             @@performance_schema = 0, performance_schema.threads empty on
//             mariadb:11.4), and PROCESSLIST has no TLS column. What it does
//             have is user statistics (`userstat`, a dynamic variable):
//             information_schema.USER_STATISTICS counts TOTAL_CONNECTIONS and
//             TOTAL_SSL_CONNECTIONS per user. So the measurement is "since the
//             admin started it": a baseline of both counters, and the plain
//             connections opened after it. That also sees PHP-FPM's
//             per-request connections, which a "current connections" view
//             almost never catches. Counters reset when the server restarts,
//             and so does userstat (SET GLOBAL is not persistent), so the
//             baseline records the server's start time and a restart since
//             makes the measurement invalid rather than silently short.
//             Connections still open from before the baseline cannot be
//             classified: connection ids only grow, so the baseline keeps the
//             id of its own session, and an open connection of the login with
//             a lower id predates it. Those are reported and block Require
//             TLS.

const SAFE_IDENT = /^[a-z][a-z0-9_]{0,62}$/;

function idents(logins) {
  for (const l of logins) {
    if (!SAFE_IDENT.test(l)) throw new Error(`managedDbTlsCheck: refusing identifier ${JSON.stringify(l)}`);
  }
  return logins.map((l) => `'${l}'`).join(', ');
}

/** One line per current client connection: "<login> t|f" (t = TLS). */
export function pgConnectionsSql(logins) {
  return 'COPY (SELECT a.usename || \' \' || CASE WHEN s.ssl THEN \'t\' ELSE \'f\' END FROM pg_stat_activity a '
    + 'JOIN pg_stat_ssl s ON s.pid = a.pid WHERE a.backend_type = \'client backend\' '
    + `AND a.usename IN (${idents(logins)})) TO STDOUT;\n`;
}

export function parsePgConnections(out, logins) {
  const per = Object.fromEntries(logins.map((l) => [l, { connections: 0, tls: 0 }]));
  for (const line of String(out || '').split('\n')) {
    const m = /^([a-z][a-z0-9_]*) ([tf])$/.exec(line.trim());
    if (!m || !per[m[1]]) continue;
    per[m[1]].connections++;
    if (m[2] === 't') per[m[1]].tls++;
  }
  return per;
}

/**
 * `S <userstat: ON/OFF, as mariadb:11.4 prints it> <server start, unix
 * seconds> <this session's id>`,
 * `U <login> <total> <ssl>` per login the counters know, `P <login> <id>` per
 * open connection of a login. `reset` first turns the counters on.
 */
export function mariadbCountersSql(logins, { reset = false } = {}) {
  const list = idents(logins);
  return [
    ...(reset ? ['SET GLOBAL userstat = 1;'] : []),
    "SELECT CONCAT_WS(' ', 'S', @@userstat, UNIX_TIMESTAMP() - VARIABLE_VALUE, CONNECTION_ID()) AS x FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME = 'UPTIME';",
    `SELECT CONCAT_WS(' ', 'U', USER, TOTAL_CONNECTIONS, TOTAL_SSL_CONNECTIONS) AS x FROM information_schema.USER_STATISTICS WHERE USER IN (${list});`,
    `SELECT CONCAT_WS(' ', 'P', USER, ID) AS x FROM information_schema.PROCESSLIST WHERE USER IN (${list});`,
  ].join('\n') + '\n';
}

export function parseMariadbCounters(out, logins) {
  const res = { userstat: false, started: null, conn_id: null, counters: {}, open: {} };
  for (const l of logins) { res.counters[l] = { total: 0, ssl: 0 }; res.open[l] = []; }
  for (const line of String(out || '').split('\n')) {
    const p = line.trim().split(/\s+/);
    if (p[0] === 'S' && p.length === 4) {
      res.userstat = p[1] === '1' || p[1] === 'ON';
      res.started = Math.round(Number(p[2]));
      res.conn_id = Number(p[3]);
    } else if (p[0] === 'U' && p.length === 4 && res.counters[p[1]]) {
      res.counters[p[1]] = { total: Number(p[2]), ssl: Number(p[3]) };
    } else if (p[0] === 'P' && p.length === 3 && res.open[p[1]]) {
      res.open[p[1]].push(Number(p[2]));
    }
  }
  return res;
}

// The server's start time is UNIX_TIMESTAMP() - Uptime, read at two moments:
// the same start reads a second or two apart.
const START_SLACK_S = 5;

/**
 * The verdict from a baseline (null when never started) and a fresh reading.
 * `ready`: Require TLS may go ahead without the "no connections" confirm.
 */
export function mariadbVerdict(base, now, logins) {
  const out = { method: 'since', since: base?.at || null, logins: {}, connections: 0, tls: 0, plain: 0, open_unclassified: 0, measured: true, reason: null };
  if (!base) return { ...out, measured: false, reason: 'not_started' };
  if (!now.userstat || base.started == null || now.started == null || !(base.conn_id > 0)
    || Math.abs(now.started - base.started) > START_SLACK_S) {
    return { ...out, measured: false, reason: 'server_restarted' };
  }
  for (const l of logins) {
    const b = base.counters?.[l] || { total: 0, ssl: 0 };
    const c = now.counters[l] || { total: 0, ssl: 0 };
    const connections = Math.max(0, c.total - b.total);
    const tls = Math.min(connections, Math.max(0, c.ssl - b.ssl));
    const open = now.open[l] || [];
    const before = open.filter((id) => !(id > base.conn_id)).length;
    out.logins[l] = { connections, tls, plain: connections - tls, open_now: open.length, open_before_check: before };
    out.connections += connections;
    out.tls += tls;
    out.open_unclassified += before;
  }
  out.plain = out.connections - out.tls;
  return out;
}

export function pgVerdict(per, logins) {
  const out = { method: 'current', since: null, logins: {}, connections: 0, tls: 0, plain: 0, open_unclassified: 0, measured: true, reason: null };
  for (const l of logins) {
    const p = per[l] || { connections: 0, tls: 0 };
    out.logins[l] = { connections: p.connections, tls: p.tls, plain: p.connections - p.tls, open_now: p.connections, open_before_check: 0 };
    out.connections += p.connections;
    out.tls += p.tls;
  }
  out.plain = out.connections - out.tls;
  return out;
}

/**
 * Why Require TLS must not go ahead, or null. `confirmNoConnections` is the
 * admin's explicit "the app has no connections to show, convert anyway".
 */
export function requireTlsRefusal(v, { confirmNoConnections = false } = {}) {
  if (!v.measured) {
    return v.reason === 'server_restarted'
      ? { code: 'TLS_CHECK_RESTARTED', message: 'The database server restarted since the TLS check started, so its counts are lost. Start the check again, use the app, then check again.' }
      : { code: 'TLS_CHECK_NOT_STARTED', message: 'Start the TLS check first, use the app so it connects, then check again: MariaDB can only count the connections opened after the check starts.' };
  }
  if (v.plain > 0) {
    return { code: 'TLS_PLAIN_CONNECTIONS', message: `${v.plain} of the app's ${v.connections} connection(s) ${v.method === 'since' ? 'since the check started' : 'open now'} do not use TLS. Requiring TLS now would refuse them. Redeploy the app so it gets the CA, then check again.` };
  }
  if (v.open_unclassified > 0) {
    return { code: 'TLS_UNCLASSIFIED_CONNECTIONS', message: `${v.open_unclassified} connection(s) were opened before the TLS check started, so whether they use TLS is unknown. Restart the app, then check again.` };
  }
  if (v.connections === 0 && !confirmNoConnections) {
    return { code: 'TLS_NO_CONNECTIONS', message: 'The app has made no connection to measure. Use the app and check again, or confirm that you want to require TLS without a measurement.' };
  }
  return null;
}
