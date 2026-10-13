/**
 * pg_stat_statements for one app's managed Postgres database, without letting
 * it see anyone else's — SQL builders.
 *
 * PURE, like managedDbTls.js. managedDb.ensurePgExtensions() runs these as the
 * superuser; test/managed-db-pg-stats.test.js pins them without a daemon.
 *
 * =========================================================================
 * WHAT THE EXTENSION LEAKS ON ITS OWN (measured, postgres:16-alpine,
 * shared_preload_libraries=pg_stat_statements)
 * =========================================================================
 * The statistics live in ONE shared-memory table for the whole server, and
 * the view reads all of it whichever database it is created in. As app A's
 * login (non-superuser, not pg_read_all_stats) with the extension created in
 * A's own database by the superuser, default grants:
 *
 *    db  |   usr    | calls |  ms   | rows | qid_null |          query
 *   -----+----------+-------+-------+------+----------+--------------------------
 *    dbb | b_u      |     1 | 4.761 |    0 | t        | <insufficient privilege>
 *    dbb | b_u      |     1 | 0.006 |    1 | t        | <insufficient privilege>
 *    dbb | postgres |     1 | 0.437 |    0 | t        | <insufficient privilege>
 *    rows_total 19 | distinct_dbids 3 | hidden 18     can_select t | read_all_stats f
 *
 * Query text and queryid are hidden, but every other database's oid, every
 * other login (joinable to its name through pg_roles), and their call counts,
 * timings and row counts are not. So the view is never handed to an app.
 *
 * And an app cannot install it anyway:
 *   ERROR:  permission denied to create extension "pg_stat_statements"
 *   HINT:  Must be superuser to create this extension.
 * (pg_available_extension_versions: trusted = f.)
 *
 * =========================================================================
 * WHAT AN APP GETS INSTEAD
 * =========================================================================
 *   - the extension, created by AppCrane as the superuser, in a schema the
 *     superuser owns (appcrane_stats), with every grant on the extension's
 *     own view and functions revoked from PUBLIC;
 *   - appcrane_stats.app_stat_statements(): SECURITY DEFINER, owned by the
 *     superuser, returning the pg_stat_statements rows of THIS database
 *     (dbid) run by THIS scope's own logins (userid: the owner and, when it
 *     exists, its `_app` login) and nothing else. As the definer it sees the
 *     query text of those rows; the filter is what keeps it to them.
 *   - appcrane_stats.app_stat_statements_reset(): resets those same rows only
 *     (owner login only).
 * The two logins are one app's one stage, so showing each the other's
 * statements crosses no boundary; the superuser's own statements in the
 * database (AppCrane's provisioning) are excluded like every other role's.
 *
 * search_path is pinned on both functions: they run as the superuser inside a
 * database whose public schema the app owns, and an unpinned path would let
 * the app shadow an operator or function the body resolves.
 */

export const PG_STATS_SCHEMA = 'appcrane_stats';
export const SUPPORTED_EXTENSIONS = { postgres: ['pg_stat_statements'] };

const SAFE_IDENT = /^[a-z][a-z0-9_]{0,62}$/;
function ident(name) {
  if (!SAFE_IDENT.test(String(name)) || Buffer.byteLength(String(name)) > 31) {
    throw new Error(`managedDbStats: refusing identifier ${JSON.stringify(name)}`);
  }
  return name;
}

/** Server flags added to the shared Postgres while the platform switch is on. */
export const PG_STATS_SERVER_ARGS = ['-c', 'shared_preload_libraries=pg_stat_statements'];

/**
 * Install (or re-assert) the extension and the filtered functions in the
 * current database. `logins` = [owner, app login?]; the owner gets reset.
 */
export function pgStatStatementsSql(logins) {
  if (!Array.isArray(logins) || !logins.length) throw new Error('managedDbStats: at least the owner login is required');
  const names = logins.map(ident);
  const [owner] = names;
  const list = names.map((n) => `'${n}'`).join(', ');
  const quoted = names.map((n) => `"${n}"`).join(', ');
  const S = PG_STATS_SCHEMA;
  return [
    `CREATE SCHEMA IF NOT EXISTS ${S} AUTHORIZATION postgres;`,
    `ALTER SCHEMA ${S} OWNER TO postgres;`,
    `REVOKE ALL ON SCHEMA ${S} FROM PUBLIC;`,
    // Moved, not duplicated, if it was ever created somewhere else (e.g. by
    // hand in public, which the app owns).
    'DO $$ BEGIN',
    "  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements') THEN",
    `    CREATE EXTENSION pg_stat_statements SCHEMA ${S};`,
    "  ELSIF (SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'pg_stat_statements') <> '" + S + "' THEN",
    `    ALTER EXTENSION pg_stat_statements SET SCHEMA ${S};`,
    '  END IF;',
    'END $$;',
    `REVOKE ALL ON ${S}.pg_stat_statements FROM PUBLIC;`,
    `REVOKE ALL ON ${S}.pg_stat_statements_info FROM PUBLIC;`,
    `REVOKE ALL ON FUNCTION ${S}.pg_stat_statements(boolean) FROM PUBLIC;`,
    `REVOKE ALL ON FUNCTION ${S}.pg_stat_statements_info() FROM PUBLIC;`,
    `REVOKE ALL ON FUNCTION ${S}.pg_stat_statements_reset(oid, oid, bigint) FROM PUBLIC;`,
    `CREATE OR REPLACE FUNCTION ${S}.app_stat_statements()`,
    `  RETURNS SETOF ${S}.pg_stat_statements`,
    '  LANGUAGE sql STABLE SECURITY DEFINER',
    '  SET search_path = pg_catalog, pg_temp',
    'AS $f$',
    `  SELECT s.* FROM ${S}.pg_stat_statements AS s`,
    '  WHERE s.dbid = (SELECT d.oid FROM pg_catalog.pg_database AS d WHERE d.datname = pg_catalog.current_database())',
    `    AND s.userid IN (SELECT r.oid FROM pg_catalog.pg_roles AS r WHERE r.rolname IN (${list}))`,
    '$f$;',
    `CREATE OR REPLACE FUNCTION ${S}.app_stat_statements_reset()`,
    '  RETURNS void',
    '  LANGUAGE sql VOLATILE SECURITY DEFINER',
    '  SET search_path = pg_catalog, pg_temp',
    'AS $f$',
    `  SELECT ${S}.pg_stat_statements_reset(r.oid, d.oid, 0)`,
    '  FROM pg_catalog.pg_roles AS r, pg_catalog.pg_database AS d',
    `  WHERE d.datname = pg_catalog.current_database() AND r.rolname IN (${list});`,
    '$f$;',
    `REVOKE ALL ON FUNCTION ${S}.app_stat_statements() FROM PUBLIC;`,
    `REVOKE ALL ON FUNCTION ${S}.app_stat_statements_reset() FROM PUBLIC;`,
    `GRANT USAGE ON SCHEMA ${S} TO ${quoted};`,
    `GRANT EXECUTE ON FUNCTION ${S}.app_stat_statements() TO ${quoted};`,
    `GRANT EXECUTE ON FUNCTION ${S}.app_stat_statements_reset() TO "${owner}";`,
  ].join('\n');
}

/** Opting out removes the schema, the functions and the extension with it. */
export function pgStatStatementsDropSql() {
  return `DROP SCHEMA IF EXISTS ${PG_STATS_SCHEMA} CASCADE;\n`;
}

/**
 * Admin query run before a dump: one line per extension the dump must keep
 * (everything but plpgsql, which is built in, and pg_stat_statements), then a
 * marker line saying whether pg_stat_statements is present. COPY so psql
 * prints bare values with no header or alignment.
 */
export const PG_DUMP_EXTENSIONS_QUERY =
  "COPY (SELECT extname FROM pg_extension WHERE extname NOT IN ('plpgsql', 'pg_stat_statements') "
  + "UNION ALL SELECT '#pgss' FROM pg_extension WHERE extname = 'pg_stat_statements' "
  + "UNION ALL SELECT '#stats' FROM pg_namespace WHERE nspname = '" + PG_STATS_SCHEMA + "') TO STDOUT;\n";

/**
 * Parse PG_DUMP_EXTENSIONS_QUERY's output. `exclude` is true when the
 * database carries AppCrane's stats wiring, in which case the dump must leave
 * it out: the restore loads as the APP login, which can neither create the
 * superuser-owned schema's contents nor the untrusted extension, and
 * --exit-on-error would fail the whole restore on the first such line.
 * The wiring is re-applied from the row after the restore instead.
 */
export function parseDumpExtensions(out) {
  const lines = String(out || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const exclude = lines.includes('#pgss') || lines.includes('#stats');
  // Extension names are free-form in Postgres (uuid-ossp has a hyphen); they
  // reach pg_dump as separate argv elements, never a shell, and are quoted so
  // the pattern matches the name literally.
  const keep = lines.filter((l) => !l.startsWith('#')).filter((l) => /^[A-Za-z0-9_-]{1,63}$/.test(l));
  return { exclude, keep };
}

/**
 * pg_dump flags that leave the stats wiring out. With no -e at all pg_dump
 * dumps every extension, so an empty `keep` still passes one: plpgsql is a
 * built-in extension pg_dump never emits, which turns "-e" into "no others".
 * Measured: `-N appcrane_stats -e plpgsql` -> no EXTENSION entry;
 * `-N appcrane_stats -e pgcrypto` -> pgcrypto only.
 */
export function pgDumpExcludeArgs(keep) {
  const names = keep && keep.length ? keep : ['plpgsql'];
  return ['-N', PG_STATS_SCHEMA, ...names.flatMap((n) => ['-e', `"${n}"`])];
}
