import pg from 'pg';

// AppCrane injects DATABASE_URL when deployhub.json declares
// "database": { "engine": "postgres" }. The URL already carries the TLS
// parameters (sslmode, sslrootcert, sslcert, sslkey) and node-postgres reads
// them from it, so nothing else is needed. Sandbox and production each get
// their own database under the same variable name.
//
// AppCrane caps each database login at 25 connections; keep the pool well
// below that.
export function createPool(url = process.env.DATABASE_URL) {
  if (!url) return null;
  return new pg.Pool({ connectionString: url, max: 5, idleTimeoutMillis: 30_000 });
}
