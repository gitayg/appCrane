-- v2.97.0 — a per-app secret for signing identity headers.
--
-- /api/identity/verify signs the X-AppCrane-* identity it issues with this
-- app's secret, and the app (appcrane-tenant verifyIdentity) checks it, so
-- identity that did not come through AppCrane's proxy is rejected even where
-- the proxy is not in the path (raw tcp/dual ports, Docker Desktop's
-- host.docker.internal route to a loopback publish). Created on first use,
-- stored encrypted.
--
-- Its own table rather than an apps column: adding an apps column means a full
-- apps rebuild (the schema guard in test/app-catalog-slug.test.js), for one
-- secret nothing else joins on. The row goes with the app.
--
-- One secret per ENVIRONMENT, not per app: sandbox runs code still under review
-- (deployable by app admins and by the coder), and a shared secret would let it
-- sign identity that production believes.
CREATE TABLE IF NOT EXISTS app_identity_secrets (
  app_id           INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  env              TEXT NOT NULL CHECK(env IN ('production', 'sandbox')),
  secret_encrypted TEXT NOT NULL,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (app_id, env)
);
