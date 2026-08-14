-- v2.42.0: layer-4 (raw TCP) ingress.
--
-- Some apps are not HTTP. The motivating case is a forward/CONNECT proxy:
-- the client opens a raw TCP connection and gets a tunnel back, which no
-- HTTP reverse proxy can express, so Caddy cannot front it. A 'tcp' app has
-- its container port published directly on the host (0.0.0.0:<public_port>)
-- with Caddy entirely out of the path.
--
-- SECURITY: that second door has NONE of the controls v2.35-v2.41 built into
-- the first one — no forward_auth, no identity headers, no per-request audit,
-- no rate limiting, no security headers, no TLS from AppCrane. Every one of
-- those assumes Caddy is the only way in. A 'tcp' app owns authentication
-- completely. Only a platform admin may set ingress_type='tcp' or touch
-- public_port, and AppCrane still does NOT open the firewall — that stays a
-- separate operator step on purpose, so a mis-click in the dashboard cannot
-- put an app on the internet.
--
-- The enum is validated in CODE (server/services/tcpIngress.js), not with a
-- CHECK constraint, following the auth_mode precedent: SQLite cannot ALTER a
-- CHECK, so a constraint here would force a full table rebuild the next time
-- the vocabulary grows.
ALTER TABLE apps ADD COLUMN ingress_type TEXT NOT NULL DEFAULT 'http';

-- NULL for every http app. Allocated and STORED, never derived from `slot`:
-- getPortsForSlot() is arithmetic on the slot number and slots get reassigned,
-- so a derived public port would silently move under clients that are pinned
-- to it by MDM or a hardcoded proxy setting.
ALTER TABLE apps ADD COLUMN public_port INTEGER;

-- The real guarantee that two apps never hold the same host port. The
-- allocator picks the lowest free port in its range, but allocate-then-write
-- is only safe because this index rejects the loser of any race.
CREATE UNIQUE INDEX IF NOT EXISTS idx_apps_public_port
  ON apps(public_port) WHERE public_port IS NOT NULL;
