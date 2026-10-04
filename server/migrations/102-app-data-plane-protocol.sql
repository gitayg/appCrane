-- v2.x: the transport of a 'dual' app's raw data plane.
--
-- Until now every public publish was `-p 0.0.0.0:<public_port>:<container>`,
-- which docker reads as TCP. Some data planes are UDP only — the motivating case
-- is a WireGuard relay, and the WireGuard clients (iOS, Android, Windows) speak
-- nothing else — so a dual app could publish its data plane on a port its
-- clients could never reach.
--
-- NULL means 'tcp', so every existing row keeps its argv byte for byte. Only a
-- dual app reads the column (a pure-tcp app IS its HTTP container port, and the
-- health probe needs that over TCP); like data_plane_port, the value survives a
-- flip away from dual so flipping back restores what clients are configured for.
ALTER TABLE apps ADD COLUMN data_plane_protocol TEXT
  CHECK (data_plane_protocol IS NULL OR data_plane_protocol IN ('tcp', 'udp'));
