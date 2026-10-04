// Nesher VPN — issues short-lived WireGuard passes that exit through the device
// in Nesher. Users sign in through AppCrane (identity arrives as X-AppCrane-*
// headers); the Nesher agent polls /agent/* with a bearer token, so the device
// never needs an inbound control port — only the WireGuard UDP port.
import { createHash, randomUUID, timingSafeEqual } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import express from 'express';
import QRCode from 'qrcode';
import { generateKeyPair, generatePresharedKey, isWgKey, renderClientConfig } from './lib/wg.js';
import { openStore } from './lib/store.js';
import { allocateAddress, desiredPeers, passStatus, purgeOld } from './lib/passes.js';

const here = dirname(fileURLToPath(import.meta.url));
const TTL_CHOICES_H = [1, 8, 24, 72, 168];

export function createApp(env = process.env) {
  const cfg = {
    agentToken: env.AGENT_TOKEN || '',
    endpoint: env.VPN_ENDPOINT || '',              // e.g. nesher.duckdns.org:51820
    port: Number(env.VPN_PORT || 51820),
    dns: env.VPN_DNS || '1.1.1.1, 1.0.0.1',
    maxTtlH: Number(env.MAX_TTL_HOURS || 168),
    maxPerUser: Number(env.MAX_PASSES_PER_USER || 5),
    devUser: env.DEV_USER || '',                   // local dev only: act as this email without AppCrane
  };
  const store = openStore(env.DATA_DIR || join(here, 'data'));
  const app = express();
  // Only AppCrane's Caddy (on the private docker network) is trusted to set X-Forwarded-For.
  app.set('trust proxy', 'loopback, uniquelocal');
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));

  const now = () => Date.now();
  const tidy = () => { store.state.passes = purgeOld(store.state.passes, now()); };

  // ---- identity (AppCrane) ------------------------------------------------
  function identity(req) {
    if (req.get('X-AppCrane-Auth-Mode') === 'authenticated' && req.get('X-AppCrane-User-Id')) {
      const role = req.get('X-AppCrane-App-Role') || 'user';
      return {
        id: req.get('X-AppCrane-User-Id'),
        email: req.get('X-AppCrane-User-Email') || req.get('X-AppCrane-User') || '',
        name: decodeURIComponent(req.get('X-AppCrane-User-Name') || ''),
        isAdmin: req.get('X-AppCrane-Is-Admin') === '1',
        canIssue: role !== 'viewer',
      };
    }
    if (cfg.devUser && !req.get('X-AppCrane-Auth-Mode')) {
      return { id: 'dev', email: cfg.devUser, name: 'Dev', isAdmin: true, canIssue: true };
    }
    return null;
  }
  const requireUser = (req, res, next) => {
    req.user = identity(req);
    if (!req.user) return res.status(401).json({ error: 'sign in through AppCrane' });
    next();
  };
  // Browser writes must be JSON: a cross-site <form> can't send that without a CORS preflight.
  const requireJson = (req, res, next) =>
    req.is('application/json') ? next() : res.status(415).json({ error: 'send application/json' });

  // ---- agent auth ---------------------------------------------------------
  const digest = (s) => createHash('sha256').update(s).digest();
  const requireAgent = (req, res, next) => {
    const got = (req.get('Authorization') || '').replace(/^Bearer\s+/i, '');
    if (cfg.agentToken.length < 32) return res.status(503).json({ error: 'AGENT_TOKEN not configured (min 32 chars)' });
    if (!got || !timingSafeEqual(digest(got), digest(cfg.agentToken))) return res.status(401).json({ error: 'bad agent token' });
    next();
  };

  const device = () => store.state.device;
  const endpoint = () => {
    if (cfg.endpoint) return cfg.endpoint;
    const ip = device()?.publicIp;
    if (!ip) return '';
    return ip.includes(':') ? `[${ip}]:${cfg.port}` : `${ip}:${cfg.port}`;
  };
  const deviceOnline = () => !!device()?.lastSeen && now() - Date.parse(device().lastSeen) < 90_000;

  const view = (p) => {
    const peer = device()?.peers?.[p.publicKey];
    return {
      id: p.id, name: p.name, owner: p.ownerEmail, address: p.address,
      createdAt: p.createdAt, expiresAt: p.expiresAt, revokedAt: p.revokedAt || null,
      status: passStatus(p, now()),
      lastHandshake: peer?.latestHandshake ? new Date(peer.latestHandshake * 1000).toISOString() : null,
      rxBytes: peer?.rx ?? 0, txBytes: peer?.tx ?? 0,
    };
  };

  // ---- routes: public -----------------------------------------------------
  app.get('/api/health', (_req, res) => res.json({ status: 'ok', version: '1.0.0' }));

  // ---- routes: users ------------------------------------------------------
  app.get('/api/me', requireUser, (req, res) => {
    const d = device();
    res.json({
      user: req.user,
      ttlChoices: TTL_CHOICES_H.filter(h => h <= cfg.maxTtlH),
      device: {
        online: deviceOnline(), lastSeen: d?.lastSeen || null,
        endpoint: endpoint() || null, ready: !!(d?.publicKey && endpoint()),
      },
    });
  });

  app.get('/api/passes', requireUser, (req, res) => {
    const all = req.user.isAdmin && req.query.all === '1';
    const list = store.state.passes.filter(p => all || p.ownerId === req.user.id);
    res.json({ passes: list.map(view).reverse() });
  });

  app.post('/api/passes', requireUser, requireJson, async (req, res) => {
    if (!req.user.canIssue) return res.status(403).json({ error: 'viewers cannot issue passes' });
    const d = device();
    if (!d?.publicKey || !endpoint()) {
      return res.status(409).json({ error: 'the Nesher device has not checked in yet (or VPN_ENDPOINT is unset)' });
    }
    const name = String(req.body?.name || '').trim().slice(0, 40) || 'device';
    const ttlH = Number(req.body?.ttlHours);
    if (!TTL_CHOICES_H.includes(ttlH) || ttlH > cfg.maxTtlH) {
      return res.status(400).json({ error: `ttlHours must be one of ${TTL_CHOICES_H.filter(h => h <= cfg.maxTtlH).join(', ')}` });
    }
    tidy();
    const t = now();
    const mine = store.state.passes.filter(p => p.ownerId === req.user.id && passStatus(p, t) === 'active');
    if (mine.length >= cfg.maxPerUser) {
      return res.status(429).json({ error: `you already hold ${mine.length} active passes — revoke one first` });
    }
    const address = allocateAddress(store.state.passes, t);
    if (!address) return res.status(503).json({ error: 'no free tunnel addresses' });

    // The private key lives only in this response: it is never stored or logged.
    const { privateKey, publicKey } = generateKeyPair();
    const pass = {
      id: randomUUID(), name, ownerId: req.user.id, ownerEmail: req.user.email,
      publicKey, presharedKey: generatePresharedKey(), address,
      createdAt: new Date(t).toISOString(), expiresAt: new Date(t + ttlH * 3600_000).toISOString(),
    };
    store.state.passes.push(pass);
    store.save();

    const config = renderClientConfig({
      privateKey, address, dns: cfg.dns, serverPublicKey: d.publicKey,
      presharedKey: pass.presharedKey, endpoint: endpoint(), name,
    });
    const qrSvg = await QRCode.toString(config, { type: 'svg', errorCorrectionLevel: 'M', margin: 1 });
    res.set('Cache-Control', 'no-store');
    res.status(201).json({ pass: view(pass), config, qrSvg, filename: `nesher-${name.replace(/[^A-Za-z0-9_-]/g, '_')}.conf` });
  });

  app.delete('/api/passes/:id', requireUser, (req, res) => {
    const p = store.state.passes.find(x => x.id === req.params.id);
    if (!p || (p.ownerId !== req.user.id && !req.user.isAdmin)) return res.status(404).json({ error: 'not found' });
    if (!p.revokedAt) { p.revokedAt = new Date(now()).toISOString(); store.save(); }
    res.json({ pass: view(p) });
  });

  // ---- routes: Nesher agent (list /agent/ in the app's auth_bypass_paths) --
  app.get('/agent/peers', requireAgent, (_req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ serverTime: Math.floor(now() / 1000), peers: desiredPeers(store.state.passes, now()) });
  });

  app.post('/agent/status', requireAgent, (req, res) => {
    const b = req.body || {};
    if (!isWgKey(b.publicKey)) return res.status(400).json({ error: 'publicKey must be a WireGuard key' });
    const peers = {};
    for (const p of Array.isArray(b.peers) ? b.peers.slice(0, 300) : []) {
      if (!isWgKey(p?.publicKey)) continue;
      peers[p.publicKey] = { latestHandshake: Number(p.latestHandshake) || 0, rx: Number(p.rx) || 0, tx: Number(p.tx) || 0 };
    }
    const prev = device();
    const publicIp = String(req.ip || '').replace(/^::ffff:/, '');
    store.state.device = { publicKey: b.publicKey, publicIp, lastSeen: new Date(now()).toISOString(), peers };
    // Persist only when something a restart would need changed — not every 15s heartbeat.
    if (!prev || prev.publicKey !== b.publicKey || prev.publicIp !== publicIp) { tidy(); store.save(); }
    res.json({ ok: true });
  });

  app.use(express.static(join(here, 'public'), { index: 'index.html' }));
  return app;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => console.log(`nesher-vpn listening on ${port}`));
}
