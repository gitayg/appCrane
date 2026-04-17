import { Router } from 'express';
import crypto from 'crypto';
import { getDb } from '../db.js';
import { encrypt, decrypt, generateSessionToken, hashApiKey, generateApiKey } from '../services/encryption.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import log from '../utils/logger.js';

const router = Router();
const SESSION_DURATION_HOURS = parseInt(process.env.SESSION_DURATION_HOURS) || 24;

// ---------------------------------------------------------------------------
// Discovery + JWKS caches (5 min / 10 min TTL)
// ---------------------------------------------------------------------------
const _discoveryCache = new Map();
const _jwksCache = new Map();

async function getDiscovery(baseUrl) {
  const now = Date.now();
  const cached = _discoveryCache.get(baseUrl);
  if (cached && now - cached.ts < 5 * 60 * 1000) return cached.doc;

  const url = baseUrl.endsWith('/.well-known/openid-configuration')
    ? baseUrl
    : baseUrl.replace(/\/$/, '') + '/.well-known/openid-configuration';

  const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error(`OIDC discovery failed (${r.status}): ${url}`);
  const doc = await r.json();
  _discoveryCache.set(baseUrl, { doc, ts: now });
  return doc;
}

async function getJwks(jwksUri) {
  const now = Date.now();
  const cached = _jwksCache.get(jwksUri);
  if (cached && now - cached.ts < 10 * 60 * 1000) return cached.keys;
  const r = await fetch(jwksUri, { signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error(`JWKS fetch failed (${r.status})`);
  const { keys } = await r.json();
  _jwksCache.set(jwksUri, { keys, ts: now });
  return keys;
}

async function verifyIdToken(idToken, jwksUri, clientId, issuer) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed id_token');

  const header  = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

  // Validate standard claims
  if (payload.iss !== issuer) throw new Error(`Token issuer mismatch: expected ${issuer}, got ${payload.iss}`);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(clientId)) throw new Error('Token audience does not include client_id');
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('id_token expired');

  // Find matching JWK (by kid, then by alg, then first key)
  const keys = await getJwks(jwksUri);
  const jwk = keys.find(k => k.kid === header.kid)
    || keys.find(k => k.alg === header.alg)
    || keys[0];
  if (!jwk) throw new Error('No matching JWK found for kid=' + header.kid);

  // Verify RS256 / RS384 / RS512 / PS256 / PS384 / PS512
  const alg = header.alg || 'RS256';
  const hashAlg = alg.includes('256') ? 'SHA256' : alg.includes('384') ? 'SHA384' : 'SHA512';
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const sigInput = Buffer.from(parts[0] + '.' + parts[1]);
  const sig = Buffer.from(parts[2], 'base64url');

  const valid = alg.startsWith('PS')
    ? crypto.verify(
        { name: 'RSA-PSS', saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST },
        sigInput,
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST },
        sig
      )
    : crypto.verify(hashAlg, sigInput, publicKey, sig);

  if (!valid) throw new Error('id_token signature verification failed');
  return payload;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function getOidcConfig() {
  const db = getDb();
  const rows = db.prepare("SELECT key, value FROM settings WHERE key LIKE 'oidc_%'").all();
  const cfg = Object.fromEntries(rows.map(r => [r.key, r.value]));
  return {
    enabled:        cfg.oidc_enabled === '1',
    discovery_url:  cfg.oidc_discovery_url || '',
    client_id:      cfg.oidc_client_id || '',
    client_secret:  cfg.oidc_client_secret_enc ? (() => { try { return decrypt(cfg.oidc_client_secret_enc); } catch { return ''; } })() : '',
    client_secret_set: !!cfg.oidc_client_secret_enc,
    provider_name:  cfg.oidc_provider_name || 'SSO',
    auto_provision: cfg.oidc_auto_provision === '1',
  };
}

function craneBaseUrl() {
  return process.env.CRANE_DOMAIN
    ? 'https://' + process.env.CRANE_DOMAIN
    : 'http://localhost:' + (process.env.PORT || 5001);
}

// HMAC-signed state prevents CSRF. Payload: { r: redirect, n: nonce, t: timestamp }
function makeState(redirect) {
  const payload = Buffer.from(JSON.stringify({ r: redirect || '', n: crypto.randomBytes(8).toString('hex'), t: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', process.env.ENCRYPTION_KEY).update(payload).digest('base64url');
  return payload + '.' + sig;
}

function parseState(state) {
  const dot = state.lastIndexOf('.');
  if (dot === -1) throw new Error('Invalid state format');
  const payload = state.slice(0, dot);
  const sig = state.slice(dot + 1);
  const expected = crypto.createHmac('sha256', process.env.ENCRYPTION_KEY).update(payload).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig, 'base64url'), Buffer.from(expected, 'base64url'))) {
    throw new Error('State signature mismatch — possible CSRF');
  }
  const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
  if (Date.now() - data.t > 10 * 60 * 1000) throw new Error('State expired (> 10 min)');
  return data;
}

function createIdentitySession(userId) {
  const db = getDb();
  const token = generateSessionToken();
  const tokenHash = hashApiKey(token);
  const expiresAt = new Date(Date.now() + SESSION_DURATION_HOURS * 3600 * 1000).toISOString();
  db.prepare('INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at) VALUES (?, ?, ?, ?)').run(userId, tokenHash, null, expiresAt);
  db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").run(userId);
  return token;
}

function upsertSetting(db, key, value, adminId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(key, String(value ?? ''), adminId);
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/**
 * GET /api/auth/oidc/config — public, returns only what the login page needs
 */
router.get('/config', (req, res) => {
  const cfg = getOidcConfig();
  res.json({ enabled: cfg.enabled, provider_name: cfg.provider_name });
});

/**
 * GET /api/auth/oidc/admin-config — admin: full config for settings page
 */
router.get('/admin-config', requireAuth, requireAdmin, (req, res) => {
  const cfg = getOidcConfig();
  res.json({
    enabled:           cfg.enabled,
    discovery_url:     cfg.discovery_url,
    client_id:         cfg.client_id,
    client_secret_set: cfg.client_secret_set,
    provider_name:     cfg.provider_name,
    auto_provision:    cfg.auto_provision,
  });
});

/**
 * PUT /api/auth/oidc/config — admin: save OIDC settings
 */
router.put('/config', requireAuth, requireAdmin, (req, res) => {
  const { enabled, discovery_url, client_id, client_secret, provider_name, auto_provision } = req.body || {};
  const db = getDb();
  const save = (k, v) => upsertSetting(db, k, v, req.user.id);

  save('oidc_enabled',        enabled ? '1' : '0');
  save('oidc_discovery_url',  discovery_url || '');
  save('oidc_client_id',      client_id || '');
  save('oidc_provider_name',  provider_name || 'SSO');
  save('oidc_auto_provision', auto_provision ? '1' : '0');
  if (client_secret) save('oidc_client_secret_enc', encrypt(client_secret));

  // Invalidate discovery cache when config changes
  _discoveryCache.clear();

  res.json({ message: 'OIDC settings saved' });
});

/**
 * POST /api/auth/oidc/test — admin: verify discovery URL is reachable
 */
router.post('/test', requireAuth, requireAdmin, async (req, res) => {
  const { discovery_url } = req.body || {};
  if (!discovery_url) return res.status(400).json({ error: { code: 'VALIDATION', message: 'discovery_url required' } });
  try {
    const doc = await getDiscovery(discovery_url);
    res.json({ ok: true, issuer: doc.issuer, authorization_endpoint: doc.authorization_endpoint });
  } catch (e) {
    res.status(400).json({ ok: false, error: { code: 'UNREACHABLE', message: e.message } });
  }
});

/**
 * GET /api/auth/oidc/start — redirect user to IdP
 */
router.get('/start', async (req, res) => {
  const cfg = getOidcConfig();
  if (!cfg.enabled || !cfg.discovery_url || !cfg.client_id) {
    return res.status(400).send('OIDC not configured');
  }
  try {
    const discovery = await getDiscovery(cfg.discovery_url);
    const redirectUri = craneBaseUrl() + '/api/auth/oidc/callback';
    const state = makeState(req.query.redirect || '');
    const params = new URLSearchParams({
      response_type: 'code',
      client_id:     cfg.client_id,
      redirect_uri:  redirectUri,
      scope:         'openid email profile',
      state,
    });
    res.redirect(302, discovery.authorization_endpoint + '?' + params.toString());
  } catch (e) {
    log.error('OIDC start error: ' + e.message);
    res.redirect(302, craneBaseUrl() + '/login?sso_error=' + encodeURIComponent(e.message));
  }
});

/**
 * GET /api/auth/oidc/callback — IdP posts back here with ?code=&state=
 */
router.get('/callback', async (req, res) => {
  const base = craneBaseUrl();
  try {
    const { code, state, error, error_description } = req.query;
    if (error) throw new Error(error_description || error);
    if (!code || !state) throw new Error('Missing code or state in callback');

    const stateData = parseState(state);
    const cfg = getOidcConfig();
    if (!cfg.enabled) throw new Error('OIDC is not enabled');

    const discovery   = await getDiscovery(cfg.discovery_url);
    const redirectUri = base + '/api/auth/oidc/callback';

    // Exchange authorization code for tokens
    const tokenRes = await fetch(discovery.token_endpoint, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  redirectUri,
        client_id:     cfg.client_id,
        client_secret: cfg.client_secret,
      }),
      signal: AbortSignal.timeout(15000),
    });

    if (!tokenRes.ok) {
      const body = await tokenRes.text();
      throw new Error('Token exchange failed: ' + body.slice(0, 120));
    }

    const tokens = await tokenRes.json();
    if (!tokens.id_token) throw new Error('No id_token in token response');

    // Verify and decode the ID token
    const claims = await verifyIdToken(tokens.id_token, discovery.jwks_uri, cfg.client_id, discovery.issuer);
    const { sub, email, name, given_name, family_name } = claims;
    if (!sub) throw new Error('id_token missing sub claim');

    const displayName = name
      || [given_name, family_name].filter(Boolean).join(' ')
      || email
      || sub;

    // Find or create user
    const db = getDb();
    let user = db.prepare('SELECT * FROM users WHERE sso_sub = ?').get(sub);

    if (!user && email) {
      // Link to existing account by email
      user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      if (user) {
        db.prepare('UPDATE users SET sso_sub = ? WHERE id = ?').run(sub, user.id);
        log.info(`OIDC: linked ${email} to sub ${sub}`);
      }
    }

    // Sync display name from IdP on every login
    if (user && displayName && displayName !== user.name) {
      db.prepare('UPDATE users SET name = ? WHERE id = ?').run(displayName, user.id);
    }

    if (!user && cfg.auto_provision) {
      const keyHash = hashApiKey(generateApiKey('dhk_user'));
      const result = db.prepare(
        "INSERT INTO users (name, email, role, sso_sub, api_key_hash, created_at) VALUES (?, ?, 'user', ?, ?, datetime('now'))"
      ).run(displayName, email || null, sub, keyHash);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
      log.info(`OIDC: auto-provisioned user "${displayName}" (${email || sub})`);
    }

    if (!user) {
      log.warn(`OIDC: no account for sub=${sub} email=${email}, auto-provision disabled`);
      return res.redirect(302, base + '/login?sso_error=no_account');
    }

    // Create session and hand token back to the browser via login page JS
    const token = createIdentitySession(user.id);
    log.info(`OIDC login: ${user.name} (${email || sub})`);

    // Always go through /login so it sets the cookie, then forward to redirect target
    const p = new URLSearchParams({ oidc_token: token });
    if (stateData.r && stateData.r.startsWith('http') && !stateData.r.includes('/login')) {
      p.set('redirect', stateData.r);
    }
    res.redirect(302, `${base}/login?${p.toString()}`);
  } catch (e) {
    log.error('OIDC callback error: ' + e.message);
    res.redirect(302, base + '/login?sso_error=' + encodeURIComponent(e.message));
  }
});

export default router;
