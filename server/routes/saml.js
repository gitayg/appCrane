import { Router } from 'express';
import { SAML } from '@node-saml/node-saml';
import { getDb } from '../db.js';
import { encrypt, decrypt, generateSessionToken, hashApiKey, generateApiKey } from '../services/encryption.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import log from '../utils/logger.js';

const router = Router();
const SESSION_DURATION_HOURS = parseInt(process.env.SESSION_DURATION_HOURS) || 24;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function craneBaseUrl() {
  return process.env.CRANE_DOMAIN
    ? 'https://' + process.env.CRANE_DOMAIN
    : 'http://localhost:' + (process.env.PORT || 5001);
}

function getSamlConfig() {
  const db = getDb();
  const rows = db.prepare("SELECT key, value FROM settings WHERE key LIKE 'saml_%'").all();
  const cfg  = Object.fromEntries(rows.map(r => [r.key, r.value]));
  const cert = cfg.saml_idp_cert_enc
    ? (() => { try { return decrypt(cfg.saml_idp_cert_enc); } catch { return ''; } })()
    : '';
  return {
    enabled:        cfg.saml_enabled === '1',
    idp_sso_url:    cfg.saml_idp_sso_url || '',
    idp_cert:       cert,
    idp_cert_set:   !!cfg.saml_idp_cert_enc,
    provider_name:  cfg.saml_provider_name || 'Okta',
    auto_provision: cfg.saml_auto_provision === '1',
  };
}

function buildSaml(cfg) {
  const base = craneBaseUrl();
  return new SAML({
    callbackUrl:            base + '/api/auth/saml/callback',
    entryPoint:             cfg.idp_sso_url,
    issuer:                 base + '/api/auth/saml/metadata',
    idpCert:                cfg.idp_cert,
    wantAuthnResponseSigned: true,
    wantAssertionsSigned:    true,
    signatureAlgorithm:     'sha256',
    digestAlgorithm:        'sha256',
  });
}

function createIdentitySession(userId) {
  const db = getDb();
  const token    = generateSessionToken();
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
 * GET /api/auth/saml/config — public, for login page button
 */
router.get('/config', (req, res) => {
  const cfg = getSamlConfig();
  res.json({ enabled: cfg.enabled, provider_name: cfg.provider_name });
});

/**
 * GET /api/auth/saml/admin-config — admin, for settings page
 */
router.get('/admin-config', requireAuth, requireAdmin, (req, res) => {
  const cfg = getSamlConfig();
  res.json({
    enabled:        cfg.enabled,
    idp_sso_url:    cfg.idp_sso_url,
    idp_cert_set:   cfg.idp_cert_set,
    provider_name:  cfg.provider_name,
    auto_provision: cfg.auto_provision,
  });
});

/**
 * PUT /api/auth/saml/config — admin: save SAML settings
 */
router.put('/config', requireAuth, requireAdmin, (req, res) => {
  const { enabled, idp_sso_url, idp_cert, provider_name, auto_provision } = req.body || {};
  const db = getDb();
  const save = (k, v) => upsertSetting(db, k, v, req.user.id);

  save('saml_enabled',        enabled ? '1' : '0');
  save('saml_idp_sso_url',    idp_sso_url || '');
  save('saml_provider_name',  provider_name || 'Okta');
  save('saml_auto_provision', auto_provision ? '1' : '0');
  if (idp_cert) save('saml_idp_cert_enc', encrypt(idp_cert.trim()));

  res.json({ message: 'SAML settings saved' });
});

/**
 * GET /api/auth/saml/metadata — SP metadata XML (import this URL into Okta)
 */
router.get('/metadata', (req, res) => {
  const cfg  = getSamlConfig();
  const base = craneBaseUrl();

  // Return minimal SP metadata even if SAML is not fully configured yet —
  // admins need the ACS URL and entity ID before they can configure Okta.
  let samlInstance;
  try {
    samlInstance = buildSaml({ ...cfg, idp_cert: cfg.idp_cert || 'placeholder', idp_sso_url: cfg.idp_sso_url || 'https://placeholder' });
  } catch (e) {
    return res.status(500).type('text/plain').send('SAML not configured: ' + e.message);
  }

  const metadata = samlInstance.generateServiceProviderMetadata(null, null);
  res.type('application/xml').send(metadata);
});

/**
 * GET /api/auth/saml/start — redirect user to Okta
 */
router.get('/start', async (req, res) => {
  const cfg = getSamlConfig();
  if (!cfg.enabled || !cfg.idp_sso_url || !cfg.idp_cert) {
    return res.status(400).send('SAML not configured');
  }
  try {
    const saml     = buildSaml(cfg);
    const redirect  = req.query.redirect || '';
    const url = await saml.getAuthorizeUrlAsync(
      redirect,   // RelayState — passed back verbatim in the callback
      req.headers.host,
      {}
    );
    res.redirect(url);
  } catch (e) {
    log.error('SAML start error: ' + e.message);
    res.redirect(302, craneBaseUrl() + '/login?saml_error=' + encodeURIComponent(e.message));
  }
});

/**
 * POST /api/auth/saml/callback — Okta posts SAMLResponse here
 */
router.post('/callback', async (req, res) => {
  const base = craneBaseUrl();
  try {
    const cfg = getSamlConfig();
    if (!cfg.enabled) throw new Error('SAML not enabled');

    const saml = buildSaml(cfg);
    const { profile } = await saml.validatePostResponseAsync(req.body);

    // Extract identity from SAML attributes
    const nameId     = profile.nameID;                              // Okta default: email
    const email      = profile.email || profile['urn:oid:1.2.840.113549.1.9.1'] || (nameId?.includes('@') ? nameId : null);
    const firstName  = profile.firstName || profile['urn:oid:2.5.4.42'] || '';
    const lastName   = profile.lastName  || profile['urn:oid:2.5.4.4']  || '';
    const displayName = [firstName, lastName].filter(Boolean).join(' ') || email || nameId;

    if (!nameId) throw new Error('SAMLResponse missing nameID');

    // Find or create user
    const db = getDb();
    let user = db.prepare('SELECT * FROM users WHERE saml_name_id = ?').get(nameId);

    if (!user && email) {
      user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      if (user) {
        db.prepare('UPDATE users SET saml_name_id = ? WHERE id = ?').run(nameId, user.id);
        log.info(`SAML: linked ${email} to nameID ${nameId}`);
      }
    }

    // Sync display name from Okta on every login
    if (user && displayName && displayName !== user.name) {
      db.prepare('UPDATE users SET name = ? WHERE id = ?').run(displayName, user.id);
    }

    if (!user && cfg.auto_provision) {
      const keyHash = hashApiKey(generateApiKey('dhk_user'));
      const result = db.prepare(
        "INSERT INTO users (name, email, role, saml_name_id, api_key_hash, created_at) VALUES (?, ?, 'user', ?, ?, datetime('now'))"
      ).run(displayName, email || null, nameId, keyHash);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
      log.info(`SAML: auto-provisioned user "${displayName}" (${email || nameId})`);
    }

    if (!user) {
      log.warn(`SAML: no account for nameID=${nameId}, auto-provision disabled`);
      return res.redirect(302, base + '/login?saml_error=no_account');
    }

    const token    = createIdentitySession(user.id);
    const relayState = req.body.RelayState || '';
    const dest     = relayState && relayState.startsWith('http') ? relayState : base + '/login';
    const sep      = dest.includes('?') ? '&' : '?';

    log.info(`SAML login: ${user.name} (${nameId})`);
    res.redirect(302, `${dest}${sep}oidc_token=${encodeURIComponent(token)}`);
  } catch (e) {
    log.error('SAML callback error: ' + e.message);
    res.redirect(302, base + '/login?saml_error=' + encodeURIComponent(e.message));
  }
});

export default router;
