import { useState, useEffect, useRef } from 'react'
import { adminApi } from '../adminApi'
import { useFlash, FocusInput, FocusTextarea } from '../components/formHelpers'
import { Users } from './Users'
import { AuditLog } from './AuditLog'
import { BrandingTab } from '../components/BrandingTab'

function SecurityTab() {
  const [certFile, setCertFile] = useState('')
  const [keyFile, setKeyFile] = useState('')
  const [tlsSaved, flashTlsSaved] = useFlash()

  const [tlsCheck, setTlsCheck] = useState<{
    skipped?: boolean; domain?: string; tls_mode?: string;
    hsts_preloaded?: boolean; cert_valid?: boolean;
    warnings?: { level: string; message: string }[]
  } | null>(null)

  const [oidc, setOidc] = useState({
    enabled: false, provider_name: '', discovery_url: '',
    client_id: '', client_secret_set: false, auto_provision: false,
  })
  const [oidcSecret, setOidcSecret] = useState('')
  const [oidcSaved, flashOidcSaved] = useFlash()
  const [oidcTest, setOidcTest] = useState<{ ok: boolean; msg: string } | null>(null)
  const oidcTestTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const [saml, setSaml] = useState({
    enabled: false, provider_name: '', idp_sso_url: '',
    idp_cert_set: false, auto_provision: false,
  })
  const [samlCert, setSamlCert] = useState('')
  const [samlSaved, flashSamlSaved] = useFlash()

  const [scim, setScim] = useState({ enabled: false, base_url: '', token_created_at: '' })
  const [scimSaved, flashScimSaved] = useFlash()
  const [scimToken, setScimToken] = useState('')

  // v2.7.0: require-SSO toggle. Disables password sign-in across the
  // instance; the IdP becomes the only browser login path.
  const [ssoOnly, setSsoOnly] = useState(false)
  const [ssoOnlySaved, flashSsoOnlySaved] = useFlash()
  const [ssoOnlyError, setSsoOnlyError] = useState<string | null>(null)

  useEffect(() => {
    adminApi.get<{ value?: string }>('/api/settings/tls_cert_file').then(r => { if (r?.value) setCertFile(r.value) }).catch(() => {})
    adminApi.get<{ value?: string }>('/api/settings/tls_key_file').then(r => { if (r?.value) setKeyFile(r.value) }).catch(() => {})
    adminApi.get<typeof tlsCheck>('/api/server/tls-check').then(setTlsCheck).catch(() => {})
    adminApi.get<typeof oidc & { client_secret_set: boolean }>('/api/auth/oidc/admin-config').then(r => {
      if (r) setOidc({ enabled: r.enabled, provider_name: r.provider_name, discovery_url: r.discovery_url, client_id: r.client_id, client_secret_set: r.client_secret_set, auto_provision: r.auto_provision })
    }).catch(() => {})
    adminApi.get<typeof saml>('/api/auth/saml/admin-config').then(r => {
      if (r) setSaml({ enabled: r.enabled, provider_name: r.provider_name, idp_sso_url: r.idp_sso_url, idp_cert_set: r.idp_cert_set, auto_provision: r.auto_provision })
    }).catch(() => {})
    adminApi.get<typeof scim>('/api/auth/scim/config').then(r => { if (r) setScim(r) }).catch(() => {})
    adminApi.get<{ value?: string }>('/api/settings/auth_sso_only').then(r => setSsoOnly(r?.value === 'true')).catch(() => {})
  }, [])

  async function saveSsoOnly(next: boolean) {
    setSsoOnlyError(null)
    try {
      await adminApi.put('/api/settings/auth_sso_only', { value: next ? 'true' : 'false' })
      setSsoOnly(next)
      flashSsoOnlySaved()
    } catch (e) {
      setSsoOnlyError(e instanceof Error ? e.message : 'Save failed')
    }
  }

  async function saveTls() {
    await Promise.all([
      adminApi.put('/api/settings/tls_cert_file', { value: certFile }),
      adminApi.put('/api/settings/tls_key_file', { value: keyFile }),
    ]).catch(() => {})
    flashTlsSaved()
    adminApi.get<typeof tlsCheck>('/api/server/tls-check').then(setTlsCheck).catch(() => {})
  }

  async function testOidc() {
    const r = await adminApi.post<{ ok: boolean; error?: string }>('/api/auth/oidc/test', { discovery_url: oidc.discovery_url }).catch(() => null)
    const ok = r?.ok ?? false
    setOidcTest({ ok, msg: ok ? 'Connection successful' : (r?.error ?? 'Test failed') })
    if (oidcTestTimer.current) clearTimeout(oidcTestTimer.current)
    oidcTestTimer.current = setTimeout(() => setOidcTest(null), 5000)
  }

  async function saveOidc() {
    const body: Record<string, unknown> = {
      enabled: oidc.enabled, provider_name: oidc.provider_name,
      discovery_url: oidc.discovery_url, client_id: oidc.client_id,
      auto_provision: oidc.auto_provision,
    }
    if (oidcSecret) body.client_secret = oidcSecret
    await adminApi.put('/api/auth/oidc/config', body).catch(() => {})
    flashOidcSaved()
    setOidcSecret('')
    adminApi.get<typeof oidc & { client_secret_set: boolean }>('/api/auth/oidc/admin-config').then(r => {
      if (r) setOidc({ enabled: r.enabled, provider_name: r.provider_name, discovery_url: r.discovery_url, client_id: r.client_id, client_secret_set: r.client_secret_set, auto_provision: r.auto_provision })
    }).catch(() => {})
  }

  async function saveSaml() {
    const body: Record<string, unknown> = {
      enabled: saml.enabled, provider_name: saml.provider_name,
      idp_sso_url: saml.idp_sso_url, auto_provision: saml.auto_provision,
    }
    if (samlCert) body.idp_cert = samlCert
    await adminApi.put('/api/auth/saml/config', body).catch(() => {})
    flashSamlSaved()
    setSamlCert('')
    adminApi.get<typeof saml>('/api/auth/saml/admin-config').then(r => { if (r) setSaml(r) }).catch(() => {})
  }

  async function saveScim() {
    await adminApi.put('/api/auth/scim/config', { enabled: scim.enabled }).catch(() => {})
    flashScimSaved()
  }

  async function generateScimToken() {
    if (!confirm('This will invalidate any existing SCIM bearer token. Continue?')) return
    const r = await adminApi.post<{ token?: string }>('/api/auth/scim/token', {}).catch(() => null)
    if (r?.token) {
      setScimToken(r.token)
      adminApi.get<typeof scim>('/api/auth/scim/config').then(r => { if (r) setScim(r) }).catch(() => {})
    }
  }

  const tlsPreBlock = tlsCheck && !tlsCheck.skipped
    ? [
        tlsCheck.domain ? `Domain:         ${tlsCheck.domain}` : null,
        tlsCheck.tls_mode ? `TLS mode:       ${tlsCheck.tls_mode}` : null,
        tlsCheck.hsts_preloaded !== undefined ? `HSTS preloaded: ${tlsCheck.hsts_preloaded ? 'yes' : 'no'}` : null,
        tlsCheck.cert_valid !== undefined ? `Cert valid:     ${tlsCheck.cert_valid ? 'yes' : 'no'}` : null,
      ].filter(Boolean).join('\n')
    : null

  const labelStyle: React.CSSProperties = { fontSize: '.78rem', color: 'var(--dim)', marginBottom: 4, display: 'block' }
  const fieldWrap: React.CSSProperties = { marginBottom: 12 }

  return (
    <>
      <div className="setting-card">
        <h3>Manual TLS Certificate</h3>
        <p>Override Caddy's automatic TLS with a manually managed certificate and private key.</p>
        <div style={fieldWrap}>
          <label style={labelStyle}>Certificate file path</label>
          <FocusInput value={certFile} onChange={e => setCertFile(e.target.value)} placeholder="/etc/ssl/certs/server.crt" />
        </div>
        <div style={fieldWrap}>
          <label style={labelStyle}>Private key file path</label>
          <FocusInput value={keyFile} onChange={e => setKeyFile(e.target.value)} placeholder="/etc/ssl/private/server.key" />
        </div>
        <div className="save-row">
          <button className="btn btn-accent" onClick={saveTls}>Save & Reload Caddy</button>
          {tlsSaved && <span className="saved-msg">Saved ✓</span>}
        </div>
      </div>

      <div className="setting-card">
        <h3>TLS Health Check</h3>
        {!tlsCheck && <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>Loading…</p>}
        {tlsCheck?.skipped && (
          <p style={{ fontSize: '.85rem', color: 'var(--dim)' }}>CRANE_DOMAIN is not set — no domain to check.</p>
        )}
        {tlsCheck && !tlsCheck.skipped && (
          <>
            {tlsPreBlock && (
              <pre style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 14px', fontSize: '.82rem', marginBottom: 12, overflowX: 'auto' }}>
                {tlsPreBlock}
              </pre>
            )}
            {(!tlsCheck.warnings || tlsCheck.warnings.length === 0) && (
              <p style={{ color: 'var(--green)', fontSize: '.85rem' }}>No issues detected.</p>
            )}
            {tlsCheck.warnings?.map((w, i) => (
              <div key={i} style={{
                background: w.level === 'error' ? 'rgba(239,68,68,.12)' : 'rgba(234,179,8,.12)',
                border: `1px solid ${w.level === 'error' ? 'var(--red)' : 'var(--yellow)'}`,
                borderRadius: 6, padding: '8px 12px', marginBottom: 8, fontSize: '.84rem',
                color: w.level === 'error' ? 'var(--red)' : 'var(--yellow)',
              }}>
                {w.message}
              </div>
            ))}
          </>
        )}
      </div>

      <div className="setting-card">
        <h3>OIDC / SSO</h3>
        <p>Configure OpenID Connect single sign-on for your users.</p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <input type="checkbox" id="oidc-enabled" checked={oidc.enabled} onChange={e => setOidc(v => ({ ...v, enabled: e.target.checked }))} />
          <label htmlFor="oidc-enabled" style={{ fontSize: '.85rem' }}>Enable SSO login</label>
        </div>
        <div style={fieldWrap}>
          <label style={labelStyle}>Provider name</label>
          <FocusInput value={oidc.provider_name} onChange={e => setOidc(v => ({ ...v, provider_name: e.target.value }))} placeholder="Okta" />
        </div>
        <div style={fieldWrap}>
          <label style={labelStyle}>Discovery URL</label>
          <FocusInput value={oidc.discovery_url} onChange={e => setOidc(v => ({ ...v, discovery_url: e.target.value }))} placeholder="https://example.okta.com/.well-known/openid-configuration" />
        </div>
        <div style={fieldWrap}>
          <label style={labelStyle}>Client ID</label>
          <FocusInput value={oidc.client_id} onChange={e => setOidc(v => ({ ...v, client_id: e.target.value }))} />
        </div>
        <div style={fieldWrap}>
          <label style={labelStyle}>Client Secret</label>
          <FocusInput
            type="password"
            value={oidcSecret}
            onChange={e => setOidcSecret(e.target.value)}
            placeholder={oidc.client_secret_set ? '••••••••••••' : 'Client secret'}
          />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <input type="checkbox" id="oidc-provision" checked={oidc.auto_provision} onChange={e => setOidc(v => ({ ...v, auto_provision: e.target.checked }))} />
          <label htmlFor="oidc-provision" style={{ fontSize: '.85rem' }}>Auto-provision new users</label>
        </div>
        <div className="save-row">
          <button className="btn" onClick={testOidc}>Test Connection</button>
          <button className="btn btn-accent" onClick={saveOidc}>Save</button>
          {oidcSaved && <span className="saved-msg">Saved ✓</span>}
          {oidcTest && (
            <span style={{ fontSize: '.82rem', color: oidcTest.ok ? 'var(--green)' : 'var(--red)' }}>
              {oidcTest.ok ? '✓' : '✗'} {oidcTest.msg}
            </span>
          )}
        </div>
      </div>

      <div className="setting-card">
        <h3>SAML 2.0 (Okta)</h3>
        <p>
          Configure SAML single sign-on. SP metadata available at{' '}
          <a href="/api/auth/saml/metadata" target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>/api/auth/saml/metadata</a>.
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <input type="checkbox" id="saml-enabled" checked={saml.enabled} onChange={e => setSaml(v => ({ ...v, enabled: e.target.checked }))} />
          <label htmlFor="saml-enabled" style={{ fontSize: '.85rem' }}>Enable SAML login</label>
        </div>
        <div style={fieldWrap}>
          <label style={labelStyle}>Provider name</label>
          <FocusInput value={saml.provider_name} onChange={e => setSaml(v => ({ ...v, provider_name: e.target.value }))} placeholder="Okta" />
        </div>
        <div style={fieldWrap}>
          <label style={labelStyle}>Okta SSO URL</label>
          <FocusInput value={saml.idp_sso_url} onChange={e => setSaml(v => ({ ...v, idp_sso_url: e.target.value }))} placeholder="https://example.okta.com/app/xxx/sso/saml" />
        </div>
        <div style={fieldWrap}>
          <label style={labelStyle}>X.509 Certificate</label>
          <FocusTextarea
            value={samlCert}
            onChange={e => setSamlCert(e.target.value)}
            placeholder={saml.idp_cert_set ? '(certificate already set — paste new one to replace)' : 'Paste IdP X.509 certificate'}
            style={{ minHeight: 120, fontFamily: 'monospace', fontSize: '.8rem' }}
          />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <input type="checkbox" id="saml-provision" checked={saml.auto_provision} onChange={e => setSaml(v => ({ ...v, auto_provision: e.target.checked }))} />
          <label htmlFor="saml-provision" style={{ fontSize: '.85rem' }}>Auto-provision new users</label>
        </div>
        <div className="save-row">
          <button className="btn btn-accent" onClick={saveSaml}>Save</button>
          {samlSaved && <span className="saved-msg">Saved ✓</span>}
        </div>
      </div>

      <div className="setting-card">
        <h3>Require SSO</h3>
        <p>
          Disable email/username + password sign-in for everyone. The SSO button becomes the only
          browser login path; the API-key break-glass paste is hidden too. OIDC or SAML must be
          enabled and configured first. CLI / API keys still work for recovery.
        </p>
        {!(oidc.enabled || saml.enabled) && (
          <div style={{
            background: 'rgba(234,179,8,.12)', border: '1px solid var(--yellow)', color: 'var(--yellow)',
            borderRadius: 6, padding: '8px 12px', marginBottom: 12, fontSize: '.84rem',
          }}>
            No SSO provider is enabled yet. Configure OIDC or SAML above before requiring SSO.
          </div>
        )}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <input
            type="checkbox"
            id="sso-only"
            checked={ssoOnly}
            disabled={!ssoOnly && !(oidc.enabled || saml.enabled)}
            onChange={e => saveSsoOnly(e.target.checked)}
          />
          <label htmlFor="sso-only" style={{ fontSize: '.85rem' }}>Require SSO (disable password sign-in)</label>
          {ssoOnlySaved && <span className="saved-msg">Saved ✓</span>}
        </div>
        {ssoOnlyError && (
          <div style={{ fontSize: '.82rem', color: 'var(--red)' }}>{ssoOnlyError}</div>
        )}
      </div>

      <div className="setting-card">
        <h3>SCIM Provisioning</h3>
        <p>Automate user provisioning and de-provisioning via SCIM 2.0.</p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <input type="checkbox" id="scim-enabled" checked={scim.enabled} onChange={e => setScim(v => ({ ...v, enabled: e.target.checked }))} />
          <label htmlFor="scim-enabled" style={{ fontSize: '.85rem' }}>Enable SCIM provisioning</label>
        </div>
        {scim.base_url && (
          <div style={{ marginBottom: 12 }}>
            <label style={labelStyle}>SCIM base URL</label>
            <code style={{
              display: 'block', background: 'var(--surface2)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '8px 12px', fontSize: '.82rem', wordBreak: 'break-all',
            }}>{scim.base_url}</code>
          </div>
        )}
        <p style={{ fontSize: '.84rem', color: 'var(--dim)', marginBottom: 12 }}>
          {scim.token_created_at
            ? `Bearer token last generated: ${new Date(scim.token_created_at).toLocaleString()}`
            : 'No bearer token generated yet.'}
        </p>
        {scimToken && (
          <div style={{ marginBottom: 12 }}>
            <code style={{
              display: 'block', background: 'rgba(234,179,8,.1)', border: '1px solid var(--yellow)',
              borderRadius: 6, padding: '10px 14px', fontSize: '.82rem', fontFamily: 'monospace',
              wordBreak: 'break-all', color: 'var(--yellow)', marginBottom: 6,
            }}>{scimToken}</code>
            <span style={{ fontSize: '.8rem', color: 'var(--yellow)' }}>Copy this token now — it will not be shown again.</span>
          </div>
        )}
        <div className="save-row">
          <button className="btn btn-accent" onClick={saveScim}>Save</button>
          <button className="btn" onClick={generateScimToken}>Generate New Token</button>
          {scimSaved && <span className="saved-msg">Saved ✓</span>}
        </div>
      </div>
    </>
  )
}

interface PermDef { key: string; label: string; description: string; scope?: 'app' | 'platform' }
type Role = 'user' | 'admin' | 'owner' | 'platform_admin'
type Matrix = Record<string, Record<Role, number>>

function RolesTab() {
  const [permissions, setPermissions] = useState<PermDef[]>([])
  const [matrix, setMatrix] = useState<Matrix>({})
  const [roles, setRoles] = useState<Role[]>(['user', 'admin', 'owner', 'platform_admin'])
  const [busy, setBusy] = useState(false)
  const [saved, flashSaved] = useFlash()
  const [error, setError] = useState<string | null>(null)

  const load = () => {
    adminApi.get<{ permissions: PermDef[]; matrix: Matrix; roles: Role[] }>('/api/settings/role-permissions/catalog')
      .then(r => {
        setPermissions(r.permissions ?? [])
        setMatrix(r.matrix ?? {})
        if (Array.isArray(r.roles) && r.roles.length) setRoles(r.roles)
      })
      .catch(e => setError(e?.message || 'Failed to load matrix'))
  }
  useEffect(() => { load() }, [])

  function toggle(perm: string, role: Role) {
    setMatrix(prev => ({
      ...prev,
      [perm]: { ...prev[perm], [role]: prev[perm]?.[role] ? 0 : 1 },
    }))
  }

  async function save() {
    if (busy) return
    setBusy(true)
    try {
      const r = await adminApi.put<{ matrix: Matrix }>('/api/settings/role-permissions', { matrix })
      if (r?.matrix) setMatrix(r.matrix)
      flashSaved()
    } catch (e) {
      alert('Save failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  async function resetRow(permKey: string) {
    if (!confirm(`Reset "${permKey}" to defaults?`)) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ matrix: Matrix }>('/api/settings/role-permissions/reset', { permissions: [permKey] })
      if (r?.matrix) setMatrix(r.matrix)
      flashSaved()
    } catch (e) {
      alert('Reset failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  async function resetAll() {
    if (!confirm('Reset all permissions to seeded defaults? This will overwrite all current settings.')) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ matrix: Matrix }>('/api/settings/role-permissions/reset', {})
      if (r?.matrix) setMatrix(r.matrix)
      flashSaved()
    } catch (e) {
      alert('Reset failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  if (error) {
    return (
      <div className="setting-card" style={{ borderColor: '#ef444444' }}>
        <h3 style={{ color: 'var(--red)' }}>Roles unavailable</h3>
        <p>{error}</p>
      </div>
    )
  }

  return (
    <>
      <div className="setting-card">
        <h3>Per-app role permissions</h3>
        <p>
          High-stakes operations where AppCrane lets you decide who's allowed. Most other authz
          stays hardcoded — these are the cells that genuinely vary across teams.
          AppCrane global admins (<code style={{ fontFamily: 'monospace', background: 'var(--surface2)', padding: '1px 5px', borderRadius: 3, fontSize: '.78rem' }}>users.role = admin</code> or <code style={{ fontFamily: 'monospace', background: 'var(--surface2)', padding: '1px 5px', borderRadius: 3, fontSize: '.78rem' }}>platform_admin</code>)
          always have every permission regardless of this matrix; the table below governs only the
          per-app role tiers. Rows tagged <span style={{ fontSize: '.68rem', letterSpacing: '.4px', textTransform: 'uppercase', color: 'var(--accent)', border: '1px solid var(--accent)', borderRadius: 3, padding: '0 4px' }}>platform</span> are
          checked against the user's global role instead — there's no app yet — so the per-app OWNER column doesn't apply.
        </p>

        <table style={{ width: '100%', fontSize: '.85rem', marginTop: 12 }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '6px 8px' }}>Permission</th>
              {roles.map(r => (
                <th key={r} style={{ textAlign: 'center', color: 'var(--dim)', fontWeight: 500, padding: '6px 8px', textTransform: 'uppercase', letterSpacing: '.4px', fontSize: '.72rem' }}>
                  {r}
                </th>
              ))}
              <th></th>
            </tr>
          </thead>
          <tbody>
            {permissions.map(p => (
              <tr key={p.key} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ padding: '10px 8px', verticalAlign: 'top' }}>
                  <div style={{ fontWeight: 600 }}>
                    {p.label}
                    {p.scope === 'platform' && (
                      <span style={{ marginLeft: 6, fontSize: '.62rem', letterSpacing: '.4px', textTransform: 'uppercase', color: 'var(--accent)', border: '1px solid var(--accent)', borderRadius: 3, padding: '0 4px', verticalAlign: 'middle' }}>platform</span>
                    )}
                  </div>
                  <div style={{ color: 'var(--dim)', fontSize: '.78rem', marginTop: 2 }}>{p.description}</div>
                  <div style={{ color: 'var(--dim)', fontFamily: 'monospace', fontSize: '.72rem', marginTop: 4 }}>{p.key}</div>
                </td>
                {roles.map(role => {
                  // Platform-scoped perms have no per-app OWNER concept.
                  const naCell = p.scope === 'platform' && role === 'owner'
                  return (
                    <td key={role} style={{ textAlign: 'center', padding: '10px 8px', verticalAlign: 'top' }}>
                      {naCell ? (
                        <span style={{ color: 'var(--dim)' }} title="Not applicable — platform permission has no per-app owner">—</span>
                      ) : (
                        <input
                          type="checkbox"
                          checked={!!(matrix[p.key]?.[role])}
                          onChange={() => toggle(p.key, role)}
                          style={{ width: 18, height: 18, cursor: 'pointer' }}
                        />
                      )}
                    </td>
                  )
                })}
                <td style={{ textAlign: 'right', padding: '10px 8px', verticalAlign: 'top' }}>
                  <button className="btn btn-xs" onClick={() => resetRow(p.key)} disabled={busy}>Reset</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div className="save-row" style={{ marginTop: 16, justifyContent: 'space-between' }}>
          <button className="btn" onClick={resetAll} disabled={busy}>Reset all to defaults</button>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {saved && <span className="saved-msg">Saved ✓</span>}
            <button className="btn btn-accent" onClick={save} disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
          </div>
        </div>
      </div>
    </>
  )
}

interface ContainerEntry {
  user_id: number
  started_at: string
  last_active_at: string
  idle_seconds: number
  alive: boolean
}

interface GithubServiceConfig {
  owner: string
  visibility: 'private' | 'internal' | 'public'
  enabled: boolean
  configured: boolean
}

function GithubTab() {
  const [idleTimeout, setIdleTimeout] = useState(600)
  const [maxConcurrent, setMaxConcurrent] = useState(10)
  const [image, setImage] = useState('ghcr.io/github/github-mcp-server:latest')
  const [containers, setContainers] = useState<ContainerEntry[]>([])
  const [saved, flashSaved] = useFlash()
  const [busy, setBusy] = useState(false)

  // Service-account config (v2.3.0+) — single platform PAT that owns the
  // per-app repos when the user opts into "AppCrane manages my code."
  const [svc, setSvc] = useState<GithubServiceConfig>({ owner: '', visibility: 'private', enabled: false, configured: false })
  const [svcToken, setSvcToken] = useState('')
  const [svcSaved, flashSvcSaved] = useFlash()
  const [svcVerify, setSvcVerify] = useState<{ ok: boolean; login?: string; type?: string; scopes?: string | null; error?: string } | null>(null)
  const [svcBusy, setSvcBusy] = useState(false)

  function loadServiceConfig() {
    adminApi.get<GithubServiceConfig>('/api/github-service/config').then(setSvc).catch(() => {})
  }

  async function saveService() {
    if (svcBusy) return
    setSvcBusy(true)
    try {
      const body: Record<string, unknown> = { owner: svc.owner, visibility: svc.visibility, enabled: svc.enabled }
      if (svcToken) body.token = svcToken
      const next = await adminApi.put<GithubServiceConfig>('/api/github-service/config', body)
      if (next) setSvc(next)
      setSvcToken('')
      flashSvcSaved()
    } catch (e) {
      alert('Save failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setSvcBusy(false)
    }
  }

  async function clearServiceToken() {
    if (!confirm('Clear the stored service-account token? This will disable the integration.')) return
    setSvcBusy(true)
    try {
      const next = await adminApi.put<GithubServiceConfig>('/api/github-service/config', { token: null })
      if (next) setSvc(next)
      setSvcToken('')
      setSvcVerify(null)
      flashSvcSaved()
    } finally { setSvcBusy(false) }
  }

  async function verifyService() {
    setSvcVerify(null)
    setSvcBusy(true)
    try {
      const r = await adminApi.post<typeof svcVerify>('/api/github-service/verify', {})
      setSvcVerify(r)
    } catch (e) {
      setSvcVerify({ ok: false, error: e instanceof Error ? e.message : String(e) })
    } finally { setSvcBusy(false) }
  }

  function loadSettings() {
    Promise.all([
      adminApi.get<{ value?: string }>('/api/settings/github_mcp_idle_timeout').catch(() => ({ value: '600' })),
      adminApi.get<{ value?: string }>('/api/settings/github_mcp_max_concurrent').catch(() => ({ value: '10' })),
      adminApi.get<{ value?: string }>('/api/settings/github_mcp_image').catch(() => ({ value: 'ghcr.io/github/github-mcp-server:latest' })),
    ]).then(([t, m, i]) => {
      if (t?.value) setIdleTimeout(Number(t.value))
      if (m?.value) setMaxConcurrent(Number(m.value))
      if (i?.value) setImage(i.value)
    })
  }

  function loadContainers() {
    adminApi.get<{ active: ContainerEntry[] }>('/api/mcp/github/containers')
      .then(r => setContainers(r.active ?? []))
      .catch(() => {})
  }

  useEffect(() => {
    loadSettings()
    loadContainers()
    loadServiceConfig()
    const iv = setInterval(loadContainers, 15000)
    return () => clearInterval(iv)
  }, [])

  async function save() {
    if (busy) return
    setBusy(true)
    try {
      await Promise.all([
        adminApi.put('/api/settings/github_mcp_idle_timeout', { value: String(idleTimeout) }),
        adminApi.put('/api/settings/github_mcp_max_concurrent', { value: String(maxConcurrent) }),
        adminApi.put('/api/settings/github_mcp_image', { value: image }),
      ])
      flashSaved()
    } catch (e) {
      alert('Save failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  async function killContainer(userId: number) {
    if (!confirm(`Force-stop the GitHub MCP container for user ${userId}?\n\nIn-flight tool calls will fail. The user's next call will spawn a new container.`)) return
    await adminApi.post(`/api/mcp/github/containers/${userId}/kill`, {}).catch(() => {})
    loadContainers()
  }

  return (
    <>
      <div className="setting-card">
        <h3>GitHub MCP — Per-user containers</h3>
        <p>
          AppCrane spawns a per-user <code style={{ fontFamily: 'monospace' }}>github-mcp-server</code> Docker container on demand
          when a user passes their PAT via <code style={{ fontFamily: 'monospace' }}>X-Github-Token</code> header in their MCP setup.
          Each container is scoped to that user; <code style={{ fontFamily: 'monospace' }}>github_*</code> tool calls are forwarded
          via stdio. Idle containers are reaped automatically.
        </p>
        <p style={{ color: 'var(--dim)', fontSize: '.8rem', marginTop: -4 }}>
          User setup: <code style={{ fontFamily: 'monospace', fontSize: '.78rem' }}>claude mcp add --transport http appcrane &lt;url&gt; --header "X-API-Key: dhk_mcp_…" --header "X-Github-Token: ghp_…"</code>
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '12px 16px', alignItems: 'center', marginTop: 16, maxWidth: 600 }}>
          <label style={{ fontSize: '.85rem', color: 'var(--dim)' }}>Idle timeout (seconds)</label>
          <FocusInput type="number" min={60} max={86400} value={idleTimeout} onChange={e => setIdleTimeout(Number(e.target.value))} style={{ width: 140 }} />

          <label style={{ fontSize: '.85rem', color: 'var(--dim)' }}>Max concurrent containers</label>
          <FocusInput type="number" min={1} max={100} value={maxConcurrent} onChange={e => setMaxConcurrent(Number(e.target.value))} style={{ width: 140 }} />

          <label style={{ fontSize: '.85rem', color: 'var(--dim)' }}>Container image</label>
          <FocusInput type="text" value={image} onChange={e => setImage(e.target.value)} placeholder="ghcr.io/github/github-mcp-server:latest" />
        </div>

        <div className="save-row" style={{ marginTop: 16 }}>
          <button className="btn btn-accent" onClick={save} disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
          {saved && <span className="saved-msg">Saved ✓</span>}
        </div>
      </div>

      <div className="setting-card">
        <h3>Active containers <span style={{ fontWeight: 400, color: 'var(--dim)', fontSize: '.82rem' }}>({containers.length} / {maxConcurrent})</span></h3>
        <p>Live roster — refreshes every 15 seconds. Force-stop to recover stuck containers (e.g. after a PAT was revoked).</p>
        {containers.length === 0 ? (
          <div style={{ color: 'var(--dim)', fontSize: '.85rem', padding: '8px 0' }}>No containers running.</div>
        ) : (
          <table style={{ width: '100%', fontSize: '.85rem', marginTop: 8 }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>User ID</th>
                <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Started</th>
                <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Last active</th>
                <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Idle</th>
                <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {containers.map(c => (
                <tr key={c.user_id}>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace' }}>{c.user_id}</td>
                  <td style={{ padding: '4px 8px', color: 'var(--dim)' }}>{new Date(c.started_at).toLocaleTimeString()}</td>
                  <td style={{ padding: '4px 8px', color: 'var(--dim)' }}>{new Date(c.last_active_at).toLocaleTimeString()}</td>
                  <td style={{ padding: '4px 8px', color: c.idle_seconds > idleTimeout / 2 ? 'var(--yellow)' : 'var(--dim)' }}>
                    {c.idle_seconds < 60 ? `${c.idle_seconds}s` : `${Math.floor(c.idle_seconds / 60)}m ${c.idle_seconds % 60}s`}
                  </td>
                  <td style={{ padding: '4px 8px', color: c.alive ? 'var(--green)' : 'var(--red)' }}>{c.alive ? 'running' : 'dead'}</td>
                  <td style={{ padding: '4px 8px', textAlign: 'right' }}>
                    <button className="btn btn-xs btn-red" onClick={() => killContainer(c.user_id)}>Kill</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="setting-card">
        <h3>Service-account — AppCrane-managed repos</h3>
        <p>
          Configure a single GitHub user or org that AppCrane uses to host per-app repositories. End users who don't have
          their own GitHub PAT can opt into "AppCrane manages my code" — AppCrane creates the repo, holds the credential,
          and proxies all reads and writes. The user never sees github.com.
        </p>
        <p style={{ color: 'var(--dim)', fontSize: '.8rem', marginTop: -4 }}>
          The PAT stays encrypted at rest (AES-256-GCM, same envelope as the SSO secrets). It's never returned to the browser.
        </p>
        <div style={{
          marginTop: 12,
          padding: '10px 12px',
          background: 'rgba(245, 158, 11, .08)',
          border: '1px solid rgba(245, 158, 11, .3)',
          borderRadius: 6,
          fontSize: '.82rem', color: 'var(--text)', lineHeight: 1.5,
        }}>
          <strong style={{ color: '#fbbf24' }}>Scope the PAT to just what AppCrane needs.</strong>
          {' '}AppCrane only touches repos it creates. Every managed repo is prefixed
          {' '}<code style={{ fontFamily: 'monospace', fontSize: '.78rem' }}>AMC_</code> (AppCrane-Managed-Code) so the
          {' '}PAT can be scoped accordingly:
          <ul style={{ margin: '6px 0 0 18px', padding: 0, color: 'var(--dim)' }}>
            <li><strong>Fine-grained PAT (recommended)</strong>: select <em>"Only select repositories"</em> and pick the
            {' '}<code style={{ fontFamily: 'monospace', fontSize: '.78rem' }}>AMC_*</code> repos. Permissions:
            {' '}Contents <em>R/W</em>, Metadata <em>R</em>, Administration <em>R/W</em> (needed to create new repos).</li>
            <li><strong>Dedicated org or sub-account</strong>: put the service account in its own GitHub org / user
            {' '}that holds only AppCrane-managed repos. A classic PAT with <code>repo</code> scope is then bounded by
            {' '}what the account itself owns. Easier to reason about; weaker isolation than fine-grained.</li>
          </ul>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '12px 16px', alignItems: 'center', marginTop: 16, maxWidth: 600 }}>
          <label style={{ fontSize: '.85rem', color: 'var(--dim)' }}>Owner (user or org)</label>
          <FocusInput
            type="text"
            value={svc.owner}
            onChange={e => setSvc(s => ({ ...s, owner: e.target.value }))}
            placeholder="appcrane-bot or my-org"
          />

          <label style={{ fontSize: '.85rem', color: 'var(--dim)' }}>
            PAT {svc.configured && <span style={{ color: 'var(--green)' }}>· stored</span>}
          </label>
          <FocusInput
            type="password"
            value={svcToken}
            onChange={e => setSvcToken(e.target.value)}
            placeholder={svc.configured ? '•••••••• (leave empty to keep current)' : 'ghp_… or fine-grained token'}
          />

          <label style={{ fontSize: '.85rem', color: 'var(--dim)' }}>Default repo visibility</label>
          <select
            value={svc.visibility}
            onChange={e => setSvc(s => ({ ...s, visibility: e.target.value as GithubServiceConfig['visibility'] }))}
            style={{ width: 200, padding: '6px 8px' }}
          >
            <option value="private">private</option>
            <option value="internal">internal</option>
            <option value="public">public</option>
          </select>

          <label style={{ fontSize: '.85rem', color: 'var(--dim)' }}>Enabled</label>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <input
              type="checkbox"
              checked={svc.enabled}
              onChange={e => setSvc(s => ({ ...s, enabled: e.target.checked }))}
            />
            <span style={{ fontSize: '.82rem', color: 'var(--dim)' }}>
              When enabled, the "+ New App" wizard offers the managed-repo path.
            </span>
          </label>
        </div>

        <div className="save-row" style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <button className="btn btn-accent" onClick={saveService} disabled={svcBusy}>{svcBusy ? 'Saving…' : 'Save'}</button>
          <button className="btn" onClick={verifyService} disabled={svcBusy || !svc.configured}>
            Verify token
          </button>
          {svc.configured && (
            <button className="btn btn-red" onClick={clearServiceToken} disabled={svcBusy}>
              Clear token
            </button>
          )}
          {svcSaved && <span className="saved-msg">Saved ✓</span>}
        </div>

        {svcVerify && (
          <div style={{ marginTop: 12, padding: '8px 12px', borderRadius: 4, background: svcVerify.ok ? 'rgba(46,125,50,.12)' : 'rgba(226,75,74,.12)', fontSize: '.85rem' }}>
            {svcVerify.ok ? (
              <>
                ✓ Authenticated as <code style={{ fontFamily: 'monospace' }}>{svcVerify.login}</code> ({svcVerify.type}).
                {' '}Scopes: <code style={{ fontFamily: 'monospace', fontSize: '.78rem' }}>{svcVerify.scopes || '(fine-grained — repo-scoped at token-creation time)'}</code>
                {/* v2.6.11: warn when the token has full classic-PAT `repo` scope.
                    AppCrane only needs Contents + Metadata + Administration on
                    AMC_*-prefixed repos. `repo` is broader than that. */}
                {svcVerify.scopes && /\brepo\b/.test(svcVerify.scopes) && (
                  <div style={{ marginTop: 6, color: '#fbbf24', fontSize: '.78rem' }}>
                    ⚠ This is a classic PAT with full <code>repo</code> scope — broader than AppCrane needs.
                    {' '}Switch to a fine-grained PAT scoped to <code>AMC_*</code> repos
                    {' '}(Contents R/W, Metadata R, Administration R/W) when convenient.
                  </div>
                )}
              </>
            ) : <>✗ {svcVerify.error}</>}
          </div>
        )}
      </div>
    </>
  )
}

type Tab = 'security' | 'users' | 'roles' | 'github' | 'branding' | 'audit'

const VALID_TABS: Tab[] = ['security', 'users', 'roles', 'github', 'branding', 'audit']

function getTab(): Tab {
  const hash = window.location.hash.replace('#', '') as Tab
  return VALID_TABS.includes(hash) ? hash : 'security'
}

export function Settings() {
  const [tab, setTab] = useState<Tab>(getTab)

  useEffect(() => {
    const handler = () => setTab(getTab())
    window.addEventListener('hashchange', handler)
    return () => window.removeEventListener('hashchange', handler)
  }, [])

  return (
    <div className="container">
      <div style={{ display: tab === 'security' ? 'block' : 'none' }}>
        <SecurityTab />
      </div>
      <div style={{ display: tab === 'users' ? 'block' : 'none' }}>
        <Users />
      </div>
      <div style={{ display: tab === 'roles' ? 'block' : 'none' }}>
        <RolesTab />
      </div>
      <div style={{ display: tab === 'github' ? 'block' : 'none' }}>
        <GithubTab />
      </div>
      {/* v2.6.9: skills tab removed from Settings — now top-level /skills */}
      <div style={{ display: tab === 'branding' ? 'block' : 'none' }}>
        <BrandingTab />
      </div>
      <div style={{ display: tab === 'audit' ? 'block' : 'none' }}>
        <AuditLog />
      </div>
    </div>
  )
}

