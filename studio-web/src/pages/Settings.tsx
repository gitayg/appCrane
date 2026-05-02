import { useState, useEffect, useRef } from 'react'
import { adminApi } from '../adminApi'
import { parseFrontmatter } from '../lib/parseFrontmatter'

const inputStyle: React.CSSProperties = {
  background: 'var(--surface2)',
  border: '1px solid var(--border)',
  color: 'var(--text)',
  padding: '8px 12px',
  borderRadius: 6,
  width: '100%',
  fontSize: '.85rem',
  fontFamily: 'inherit',
  outline: 'none',
  boxSizing: 'border-box',
}

function useFlash(): [boolean, () => void] {
  const [show, setShow] = useState(false)
  const t = useRef<ReturnType<typeof setTimeout> | null>(null)
  const flash = () => {
    setShow(true)
    if (t.current) clearTimeout(t.current)
    t.current = setTimeout(() => setShow(false), 2500)
  }
  return [show, flash]
}

function FocusInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      style={{ ...inputStyle, ...props.style }}
      onFocus={e => {
        e.currentTarget.style.borderColor = 'var(--accent)'
        props.onFocus?.(e)
      }}
      onBlur={e => {
        e.currentTarget.style.borderColor = 'var(--border)'
        props.onBlur?.(e)
      }}
    />
  )
}

function FocusTextarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      style={{ ...inputStyle, resize: 'vertical', ...props.style }}
      onFocus={e => {
        e.currentTarget.style.borderColor = 'var(--accent)'
        props.onFocus?.(e)
      }}
      onBlur={e => {
        e.currentTarget.style.borderColor = 'var(--border)'
        props.onBlur?.(e)
      }}
    />
  )
}

function AppStudioTab() {
  const [keyInfo, setKeyInfo] = useState<{ configured: boolean; source?: string; suffix?: string } | null>(null)
  const [keyInput, setKeyInput] = useState('')
  const [keyFocused, setKeyFocused] = useState(false)
  const [keySaved, flashKeySaved] = useFlash()
  const [maxContainers, setMaxContainers] = useState(5)
  const [containerSaved, flashContainerSaved] = useFlash()

  useEffect(() => {
    adminApi.get<{ configured: boolean; source?: string; suffix?: string }>('/api/appstudio/anthropic-key')
      .then(setKeyInfo).catch(() => {})
    adminApi.get<{ value?: string }>('/api/settings/max_dev_containers')
      .then(r => { if (r?.value) setMaxContainers(Number(r.value)) }).catch(() => {})
  }, [])

  async function saveKey() {
    await adminApi.put('/api/appstudio/anthropic-key', { key: keyInput }).catch(() => {})
    flashKeySaved()
    adminApi.get<{ configured: boolean; source?: string; suffix?: string }>('/api/appstudio/anthropic-key')
      .then(setKeyInfo).catch(() => {})
  }

  async function saveContainers() {
    await adminApi.put('/api/settings/max_dev_containers', { value: String(maxContainers) }).catch(() => {})
    flashContainerSaved()
  }

  const showEnvKey = keyInfo?.source === 'env'
  let keyStatusText = 'Not configured'
  if (keyInfo?.configured) {
    if (keyInfo.source === 'env') {
      keyStatusText = `Configured — via ANTHROPIC_API_KEY environment variable (ends in ••••${keyInfo.suffix ?? ''})`
    } else {
      keyStatusText = 'Configured — stored in .env file'
    }
  }

  return (
    <>
      <div className="setting-card">
        <h3>Anthropic API Key</h3>
        <p>Required for AppStudio and Ask Claude features.</p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <span style={{
            width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
            background: keyInfo?.configured ? 'var(--green)' : 'var(--red)',
          }} />
          <span style={{ fontSize: '.85rem', color: 'var(--dim)' }}>{keyStatusText}</span>
        </div>
        {!showEnvKey && (
          <div style={{ marginBottom: 10 }}>
            <FocusInput
              type={keyFocused ? 'text' : (keyInfo?.configured ? 'password' : 'text')}
              value={keyFocused ? keyInput : (keyInput || (keyInfo?.configured ? '••••••••••••••••' : ''))}
              placeholder="sk-ant-..."
              onFocus={() => { setKeyFocused(true); setKeyInput('') }}
              onBlur={() => setKeyFocused(false)}
              onChange={e => setKeyInput(e.target.value)}
            />
          </div>
        )}
        <div className="save-row">
          {!showEnvKey && (
            <button className="btn btn-accent" onClick={saveKey}>Save Key</button>
          )}
          {keySaved && <span className="saved-msg">Saved ✓</span>}
        </div>
      </div>

      <div className="setting-card">
        <h3>Dev Container Limit</h3>
        <p>Maximum number of AppStudio and Ask Claude containers that can run simultaneously. Default: 5.</p>
        <FocusInput
          type="number"
          min={1}
          max={50}
          value={maxContainers}
          onChange={e => setMaxContainers(Number(e.target.value))}
          style={{ width: 120 }}
        />
        <div className="save-row">
          <button className="btn btn-accent" onClick={saveContainers}>Save</button>
          {containerSaved && <span className="saved-msg">Saved ✓</span>}
        </div>
      </div>
    </>
  )
}

function BrandingTab() {
  const [guidelines, setGuidelines] = useState('')
  const [saved, flashSaved] = useFlash()
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    adminApi.get<{ value?: string }>('/api/settings/branding')
      .then(r => { if (r?.value) setGuidelines(r.value) }).catch(() => {})
  }, [])

  async function save() {
    await adminApi.put('/api/settings/branding', { value: guidelines }).catch(() => {})
    flashSaved()
  }

  function importFile() {
    fileRef.current?.click()
  }

  function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => { setGuidelines(ev.target?.result as string) }
    reader.readAsText(file)
    e.target.value = ''
  }

  return (
    <div className="setting-card">
      <h3>Branding Guidelines</h3>
      <p>Paste your brand guidelines here — AI agents read this via GET /api/settings/branding before building apps.</p>
      <FocusTextarea
        value={guidelines}
        onChange={e => setGuidelines(e.target.value)}
        style={{ minHeight: 220 }}
      />
      <input ref={fileRef} type="file" accept=".txt,.md" style={{ display: 'none' }} onChange={onFileChange} />
      <div className="save-row">
        <button className="btn" onClick={importFile}>Import from file</button>
        <button className="btn btn-accent" onClick={save}>Save Guidelines</button>
        {saved && <span className="saved-msg">Saved ✓</span>}
      </div>
    </div>
  )
}

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
  }, [])

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

type Tab = 'appstudio' | 'branding' | 'security' | 'skills'

const VALID_TABS: Tab[] = ['appstudio', 'branding', 'security', 'skills']

function getTab(): Tab {
  const hash = window.location.hash.replace('#', '') as Tab
  return VALID_TABS.includes(hash) ? hash : 'appstudio'
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
      <div style={{ display: tab === 'appstudio' ? 'block' : 'none' }}>
        <AppStudioTab />
      </div>
      <div style={{ display: tab === 'branding' ? 'block' : 'none' }}>
        <BrandingTab />
      </div>
      <div style={{ display: tab === 'security' ? 'block' : 'none' }}>
        <SecurityTab />
      </div>
      <div style={{ display: tab === 'skills' ? 'block' : 'none' }}>
        <SkillsTab />
      </div>
    </div>
  )
}

interface Skill {
  id: number
  slug: string
  name: string
  description: string | null
  enabled: 0 | 1
  uploaded_at: string
}

function SkillsTab() {
  const [skills, setSkills] = useState<Skill[]>([])
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [description, setDescription] = useState('')
  const [content, setContent] = useState('')
  const [bundle, setBundle] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [autoFilled, setAutoFilled] = useState<{ name?: boolean; slug?: boolean; description?: boolean }>({})

  // Pre-fill empty form fields from a SKILL.md frontmatter. Operator-typed
  // values always win — we only touch fields that are blank OR were
  // previously auto-filled by us (so re-picking a different file updates).
  function applyFrontmatter(text: string) {
    const fm = parseFrontmatter(text)
    if (!Object.keys(fm).length) return
    const next: typeof autoFilled = {}
    if (fm.name && (!name || autoFilled.name))               { setName(fm.name); next.name = true }
    if (fm.slug && (!slug || autoFilled.slug))               { setSlug(fm.slug); next.slug = true }
    if (fm.description && (!description || autoFilled.description)) { setDescription(fm.description); next.description = true }
    setAutoFilled(prev => ({ ...prev, ...next }))
  }

  function onPickFile(file: File | null) {
    setBundle(file)
    if (!file) return
    const lower = file.name.toLowerCase()
    if (!(lower.endsWith('.md') || lower.endsWith('.markdown'))) return // .zip not parsed client-side
    file.text().then(applyFrontmatter).catch(() => {})
  }

  function load() {
    setLoading(true)
    adminApi.get<{ skills: Skill[] }>('/api/skills')
      .then(d => setSkills(d.skills || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  function flash(text: string, ok: boolean) {
    setMsg({ text, ok })
    setTimeout(() => setMsg(null), 5000)
  }

  async function toggle(s: Skill) {
    try {
      await adminApi.put(`/api/skills/${s.slug}`, { enabled: s.enabled === 0 })
      setSkills(prev => prev.map(p => p.slug === s.slug ? { ...p, enabled: s.enabled === 0 ? 1 : 0 } : p))
    } catch (e) {
      flash((e as Error).message, false)
    }
  }

  async function remove(s: Skill) {
    if (!confirm(`Delete skill "${s.name}"? This removes its files from disk.`)) return
    try {
      await adminApi.del(`/api/skills/${s.slug}`)
      setSkills(prev => prev.filter(p => p.slug !== s.slug))
    } catch (e) {
      flash((e as Error).message, false)
    }
  }

  async function upload(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) { flash('Name required', false); return }
    if (!content.trim() && !bundle) { flash('Either paste SKILL.md content OR pick a .md or .zip file', false); return }
    setUploading(true)
    try {
      if (bundle) {
        const fd = new FormData()
        fd.append('bundle', bundle)
        fd.append('name', name.trim())
        if (slug.trim())        fd.append('slug', slug.trim())
        if (description.trim()) fd.append('description', description.trim())
        const r = await fetch('/api/skills', { method: 'POST', headers: adminApi.authHeaders(), body: fd })
        if (!r.ok) {
          const body = await r.json().catch(() => ({}))
          throw new Error(body?.error?.message || `HTTP ${r.status}`)
        }
      } else {
        await adminApi.post('/api/skills', {
          name: name.trim(),
          slug: slug.trim() || undefined,
          description: description.trim() || undefined,
          content,
        })
      }
      setName(''); setSlug(''); setDescription(''); setContent(''); setBundle(null); setAutoFilled({})
      flash('Skill uploaded', true)
      load()
    } catch (e) {
      flash((e as Error).message, false)
    } finally {
      setUploading(false)
    }
  }

  return (
    <div>
      <h2>Skills</h2>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 16 }}>
        Anthropic-style skill bundles loaded by every CLI agent (Builder chat, Ask, enhancement coder, planner, contextBuilder)
        via the Claude Code CLI's native <code>~/.claude/skills/</code> loader. Toggle to enable/disable globally — toggle changes
        affect new dispatches; live Builder/Ask sessions need a pause + resume to pick up changes.
      </p>

      {msg && (
        <div style={{
          padding: '8px 12px', borderRadius: 6, marginBottom: 12, fontSize: '.85rem',
          background: msg.ok ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
          color: msg.ok ? 'var(--green)' : 'var(--red)',
          border: `1px solid ${msg.ok ? 'var(--green)' : 'var(--red)'}`,
        }}>{msg.text}</div>
      )}

      <h3 style={{ marginTop: 24, marginBottom: 8, fontSize: '.95rem' }}>Installed skills</h3>
      {loading ? <div style={{ color: 'var(--dim)' }}>Loading…</div> :
       skills.length === 0 ? <div style={{ color: 'var(--dim)' }}>No skills installed yet.</div> :
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', padding: 6, borderBottom: '1px solid var(--border)' }}>Enabled</th>
              <th style={{ textAlign: 'left', padding: 6, borderBottom: '1px solid var(--border)' }}>Name</th>
              <th style={{ textAlign: 'left', padding: 6, borderBottom: '1px solid var(--border)' }}>Slug</th>
              <th style={{ textAlign: 'left', padding: 6, borderBottom: '1px solid var(--border)' }}>Description</th>
              <th style={{ textAlign: 'right', padding: 6, borderBottom: '1px solid var(--border)' }}></th>
            </tr>
          </thead>
          <tbody>
            {skills.map(s => (
              <tr key={s.slug}>
                <td style={{ padding: 6 }}>
                  <input type="checkbox" checked={s.enabled === 1} onChange={() => toggle(s)} />
                </td>
                <td style={{ padding: 6 }}>{s.name}</td>
                <td style={{ padding: 6, fontFamily: 'monospace', fontSize: '.82rem', color: 'var(--dim)' }}>{s.slug}</td>
                <td style={{ padding: 6, color: 'var(--dim)', fontSize: '.85rem' }}>{s.description || '—'}</td>
                <td style={{ padding: 6, textAlign: 'right' }}>
                  <button className="btn btn-red" onClick={() => remove(s)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      }

      <h3 style={{ marginTop: 32, marginBottom: 8, fontSize: '.95rem' }}>Add a skill</h3>
      <form onSubmit={upload} style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 640 }}>
        <input
          className="editable" placeholder="Name" value={name}
          onChange={e => { setName(e.target.value); setAutoFilled(p => ({ ...p, name: false })) }}
        />
        <input
          className="editable" placeholder="Slug (auto-generated if empty)" value={slug}
          onChange={e => { setSlug(e.target.value); setAutoFilled(p => ({ ...p, slug: false })) }}
        />
        <input
          className="editable" placeholder="Description (optional)" value={description}
          onChange={e => { setDescription(e.target.value); setAutoFilled(p => ({ ...p, description: false })) }}
        />
        <textarea
          className="editable" rows={8}
          placeholder="Paste SKILL.md content here, OR upload a .md / .zip file below"
          value={content}
          onChange={e => { setContent(e.target.value); applyFrontmatter(e.target.value) }}
          style={{ fontFamily: 'monospace', fontSize: '.85rem' }}
        />
        <div>
          <label style={{ fontSize: '.85rem', color: 'var(--dim)' }}>or upload a .md file (single skill) or .zip bundle (multi-file skill):</label><br/>
          <input type="file" accept=".md,.markdown,.zip" onChange={e => onPickFile(e.target.files?.[0] || null)} />
          {bundle && <span style={{ marginLeft: 8, fontSize: '.82rem', color: 'var(--dim)' }}>{bundle.name}</span>}
        </div>
        <div>
          <button type="submit" className="btn btn-primary" disabled={uploading}>
            {uploading ? 'Uploading…' : 'Add skill'}
          </button>
        </div>
      </form>
    </div>
  )
}
