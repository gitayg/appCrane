import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthContext, useAuthState } from './hooks/useAuth'
import { Layout } from './components/Layout'
import { Login } from './components/Login'
import { Dashboard } from './pages/Dashboard'
import { Applications } from './pages/Applications'
import { AppStudio } from './pages/AppStudio'
import { Settings } from './pages/Settings'
import { Docs } from './pages/Docs'
import { AppManager } from './pages/AppManager'

// AppStudio top-level nav was collapsed in v1.27.38: Requests + Builders
// became top-level nav items, Skills + Style Guide (renamed from Branding)
// + Audit Log moved into Settings.
const SETTINGS_SUB = [
  { id: 'appstudio',  label: 'AppStudio',   href: '#appstudio' },
  { id: 'security',   label: 'Security',    href: '#security' },
  { id: 'users',      label: 'Users',       href: '#users' },
  { id: 'agents',     label: 'App Agents',  href: '#agents' },
  { id: 'skills',     label: 'Skills',      href: '#skills' },
  { id: 'branding',   label: 'Style Guide', href: '#branding' },
  { id: 'audit',      label: 'Audit Log',   href: '#audit' },
]

function useHash() {
  const [hash, setHash] = useState(() => window.location.hash.replace('#', ''))
  useEffect(() => {
    const fn = () => setHash(window.location.hash.replace('#', ''))
    window.addEventListener('hashchange', fn)
    return () => window.removeEventListener('hashchange', fn)
  }, [])
  return hash
}

function SettingsRoute() {
  const hash = useHash()
  const valid = ['appstudio', 'security', 'users', 'agents', 'skills', 'branding', 'audit']
  const activeSub = valid.includes(hash) ? hash : 'appstudio'
  return (
    <Layout subItems={SETTINGS_SUB} activeSub={activeSub}>
      <Settings />
    </Layout>
  )
}

export function AdminApp() {
  const auth = useAuthState()

  if (!auth.isAuthed) {
    return (
      <AuthContext.Provider value={auth}>
        <Login />
      </AuthContext.Provider>
    )
  }

  return (
    <AuthContext.Provider value={auth}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Layout><Dashboard /></Layout>} />
          <Route path="/applications" element={<Layout><Applications /></Layout>} />
          {/* Routes moved to Settings sub-tabs in v1.27.x — keep redirects
              so old bookmarks still work. */}
          <Route path="/users-page"  element={<Navigate to="/settings#users" replace />} />
          <Route path="/audit-page"  element={<Navigate to="/settings#audit" replace />} />
          {/* AppStudio collapsed in v1.27.38: Requests + Builders are
              top-level; Skills/Style Guide moved to Settings. */}
          <Route path="/requests"    element={<Layout><AppStudio tab="requests" /></Layout>} />
          <Route path="/builders"    element={<Layout><AppStudio tab="builders" /></Layout>} />
          <Route path="/appstudio"   element={<Navigate to="/requests" replace />} />
          <Route path="/settings"    element={<SettingsRoute />} />
          <Route path="/docs"        element={<Layout><Docs /></Layout>} />
          <Route path="/app"         element={<Layout><AppManager /></Layout>} />
          <Route path="*"            element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthContext.Provider>
  )
}
