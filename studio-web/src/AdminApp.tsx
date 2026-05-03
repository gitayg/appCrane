import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthContext, useAuthState } from './hooks/useAuth'
import { Layout } from './components/Layout'
import { Login } from './components/Login'
import { Dashboard } from './pages/Dashboard'
import { Applications } from './pages/Applications'
import { AuditLog } from './pages/AuditLog'
import { AppStudio } from './pages/AppStudio'
import { Settings } from './pages/Settings'
import { Docs } from './pages/Docs'
import { AppManager } from './pages/AppManager'

const STUDIO_SUB = [
  { id: 'requests', label: 'Requests', href: '#requests' },
  { id: 'builders', label: 'Builders', href: '#builders' },
  { id: 'skills',   label: 'Skills',   href: '#skills' },
  { id: 'branding', label: 'Branding', href: '#branding' },
]

const SETTINGS_SUB = [
  { id: 'appstudio', label: 'AppStudio', href: '#appstudio' },
  { id: 'security',  label: 'Security',  href: '#security' },
  { id: 'users',     label: 'Users',     href: '#users' },
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

function AppStudioRoute() {
  const hash = useHash()
  // Back-compat: old #library and #studio hashes both map to the merged Builders view
  const remapped = (hash === 'library' || hash === 'studio') ? 'builders' : hash
  const activeSub = ['requests', 'builders', 'skills', 'branding'].includes(remapped) ? remapped : 'requests'
  return (
    <Layout subItems={STUDIO_SUB} activeSub={activeSub}>
      <AppStudio />
    </Layout>
  )
}

function SettingsRoute() {
  const hash = useHash()
  const activeSub = ['appstudio', 'security', 'users'].includes(hash) ? hash : 'appstudio'
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
          {/* Users moved to Settings → Users in v1.27.27. Keep the old
              path as a redirect so any bookmarked URLs still work. */}
          <Route path="/users-page" element={<Navigate to="/settings#users" replace />} />
          <Route path="/audit-page" element={<Layout><AuditLog /></Layout>} />
          <Route path="/appstudio" element={<AppStudioRoute />} />
          <Route path="/settings" element={<SettingsRoute />} />
          <Route path="/docs" element={<Layout><Docs /></Layout>} />
          <Route path="/app" element={<Layout><AppManager /></Layout>} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthContext.Provider>
  )
}
