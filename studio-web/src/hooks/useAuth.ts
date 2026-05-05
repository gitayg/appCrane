import { createContext, useContext, useState, useCallback, useEffect } from 'react'

const KEY_STORE = 'cc_api_key'
const TOKEN_STORE = 'cc_identity_token'

interface AuthCtx {
  key: string
  setKey: (k: string) => void
  isAuthed: boolean
  signOut: () => void
}

export const AuthContext = createContext<AuthCtx>({
  key: '',
  setKey: () => {},
  isAuthed: false,
  signOut: () => {},
})

export function useAuth() {
  return useContext(AuthContext)
}

function readAuth(): { key: string; identityToken: string } {
  const key = localStorage.getItem(KEY_STORE) || ''
  const identityToken = localStorage.getItem(TOKEN_STORE) || ''
  return { key, identityToken }
}

export function useAuthState(): AuthCtx {
  const [key, setKeyState] = useState(() => readAuth().key)
  const [identityToken, setIdentityToken] = useState(() => readAuth().identityToken)

  const setKey = useCallback((k: string) => {
    setKeyState(k)
    if (k) localStorage.setItem(KEY_STORE, k)
    else   localStorage.removeItem(KEY_STORE)
  }, [])

  const signOut = useCallback(() => {
    // Server-side invalidate identity sessions (password / OIDC / SAML).
    // Without this, the bearer token survives 24h on the server even if
    // the user clears localStorage — anyone who recovers the token wins.
    // Fire-and-forget; redirect doesn't wait for response.
    const bearer = localStorage.getItem(TOKEN_STORE)
    if (bearer) {
      try {
        // navigator.sendBeacon survives the page navigation that follows;
        // a regular fetch can be aborted by the redirect.
        const ok = navigator.sendBeacon
          && navigator.sendBeacon('/api/identity/logout-beacon',
              new Blob([JSON.stringify({ token: bearer })], { type: 'application/json' }))
        if (!ok) {
          // Fallback for browsers without sendBeacon
          fetch('/api/identity/logout', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${bearer}` },
            keepalive: true,
          }).catch(() => {})
        }
      } catch (_) {}
    }
    // NOTE: API keys (dhk_admin_*, dhk_user_*, dhk_app_*, dhk_mcp_*) are
    // long-lived and have no server-side "logout" — the only way to
    // invalidate them is via the regenerate-key flow. Clearing localStorage
    // removes them from THIS browser; other holders of the same key keep
    // working. Document this in the UI eventually.

    localStorage.removeItem(KEY_STORE)
    localStorage.removeItem(TOKEN_STORE)
    setKeyState('')
    setIdentityToken('')
    // Hard-reload so the browser drops any in-memory React state on this
    // tab and the Login screen re-mounts cleanly (also evicts BFCache).
    window.location.replace('/dashboard')
  }, [])

  // Cross-tab sync: if another tab clears credentials, this tab must
  // immediately reflect it. localStorage `storage` events fire in *other*
  // tabs only — exactly the boundary we need.
  useEffect(() => {
    function onStorage(e: StorageEvent) {
      if (e.key === KEY_STORE || e.key === TOKEN_STORE) {
        const { key: k, identityToken: t } = readAuth()
        setKeyState(k)
        setIdentityToken(t)
      }
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  // BFCache (browser back/forward): pageshow fires with `persisted=true`
  // when the page is restored from cache. Re-read auth from localStorage
  // so a logged-out user clicking BACK doesn't see a cached authed page.
  // visibilitychange catches the case where the user signed out in
  // another tab and switches focus to this one.
  useEffect(() => {
    function reread() {
      const { key: k, identityToken: t } = readAuth()
      if (k !== key) setKeyState(k)
      if (t !== identityToken) setIdentityToken(t)
    }
    function onShow(e: PageTransitionEvent) {
      if (e.persisted) reread()
    }
    function onVis() {
      if (document.visibilityState === 'visible') reread()
    }
    window.addEventListener('pageshow', onShow)
    document.addEventListener('visibilitychange', onVis)
    return () => {
      window.removeEventListener('pageshow', onShow)
      document.removeEventListener('visibilitychange', onVis)
    }
  }, [key, identityToken])

  const isAuthed = key.length > 5 || identityToken.length > 5

  return { key, setKey, isAuthed, signOut }
}
