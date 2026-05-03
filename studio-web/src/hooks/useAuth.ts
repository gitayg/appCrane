import { createContext, useContext, useState, useCallback } from 'react'

const KEY_STORE = 'cc_api_key'

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

export function useAuthState(): AuthCtx {
  const [key, setKeyState] = useState(() => localStorage.getItem(KEY_STORE) || '')

  const setKey = useCallback((k: string) => {
    setKeyState(k)
    localStorage.setItem(KEY_STORE, k)
  }, [])

  const signOut = useCallback(() => {
    setKey('')
    localStorage.removeItem('cc_identity_token')
    window.location.href = '/dashboard'
  }, [setKey])

  // A portal Bearer token (cc_identity_token, set by /api/identity/login)
  // also counts as authed — adminApi's authHeaders already falls back to
  // it as a Bearer header for SPA-side calls (v1.27.56). Without this,
  // a user who logged in via password on /dashboard saw the Login screen
  // forever because cc_api_key was empty.
  const identityToken = typeof localStorage !== 'undefined'
    ? (localStorage.getItem('cc_identity_token') || '')
    : ''
  const isAuthed = key.length > 5 || identityToken.length > 5

  return { key, setKey, isAuthed, signOut }
}
