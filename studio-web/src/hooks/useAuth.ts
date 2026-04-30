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
    window.location.href = '/dashboard'
  }, [setKey])

  return { key, setKey, isAuthed: key.length > 5, signOut }
}
