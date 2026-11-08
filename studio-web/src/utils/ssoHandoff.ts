/**
 * The SPA's session token after an SSO login.
 *
 * The API authenticates a Bearer, and the token is read from localStorage for it,
 * so the SPA still needs the token even though the callback set the cookie. It
 * no longer travels in a URL: /login?oidc_token=<attacker's token> used to sign a
 * victim in as the attacker. The callback sends a short-lived, single-use code that
 * only the browser holding the login's binding cookie can exchange
 * (server/routes/oidc.js).
 *
 * Kept free of imports and non-erasable TypeScript so node:test can load it
 * directly.
 */

export const SSO_HANDOFF_URL = '/api/auth/oidc/handoff'

interface Deps {
  fetch: (url: string, init: RequestInit) => Promise<{ ok: boolean; json: () => Promise<{ token?: unknown }> }>
  store: { setItem: (key: string, value: string) => void }
}

/** True once the token is stored; false for a refused code or a failed request. */
export async function redeemSsoCode(code: string, deps: Deps): Promise<boolean> {
  try {
    const r = await deps.fetch(SSO_HANDOFF_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    })
    if (!r.ok) return false
    const { token } = await r.json()
    if (typeof token !== 'string' || !token) return false
    deps.store.setItem('cc_identity_token', token)
    return true
  } catch {
    return false
  }
}
