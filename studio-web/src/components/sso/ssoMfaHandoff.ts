/**
 * AppCrane's own MFA after SSO, on the sign-in page.
 *
 * For a user who enrolled AppCrane MFA the SSO callback issues no session: the
 * handoff (POST /api/auth/oidc/handoff) answers with the same second step
 * password sign-in gets ({ mfa_required, mfa_token }), and the page then asks
 * for the code and posts it to /api/identity/mfa/verify. In popup mode the
 * callback sends the popup here with ?sso_popup=1; once the code is accepted the
 * popup tells the waiting frame, as the server's completion page would, and
 * closes.
 *
 * Kept free of imports and non-erasable TypeScript so node:test can load it
 * directly.
 */

export const SSO_POPUP_PARAM = 'sso_popup'

export interface SsoMfaStep { token: string; rememberDays: number }

/** The second step in a handoff answer, or null when it carries none. */
export function mfaStepFrom(body: unknown): SsoMfaStep | null {
  const b = body as { mfa_required?: unknown; mfa_token?: unknown; remember_device_days?: unknown } | null
  if (!b || b.mfa_required !== true || typeof b.mfa_token !== 'string' || !b.mfa_token) return null
  return { token: b.mfa_token, rememberDays: Number(b.remember_device_days) || 0 }
}

type FetchLike = (url: string, init: RequestInit) => Promise<{ ok: boolean; json: () => Promise<any> }>

/** A fetch for redeemSsoCode that also hands any second step in the answer to `onStep`. */
export function capturingMfaStep(fetchImpl: FetchLike, onStep: (step: SsoMfaStep) => void): FetchLike {
  return async (url, init) => {
    const r = await fetchImpl(url, init)
    return {
      ok: r.ok,
      json: async () => {
        const body = await r.json()
        const step = r.ok ? mfaStepFrom(body) : null
        if (step) onStep(step)
        return body
      },
    }
  }
}

interface PopupWindow {
  BroadcastChannel?: new (name: string) => { postMessage: (m: unknown) => void; close: () => void }
  setTimeout: (fn: () => void, ms: number) => unknown
  close: () => void
}

/** Tell the frame that opened this popup how the sign-in ended; close on success. */
export function tellOpenerFrame(win: PopupWindow, channel: string, type: 'signed-in' | 'sign-in-failed'): void {
  try {
    const ch = new (win.BroadcastChannel as NonNullable<PopupWindow['BroadcastChannel']>)(channel)
    ch.postMessage({ type })
    ch.close()
  } catch { /* the frame also polls /api/me */ }
  if (type === 'signed-in') win.setTimeout(() => win.close(), 300)
}
