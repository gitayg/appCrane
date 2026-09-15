import { isFramed } from '../utils/popupSignIn'

/**
 * Screens the sign-in landing page shows instead of forwarding to ?redirect=.
 * See utils/landingRedirect.ts for when each one is chosen.
 *
 * The app name arrives in the URL, so it is rendered as React text (escaped),
 * never as HTML.
 */

export function AccessDenied({ appName, onSwitchUser }: { appName: string; onSwitchUser: () => void }) {
  return (
    <div className="login-wrap">
      <div className="login-box" role="alert">
        <h2 style={{ marginBottom: 8, fontSize: '1.3rem' }}>No access</h2>
        <p style={{ marginBottom: 6 }}>
          You don't have access to {appName ? <strong>{appName}</strong> : 'this app'}.
        </p>
        <p style={{ color: 'var(--dim)', marginBottom: 18, fontSize: '.9rem' }}>
          Ask the app's owner to add you, or sign in with another account.
        </p>
        <button type="button" className="btn btn-accent" onClick={onSwitchUser} style={{ width: '100%', padding: 10 }}>
          Sign in as a different user
        </button>
        {/* Only top-level: the app picker is not embeddable, so a frame would refuse it. */}
        {!isFramed(window) && (
          <p style={{ marginTop: 14, marginBottom: 0, textAlign: 'center', fontSize: '.85rem' }}>
            <a href="/launch">Go to your apps</a>
          </p>
        )}
      </div>
    </div>
  )
}

export function SignInStuck({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="login-wrap">
      <div className="login-box" role="alert">
        <h2 style={{ marginBottom: 8, fontSize: '1.3rem' }}>Sign-in couldn't complete</h2>
        <p style={{ color: 'var(--dim)', marginBottom: 18, fontSize: '.9rem' }}>
          This page kept being sent back to sign-in, so it stopped.
        </p>
        <button type="button" className="btn btn-accent" onClick={onRetry} style={{ width: '100%', padding: 10 }}>
          Sign in again
        </button>
      </div>
    </div>
  )
}

export function CheckingSession() {
  return (
    <div className="login-wrap">
      <div className="login-box">
        <p style={{ color: 'var(--dim)', margin: 0, fontSize: '.9rem' }}>Signing you in…</p>
      </div>
    </div>
  )
}
