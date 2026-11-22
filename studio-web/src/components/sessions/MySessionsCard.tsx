import { useAuth } from '../../hooks/useAuth'
import { SessionsTable } from './SessionsTable'

// Settings -> Account: the signed-in person's own sessions, on AppCrane and on
// app hosts. Revoking an AppCrane session also ends the app sessions it signed in.
export function MySessionsCard() {
  const { signOut } = useAuth()
  return (
    <div className="setting-card">
      <h3>Sessions</h3>
      <p>Where you are signed in. Revoke a session you do not recognise; that browser has to sign in again.</p>
      <SessionsTable base="/api/me/sessions" onSignedOut={signOut} />
    </div>
  )
}
