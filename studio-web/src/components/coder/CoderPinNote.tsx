export type PinKind = 'ended' | 'other_user' | 'gone' | 'forbidden'

const TEXT: Record<PinKind, string> = {
  ended:
    'This request went to a coder session that has ended. Its conversation is below, read-only. ' +
    'To keep working on the request, open the app’s current session or start a new one.',
  other_user:
    'This request went to a coder session that belongs to another user. You can follow it here, ' +
    'but only they can send it messages — ask them, or wait for it to end and start your own.',
  gone:
    'This request went to a coder session that no longer exists. ' +
    'Open the app’s current session, or start a new one.',
  forbidden:
    'This request went to a coder session you can’t open on this app. ' +
    'Open the app’s current session, or start a new one.',
}

/**
 * Why the panel is not simply showing the session a request was sent to.
 * Shown instead of silently opening a different session.
 */
export function CoderPinNote({ kind, onUnpin }: { kind: PinKind; onUnpin: () => void }) {
  return (
    <div className="coder-paused" role="status">
      {TEXT[kind]}
      {kind !== 'other_user' && (
        <button type="button" className="coder-btn coder-btn-xs" onClick={onUnpin}>
          Open the current session
        </button>
      )}
    </div>
  )
}
