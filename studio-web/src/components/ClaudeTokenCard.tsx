import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { FocusInput } from './formHelpers'

/**
 * The signed-in user's own Claude subscription token.
 *
 * Backed by /api/me/claude-token (server/routes/me.js), which is write-only by
 * construction: GET answers `{ present, expiresAt }` and NO route returns the
 * token. So this card never renders a token, never keeps one in state after a
 * successful save, and never pre-fills the field with a masked stand-in that
 * a person could mistake for the stored value.
 *
 * Two things the server knows that the person has to be told here:
 *
 *  - `claude setup-token` needs a paid Claude plan. A person on a free account
 *    can run the command and it will not produce a token, so the requirement is
 *    stated rather than implied.
 *  - The token expires in a year and NOTHING refreshes it. Anthropic issues it
 *    from a browser login, so it cannot be renewed server-side. Left unsaid,
 *    the failure mode is an opaque auth error months later, on a session the
 *    person did not connect to a credential they pasted once.
 *
 * Rejections are the SERVER's message, shown verbatim.
 *
 * WHITESPACE IS STRIPPED, AND THE STRIP IS ANNOUNCED. `claude setup-token`
 * prints the token to a terminal, so copying it picks up a trailing newline
 * and, in a narrow window, line breaks mid-token. A token is printable ASCII
 * with no spaces by definition, so no whitespace anywhere is ever part of the
 * value and removing it cannot change what Anthropic issued. What would be
 * wrong is doing it silently, so the card says what it removed. Anything else
 * the server refuses stays refused, in the server's own words: the strip
 * handles copy mechanics, not validity.
 *
 * Nothing else is repaired on the way out: the rules exist
 * because the token ends up in a container's environment block, and a client
 * that quietly "fixes" a paste stores a token that differs from the one
 * Anthropic issued — which fails at spawn time instead of here.
 */

interface TokenMeta {
  present:   boolean
  expiresAt: string | null
}

/** Days until `iso`, or null when it is absent/unparseable. Negative = past. */
export function daysUntil(iso: string | null, now: number = Date.now()): number | null {
  if (!iso) return null
  const ms = Date.parse(iso)
  if (Number.isNaN(ms)) return null
  return Math.floor((ms - now) / 86_400_000)
}

/** Warn inside 30 days. One number, so the copy and the colour cannot disagree. */
export const EXPIRY_WARN_DAYS = 30

function fmtDate(iso: string | null): string {
  if (!iso) return 'unknown'
  const ms = Date.parse(iso)
  if (Number.isNaN(ms)) return iso
  return new Date(ms).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

const labelStyle: React.CSSProperties = { fontSize: '.78rem', color: 'var(--dim)', marginBottom: 4, display: 'block' }


/**
 * Every space, tab, CR and LF removed — not just the ends. A terminal that
 * wrapped the token puts a newline in the middle of it, and `\s` covers the
 * non-breaking space a copy through a rich-text field can introduce too.
 */
function stripWhitespace(v: string): string {
  return v.replace(/\s+/g, '')
}

export function ClaudeTokenCard() {
  const [meta, setMeta]     = useState<TokenMeta | null>(null)
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [token, setToken]   = useState('')
  const [busy, setBusy]     = useState(false)
  const [msg, setMsg]       = useState<{ ok: boolean; text: string } | null>(null)

  useEffect(() => {
    adminApi.get<TokenMeta>('/api/me/claude-token')
      .then(setMeta)
      .catch(e => setLoadErr(e instanceof Error ? e.message : 'Could not read token status'))
  }, [])

  async function save() {
    const clean = stripWhitespace(token)
    if (!clean || busy) return
    setBusy(true)
    setMsg(null)
    try {
      const next = await adminApi.put<TokenMeta>('/api/me/claude-token', { token: clean })
      setMeta(next)
      // Cleared on success and not echoed anywhere. Nothing can read it back.
      setToken('')
      const removed = token.length - clean.length
      setMsg({
        ok: true,
        text: removed > 0
          ? `Token saved. Removed ${removed} whitespace character${removed === 1 ? '' : 's'} from the paste.`
          : 'Token saved.',
      })
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Save failed' })
    } finally {
      setBusy(false)
    }
  }

  async function remove() {
    if (busy) return
    if (!confirm('Remove your stored Claude token? Sessions you start will fall back to the app or platform credential.')) return
    setBusy(true)
    setMsg(null)
    try {
      const next = await adminApi.del<TokenMeta>('/api/me/claude-token')
      setMeta({ present: next.present, expiresAt: next.expiresAt })
      setToken('')
      setMsg({ ok: true, text: 'Token removed.' })
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Remove failed' })
    } finally {
      setBusy(false)
    }
  }

  const days = daysUntil(meta?.expiresAt ?? null)
  const expired = days !== null && days < 0
  const expiringSoon = days !== null && days >= 0 && days <= EXPIRY_WARN_DAYS

  return (
    <div className="setting-card">
      <h3>Claude subscription token</h3>
      <p>
        Agent sessions you start run on your own Claude subscription instead of a
        platform-wide API key.
      </p>

      <div style={{ marginBottom: 14 }}>
        {loadErr && <p style={{ color: 'var(--red)', fontSize: '.85rem', margin: 0 }}>{loadErr}</p>}
        {!loadErr && meta === null && <p style={{ color: 'var(--dim)', fontSize: '.85rem', margin: 0 }}>Loading…</p>}
        {meta !== null && !meta.present && (
          <p style={{ color: 'var(--dim)', fontSize: '.85rem', margin: 0 }}>
            No token stored. Your sessions use the app's stored credentials or the platform API key.
          </p>
        )}
        {meta !== null && meta.present && (
          <p style={{
            margin: 0, fontSize: '.85rem',
            color: expired ? 'var(--red)' : expiringSoon ? 'var(--yellow)' : 'var(--green)',
          }}>
            {expired
              ? `Token stored, but it EXPIRED on ${fmtDate(meta.expiresAt)}. Sessions using it will fail to authenticate — generate a new one and save it below.`
              : expiringSoon
                ? `Token stored — expires ${fmtDate(meta.expiresAt)} (${days} day${days === 1 ? '' : 's'} left). Nothing renews it; generate a new one before then.`
                : `Token stored — expires ${fmtDate(meta.expiresAt)}${days !== null ? ` (${days} days left)` : ''}.`}
          </p>
        )}
      </div>

      <div style={{ marginBottom: 12 }}>
        <label style={labelStyle}>Paste a token</label>
        <FocusInput
          type="password"
          value={token}
          onChange={e => setToken(e.target.value)}
          onPaste={e => {
            // Normalise at paste time as well as at save, so a newline the
            // terminal added never reaches the field and the length the person
            // sees is the length that gets stored.
            const text = e.clipboardData?.getData('text')
            if (text && /\s/.test(text)) {
              e.preventDefault()
              setToken(stripWhitespace(text))
            }
          }}
          placeholder={meta?.present ? 'Paste a new token to replace the stored one' : 'sk-ant-oat01-…'}
          autoComplete="off"
          spellCheck={false}
          disabled={busy}
        />
      </div>

      <div className="save-row">
        <button className="btn btn-accent" onClick={save} disabled={busy || !token}>
          {busy ? 'Saving…' : meta?.present ? 'Replace token' : 'Save token'}
        </button>
        {meta?.present && (
          <button className="btn" onClick={remove} disabled={busy} style={{ marginLeft: 8 }}>Remove</button>
        )}
        {msg && (
          <span style={{ marginLeft: 10, fontSize: '.85rem', color: msg.ok ? 'var(--green)' : 'var(--red)' }}>
            {msg.ok ? `${msg.text} ✓` : `⚠️ ${msg.text}`}
          </span>
        )}
      </div>

      <div style={{
        marginTop: 16, padding: '10px 14px', borderRadius: 6,
        background: 'var(--surface2)', border: '1px solid var(--border)',
        fontSize: '.82rem', lineHeight: 1.55,
      }}>
        <strong style={{ display: 'block', marginBottom: 6 }}>How to get a token</strong>
        Run <code>claude setup-token</code> in a terminal where Claude Code is
        installed and paste what it prints. It requires a Claude <strong>Pro, Max,
        Team or Enterprise plan</strong> — a free Claude account cannot produce one.
        <div style={{ marginTop: 8, color: 'var(--dim)' }}>
          The token is valid for one year and nothing refreshes it: regenerating
          needs a browser login, so AppCrane stores the expiry and shows it above
          rather than letting you discover it as an auth failure mid-session.
        </div>
        <div style={{ marginTop: 8, color: 'var(--dim)' }}>
          Stored encrypted and write-only — no one, platform admins included, can
          read it back, and this page never displays it.
        </div>
      </div>
    </div>
  )
}
