import { usePresence, type Viewer } from '../../hooks/usePresence'

interface Props {
  slug: string | null | undefined
}

const PALETTE = ['#3b82f6', '#8b5cf6', '#ec4899', '#f97316', '#22c55e', '#14b8a6', '#f59e0b', '#ef4444']

function colorFor(s: string): string {
  let h = 0
  for (const c of s || '') h = (h * 31 + c.charCodeAt(0)) & 0xffffffff
  return PALETTE[Math.abs(h) % PALETTE.length]
}

function initials(name: string): string {
  return (name || '?').trim().split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase()
}

/**
 * Right-side stack of avatars showing other users currently viewing this
 * app. Hover to see the full list. Hidden when nobody else is watching.
 * Same UX the portal iframe topbar shows.
 */
export function PresenceAvatars({ slug }: Props) {
  const viewers = usePresence(slug)
  if (!viewers.length) return null

  const shown = viewers.slice(0, 4)
  const label = viewers.length === 1 ? '1 other here' : `${viewers.length} others here`

  return (
    <div className="presence-wrap">
      <div className="presence-avatars">
        {shown.map((v: Viewer, i: number) => (
          <div
            key={(v.user_id ?? v.name) + ':' + i}
            className="presence-avatar"
            style={{ background: colorFor(v.name) }}
            title={v.name}
          >
            {initials(v.name)}
          </div>
        ))}
      </div>
      <span className="presence-label">{label}</span>
      <div className="presence-tooltip">
        <div className="presence-tooltip-title">Also viewing</div>
        {viewers.map((v, i) => (
          <div key={(v.user_id ?? v.name) + ':row:' + i} className="presence-tooltip-row">
            <div className="presence-tooltip-dot" />
            <span>{v.name}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
