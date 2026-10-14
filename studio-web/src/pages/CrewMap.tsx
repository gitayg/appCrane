import { useMemo, useState } from 'react'
import { serverDate } from '../utils/serverDate'

// Crew → Map (v2.106.0): who sends tasks to whom, drawn from GET /api/crew/map.
// The server sends counts only (never titles or bodies) and decides which
// tasks each viewer may count; this component only lays them out.
//
// Layout: a deterministic circle, agents grouped by owner then name, so the
// same roster always draws the same picture and one person's agents sit
// together. Plain SVG, no graph library: studio-web has none, and 2-50 nodes
// on a circle need no force simulation.

export interface MapNode { name: string; owner: string; owner_key: number; is_mine: boolean; runs_as: 'mcp' | 'hosted' }
export interface MapEdge {
  from: string
  to: string
  total: number
  pending_first_contact: number
  last_activity: string | null
  states: Record<'submitted' | 'working' | 'input_required' | 'completed' | 'failed' | 'canceled' | 'rejected', number>
  blocked?: boolean
  refused?: boolean
}
export interface CrewMapData { window_days: number; nodes: MapNode[]; edges: MapEdge[] }

type Outcome = 'done' | 'open' | 'trouble' | 'pending' | 'stopped' | 'canceled'

const OUTCOME_COLOR: Record<Outcome, string> = {
  done: 'var(--green)',
  open: 'var(--accent)',
  trouble: 'var(--red)',
  pending: 'var(--yellow)',
  stopped: 'var(--red)',
  canceled: 'var(--dim)',
}
const OUTCOME_LABEL: Record<Outcome, string> = {
  done: 'Mostly completed',
  open: 'Mostly in progress',
  trouble: 'Mostly failed',
  pending: 'Waiting on a first contact',
  stopped: 'Blocked, refused or rejected',
  canceled: 'Mostly canceled',
}

/** Rejected-only edges and edges the viewer blocked or refused. */
function isStopped(e: MapEdge): boolean {
  return !!e.blocked || !!e.refused || (e.total > 0 && e.states.rejected === e.total)
}

function outcomeOf(e: MapEdge): Outcome {
  if (isStopped(e)) return 'stopped'
  const s = e.states
  const live = e.total - s.rejected
  if (e.pending_first_contact > 0 && e.pending_first_contact * 2 >= live) return 'pending'
  const open = s.submitted + s.working + s.input_required - e.pending_first_contact
  const best = [
    ['done', s.completed], ['open', open], ['trouble', s.failed], ['canceled', s.canceled],
  ] as [Outcome, number][]
  best.sort((a, b) => b[1] - a[1])
  return best[0][1] > 0 ? best[0][0] : 'open'
}

function ownerColor(key: number): string {
  // Golden-angle hues: distinct for any number of owners, readable on the
  // dark and the light admin theme at this lightness.
  return `hsl(${Math.round((key * 137.508) % 360)} 62% 58%)`
}

function width(total: number): number {
  return Math.min(10, 1.5 + 2 * Math.log2(1 + total))
}

function when(raw: string | null): string {
  if (!raw) return '-'
  const d = serverDate(raw)
  return isNaN(d.getTime()) ? '-' : d.toLocaleString()
}

const NODE_R = 13

const MAP_MIN_W = 460

export function CrewMap({ data }: { data: CrewMapData | null }) {
  const [showStopped, setShowStopped] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const [hovered, setHovered] = useState<string | null>(null)

  const layout = useMemo(() => {
    const nodes = [...(data?.nodes || [])].sort((a, b) => a.owner_key - b.owner_key || a.name.localeCompare(b.name))
    const n = nodes.length
    const R = Math.max(120, Math.min(340, n * 18))
    // Labels sit outside the circle, left or right of each node: they need
    // width, not much height.
    const padX = 135
    const padY = 45
    const w = 2 * (R + padX)
    const h = 2 * (R + padY)
    const pos = new Map<string, { x: number; y: number; angle: number }>()
    nodes.forEach((node, i) => {
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(n, 1)
      pos.set(node.name, { x: w / 2 + R * Math.cos(angle), y: h / 2 + R * Math.sin(angle), angle })
    })
    return { nodes, pos, w, h }
  }, [data])

  if (!data) return <div style={{ color: 'var(--dim)', padding: '20px 0' }}>Loading the map...</div>
  if (data.nodes.length === 0) return <div style={{ color: 'var(--dim)', padding: '20px 0' }}>No agents have registered yet.</div>

  const edges = data.edges.filter((e) => showStopped || !isStopped(e))
  const hiddenCount = data.edges.length - edges.length
  const focus = hovered || selected
  const pairs = new Set(data.edges.map((e) => `${e.from}>${e.to}`))
  const nodeByName = new Map(data.nodes.map((n) => [n.name, n]))

  const stats = (name: string) => {
    const out = data.edges.filter((e) => e.from === name)
    const inc = data.edges.filter((e) => e.to === name)
    const sum = (list: MapEdge[]) => list.reduce((n, e) => n + e.total, 0)
    return { sent: sum(out), received: sum(inc), out, inc }
  }

  const { pos, w: vw, h: vh } = layout
  const sel = selected ? nodeByName.get(selected) : null
  const selStats = selected ? stats(selected) : null

  return (
    <div>
      <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
        <span style={{ color: 'var(--dim)', fontSize: '.85rem' }}>
          Tasks sent between agents in the last {data.window_days} days. Arrow thickness is the number of tasks. Counts only: what a task is about stays with the people involved.
        </span>
        <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: '.85rem', marginLeft: 'auto' }}>
          <input type="checkbox" checked={showStopped} onChange={(e) => setShowStopped(e.target.checked)} />
          Show blocked, refused and rejected{hiddenCount > 0 && !showStopped ? ` (${hiddenCount} hidden)` : ''}
        </label>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(220px, 280px)', gap: 16, alignItems: 'start' }} className="crew-map-grid">
        {/* A phone would shrink the drawing until the 11-13 px labels were
            7-8 px; below MAP_MIN_W it scrolls inside this box instead. */}
        <div style={{ border: '1px solid var(--border)', borderRadius: 8, background: 'var(--surface)', overflowX: 'auto', overflowY: 'hidden' }}>
          <svg
            viewBox={`0 0 ${vw} ${vh}`}
            style={{ width: '100%', minWidth: MAP_MIN_W, height: 'auto', display: 'block', maxHeight: '75vh' }}
            role="img"
            aria-label={`Communication map of ${data.nodes.length} agents and ${edges.length} connections`}
            onClick={() => setSelected(null)}
          >

            {edges.map((e) => {
              const a = pos.get(e.from)
              const b = pos.get(e.to)
              if (!a || !b) return null
              const o = outcomeOf(e)
              // Curve every edge a little to its left, so A→B and B→A are two
              // visible arrows rather than one line drawn twice.
              const dx = b.x - a.x
              const dy = b.y - a.y
              const bend = pairs.has(`${e.to}>${e.from}`) ? 0.18 : 0.08
              const mx = (a.x + b.x) / 2 - dy * bend
              const my = (a.y + b.y) / 2 + dx * bend
              // Shorten both ends to the node rim along the curve's tangents.
              const t1 = Math.hypot(mx - a.x, my - a.y) || 1
              const t2 = Math.hypot(b.x - mx, b.y - my) || 1
              const sx = a.x + ((mx - a.x) / t1) * NODE_R
              const sy = a.y + ((my - a.y) / t1) * NODE_R
              const sw = width(e.total)
              // The arrowhead is drawn as its own triangle, sized from the
              // stroke so it stays visible on a thick edge and never swallows
              // the target node (an SVG marker scales with the stroke).
              const ux = (b.x - mx) / t2
              const uy = (b.y - my) / t2
              const headLen = 7 + sw * 1.3
              const headHalf = headLen * 0.55
              const tipX = b.x - ux * (NODE_R + 1)
              const tipY = b.y - uy * (NODE_R + 1)
              const baseX = tipX - ux * headLen
              const baseY = tipY - uy * headLen
              const ex = tipX - ux * headLen * 0.7
              const ey = tipY - uy * headLen * 0.7
              const head = `${tipX},${tipY} ${baseX - uy * headHalf},${baseY + ux * headHalf} ${baseX + uy * headHalf},${baseY - ux * headHalf}`
              const touches = !focus || e.from === focus || e.to === focus
              const s = e.states
              const label = `${e.from} → ${e.to}: ${e.total} task${e.total === 1 ? '' : 's'}`
                + ` (completed ${s.completed}, in progress ${s.submitted + s.working + s.input_required}, failed ${s.failed}, canceled ${s.canceled}`
                + `${s.rejected ? `, rejected ${s.rejected}` : ''})`
                + `${e.pending_first_contact ? `; ${e.pending_first_contact} waiting on a first contact` : ''}`
                + `${e.blocked ? '; you blocked this agent' : e.refused ? '; you refused this agent' : ''}`
                + `; last activity ${when(e.last_activity)}`
              return (
                <g key={`${e.from}>${e.to}`} opacity={touches ? 0.9 : 0.1} style={{ transition: 'opacity 150ms' }}>
                  <title>{label}</title>
                  <path
                    d={`M${sx},${sy} Q${mx},${my} ${ex},${ey}`}
                    fill="none"
                    stroke={OUTCOME_COLOR[o]}
                    strokeWidth={sw}
                    strokeLinecap="butt"
                    strokeDasharray={o === 'stopped' ? '6 5' : undefined}
                  />
                  <polygon points={head} fill={OUTCOME_COLOR[o]} />
                </g>
              )
            })}

            {layout.nodes.map((n) => {
              const p = pos.get(n.name)!
              const right = Math.cos(p.angle) >= 0
              const lx = p.x + Math.cos(p.angle) * (NODE_R + 8)
              const ly = p.y + Math.sin(p.angle) * (NODE_R + 8)
              const dimmed = focus && focus !== n.name && !data.edges.some((e) => (e.from === focus && e.to === n.name) || (e.to === focus && e.from === n.name))
              return (
                <g
                  key={n.name}
                  tabIndex={0}
                  role="button"
                  aria-label={`${n.name}, owned by ${n.owner}${n.is_mine ? ' (you)' : ''}`}
                  aria-pressed={selected === n.name}
                  onMouseEnter={() => setHovered(n.name)}
                  onMouseLeave={() => setHovered(null)}
                  onFocus={() => setHovered(n.name)}
                  onBlur={() => setHovered(null)}
                  onClick={(ev) => { ev.stopPropagation(); setSelected(selected === n.name ? null : n.name) }}
                  onKeyDown={(ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); setSelected(selected === n.name ? null : n.name) } }}
                  style={{ cursor: 'pointer', opacity: dimmed ? 0.35 : 1, transition: 'opacity 150ms', outline: 'none' }}
                >
                  <circle cx={p.x} cy={p.y} r={NODE_R} fill={ownerColor(n.owner_key)} stroke={selected === n.name ? 'var(--text)' : 'var(--bg)'} strokeWidth={selected === n.name ? 3 : 2} />
                  {n.is_mine && <circle cx={p.x} cy={p.y} r={4} fill="var(--bg)" />}
                  <text x={lx} y={ly - 3} textAnchor={right ? 'start' : 'end'} fontSize="13" fontFamily="monospace" fontWeight={600} fill="var(--text)">{n.name}</text>
                  <text x={lx} y={ly + 12} textAnchor={right ? 'start' : 'end'} fontSize="11" fill="var(--dim)">{n.owner}{n.is_mine ? ' (you)' : ''}</text>
                </g>
              )
            })}
            {edges.length === 0 && (
              <text x={vw / 2} y={vh / 2} textAnchor="middle" fontSize="13" fill="var(--dim)">No tasks between agents in the last {data.window_days} days.</text>
            )}
          </svg>
        </div>

        <div style={{ fontSize: '.85rem' }}>
          {sel && selStats ? (
            <div style={{ border: '1px solid var(--border)', borderRadius: 8, background: 'var(--surface)', padding: '12px 14px' }}>
              <div style={{ fontFamily: 'monospace', fontWeight: 600 }}>{sel.name}</div>
              <div style={{ color: 'var(--dim)', marginBottom: 8 }}>{sel.owner}{sel.is_mine ? ' (you)' : ''} · {sel.runs_as === 'mcp' ? 'Local agent · MCP' : 'Hosted'}</div>
              <div>Sent {selStats.sent} · received {selStats.received}</div>
              {[['Sent to', selStats.out, 'to'], ['Received from', selStats.inc, 'from']].map(([title, list, key]) => (
                (list as MapEdge[]).length > 0 && (
                  <div key={title as string} style={{ marginTop: 10 }}>
                    <div style={{ color: 'var(--dim)', fontSize: '.75rem', textTransform: 'uppercase', letterSpacing: '.04em' }}>{title as string}</div>
                    {(list as MapEdge[]).map((e) => (
                      <div key={`${e.from}>${e.to}`} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, padding: '3px 0' }}>
                        <span style={{ fontFamily: 'monospace' }}>
                          <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 4, background: OUTCOME_COLOR[outcomeOf(e)], marginRight: 6 }} />
                          {key === 'to' ? e.to : e.from}
                        </span>
                        <span style={{ color: 'var(--dim)' }}>{e.total}{e.states.completed ? ` · ${e.states.completed} done` : ''}{e.blocked ? ' · blocked' : e.refused ? ' · refused' : ''}</span>
                      </div>
                    ))}
                  </div>
                )
              ))}
            </div>
          ) : (
            <div style={{ color: 'var(--dim)' }}>Hover or select an agent to see its connections. Hover an arrow for its counts.</div>
          )}
          <div style={{ marginTop: 14 }}>
            {(Object.keys(OUTCOME_LABEL) as Outcome[]).filter((o) => o !== 'stopped' || showStopped).map((o) => (
              <div key={o} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '2px 0' }}>
                <svg width="28" height="8" aria-hidden="true"><line x1="0" y1="4" x2="28" y2="4" stroke={OUTCOME_COLOR[o]} strokeWidth="3" strokeDasharray={o === 'stopped' ? '6 5' : undefined} /></svg>
                <span style={{ color: 'var(--dim)' }}>{OUTCOME_LABEL[o]}</span>
              </div>
            ))}
            <div style={{ color: 'var(--dim)', marginTop: 6, fontSize: '.78rem' }}>Node colour is the owner. A dot in the middle marks your agents. Blocks are shown only to the person who placed them.</div>
          </div>
        </div>
      </div>
    </div>
  )
}
