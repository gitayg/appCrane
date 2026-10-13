import { useState, useEffect, useCallback } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'
import { CrewMap, type CrewMapData } from './CrewMap'

// Crew (v2.105.0): the platform-wide agent hub, as its owners see it.
// Shapes mirror server/services/crew.js (roster, crewLog, listBlocks).
// v2.106.0: the Map tab (CrewMap.tsx, GET /api/crew/map) and A2A tokens on My agents.

interface RosterRow {
  name: string
  owner: string
  is_mine: boolean
  runs_as: 'mcp' | 'hosted'
  description: string
  skills: string[]
  knows_about: string
  status: 'working' | 'waiting_for_input' | 'idle' | 'blocked_by_you'
  doing_now: string | null
  last_task: { title: string; state: string; at: string } | null
  last_seen_at: string | null
  blocked_by_count?: number
}

interface LogEntry {
  task_id: string
  title: string
  state: string
  direction: 'sent' | 'received' | 'own'
  from_agent: string
  from_owner: string
  to_agent: string
  to_owner: string
  preview: string | null
  message_count: number
  artifact_name: string | null
  created_at: string
  updated_at: string
  waiting_for_approval?: boolean
  awaiting_your_decision: boolean
  connection_id?: number
}

interface BlockRow { id: number; agent: string; owner: string; created_at: string; refused_since: number }
interface TokenRow { agent: string; hint: string; created_at: string; last_used_at: string | null }
interface RefusedRow { connection_id: number; agent: string; owner: string; decided_at: string | null }

type Tab = 'roster' | 'log' | 'map' | 'agents' | 'rules'
const TABS: { id: Tab; label: string }[] = [
  { id: 'roster', label: 'Roster' },
  { id: 'log',    label: 'Crew log' },
  { id: 'map',    label: 'Map' },
  { id: 'agents', label: 'My agents' },
  { id: 'rules',  label: 'Rules & blocks' },
]

function readTab(): Tab {
  const h = window.location.hash.replace('#', '')
  return (TABS.some(t => t.id === h) ? h : 'roster') as Tab
}

function when(raw: string | null | undefined): string {
  const d = serverDate(raw)
  if (isNaN(d.getTime())) return '-'
  const mins = Math.round((Date.now() - d.getTime()) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  if (mins < 24 * 60) return `${Math.round(mins / 60)} h ago`
  return d.toLocaleDateString()
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

const STATUS_LABEL: Record<RosterRow['status'], string> = {
  working: 'Working', waiting_for_input: 'Waiting for input', idle: 'Idle', blocked_by_you: 'Blocked by you',
}
const STATUS_CLASS: Record<RosterRow['status'], string> = {
  working: 'badge badge-live', waiting_for_input: 'badge badge-building', idle: 'badge badge-pending', blocked_by_you: 'badge badge-failed',
}
const STATE_CLASS: Record<string, string> = {
  submitted: 'badge badge-pending', working: 'badge badge-live', input_required: 'badge badge-building',
  completed: 'badge badge-live', failed: 'badge badge-failed', canceled: 'badge badge-offline', rejected: 'badge badge-failed',
}

function ErrorBox({ text }: { text: string }) {
  return (
    <div role="alert" style={{
      padding: '10px 12px', borderRadius: 6, marginBottom: 12,
      background: 'rgba(239,68,68,.10)', border: '1px solid var(--red)', color: 'var(--red)',
    }}>{text}</div>
  )
}

const dim = { color: 'var(--dim)' } as const
const mono = { fontFamily: 'monospace', fontSize: '.8rem' } as const
const agentCell = { fontFamily: 'monospace', fontSize: '.8rem', fontWeight: 600, whiteSpace: 'nowrap' } as const
const h3 = { margin: '22px 0 6px' } as const
const note = { color: 'var(--dim)', margin: '0 0 10px' } as const

// ── Roster ──────────────────────────────────────────────────────────────────

function RosterTab({ rows, onBlock }: { rows: RosterRow[]; onBlock: (name: string) => void }) {
  const [skill, setSkill] = useState('')
  const q = skill.trim().toLowerCase()
  const visible = q ? rows.filter(r => r.skills.some(s => s.includes(q)) || r.name.includes(q)) : rows
  return (
    <>
      <div className="filter-row">
        <input type="text" placeholder="Find by skill..." value={skill} onChange={e => setSkill(e.target.value)} aria-label="Find by skill" />
      </div>
      {rows.length === 0 && <div style={{ ...dim, padding: '20px 0' }}>No agents have registered yet. Agents register over MCP with appcrane_crew_register; hosted agents from My agents.</div>}
      {visible.length > 0 && (
        <div className="apps-table-wrap">
          <table>
            <thead>
              <tr><th>Agent</th><th>Owner</th><th>Runs as</th><th>Skills</th><th>Status</th><th>Doing now</th><th></th></tr>
            </thead>
            <tbody>
              {visible.map(r => (
                <tr key={r.name}>
                  <td style={agentCell} title={r.description || undefined}>{r.name}</td>
                  <td>{r.owner}{r.is_mine && <span style={dim}> (you)</span>}</td>
                  <td style={dim}>{r.runs_as === 'mcp' ? 'Local agent · MCP' : 'Hosted'}</td>
                  <td>{r.skills.length ? r.skills.map(s => <span key={s} className="tag" style={{ marginRight: 4 }}>{s}</span>) : <span style={dim}>-</span>}</td>
                  <td>
                    <span className={STATUS_CLASS[r.status]}>{STATUS_LABEL[r.status]}</span>
                    {r.blocked_by_count ? <span style={{ ...dim, fontSize: '.75rem', marginLeft: 6 }} title="Platform admins see how many people block an agent">blocked by {r.blocked_by_count}</span> : null}
                  </td>
                  <td style={dim}>
                    {r.status === 'blocked_by_you'
                      ? 'Requests to your agents are refused'
                      : r.doing_now
                        ? <span style={{ color: 'var(--text)' }}>{r.doing_now}</span>
                        : r.last_task ? `Last: ${r.last_task.title}, ${when(r.last_task.at)}` : '-'}
                  </td>
                  <td>
                    {!r.is_mine && r.status !== 'blocked_by_you' && (
                      <button className="btn btn-xs" onClick={() => onBlock(r.name)} title="Refuse every request from this agent to your agents, silently">Block</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {rows.length > 0 && visible.length === 0 && <div style={{ ...dim, padding: '20px 0' }}>No agent has that skill.</div>}
    </>
  )
}

// ── Crew log ────────────────────────────────────────────────────────────────

function LogTab({ entries, onDecide }: { entries: LogEntry[]; onDecide: (e: LogEntry, d: 'allow' | 'allow_once' | 'refuse' | 'block') => void }) {
  if (entries.length === 0) {
    return <div style={{ ...dim, padding: '20px 0' }}>Nothing yet. Tasks your agents send or receive appear here. History is kept for 30 days.</div>
  }
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, background: 'var(--surface)' }}>
      {entries.map(e => {
        const verb = e.direction === 'received'
          ? <><b>{e.from_agent}</b> <span style={dim}>({e.from_owner})</span> sent your agent <b>{e.to_agent}</b></>
          : e.direction === 'sent'
            ? <>Your agent <b>{e.from_agent}</b> sent <b>{e.to_agent}</b> <span style={dim}>({e.to_owner})</span></>
            : <><b>{e.from_agent}</b> sent <b>{e.to_agent}</b> <span style={dim}>(both yours)</span></>
        return (
          <div key={e.task_id} style={{ display: 'grid', gridTemplateColumns: 'minmax(70px, 90px) 1fr auto', gap: 12, padding: '11px 14px', borderBottom: '1px solid var(--border)', alignItems: 'start' }}>
            <div style={{ ...mono, ...dim }} title={serverDate(e.updated_at).toLocaleString()}>{when(e.updated_at)}</div>
            <div style={{ minWidth: 0 }}>
              {e.awaiting_your_decision && <div style={{ fontSize: '.72rem', fontWeight: 600, color: 'var(--yellow)', textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 2 }}>First contact</div>}
              <div>{verb} "{e.title}"</div>
              {e.awaiting_your_decision && (
                <div style={{ ...dim, fontSize: '.8rem', marginTop: 2 }}>
                  Agents of different people need your approval the first time. Until you decide, your agents do not see this task.
                </div>
              )}
              {e.preview && (
                <div style={{ ...dim, fontSize: '.8rem', marginTop: 4, borderLeft: '2px solid var(--border)', paddingLeft: 8, overflowWrap: 'anywhere' }}>{e.preview}</div>
              )}
              <div style={{ ...dim, fontSize: '.75rem', marginTop: 4 }}>
                {e.message_count} message{e.message_count === 1 ? '' : 's'}
                {e.artifact_name && <> · artifact: <span style={mono}>{e.artifact_name}</span></>}
                {e.waiting_for_approval && !e.awaiting_your_decision && <> · waiting for {e.to_owner} to approve</>}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end', alignItems: 'center' }}>
              {e.awaiting_your_decision ? (
                <>
                  <button className="btn btn-xs btn-accent" onClick={() => onDecide(e, 'allow')} title="Let this agent send tasks to your agents from now on">Allow</button>
                  <button className="btn btn-xs" onClick={() => onDecide(e, 'allow_once')} title="Release this task only; ask again next time">Allow once</button>
                  <button className="btn btn-xs" onClick={() => onDecide(e, 'refuse')} title="Reject this and later tasks from this agent; you can allow it later from Rules & blocks">Refuse</button>
                  <button className="btn btn-xs btn-red" onClick={() => onDecide(e, 'block')} title="Refuse everything from this agent, silently">Block</button>
                </>
              ) : (
                <span className={STATE_CLASS[e.state] || 'badge'}>{e.state.replace('_', ' ')}</span>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── My agents ───────────────────────────────────────────────────────────────

/** A token shown once, right after it was issued, with a copy button. */
function NewToken({ agent, token, onDone }: { agent: string; token: string; onDone: () => void }) {
  const [copied, setCopied] = useState(false)
  return (
    <div role="status" style={{ border: '1px solid var(--yellow)', borderRadius: 8, padding: '12px 14px', marginBottom: 14, background: 'var(--surface)' }}>
      <div style={{ fontWeight: 600, marginBottom: 4 }}>A2A token for {agent}</div>
      <div style={{ ...dim, fontSize: '.82rem', marginBottom: 8 }}>
        Shown once. Store it where the agent keeps its secrets; AppCrane keeps only a hash. The agent sends it as <code>Authorization: Bearer ...</code> to <code>/a2a</code>.
      </div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <code style={{ ...mono, overflowWrap: 'anywhere', flex: '1 1 260px' }}>{token}</code>
        <button className="btn btn-xs" onClick={() => { navigator.clipboard?.writeText(token).then(() => setCopied(true), () => {}) }}>{copied ? 'Copied' : 'Copy'}</button>
        <button className="btn btn-xs" onClick={onDone}>I stored it</button>
      </div>
    </div>
  )
}

function AgentsTab({ mine, tokens, onChanged, setError }: { mine: RosterRow[]; tokens: TokenRow[]; onChanged: () => void; setError: (s: string | null) => void }) {
  const [issued, setIssued] = useState<{ agent: string; token: string } | null>(null)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [skills, setSkills] = useState('')
  const [knowsAbout, setKnowsAbout] = useState('')
  const [card, setCard] = useState('')
  const [busy, setBusy] = useState(false)

  const register = async () => {
    setBusy(true)
    try {
      const r = await adminApi.post<{ agent: { name: string }; a2a_token?: string }>('/api/crew/agents', {
        name: name.trim() || undefined,
        description: description.trim() || undefined,
        skills: skills.trim() || undefined,
        knows_about: knowsAbout.trim() || undefined,
        card_json: card.trim() || undefined,
      })
      setName(''); setDescription(''); setSkills(''); setKnowsAbout(''); setCard('')
      if (r.a2a_token) setIssued({ agent: r.agent.name, token: r.a2a_token })
      setError(null)
      onChanged()
    } catch (e) { setError(errText(e)) } finally { setBusy(false) }
  }
  const rotate = async (n: string, hadToken: boolean) => {
    if (hadToken && !window.confirm(`Issue a new A2A token for ${n}? The current token stops working at once.`)) return
    try {
      const r = await adminApi.post<{ agent: string; token: string }>(`/api/crew/agents/${encodeURIComponent(n)}/token`, {})
      setIssued({ agent: r.agent, token: r.token }); setError(null); onChanged()
    } catch (e) { setError(errText(e)) }
  }
  const revoke = async (n: string) => {
    if (!window.confirm(`Revoke ${n}'s A2A token? Calls with it are refused at once.`)) return
    try { await adminApi.del(`/api/crew/agents/${encodeURIComponent(n)}/token`); setError(null); onChanged() } catch (e) { setError(errText(e)) }
  }
  const tokenOf = (n: string) => tokens.find(t => t.agent === n)
  const remove = async (n: string) => {
    if (!window.confirm(`Remove ${n}? Its tasks are deleted with it.`)) return
    try { await adminApi.del(`/api/crew/agents/${encodeURIComponent(n)}`); setError(null); onChanged() } catch (e) { setError(errText(e)) }
  }

  const label = { display: 'block', fontSize: '.8rem', ...dim, margin: '10px 0 4px' } as const
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 18, alignItems: 'start' }}>
      <div>
        <h3 style={{ marginTop: 0 }}>Your agents</h3>
        {issued && <NewToken agent={issued.agent} token={issued.token} onDone={() => setIssued(null)} />}
        {mine.length === 0 && <div style={dim}>You have no agents registered.</div>}
        {mine.length > 0 && (
          <div className="apps-table-wrap">
            <table>
              <thead><tr><th>Agent</th><th>Runs as</th><th>Last seen</th><th>A2A token</th><th></th></tr></thead>
              <tbody>
                {mine.map(a => {
                  const t = tokenOf(a.name)
                  return (
                    <tr key={a.name}>
                      <td style={agentCell}>{a.name}</td>
                      <td style={dim}>{a.runs_as === 'mcp' ? 'Local agent · MCP' : 'Hosted'}</td>
                      <td style={dim}>{when(a.last_seen_at)}</td>
                      <td style={dim}>
                        {t
                          ? <span title={`Issued ${serverDate(t.created_at).toLocaleString()}`}><span style={mono}>dhk_crew_{t.hint}...</span>{t.last_used_at ? `, used ${when(t.last_used_at)}` : ', never used'}</span>
                          : 'none'}
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <button className="btn btn-xs" onClick={() => rotate(a.name, !!t)} title="Issue a token this agent uses to call AppCrane's A2A endpoint">{t ? 'Rotate' : 'Issue token'}</button>{' '}
                        {t && <button className="btn btn-xs" onClick={() => revoke(a.name)}>Revoke</button>}{' '}
                        <button className="btn btn-xs btn-red" onClick={() => remove(a.name)}>Remove</button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        <p style={{ ...dim, fontSize: '.82rem', marginTop: 12 }}>
          Local agents (Claude Code, Cursor) register themselves over MCP with <code>appcrane_crew_register</code>, using your key. An agent can never do more than you may.
          Hosted agents talk A2A: each gets its own token, which acts only as that agent.
        </p>
      </div>
      <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '14px 16px', background: 'var(--surface)' }}>
        <h3 style={{ marginTop: 0 }}>Register a hosted agent</h3>
        <label style={label} htmlFor="crew-name">Name</label>
        <input id="crew-name" type="text" placeholder="release-bot" value={name} onChange={e => setName(e.target.value)} style={{ width: '100%' }} />
        <label style={label} htmlFor="crew-desc">Description</label>
        <input id="crew-desc" type="text" placeholder="Writes release notes" value={description} onChange={e => setDescription(e.target.value)} style={{ width: '100%' }} />
        <label style={label} htmlFor="crew-skills">Skills (comma-separated)</label>
        <input id="crew-skills" type="text" placeholder="release-notes, promote" value={skills} onChange={e => setSkills(e.target.value)} style={{ width: '100%' }} />
        <label style={label} htmlFor="crew-knows">Knows about (optional, helps discovery)</label>
        <input id="crew-knows" type="text" placeholder="release process, changelogs" value={knowsAbout} onChange={e => setKnowsAbout(e.target.value)} style={{ width: '100%' }} />
        <label style={label} htmlFor="crew-card">Or paste its Agent Card (JSON)</label>
        <textarea id="crew-card" rows={5} placeholder='{"name": "release-bot", "skills": [{"id": "release-notes"}]}' value={card} onChange={e => setCard(e.target.value)} style={{ width: '100%', ...mono }} />
        <p style={{ ...dim, fontSize: '.78rem', margin: '6px 0 10px' }}>
          Paste the card's contents; AppCrane does not fetch card URLs. Others' agents can send it tasks only after you approve them. Registering shows the agent's A2A token once.
        </p>
        <button className="btn btn-accent" onClick={register} disabled={busy || (!name.trim() && !card.trim())}>{busy ? 'Registering...' : 'Register'}</button>
      </div>
    </div>
  )
}

// ── Rules & blocks ──────────────────────────────────────────────────────────

function RulesTab({ blocks, refused, onUnblock, onAllow }: { blocks: BlockRow[]; refused: RefusedRow[]; onUnblock: (id: number) => void; onAllow: (connectionId: number) => void }) {
  return (
    <>
      <h3 style={{ ...h3, marginTop: 0 }}>Standing rules</h3>
      <p style={note}>Standing rules arrive in a later release. Until then, every first contact from another person's agent asks you.</p>

      <h3 style={h3}>Blocked agents</h3>
      <p style={note}>Their requests to your agents are refused automatically. You are never notified about them.</p>
      {blocks.length === 0 ? <div style={dim}>You have not blocked any agent.</div> : (
        <table>
          <thead><tr><th>Agent</th><th>Owner</th><th>Blocked</th><th>Refused since</th><th></th></tr></thead>
          <tbody>
            {blocks.map(b => (
              <tr key={b.id}>
                <td style={agentCell}>{b.agent}</td>
                <td>{b.owner}</td>
                <td style={dim}>{serverDate(b.created_at).toLocaleDateString()}</td>
                <td style={dim}>{b.refused_since}</td>
                <td><button className="btn btn-xs" onClick={() => onUnblock(b.id)}>Unblock</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h3 style={h3}>Refused agents</h3>
      <p style={note}>You refused these agents' first contact. Their tasks are rejected until you allow them.</p>
      {refused.length === 0 ? <div style={dim}>None.</div> : (
        <table>
          <thead><tr><th>Agent</th><th>Owner</th><th>Refused</th><th></th></tr></thead>
          <tbody>
            {refused.map(r => (
              <tr key={r.connection_id}>
                <td style={agentCell}>{r.agent}</td>
                <td>{r.owner}</td>
                <td style={dim}>{when(r.decided_at)}</td>
                <td><button className="btn btn-xs" onClick={() => onAllow(r.connection_id)}>Allow</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  )
}

// ── Page ────────────────────────────────────────────────────────────────────

export function Crew() {
  const [tab, setTab] = useState<Tab>(readTab)
  const [rosterRows, setRosterRows] = useState<RosterRow[]>([])
  const [entries, setEntries] = useState<LogEntry[]>([])
  const [blocks, setBlocks] = useState<BlockRow[]>([])
  const [refused, setRefused] = useState<RefusedRow[]>([])
  const [tokens, setTokens] = useState<TokenRow[]>([])
  const [mapData, setMapData] = useState<CrewMapData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fn = () => setTab(readTab())
    window.addEventListener('hashchange', fn)
    return () => window.removeEventListener('hashchange', fn)
  }, [])

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([
      adminApi.get<{ agents: RosterRow[] }>('/api/crew/roster'),
      adminApi.get<{ entries: LogEntry[] }>('/api/crew/log'),
      adminApi.get<{ blocks: BlockRow[]; refused: RefusedRow[] }>('/api/crew/blocks'),
      adminApi.get<{ tokens: TokenRow[] }>('/api/crew/agents'),
      adminApi.get<CrewMapData>('/api/crew/map'),
    ])
      .then(([r, l, b, a, m]) => {
        setRosterRows(r.agents || [])
        setEntries(l.entries || [])
        setBlocks(b.blocks || [])
        setRefused(b.refused || [])
        setTokens(a.tokens || [])
        setMapData(m)
        setError(null)
      })
      .catch(e => setError(errText(e)))
      .finally(() => setLoading(false))
  }, [])
  useEffect(() => { load() }, [load])

  const act = async (fn: () => Promise<unknown>) => {
    try { await fn(); setError(null); load() } catch (e) { setError(errText(e)) }
  }
  const decide = (e: LogEntry, decision: 'allow' | 'allow_once' | 'refuse' | 'block') => {
    if (decision === 'block' && !window.confirm(`Block ${e.from_agent}? Its requests to your agents will be refused silently.`)) return
    act(() => adminApi.post(`/api/crew/connections/${e.connection_id}/decision`, { decision, task_id: e.task_id }))
  }
  const block = (name: string) => {
    if (!window.confirm(`Block ${name}? Its requests to your agents will be refused silently.`)) return
    act(() => adminApi.post('/api/crew/blocks', { agent: name }))
  }

  const mine = rosterRows.filter(r => r.is_mine)
  const working = rosterRows.filter(r => r.status === 'working').length
  const waiting = entries.filter(e => e.awaiting_your_decision).length

  return (
    <div className="container">
      <h2>Crew</h2>
      <p style={{ ...dim, marginTop: -6 }}>
        {rosterRows.length} agent{rosterRows.length === 1 ? '' : 's'} registered · {working} working now
        {waiting > 0 && <> · <b style={{ color: 'var(--yellow)' }}>{waiting} decision{waiting === 1 ? '' : 's'} waiting for you</b></>}
        {blocks.length > 0 && <> · {blocks.length} blocked</>}
      </p>

      <div className="phase-tab-strip" role="tablist">
        {TABS.map(t => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={'phase-tab' + (tab === t.id ? ' active' : '')}
            onClick={() => { window.location.hash = t.id; setTab(t.id) }}
          >
            {t.label}
            {t.id === 'log' && waiting > 0 && <span className="sidebar-link-badge" style={{ marginLeft: 4 }}>{waiting}</span>}
          </button>
        ))}
        <button className="btn btn-sm" style={{ marginLeft: 'auto', alignSelf: 'center' }} onClick={load} disabled={loading}>
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {error && <ErrorBox text={error} />}

      {tab === 'roster' && <RosterTab rows={rosterRows} onBlock={block} />}
      {tab === 'log' && <LogTab entries={entries} onDecide={decide} />}
      {tab === 'map' && <CrewMap data={mapData} />}
      {tab === 'agents' && <AgentsTab mine={mine} tokens={tokens} onChanged={load} setError={setError} />}
      {tab === 'rules' && (
        <RulesTab
          blocks={blocks}
          refused={refused}
          onUnblock={id => act(() => adminApi.del(`/api/crew/blocks/${id}`))}
          onAllow={id => act(() => adminApi.post(`/api/crew/connections/${id}/decision`, { decision: 'allow' }))}
        />
      )}
    </div>
  )
}
