import type { Agent, AppCraneApp, Message, SessionStatus, ShipResult } from './types'

function getToken(): string {
  return localStorage.getItem('cc_identity_token') || ''
}

function authHeaders(): Record<string, string> {
  const t = getToken()
  return t ? { Authorization: `Bearer ${t}` } : {}
}

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(init?.headers || {}),
    },
  })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text()}`)
  if (r.status === 204) return undefined as T
  return r.json() as Promise<T>
}

export const api = {
  // Apps list (primary sidebar source)
  listApps:      () => j<AppCraneApp[]>('/api/agents/apps'),

  // Session (agent) operations
  getAgent:      (id: string) => j<Agent>(`/api/agents/${id}`),
  createSession: (appSlug: string) =>
                   j<Agent>('/api/agents', { method: 'POST', body: JSON.stringify({ name: appSlug }) }),
  deleteAgent:   (id: string) => j<void>(`/api/agents/${id}`, { method: 'DELETE' }),

  messages:      (id: string) => j<Message[]>(`/api/agents/${id}/messages`),
  dispatch:      (id: string, text: string) =>
                   j<{ queued: boolean }>(`/api/agents/${id}/dispatch`,
                     { method: 'POST', body: JSON.stringify({ text }) }),
  stop:          (id: string) => j<void>(`/api/agents/${id}/stop`, { method: 'POST' }),
  resume:        (id: string) => j<Agent>(`/api/agents/${id}/resume`, { method: 'POST' }),

  shipSandbox:   (id: string, message?: string) =>
                   j<ShipResult>(`/api/agents/${id}/ship-sandbox`,
                     { method: 'POST', body: JSON.stringify({ message }) }),
  promoteProd:   (id: string) =>
                   j<{ message: string; deploy_id: number }>(`/api/agents/${id}/promote-prod`,
                     { method: 'POST' }),

  events: (
    id: string,
    onMessages: (msgs: Message[]) => void,
    onStatus: (s: SessionStatus) => void,
  ): EventSource => {
    const t = getToken()
    const url = `/api/agents/${id}/events${t ? `?token=${encodeURIComponent(t)}` : ''}`
    const es = new EventSource(url)
    es.addEventListener('messages', (e) => onMessages(JSON.parse((e as MessageEvent).data)))
    es.addEventListener('status',   (e) => onStatus(JSON.parse((e as MessageEvent).data)))
    return es
  },
}
