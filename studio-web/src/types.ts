export type MessageRole = 'user' | 'agent' | 'mcp' | 'error' | 'queued' | 'status'

export interface Message {
  id: string
  role: MessageRole
  text: string
  ts: number
  streaming?: boolean
  tokens?: number
  duration_ms?: number
  cost_usd?: number
  plan_mode?: boolean
}

export interface Agent {
  id: string
  name: string
  tags: string[]
  dir: string
  githubTokenName: string
  claudeProfile: string
  claudeModel: string
  claudeArgs: string
  autoGitPull: boolean
  gitUseAideToken: boolean
  tasks: { id: string; text: string; done: boolean; createdAt: string }[]
  notes: string
  permissionsAlwaysAllow: Record<string, string[]>
  env: Record<string, string>
  useMCP: boolean
  claudeSessionId?: string
  manuallyFlagged: boolean
  // AppCrane extensions
  appSlug?: string
  branchName?: string
  sessionStatus?: 'idle' | 'active' | 'paused' | 'shipped' | 'error'
  costTokens?: number
  costUsdCents?: number
  createdAt?: string
  shippedAt?: string
}

export interface SessionStatus {
  isStreaming: boolean
  queuedTasks: { text: string; planMode: boolean }[]
  hasUncommittedChanges: boolean
  uncommittedCount: number
  lastError: string | null
}

export interface ShipResult {
  message: string
  deployed: boolean
  deploy_id?: number
  branch?: string
}
