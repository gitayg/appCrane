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

export type HealthStatus = 'healthy' | 'down' | 'unknown'

export interface AppSession {
  id: string
  status: 'idle' | 'active' | 'paused' | 'shipped' | 'error'
  branchName: string | null
  createdAt: string
  shippedAt: string | null
}

export interface AppCraneApp {
  id: number
  name: string
  slug: string
  description: string | null
  github_url: string | null
  source_type: string
  category: string | null
  has_claude_credentials?: boolean
  claude_credentials_expires_at?: string | number | null
  production: {
    health: { status: HealthStatus }
    deploy: { version: string; status: string; finished_at: string } | null
  }
  sandbox: {
    health: { status: HealthStatus }
  }
  currentSession: AppSession | null
}
