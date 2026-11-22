// Shapes of GET /api/signin-security (server/routes/signinSecurity.js).

export interface RiskPolicy {
  new_device_mail: boolean
  lockout_threshold: number
  lockout_window_minutes: number
  lockout_base_minutes: number
  lockout_max_minutes: number
  stuffing_accounts: number
  stuffing_window_minutes: number
  stuffing_penalty_minutes: number
  stuffing_logins_per_minute: number
  stale_days: number
  stale_deactivate_days: number
}

export interface PolicyField { type: 'bool' | 'int'; min?: number; max?: number; default: number | boolean }

export interface LockedAccount {
  user_id: number
  name: string | null
  username: string | null
  email: string | null
  role: string
  scope: 'account' | 'device'
  locked_until: string
  lock_count: number
  last_ip: string | null
}

export interface FlaggedNetwork { network: string; accounts: number; flagged_at: string; until: string }

export interface StaleAccount {
  id: number
  name: string | null
  username: string | null
  email: string | null
  role: string
  last_login_at: string | null
  idle_days: number
  never_signed_in: boolean
}

export interface RiskSignal {
  id: number
  ts: string
  kind: string
  severity: 'info' | 'warning' | 'critical'
  subject_user_id: number | null
  subject_name: string | null
  subject_username: string | null
  summary: string
}

export interface RiskOverview {
  policy: RiskPolicy
  policy_fields: Record<keyof RiskPolicy, PolicyField>
  locked: LockedAccount[]
  flagged_networks: FlaggedNetwork[]
  stale: StaleAccount[]
  signals: RiskSignal[]
  geo: { available: boolean; reason: string }
}

export const POLICY_LABELS: Record<keyof RiskPolicy, string> = {
  new_device_mail: 'E-mail people when their account signs in from a new browser',
  lockout_threshold: 'Wrong passwords before an account is locked',
  lockout_window_minutes: 'Counting window (minutes)',
  lockout_base_minutes: 'First lock (minutes, doubles each time)',
  lockout_max_minutes: 'Longest lock (minutes)',
  stuffing_accounts: 'Different accounts failing from one network before it is flagged',
  stuffing_window_minutes: 'Stuffing window (minutes)',
  stuffing_penalty_minutes: 'How long a flagged network stays flagged (minutes)',
  stuffing_logins_per_minute: 'Password sign-ins per minute per address while flagged',
  stale_days: 'An account is stale after this many days without a sign-in',
  stale_deactivate_days: 'Deactivate stale accounts after this many days (0 = off)',
}
