import { adminApi } from '../adminApi'

export interface ViewAsStatus {
  active: boolean
  role?: string
  app_slug?: string | null
  app_name?: string | null
  expires_at?: string
  real_role: string
}

export interface ViewAsOptions {
  platform_roles: string[]
  apps: { slug: string; name: string; roles: string[] }[]
  current: ViewAsStatus
}

export const ROLE_LABELS: Record<string, string> = {
  owner: 'App owner',
  admin: 'App admin',
  user: 'Member',
  none: 'No role',
}

export function roleLabel(role: string | undefined, platformWide: boolean): string {
  if (!role) return ''
  if (platformWide && role === 'user') return 'User'
  return ROLE_LABELS[role] || role
}

export const getViewAs = () => adminApi.get<ViewAsStatus>('/api/auth/view-as')
export const getViewAsOptions = () => adminApi.get<ViewAsOptions>('/api/auth/view-as-options')
export const startViewAs = (role: string, appSlug?: string) =>
  adminApi.post<ViewAsStatus>('/api/auth/view-as', appSlug ? { role, app_slug: appSlug } : { role })
export const stopViewAs = () => adminApi.post<ViewAsStatus>('/api/auth/stop-viewing-as', {})

// Every cached role decision in the SPA (useMe, per-app tiles) was made as the
// real user, so a change of view reloads the page rather than patching state.
export function reloadView() {
  window.location.reload()
}
