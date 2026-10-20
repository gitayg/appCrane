import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

export interface TaskCounts { open_assigned: number; unread: number }

// Polls /api/tasks/count for a nav or topbar badge. Refreshes every minute and
// when the Tasks page announces a change (window event 'appcrane:tasks-changed').
export function useTaskCount(intervalMs = 60_000): TaskCounts {
  const [counts, setCounts] = useState<TaskCounts>({ open_assigned: 0, unread: 0 })
  useEffect(() => {
    let alive = true
    const load = () => {
      adminApi.get<TaskCounts>('/api/tasks/count')
        .then(c => { if (alive) setCounts({ open_assigned: c.open_assigned || 0, unread: c.unread || 0 }) })
        .catch(() => {})
    }
    load()
    const t = window.setInterval(load, intervalMs)
    window.addEventListener('appcrane:tasks-changed', load)
    return () => { alive = false; window.clearInterval(t); window.removeEventListener('appcrane:tasks-changed', load) }
  }, [intervalMs])
  return counts
}

export function announceTasksChanged() {
  window.dispatchEvent(new Event('appcrane:tasks-changed'))
}
